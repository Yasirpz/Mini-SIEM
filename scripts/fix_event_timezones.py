"""
Rewrite events that were stored in a monitored host's local time as UTC.

Until this was fixed, the Windows collector sent `TimeCreated` verbatim and
the Linux one read journald's epoch through the local clock, so every
collected event was stored on the *monitored machine's* wall clock while the
rest of the database — and the dashboard, which converts from UTC for display
— assumed UTC. The visible symptom was events dated hours into the future for
a host east of the SIEM, and hours into the past for one west of it.

New collections are correct. This script repairs the rows already stored.

    python scripts/fix_event_timezones.py                  # report only
    python scripts/fix_event_timezones.py --apply          # rewrite them
    python scripts/fix_event_timezones.py --host 3 --offset +5 --apply

How the offset is worked out
----------------------------
`ingested_at` was always written with the SIEM's own UTC clock, so it is
trustworthy. For any event, `timestamp - ingested_at` is the host's UTC offset
minus however old the record already was when it was collected. An event can
never be logged *after* it was ingested, so the largest of those differences
for a host is the closest thing to its offset, and rounding it to the nearest
quarter of an hour lands on a real timezone — including the half and quarter
hour zones such as India (+5:30) and Nepal (+5:45).

That estimate is shown, never assumed: run without --apply first, and use
--offset to state the value yourself if a host's history makes the guess a bad
one.

Alerts move with the events they came from
------------------------------------------
An alert is stamped with the time of the event that triggered it, not with
the clock reading at the moment the rule fired -- see `DetectionEngine`, which
sets `timestamp=candidate.event.timestamp`. So an event stored on the wrong
clock raised an alert on the wrong clock, and repairing only the event would
leave the Alerts page contradicting the Events page about when one incident
happened.

Both are therefore shifted together. An alert whose time does *not* match its
event was not copied from it, so it is left exactly as it is: this script only
corrects times it can show are wrong.
"""
import argparse
import sys
from collections import defaultdict
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from app.extensions import db
from app.models import Alert, Event, Host

# Timezones exist on quarter-hour boundaries, so rounding to one turns a
# noisy estimate into a real offset instead of something like 4h 59m.
ROUND_TO_SECONDS = 15 * 60

# Real UTC offsets run from -12:00 to +14:00. An estimate outside that range
# is not a timezone at all: it means the events were not collected near the
# time they happened, which is exactly what an imported sample log looks like
# -- one dated last week and stored today reads as an offset of days. The
# estimate is refused rather than offered, because the whole method rests on
# an assumption those rows break.
MIN_OFFSET_SECONDS = -12 * 3600
MAX_OFFSET_SECONDS = 14 * 3600


def is_plausible_offset(seconds):
    """Whether an estimated offset lands somewhere a timezone actually is."""
    return MIN_OFFSET_SECONDS <= seconds <= MAX_OFFSET_SECONDS


def estimate_offset_seconds(events):
    """
    The host's apparent UTC offset, in seconds, or None if it cannot be told.

    Returns the largest `timestamp - ingested_at` seen, rounded to the nearest
    quarter hour. See the module docstring for why the maximum is the right
    statistic rather than the mean.
    """
    differences = [
        (event.timestamp - event.ingested_at).total_seconds()
        for event in events
        if event.timestamp and event.ingested_at
    ]
    if not differences:
        return None

    widest = max(differences)
    return int(round(widest / ROUND_TO_SECONDS) * ROUND_TO_SECONDS)


def alerts_following(events, alerts_by_event):
    """
    The alerts that took their timestamp from one of these events.

    See the module docstring: an alert copies the triggering event's time, so
    the two have to be corrected together. An alert whose time differs from
    its event's was not copied from it -- a rule that timestamps its own
    findings, or a row already repaired -- and is excluded rather than moved
    on a guess.
    """
    following = []
    for event in events:
        for alert in alerts_by_event.get(event.id, ()):
            if alert.timestamp == event.timestamp:
                following.append(alert)
    return following


def describe(seconds):
    """Render an offset the way a timezone is usually written."""
    sign = '+' if seconds >= 0 else '-'
    seconds = abs(seconds)
    return f"UTC{sign}{seconds // 3600:02d}:{(seconds % 3600) // 60:02d}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--apply', action='store_true',
        help='rewrite the timestamps (without this, nothing is changed)',
    )
    parser.add_argument(
        '--host', type=int, default=None,
        help='only this host id (default: every host with stored events)',
    )
    parser.add_argument(
        '--offset', type=float, default=None,
        help='the host offset in hours, e.g. +5 or -7, instead of estimating it',
    )
    args = parser.parse_args()

    if args.offset is not None and args.host is None:
        parser.error('--offset applies to one host, so it needs --host as well')

    app = create_app()
    with app.app_context():
        query = Event.query
        if args.host is not None:
            query = query.filter_by(host_id=args.host)

        by_host = defaultdict(list)
        for event in query.all():
            by_host[event.host_id].append(event)

        if not by_host:
            print('No stored events to examine.')
            return

        # Grouped once rather than queried per host, so a database with a long
        # history does not turn this into one query per host -- and so the
        # lookup never depends on how many ids fit in a SQL IN clause.
        alerts_by_event = defaultdict(list)
        for alert in Alert.query.filter(Alert.event_id.isnot(None)).all():
            alerts_by_event[alert.event_id].append(alert)

        total_shifted = 0
        total_alerts = 0

        for host_id, events in sorted(by_host.items()):
            host = db.session.get(Host, host_id)
            name = host.hostname if host else f'host {host_id}'

            if args.offset is not None:
                offset = int(round(args.offset * 3600))
                source = 'given'
            else:
                offset = estimate_offset_seconds(events)
                source = 'estimated'

            if offset is None:
                print(f'{name}: cannot tell - no event has an ingestion time.')
                continue

            if source == 'estimated' and not is_plausible_offset(offset):
                print(
                    f'{name}: {len(events)} event(s) estimate to '
                    f'{describe(offset)}, which is not a timezone. They were '
                    f'already old when they were stored - imported sample logs '
                    f'usually are - so the gap is age, not offset, and nothing '
                    f'is assumed. Pass --host {host_id} --offset <hours> if '
                    f'you know it.'
                )
                continue

            if offset == 0:
                print(f'{name}: {len(events)} event(s) already on UTC, nothing to do.')
                continue

            print(
                f'{name}: {len(events)} event(s) look like {describe(offset)} '
                f'({source}); shifting them by {-offset / 3600:+g} hour(s).'
            )
            shift = timedelta(seconds=offset)
            newest = max(events, key=lambda e: e.timestamp or e.ingested_at)
            print(
                f'    newest event {newest.timestamp} '
                f'-> {newest.timestamp - shift}'
            )

            following = alerts_following(events, alerts_by_event)
            if following:
                print(
                    f'    {len(following)} alert(s) inherited those times '
                    f'and move with them.'
                )

            if args.apply:
                for event in events:
                    if event.timestamp:
                        event.timestamp -= shift
                for alert in following:
                    alert.timestamp -= shift
                total_shifted += len(events)
                total_alerts += len(following)

        if args.apply:
            db.session.commit()
            print(
                f'\nRewrote {total_shifted} event timestamp(s) '
                f'and {total_alerts} alert timestamp(s).'
            )
        else:
            print('\nNothing was changed. Re-run with --apply to rewrite them.')


if __name__ == '__main__':
    main()
