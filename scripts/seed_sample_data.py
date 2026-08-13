"""
Seed Mini-SIEM with sample data for a self-contained demonstration.

Creates two monitored hosts, imports the bundled Linux sample log against
both, and runs the detection rules. Importing the same source IP against two
hosts is what makes rule R-04 (Multiple Host Attempt) fire.

The suspicious address used throughout is 203.0.113.50, which belongs to the
RFC 5737 documentation range — it is reserved for examples and never routes to
a real machine.

Usage:
    python scripts/seed_sample_data.py
    python scripts/seed_sample_data.py --ban              # mark the IP BANNED (R-03 fires)
    python scripts/seed_sample_data.py --reset            # clear events/alerts first
    python scripts/seed_sample_data.py --reset-registry   # also clear the IP registry

Note: --reset keeps the Threat Intelligence registry, because it holds an
administrator's decisions rather than collected data. If an address was
previously marked BANNED, rule R-03 will therefore fire on the very first
run. Use --reset-registry for a genuinely clean starting state.
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from app.extensions import db
from app.models import Alert, Event, Host, IPRegistry, utcnow
from app.services.detection import DetectionEngine
from app.services.log_analyzer import LogAnalyzer
from app.services.sample_loader import SampleLoader

SAMPLE_HOSTS = [
    {
        'hostname': 'Lab-PC',
        'ip_address': '127.0.0.1',
        'os_type': 'LINUX',
        'description': 'Primary lab workstation used for the demonstration',
    },
    {
        'hostname': 'Lab-Server',
        'ip_address': '192.168.56.10',
        'os_type': 'LINUX',
        'description': 'Secondary host, used to demonstrate rule R-04',
    },
]

SUSPICIOUS_IP = '203.0.113.50'
SAMPLE_FILE = 'linux_auth_sample.log'


def ensure_hosts():
    """Create the demo hosts if they don't already exist."""
    hosts = []
    for spec in SAMPLE_HOSTS:
        host = Host.query.filter_by(ip_address=spec['ip_address']).first()
        if host:
            print(f"  Host '{host.hostname}' already exists.")
        else:
            host = Host(**spec)
            db.session.add(host)
            db.session.commit()
            print(f"  Created host '{host.hostname}' ({host.ip_address}).")
        hosts.append(host)
    return hosts


def ensure_threat_ip(ban=False):
    """Add the demo suspicious IP to the registry."""
    status = 'BANNED' if ban else 'UNKNOWN'
    entry = IPRegistry.query.filter_by(ip_address=SUSPICIOUS_IP).first()

    if entry:
        if ban and entry.status != 'BANNED':
            entry.status = 'BANNED'
            db.session.commit()
            print(f"  Updated {SUSPICIOUS_IP} to BANNED.")
        else:
            print(f"  {SUSPICIOUS_IP} already in the registry as {entry.status}.")
        return entry

    entry = IPRegistry(
        ip_address=SUSPICIOUS_IP,
        status=status,
        source='Seed script (RFC 5737 documentation range)',
        notes='Synthetic attacker used for the FYP demonstration',
        date_added=utcnow(),
        last_seen=utcnow(),
    )
    db.session.add(entry)
    db.session.commit()
    print(f"  Added {SUSPICIOUS_IP} to the Threat Intel registry as {status}.")
    return entry


def reset_data(include_registry=False):
    """
    Remove stored events and alerts so the demo starts clean.

    The Threat Intelligence registry is kept by default, since it represents
    an administrator's accumulated decisions rather than collected data. Pass
    include_registry=True to clear it too — needed to reproduce the
    "before banning" figures quoted in the reports, because a registry entry
    left at BANNED would make rule R-03 fire immediately.
    """
    alerts = Alert.query.delete()
    events = Event.query.delete()
    db.session.commit()
    print(f"  Cleared {events} event(s) and {alerts} alert(s).")

    if include_registry:
        entries = IPRegistry.query.delete()
        db.session.commit()
        print(f"  Cleared {entries} Threat Intel registry entr(y/ies).")


def load_sample(app):
    """Read the bundled sample log file."""
    path = Path(app.config['SAMPLES_FOLDER']) / SAMPLE_FILE
    if not path.exists():
        print(f"ERROR: sample file not found at {path}")
        return None
    return path.read_text(encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description='Seed Mini-SIEM with demo data.')
    parser.add_argument('--ban', action='store_true',
                        help=f"mark {SUSPICIOUS_IP} as BANNED so rule R-03 fires")
    parser.add_argument('--reset', action='store_true',
                        help='delete existing events and alerts first')
    parser.add_argument('--reset-registry', action='store_true',
                        help='also clear the Threat Intel registry (implies --reset); '
                             'use this to reproduce the "before banning" figures')
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        if args.reset or args.reset_registry:
            print('Resetting existing data...')
            reset_data(include_registry=args.reset_registry)

        print('Creating monitored hosts...')
        hosts = ensure_hosts()

        print('Updating the Threat Intelligence registry...')
        ensure_threat_ip(ban=args.ban)

        content = load_sample(app)
        if content is None:
            return 1

        events, detected_format = SampleLoader.parse(content, filename=SAMPLE_FILE)
        print(f"\nParsed {len(events)} events from {SAMPLE_FILE} ({detected_format}).")

        print('Importing against each host...')
        for host in hosts:
            result = LogAnalyzer.ingest(events, host.id, origin='IMPORTED')
            print(
                f"  {host.hostname}: stored {result['events_stored']} new event(s), "
                f"skipped {result['duplicates_skipped']} duplicate(s)."
            )

        # Ingest already applies the rules per host; this final pass picks up
        # cross-host correlations (R-04) now that every host has its events.
        print('\nRunning the detection engine over all stored events...')
        DetectionEngine.run()

        # Report what is actually stored, not just what the last pass added —
        # the engine is idempotent, so a re-run legitimately reports zero new.
        print('\nDetection summary (total alerts stored):')
        for rule_id, name in (
            ('R-01', 'Failed Login         '),
            ('R-02', 'Invalid User         '),
            ('R-03', 'Threat IP Match      '),
            ('R-04', 'Multiple Host Attempt'),
        ):
            print(f"  {rule_id} {name} : {Alert.query.filter_by(rule_id=rule_id).count()} alert(s)")

        print('\n  By severity:')
        for level in ('HIGH', 'MEDIUM', 'LOW'):
            print(f"    {level:<7}: {Alert.query.filter_by(severity=level).count()}")

        print(f"\n  Events in database : {Event.query.count()}")
        print(f"  Alerts in database : {Alert.query.count()}")

        # Only nudge about R-03 when it genuinely has not fired — the address
        # may already be banned from an earlier run.
        if Alert.query.filter_by(rule_id='R-03').count() == 0:
            print(
                f"\nTip: rule R-03 stays at zero until {SUSPICIOUS_IP} is marked BANNED.\n"
                '     Either re-run this script with --ban, or mark it in the\n'
                '     Configuration page and press "Re-run detection" on the Alerts page.'
            )

        print('\nDone. Log in and open the dashboard to review the results.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
