"""
Every stored time is UTC.

This is a cross-cutting rule rather than a property of any one collector, so
it is tested in one place. The rule exists because a monitored machine keeps
its event log in *its own* local time: a Windows PC in Pakistan writes 01:35
for the same instant a laptop in California writes 13:35 the previous day.
Storing whichever of those two numbers happened to arrive would make the two
hosts impossible to correlate, would break the time-window arithmetic in the
detection rules, and -- because the dashboard converts stored times from UTC
for display -- would put events hours into the future on screen.

The regression these tests lock down was exactly that: the Windows query sent
`TimeCreated` verbatim, so events collected from a host five hours ahead of
the SIEM appeared five hours ahead of the present.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app.models import utcnow
from app.services.log_collector import LogCollector


# ---------------------------------------------------------------------------
# Windows: the conversion happens on the machine that owns the clock
# ---------------------------------------------------------------------------

def test_the_windows_query_converts_event_times_to_utc(app):
    """
    Only the monitored machine knows its own offset, so it does the
    conversion. Reading TimeCreated verbatim is what produced future-dated
    events on the dashboard.
    """
    cmd = LogCollector.build_windows_query()

    assert '$rec.TimeCreated.ToUniversalTime()' in cmd
    # The naive form must be gone entirely, not merely accompanied.
    assert "$rec.TimeCreated.ToString(" not in cmd


def test_the_start_time_watermark_is_sent_as_utc(app):
    """
    The stored watermark is UTC but Get-WinEvent matches against local
    timestamps, so the kind is stated explicitly and converted on the host
    being queried -- which for a remote host means *its* offset, not ours.
    """
    cmd = LogCollector.build_windows_query(
        last_fetch_time=datetime(2026, 8, 15, 8, 0, 0)
    )

    assert '2026-08-15 08:00:00' in cmd
    assert 'SpecifyKind' in cmd
    assert '[System.DateTimeKind]::Utc' in cmd
    assert '.ToLocalTime()' in cmd


def test_a_windows_event_time_is_stored_exactly_as_sent():
    """The query already converted it, so parsing must not shift it again."""
    parsed = LogCollector.parse_windows_event({
        'Timestamp': '2026-08-20 20:35:12',
        'EventId': 4625,
        'TargetUserName': 'yasir',
        'IpAddress': '203.0.113.9',
        'LogonType': '2',
    })

    assert parsed['timestamp'] == datetime(2026, 8, 20, 20, 35, 12)


def test_an_unreadable_windows_time_falls_back_to_utc_not_local():
    """
    A record whose time cannot be read still has to sort alongside the ones
    that can, so the fallback uses the same clock everything else does.
    """
    parsed = LogCollector.parse_windows_event({
        'Timestamp': 'not a date',
        'EventId': 4625,
        'TargetUserName': 'yasir',
    })

    drift = abs((parsed['timestamp'] - utcnow()).total_seconds())
    assert drift < 60, 'fallback timestamp is not on the UTC clock'


# ---------------------------------------------------------------------------
# Linux: journald hands over epoch microseconds, which are already UTC
# ---------------------------------------------------------------------------

class _FakeSSH:
    def __init__(self, stdout):
        self._stdout = stdout

    def run(self, cmd):
        self.command = cmd
        return self._stdout, ''


def test_a_journald_event_is_stored_in_utc():
    """
    __REALTIME_TIMESTAMP is epoch microseconds. Reading it back through the
    local clock silently re-labelled every Linux event with the SIEM server's
    own offset.
    """
    moment = datetime(2026, 8, 20, 20, 35, 12, tzinfo=timezone.utc)
    micros = int(moment.timestamp() * 1_000_000)
    line = (
        '{"__REALTIME_TIMESTAMP": "%d", '
        '"MESSAGE": "Failed password for root from 203.0.113.9 port 22 ssh2"}'
        % micros
    )

    logs = LogCollector.get_linux_logs(_FakeSSH(line))

    assert len(logs) == 1
    assert logs[0]['timestamp'] == moment.replace(tzinfo=None)


def test_the_journalctl_window_is_asked_for_in_utc():
    """
    journalctl reads a bare timestamp in the host's local time, so the stored
    UTC watermark has to say so or the window slides by the host's offset.
    """
    ssh = _FakeSSH('')
    LogCollector.get_linux_logs(ssh, last_fetch_time=datetime(2026, 8, 15, 8, 0, 0))

    assert '--since "2026-08-15 08:00:00 UTC"' in ssh.command


# ---------------------------------------------------------------------------
# The watermark written after a successful collection
# ---------------------------------------------------------------------------

class _FakeWinClient:
    """Stands in for WinClient, returning one canned Security-log record."""

    def __init__(self, record):
        self._record = record

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def security_log_status(self):
        return True, 'READABLE'

    def pnp_audit_status(self):
        return 'UNKNOWN', 'not probed in tests'

    @staticmethod
    def is_elevated():
        return True

    def run_ps(self, cmd, timeout=120):
        import json as _json

        self.last_command = cmd
        return _json.dumps(self._record)


def test_the_collection_watermark_is_utc(app, monkeypatch):
    """
    `LogSource.last_fetch` becomes the next query's StartTime, so writing it
    on the local clock made the window wrong by the server's offset -- on a
    laptop set to US Pacific time while collecting from a host in Pakistan,
    by twelve hours.
    """
    from app.extensions import db
    from app.models import COLLECT_LOCAL, Host, LogSource
    from app.services import collection as collection_service

    host = Host(hostname='Lab-PC', ip_address='10.0.0.9', os_type='WINDOWS',
                collection_method=COLLECT_LOCAL)
    db.session.add(host)
    db.session.commit()

    monkeypatch.setattr(
        collection_service,
        'WinClient',
        lambda: _FakeWinClient({
            'Timestamp': '2026-08-20 20:35:12',
            'EventId': 4625,
            'TargetUserName': 'yasir',
            'IpAddress': '203.0.113.9',
            'LogonType': '2',
        }),
    )

    payload, status = collection_service.collect_host(host)
    assert status == 200, payload

    source = LogSource.query.filter_by(host_id=host.id).first()
    drift = abs((source.last_fetch - utcnow()).total_seconds())
    assert drift < 60, 'the collection watermark is not on the UTC clock'


# ---------------------------------------------------------------------------
# Repairing rows that were stored before the fix
# ---------------------------------------------------------------------------

def _stored(timestamp, ingested_at):
    """A stand-in for an Event, carrying only the two fields that matter."""
    from types import SimpleNamespace

    return SimpleNamespace(timestamp=timestamp, ingested_at=ingested_at)


def test_a_hosts_offset_is_recovered_from_its_ingestion_times():
    """
    `ingested_at` was always written on the SIEM's own UTC clock, so the gap
    between it and the stored event time reveals the host's offset. A host
    five hours ahead produces events that appear five hours in the future.
    """
    from scripts.fix_event_timezones import estimate_offset_seconds

    ingested = datetime(2026, 8, 20, 20, 35, 39)
    events = [
        # Collected seconds after it happened: the gap is the whole offset.
        _stored(datetime(2026, 8, 21, 1, 35, 12), ingested),
        # Older records collected in the same batch understate it, which is
        # why the widest gap is the one that counts.
        _stored(datetime(2026, 8, 20, 23, 8, 36), ingested),
    ]

    assert estimate_offset_seconds(events) == 5 * 3600


def test_a_host_behind_utc_is_recovered_too():
    """The same arithmetic has to work in the other direction."""
    from scripts.fix_event_timezones import estimate_offset_seconds

    events = [_stored(
        datetime(2026, 8, 20, 13, 38, 20),
        datetime(2026, 8, 20, 20, 38, 42),
    )]

    assert estimate_offset_seconds(events) == -7 * 3600


def test_an_offset_is_rounded_to_a_real_timezone():
    """
    Collection lag means the raw gap is never exactly whole. Rounding to a
    quarter hour lands on an offset a timezone actually uses -- including the
    half and quarter hour ones such as India and Nepal.
    """
    from scripts.fix_event_timezones import estimate_offset_seconds

    events = [_stored(
        datetime(2026, 8, 21, 2, 5, 1),
        datetime(2026, 8, 20, 20, 35, 39),
    )]

    assert estimate_offset_seconds(events) == 5 * 3600 + 30 * 60


def test_a_host_with_no_ingestion_times_is_reported_rather_than_guessed():
    from scripts.fix_event_timezones import estimate_offset_seconds

    assert estimate_offset_seconds([_stored(datetime(2026, 8, 20, 1, 0, 0), None)]) is None
    assert estimate_offset_seconds([]) is None


def test_an_offset_is_described_the_way_a_timezone_is_written():
    from scripts.fix_event_timezones import describe

    assert describe(5 * 3600) == 'UTC+05:00'
    assert describe(-7 * 3600) == 'UTC-07:00'
    assert describe(5 * 3600 + 30 * 60) == 'UTC+05:30'


# ---------------------------------------------------------------------------
# What the dashboard displays: Pakistan Standard Time
# ---------------------------------------------------------------------------
#
# Storage stays UTC -- that is what the tests above are about. Display is a
# separate decision, and leaving it to the viewing browser was not good
# enough: an operator has to be able to state when an incident happened, and
# "whatever this machine's clock is set to" is not an answer. The zone is
# therefore pinned in configuration and published to the page, where
# app/static/js/dom.js reads it.

def test_the_display_timezone_defaults_to_pakistan():
    """
    The lab, the monitored hosts and the analysts are all in Pakistan, so a
    freshly installed Mini-SIEM must read in PKT without anyone configuring
    anything.
    """
    from config import Config

    assert Config.DISPLAY_TIMEZONE == 'Asia/Karachi'


def test_an_empty_setting_still_means_pakistan(monkeypatch):
    """
    .env.example ships the key with no value, so "copy the example to .env"
    sets it to the empty string. Reading that as "use the browser's zone"
    would switch Pakistan time off for everyone who followed the setup
    instructions -- which is the one group that must not be caught out by it.
    """
    import importlib

    import config

    monkeypatch.setenv('MINISIEM_DISPLAY_TIMEZONE', '')
    reloaded = importlib.reload(config)
    try:
        assert reloaded.Config.DISPLAY_TIMEZONE == 'Asia/Karachi'
    finally:
        monkeypatch.delenv('MINISIEM_DISPLAY_TIMEZONE')
        importlib.reload(config)


def test_the_display_timezone_reaches_the_page(auth_client):
    """
    The front end cannot ask Flask for its configuration, so the zone travels
    in a meta tag. If this stops being rendered every timestamp silently falls
    back to the browser's own zone.
    """
    html = auth_client.get('/').get_data(as_text=True)

    assert '<meta name="display-timezone" content="Asia/Karachi">' in html


def test_the_display_timezone_can_be_handed_back_to_the_browser(monkeypatch):
    """
    A deployment outside Pakistan needs a way out, and "unset the variable"
    cannot be it -- an unset variable is what selects the default. The literal
    word "local" is that way out.
    """
    import importlib

    import config

    monkeypatch.setenv('MINISIEM_DISPLAY_TIMEZONE', 'local')
    reloaded = importlib.reload(config)
    try:
        assert reloaded.Config.DISPLAY_TIMEZONE == ''
    finally:
        monkeypatch.delenv('MINISIEM_DISPLAY_TIMEZONE')
        importlib.reload(config)


def test_a_named_zone_is_honoured(monkeypatch):
    import importlib

    import config

    monkeypatch.setenv('MINISIEM_DISPLAY_TIMEZONE', 'Europe/London')
    reloaded = importlib.reload(config)
    try:
        assert reloaded.Config.DISPLAY_TIMEZONE == 'Europe/London'
    finally:
        monkeypatch.delenv('MINISIEM_DISPLAY_TIMEZONE')
        importlib.reload(config)


def test_pakistan_time_is_five_hours_ahead_of_what_is_stored():
    """
    The arithmetic the dashboard performs, checked against the zone database
    rather than a hard-coded five. Pakistan does not currently observe summer
    time, but stating the check this way means the test still describes the
    truth if that ever changes.
    """
    from zoneinfo import ZoneInfo

    stored = datetime(2026, 8, 21, 20, 35, 42, tzinfo=timezone.utc)

    displayed = stored.astimezone(ZoneInfo('Asia/Karachi'))

    assert displayed.strftime('%d %b %Y, %H:%M:%S') == '22 Aug 2026, 01:35:42'
