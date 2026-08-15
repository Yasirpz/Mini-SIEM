"""
Windows Security log collection (Event IDs 4625 and 4624).

Covers the real-host demonstration path: reading this machine's own Security
log, normalizing both failed and successful logons, and confirming that a
successful logon never contributes to the R-01 brute-force rule.
"""
import json
from datetime import datetime, timedelta

import pytest

from app.extensions import db
from app.models import (
    Event,
    Host,
    EVT_SUCCESSFUL_LOGIN,
    EVT_WIN_FAILED_LOGIN,
    utcnow,
)
from app.services.detection import DetectionEngine
from app.services.log_analyzer import LogAnalyzer
from app.services.log_collector import LogCollector


def win_record(event_id, user='yasir', ip='-', logon_type='2',
               workstation='YASIR', timestamp='2026-08-15 10:15:00'):
    """Build a record shaped like the PowerShell collector's JSON output."""
    return {
        'Timestamp': timestamp,
        'EventId': event_id,
        'TargetUserName': user,
        'IpAddress': ip,
        'LogonType': logon_type,
        'WorkstationName': workstation,
    }


class FakeWinClient:
    """Stands in for WinClient, returning canned PowerShell output."""

    def __init__(self, payload, readable=True):
        self.payload = payload
        self.readable = readable
        self.last_command = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def can_read_security_log(self):
        return self.readable

    def run_ps(self, cmd):
        self.last_command = cmd
        if self.payload is None:
            return ''
        return json.dumps(self.payload)


# ---------------------------------------------------------------------------
# Parsing a single record
# ---------------------------------------------------------------------------

def test_event_4625_becomes_a_windows_failed_login():
    parsed = LogCollector.parse_windows_event(win_record(4625, user='administrator'))

    assert parsed['alert_type'] == EVT_WIN_FAILED_LOGIN
    assert parsed['user'] == 'administrator'
    assert 'logon failure' in parsed['message']
    assert '4625' in parsed['message']


def test_event_4624_becomes_a_successful_login():
    parsed = LogCollector.parse_windows_event(win_record(4624, user='yasir'))

    assert parsed['alert_type'] == EVT_SUCCESSFUL_LOGIN
    assert parsed['user'] == 'yasir'
    assert 'successful logon' in parsed['message']
    assert '4624' in parsed['message']


def test_event_id_is_accepted_as_a_string():
    """PowerShell's JSON sometimes quotes the event id."""
    parsed = LogCollector.parse_windows_event(win_record('4625'))
    assert parsed['alert_type'] == EVT_WIN_FAILED_LOGIN


def test_unrelated_event_id_is_skipped_not_mislabelled():
    assert LogCollector.parse_windows_event(win_record(4672)) is None


def test_missing_event_id_is_skipped():
    record = win_record(4625)
    del record['EventId']
    assert LogCollector.parse_windows_event(record) is None


def test_non_dict_input_is_skipped():
    assert LogCollector.parse_windows_event('not a record') is None


@pytest.mark.parametrize('raw_ip', ['-', '', '::1', '127.0.0.1', None])
def test_local_sign_in_is_marked_as_console(raw_ip):
    """A sign-in at the keyboard must not look like a remote attacker."""
    parsed = LogCollector.parse_windows_event(win_record(4625, ip=raw_ip))
    assert parsed['source_ip'] == 'LOCAL_CONSOLE'


def test_remote_source_address_is_preserved():
    parsed = LogCollector.parse_windows_event(win_record(4625, ip='192.168.100.42'))
    assert parsed['source_ip'] == '192.168.100.42'


def test_logon_type_is_described_in_the_message():
    parsed = LogCollector.parse_windows_event(win_record(4624, logon_type='10'))
    assert 'remote interactive' in parsed['message']


def test_workstation_name_is_included_when_present():
    parsed = LogCollector.parse_windows_event(win_record(4625, workstation='LAB-PC'))
    assert 'LAB-PC' in parsed['message']


def test_placeholder_workstation_is_omitted():
    parsed = LogCollector.parse_windows_event(win_record(4625, workstation='-'))
    assert ' from -' not in parsed['message']


def test_blank_username_falls_back_to_unknown():
    parsed = LogCollector.parse_windows_event(win_record(4625, user='   '))
    assert parsed['user'] == 'UNKNOWN'


def test_timestamp_is_parsed():
    parsed = LogCollector.parse_windows_event(
        win_record(4625, timestamp='2026-08-15 09:30:15')
    )
    assert parsed['timestamp'] == datetime(2026, 8, 15, 9, 30, 15)


def test_unparseable_timestamp_falls_back_to_now():
    parsed = LogCollector.parse_windows_event(win_record(4625, timestamp='not a date'))
    assert isinstance(parsed['timestamp'], datetime)


def test_raw_record_is_retained_as_evidence():
    parsed = LogCollector.parse_windows_event(win_record(4625, user='yasir'))
    assert 'yasir' in parsed['raw_log']


# ---------------------------------------------------------------------------
# The PowerShell query
# ---------------------------------------------------------------------------

def test_query_requests_both_event_ids(app):
    cmd = LogCollector.build_windows_query()
    assert '4625,4624' in cmd


def test_query_filters_successful_logons_to_interactive_types(app):
    cmd = LogCollector.build_windows_query()
    # Failures always pass; successes must match an interactive logon type.
    assert "'2','7','10','11'" in cmd.replace(' ', '')
    assert 'SYSTEM' in cmd
    assert "-notlike '*$'" in cmd


def test_query_uses_a_start_time_for_incremental_collection(app):
    cmd = LogCollector.build_windows_query(
        last_fetch_time=datetime(2026, 8, 15, 8, 0, 0)
    )
    assert 'StartTime' in cmd
    assert '2026-08-15 08:00:00' in cmd


def test_query_without_last_fetch_has_no_start_time(app):
    assert 'StartTime' not in LogCollector.build_windows_query()


# ---------------------------------------------------------------------------
# Collecting a batch
# ---------------------------------------------------------------------------

def test_collection_handles_a_list_of_records(app):
    client = FakeWinClient([win_record(4625), win_record(4624)])
    logs = LogCollector.get_windows_logs(client)

    assert [entry['alert_type'] for entry in logs] == [
        EVT_WIN_FAILED_LOGIN, EVT_SUCCESSFUL_LOGIN
    ]


def test_collection_handles_a_single_record(app):
    """PowerShell emits a bare object rather than an array for one result."""
    logs = LogCollector.get_windows_logs(FakeWinClient(win_record(4625)))
    assert len(logs) == 1


def test_collection_returns_empty_on_no_output(app):
    assert LogCollector.get_windows_logs(FakeWinClient(None)) == []


def test_collection_survives_invalid_json(app):
    class BadClient(FakeWinClient):
        def run_ps(self, cmd):
            return '{not json'

    assert LogCollector.get_windows_logs(BadClient(None)) == []


def test_collection_survives_a_powershell_failure(app):
    class ExplodingClient(FakeWinClient):
        def run_ps(self, cmd):
            raise OSError('powershell not found')

    assert LogCollector.get_windows_logs(ExplodingClient(None)) == []


def test_unrelated_records_are_dropped_from_the_batch(app):
    client = FakeWinClient([win_record(4625), win_record(4672), win_record(4624)])
    logs = LogCollector.get_windows_logs(client)
    assert len(logs) == 2


# ---------------------------------------------------------------------------
# Detection behaviour: successes must not feed the brute-force rule
# ---------------------------------------------------------------------------

def _windows_host():
    entry = Host(hostname='Yasir', ip_address='192.168.100.68', os_type='WINDOWS')
    db.session.add(entry)
    db.session.commit()
    return entry


def test_successful_logons_do_not_trigger_r01(app):
    """
    Ten successful sign-ins in a minute are normal activity, not an attack.
    R-01 must ignore them entirely.
    """
    host = _windows_host()
    base = utcnow()

    events = [
        {
            'timestamp': base + timedelta(seconds=i * 5),
            'alert_type': EVT_SUCCESSFUL_LOGIN,
            'source_ip': '192.168.100.42',
            'user': 'yasir',
            'message': 'Windows successful logon',
            'raw_log': '{}',
        }
        for i in range(10)
    ]

    result = LogAnalyzer.ingest(events, host.id, origin='COLLECTED')

    assert result['events_stored'] == 10
    assert result['alerts']['R-01'] == 0
    assert result['alerts']['total'] == 0


def test_windows_failures_still_trigger_r01_at_the_existing_threshold(app):
    """The real rule is unchanged: five failures inside the window fire it."""
    host = _windows_host()
    base = utcnow()

    events = [
        {
            'timestamp': base + timedelta(seconds=i * 20),
            'alert_type': EVT_WIN_FAILED_LOGIN,
            'source_ip': '192.168.100.42',
            'user': 'yasir',
            'message': 'Windows logon failure',
            'raw_log': '{}',
        }
        for i in range(5)
    ]

    result = LogAnalyzer.ingest(events, host.id, origin='COLLECTED')
    assert result['alerts']['R-01'] == 1


def test_four_windows_failures_stay_below_the_threshold(app):
    host = _windows_host()
    base = utcnow()

    events = [
        {
            'timestamp': base + timedelta(seconds=i * 20),
            'alert_type': EVT_WIN_FAILED_LOGIN,
            'source_ip': '192.168.100.42',
            'user': 'yasir',
            'message': 'Windows logon failure',
            'raw_log': '{}',
        }
        for i in range(4)
    ]

    result = LogAnalyzer.ingest(events, host.id, origin='COLLECTED')
    assert result['alerts']['R-01'] == 0


def test_console_failures_do_not_raise_remote_attacker_alerts(app):
    """
    Failures typed at the keyboard carry LOCAL_CONSOLE, which the engine
    treats as non-routable — so a mistyped password on your own laptop does
    not register as a remote brute-force attempt.
    """
    host = _windows_host()
    base = utcnow()

    events = [
        {
            'timestamp': base + timedelta(seconds=i * 20),
            'alert_type': EVT_WIN_FAILED_LOGIN,
            'source_ip': 'LOCAL_CONSOLE',
            'user': 'yasir',
            'message': 'Windows logon failure',
            'raw_log': '{}',
        }
        for i in range(6)
    ]

    result = LogAnalyzer.ingest(events, host.id, origin='COLLECTED')

    assert result['events_stored'] == 6      # still recorded as evidence
    assert result['alerts']['R-01'] == 0     # but not treated as an attack


def test_mixed_collection_stores_both_outcomes(app):
    """The exact demo: wrong, wrong, correct."""
    host = _windows_host()
    logs = LogCollector.get_windows_logs(FakeWinClient([
        win_record(4625, timestamp='2026-08-15 10:00:00'),
        win_record(4625, timestamp='2026-08-15 10:00:20'),
        win_record(4624, timestamp='2026-08-15 10:00:40'),
    ]))

    result = LogAnalyzer.ingest(logs, host.id, origin='COLLECTED')
    assert result['events_stored'] == 3

    stored = {e.event_type for e in Event.query.filter_by(host_id=host.id).all()}
    assert stored == {EVT_WIN_FAILED_LOGIN, EVT_SUCCESSFUL_LOGIN}


# ---------------------------------------------------------------------------
# The collection endpoint
# ---------------------------------------------------------------------------

def test_collect_endpoint_requires_authentication(client, app):
    host = _windows_host()
    response = client.post(f'/api/hosts/{host.id}/logs')
    assert response.status_code == 401


def test_collect_endpoint_reports_missing_elevation(auth_client, app, monkeypatch):
    """
    Without Administrator rights the Security log is unreadable. The API must
    say so rather than silently reporting "no new entries".
    """
    host = _windows_host()

    import app.blueprints.api.hosts as hosts_module
    monkeypatch.setattr(
        hosts_module, 'WinClient', lambda: FakeWinClient(None, readable=False)
    )

    response = auth_client.post(f'/api/hosts/{host.id}/logs')
    assert response.status_code == 403
    assert 'Administrator' in response.get_json()['error']


def test_collect_endpoint_stores_collected_events(auth_client, app, monkeypatch):
    host = _windows_host()

    import app.blueprints.api.hosts as hosts_module
    monkeypatch.setattr(
        hosts_module,
        'WinClient',
        lambda: FakeWinClient([
            win_record(4625, timestamp='2026-08-15 11:00:00'),
            win_record(4624, timestamp='2026-08-15 11:00:30'),
        ]),
    )

    response = auth_client.post(f'/api/hosts/{host.id}/logs')
    assert response.status_code == 200

    payload = response.get_json()
    assert payload['events_stored'] == 2
    assert 'Collected 2 log entries' in payload['message']
    assert Event.query.filter_by(host_id=host.id).count() == 2


def test_repeated_collection_does_not_duplicate_events(auth_client, app, monkeypatch):
    host = _windows_host()

    import app.blueprints.api.hosts as hosts_module
    monkeypatch.setattr(
        hosts_module,
        'WinClient',
        lambda: FakeWinClient([win_record(4625, timestamp='2026-08-15 11:00:00')]),
    )

    auth_client.post(f'/api/hosts/{host.id}/logs')
    second = auth_client.post(f'/api/hosts/{host.id}/logs').get_json()

    assert second['events_stored'] == 0
    assert second['duplicates_skipped'] == 1
    assert Event.query.filter_by(host_id=host.id).count() == 1
