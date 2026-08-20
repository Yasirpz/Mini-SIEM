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
    EVT_USB_DEVICE_CONNECTED,
    EVT_WIN_FAILED_LOGIN,
    utcnow,
)
from app.services.detection import DetectionEngine
from app.services.log_analyzer import LogAnalyzer
from app.services.log_collector import LogCollector
from app.services.win_client import PowerShellError, WinClient


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


def ndjson(records):
    """Render records the way the PowerShell query does: one JSON per line."""
    return '\n'.join(json.dumps(record) for record in records)


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

    def security_log_status(self):
        return self.readable, 'READABLE' if self.readable else 'Access is denied'

    @staticmethod
    def is_elevated():
        return True

    def run_ps(self, cmd, timeout=120):
        self.last_command = cmd
        if self.payload is None:
            return ''
        if isinstance(self.payload, list):
            return ndjson(self.payload)
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


@pytest.mark.parametrize('event_id, expected', [
    (4740, 'ACCOUNT_LOCKOUT'),
    (4648, 'EXPLICIT_CREDENTIALS'),
    (4672, 'ADMIN_LOGON'),
    (4720, 'ACCOUNT_CREATED'),
    (4722, 'ACCOUNT_ENABLED'),
    (4724, 'PASSWORD_RESET'),
    (4732, 'GROUP_MEMBER_ADDED'),
    (1102, 'AUDIT_LOG_CLEARED'),
])
def test_wider_security_events_are_classified(event_id, expected):
    parsed = LogCollector.parse_windows_event(win_record(event_id))
    assert parsed['alert_type'] == expected
    assert str(event_id) in parsed['message']


def test_an_unrecognised_event_id_is_skipped_not_mislabelled():
    """An event the collector does not understand must be dropped, not guessed."""
    assert LogCollector.parse_windows_event(win_record(4689)) is None


def test_account_management_events_fall_back_to_the_acting_user():
    """4720 and friends may leave TargetUserName empty; the actor still matters."""
    record = win_record(4720, user='')
    record['SubjectUserName'] = 'attacker'

    parsed = LogCollector.parse_windows_event(record)
    assert parsed['user'] == 'attacker'


def test_new_event_types_do_not_feed_the_brute_force_rule(app):
    """
    A lockout is the *consequence* of failures R-01 has already counted.
    Letting it feed the rule would double-count the same incident.
    """
    from app.models import FAILURE_EVENT_TYPES

    for event_type in ('ACCOUNT_LOCKOUT', 'ADMIN_LOGON', 'AUDIT_LOG_CLEARED',
                       'ACCOUNT_CREATED', 'EXPLICIT_CREDENTIALS'):
        assert event_type not in FAILURE_EVENT_TYPES


def test_query_requests_every_supported_event_id(app):
    cmd = LogCollector.build_windows_query()
    for event_id in (4625, 4624, 4740, 4648, 4672, 4720, 4722, 4724, 4732, 1102):
        assert str(event_id) in cmd


def test_administrative_events_bypass_the_interactive_logon_filter(app):
    """
    The interactive filter exists to suppress service-account noise on logon
    events. Applying it to account-management events would discard them,
    since they carry no logon type at all.
    """
    cmd = LogCollector.build_windows_query()
    assert '$keep = $true' in cmd


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
    # Machine accounts end in '$' and log on constantly.
    assert "EndsWith('$')" in cmd


def test_query_uses_a_start_time_for_incremental_collection(app):
    cmd = LogCollector.build_windows_query(
        last_fetch_time=datetime(2026, 8, 15, 8, 0, 0)
    )
    assert 'StartTime' in cmd
    assert '2026-08-15 08:00:00' in cmd


def test_query_without_last_fetch_has_no_start_time(app):
    assert 'StartTime' not in LogCollector.build_windows_query()


def test_query_emits_one_json_object_per_record(app):
    """
    NDJSON avoids ConvertTo-Json's object-vs-array ambiguity, where a batch of
    exactly one event would otherwise parse differently from every other batch.
    """
    cmd = LogCollector.build_windows_query()
    assert 'ConvertTo-Json -Compress' in cmd
    assert 'foreach ($rec in $records)' in cmd


def test_query_treats_an_empty_match_as_success_not_failure(app):
    """Get-WinEvent errors when nothing matches; that must not look like a fault."""
    cmd = LogCollector.build_windows_query()
    assert "notmatch 'No events were found'" in cmd
    assert 'exit 0' in cmd


def test_query_reports_real_errors_on_stderr(app):
    cmd = LogCollector.build_windows_query()
    assert '[Console]::Error.WriteLine' in cmd
    assert 'exit 2' in cmd


# ---------------------------------------------------------------------------
# WinClient behaviour
# ---------------------------------------------------------------------------

def test_no_events_found_is_not_treated_as_an_error():
    """An empty Security log must return empty output, not raise."""
    class EmptyClient(WinClient):
        def run_ps_raw(self, cmd, timeout=120):
            return '', 'No events were found that match the specified criteria.', 1

    assert EmptyClient().run_ps('anything') == ''


def test_a_real_stderr_message_is_raised():
    class DeniedClient(WinClient):
        def run_ps_raw(self, cmd, timeout=120):
            return '', 'Attempted to perform an unauthorized operation.', 1

    with pytest.raises(PowerShellError, match='unauthorized'):
        DeniedClient().run_ps('anything')


def test_output_is_kept_even_when_the_exit_code_is_nonzero():
    """
    PowerShell exits non-zero for a pipeline that merely produced nothing.
    Discarding stdout in that case would throw away real collected events.
    """
    class NoisyClient(WinClient):
        def run_ps_raw(self, cmd, timeout=120):
            return '{"EventId": 4625}', 'some warning', 1

    assert NoisyClient().run_ps('anything') == '{"EventId": 4625}'


def test_security_log_status_reports_readable():
    class OkClient(WinClient):
        def run_ps_raw(self, cmd, timeout=120):
            return 'READABLE', '', 0

    ok, detail = OkClient().security_log_status()
    assert ok is True
    assert 'READABLE' in detail


def test_an_empty_security_log_still_counts_as_readable():
    class EmptyLogClient(WinClient):
        def run_ps_raw(self, cmd, timeout=120):
            return 'EMPTY', '', 0

    ok, _ = EmptyLogClient().security_log_status()
    assert ok is True


def test_security_log_status_surfaces_the_real_reason():
    class DeniedClient(WinClient):
        def run_ps_raw(self, cmd, timeout=120):
            return 'ERROR: Attempted to perform an unauthorized operation.', '', 0

    ok, detail = DeniedClient().security_log_status()
    assert ok is False
    assert 'unauthorized' in detail
    assert 'ERROR:' not in detail  # prefix stripped for display


# ---------------------------------------------------------------------------
# The collection endpoint
# ---------------------------------------------------------------------------

def test_collection_endpoint_explains_why_the_log_is_unreadable(auth_client, app, monkeypatch):
    """
    A refused Security log must produce an actionable message naming the real
    cause, not a bare instruction to run as Administrator.
    """
    host = Host(hostname='Yasir', ip_address='192.168.100.68', os_type='WINDOWS')
    db.session.add(host)
    db.session.commit()

    from app.services import collection as collection_service

    class DeniedClient:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def security_log_status(self):
            return False, 'Attempted to perform an unauthorized operation.'

        @staticmethod
        def is_elevated():
            return False

    # The collect route delegates to app.services.collection, so the
    # patch has to land where the pipeline actually looks the name up.
    monkeypatch.setattr(collection_service, 'WinClient', DeniedClient)

    response = auth_client.post(f'/api/hosts/{host.id}/logs')
    payload = response.get_json()

    assert response.status_code == 403
    assert 'unauthorized' in payload['detail']
    assert payload['server_is_elevated'] is False
    assert 'Run as Administrator' in payload['hint']


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
    """A one-event batch must parse the same way as a many-event batch."""
    logs = LogCollector.get_windows_logs(FakeWinClient(win_record(4625)))
    assert len(logs) == 1


def test_collection_returns_empty_on_no_output(app):
    assert LogCollector.get_windows_logs(FakeWinClient(None)) == []


def test_one_bad_line_does_not_discard_the_rest_of_the_batch(app):
    """A single malformed record must not cost the operator the whole batch."""
    payload = '\n'.join([
        json.dumps(win_record(4625, user='alice')),
        '{not json',
        json.dumps(win_record(4624, user='bob')),
    ])

    logs = LogCollector.parse_windows_ndjson(payload)

    assert [entry['user'] for entry in logs] == ['alice', 'bob']


def test_collection_survives_invalid_json(app):
    class BadClient(FakeWinClient):
        def run_ps(self, cmd, timeout=120):
            return '{not json'

    assert LogCollector.get_windows_logs(BadClient(None)) == []


def test_blank_lines_are_ignored(app):
    payload = f'\n\n{json.dumps(win_record(4625))}\n\n'
    assert len(LogCollector.parse_windows_ndjson(payload)) == 1


def test_a_powershell_failure_is_raised_not_swallowed(app):
    """
    A genuine failure must reach the caller. Returning an empty list would be
    reported to the operator as "no new logs", hiding the real problem.
    """
    class ExplodingClient(FakeWinClient):
        def run_ps(self, cmd, timeout=120):
            raise PowerShellError('Attempted to perform an unauthorized operation')

    with pytest.raises(PowerShellError, match='unauthorized'):
        LogCollector.get_windows_logs(ExplodingClient(None))


def test_unrelated_records_are_dropped_from_the_batch(app):
    # 4689 (process exited) is not a security-relevant logon or account event.
    client = FakeWinClient([win_record(4625), win_record(4689), win_record(4624)])
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

    import app.services.collection as collection_service
    monkeypatch.setattr(
        collection_service, 'WinClient', lambda: FakeWinClient(None, readable=False)
    )

    response = auth_client.post(f'/api/hosts/{host.id}/logs')
    payload = response.get_json()

    assert response.status_code == 403
    assert 'Cannot read the Windows Security log' in payload['error']
    # The remedy lives in `hint`, the underlying cause in `detail`.
    assert 'Run as Administrator' in payload['hint']
    assert payload['detail']


def test_collect_endpoint_stores_collected_events(auth_client, app, monkeypatch):
    host = _windows_host()

    import app.services.collection as collection_service
    monkeypatch.setattr(
        collection_service,
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
    # The message now reports received / new / duplicate counts separately.
    assert 'Received 2' in payload['message']
    assert 'stored 2 new' in payload['message']
    assert Event.query.filter_by(host_id=host.id).count() == 2


def test_repeated_collection_does_not_duplicate_events(auth_client, app, monkeypatch):
    host = _windows_host()

    import app.services.collection as collection_service
    monkeypatch.setattr(
        collection_service,
        'WinClient',
        lambda: FakeWinClient([win_record(4625, timestamp='2026-08-15 11:00:00')]),
    )

    auth_client.post(f'/api/hosts/{host.id}/logs')
    second = auth_client.post(f'/api/hosts/{host.id}/logs').get_json()

    assert second['events_stored'] == 0
    assert second['duplicates_skipped'] == 1
    assert Event.query.filter_by(host_id=host.id).count() == 1


# ---------------------------------------------------------------------------
# Removable media (Event ID 6416)
# ---------------------------------------------------------------------------

def usb_record(description='SanDisk Cruzer USB Device', user='yasir',
               vendor_ids=r'USBSTOR\DiskSanDisk_Cruzer_Blade',
               compatible_ids=r'USBSTOR\Disk',
               timestamp='2026-08-15 14:20:00'):
    """
    Build a 6416 record shaped like the PowerShell collector's output.

    6416 carries no TargetUserName, no logon type and no address — only the
    device identifiers and the account that was signed in at the time.
    """
    return {
        'Timestamp': timestamp,
        'EventId': 6416,
        'SubjectUserName': user,
        'DeviceDescription': description,
        'VendorIds': vendor_ids,
        'CompatibleIds': compatible_ids,
    }


def test_event_6416_becomes_a_usb_device_event():
    parsed = LogCollector.parse_windows_event(usb_record())

    assert parsed['alert_type'] == EVT_USB_DEVICE_CONNECTED
    assert parsed['device_name'] == 'SanDisk Cruzer USB Device'
    assert parsed['user'] == 'yasir'


def test_usb_message_names_the_device_and_the_user():
    parsed = LogCollector.parse_windows_event(
        usb_record(description='Kingston DataTraveler', user='student')
    )
    assert parsed['message'] == "USB device connected: Kingston DataTraveler by user 'student'"


def test_a_usb_event_is_recorded_as_a_physical_not_a_network_event():
    """
    Plugging a drive in happens at the keyboard. Marking it LOCAL_CONSOLE
    keeps it out of the brute-force and threat-IP correlations, which only
    make sense for routable addresses.
    """
    parsed = LogCollector.parse_windows_event(usb_record())
    assert parsed['source_ip'] == 'LOCAL_CONSOLE'


def test_a_usb_event_with_no_description_still_names_something():
    """A device that reports no description must not appear as a blank row."""
    parsed = LogCollector.parse_windows_event(usb_record(description=''))
    assert parsed['device_name'] == 'Unknown device'
    assert 'Unknown device' in parsed['message']


def test_a_usb_event_with_no_user_falls_back_to_unknown():
    parsed = LogCollector.parse_windows_event(usb_record(user=''))
    assert parsed['user'] == 'UNKNOWN'


def test_other_event_types_carry_no_device_name():
    """device_name belongs to removable media only; everything else leaves it NULL."""
    assert LogCollector.parse_windows_event(win_record(4625))['device_name'] is None
    assert LogCollector.parse_windows_event(win_record(4624))['device_name'] is None


def test_the_query_requests_device_events(app):
    cmd = LogCollector.build_windows_query()
    assert '6416' in cmd
    assert 'DeviceDescription' in cmd


def test_the_query_keeps_only_usb_hardware_ids(app):
    """
    6416 fires for the internal disk, keyboard and network card at every boot.
    Filtering in PowerShell means that flood never crosses the process
    boundary, exactly as the interactive-logon filter does for 4624.
    """
    cmd = LogCollector.build_windows_query()
    assert "$vendorIds -like '*USB*'" in cmd
    assert "$compatibleIds -like '*USB*'" in cmd


def test_a_usb_event_survives_a_full_collection(app):
    """The whole path: PowerShell output to normalized event."""
    client = FakeWinClient([usb_record()])
    logs = LogCollector.get_windows_logs(client)

    assert len(logs) == 1
    assert logs[0]['alert_type'] == EVT_USB_DEVICE_CONNECTED
    assert logs[0]['device_name'] == 'SanDisk Cruzer USB Device'


def test_a_usb_event_is_stored_with_its_device_name(app):
    """The device name must reach the Event row, not stop at the parser."""
    host = _windows_host()
    LogAnalyzer.ingest(
        LogCollector.parse_windows_ndjson(ndjson([usb_record()])),
        host.id,
        archive=False,
    )

    event = Event.query.filter_by(event_type=EVT_USB_DEVICE_CONNECTED).one()
    assert event.device_name == 'SanDisk Cruzer USB Device'
    assert event.to_dict()['device_name'] == 'SanDisk Cruzer USB Device'


def test_collection_still_works_when_pnp_auditing_is_disabled(app):
    """
    A host without Plug and Play auditing simply emits no 6416 records. That
    must look like "no USB events", never like a collection failure.
    """
    client = FakeWinClient([win_record(4625), win_record(4624)])
    logs = LogCollector.get_windows_logs(client)

    assert len(logs) == 2
    assert all(log['alert_type'] != EVT_USB_DEVICE_CONNECTED for log in logs)
