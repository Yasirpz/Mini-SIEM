"""
Host health, connection testing, and detection rules R-05 to R-08.

Health must reflect what collection actually did. A host that merely exists
in the database has proved nothing about its reachability, and reporting it
as ONLINE would make the dashboard lie.
"""
from datetime import timedelta

import pytest

from app.extensions import db
from app.models import (
    COLLECT_LOCAL,
    COLLECT_SSH,
    COLLECT_WINRM,
    EVT_ACCOUNT_CREATED,
    EVT_ACCOUNT_DELETED,
    EVT_ACCOUNT_LOCKOUT,
    EVT_ADMIN_LOGON,
    EVT_AUDIT_LOG_CLEARED,
    EVT_GROUP_MEMBER_ADDED,
    EVT_PASSWORD_RESET,
    EVT_PROCESS_CREATED,
    HOST_DEGRADED,
    HOST_OFFLINE,
    HOST_ONLINE,
    HOST_UNKNOWN,
    Host,
    USB_AUDIT_DISABLED,
    USB_AUDIT_ENABLED,
    USB_AUDIT_UNKNOWN,
    utcnow,
)
from app.services.log_analyzer import LogAnalyzer
from app.services.log_collector import LogCollector


def _host(**kwargs):
    defaults = dict(hostname='Yasir', ip_address='192.168.100.68', os_type='WINDOWS')
    defaults.update(kwargs)
    entry = Host(**defaults)
    db.session.add(entry)
    db.session.commit()
    return entry


# ---------------------------------------------------------------------------
# Health derivation
# ---------------------------------------------------------------------------

def test_a_never_contacted_host_is_unknown_not_online(app):
    """Existing in the database proves nothing about reachability."""
    assert _host().health() == HOST_UNKNOWN


def test_a_recent_success_is_online(app):
    host = _host()
    host.record_attempt(True, latency_ms=42)
    db.session.commit()
    assert host.health() == HOST_ONLINE


def test_a_failure_after_a_recent_success_is_degraded(app):
    host = _host()
    host.record_attempt(True)
    host.record_attempt(False, error='WinRM timed out')
    db.session.commit()
    assert host.health() == HOST_DEGRADED


def test_a_failure_with_no_recent_success_is_offline(app):
    host = _host()
    host.record_attempt(False, error='unreachable')
    db.session.commit()
    assert host.health() == HOST_OFFLINE


def test_a_stale_success_stops_counting_as_online(app):
    """Silence is not health: an old success must not read as ONLINE forever."""
    host = _host()
    host.record_attempt(True)
    host.last_success = utcnow() - timedelta(hours=3)
    host.last_attempt = host.last_success
    db.session.commit()
    assert host.health() == HOST_DEGRADED


def test_recording_a_success_clears_the_previous_error(app):
    host = _host()
    host.record_attempt(False, error='temporary glitch')
    host.record_attempt(True)
    db.session.commit()
    assert host.last_error is None


def test_a_long_error_is_truncated_to_fit_the_column(app):
    host = _host()
    host.record_attempt(False, error='x' * 900)
    db.session.commit()
    assert len(host.last_error) <= 500


def test_health_is_exposed_to_the_api(app):
    host = _host()
    host.record_attempt(True, latency_ms=15)
    db.session.commit()

    payload = host.to_dict()
    assert payload['status'] == HOST_ONLINE
    assert payload['last_latency_ms'] == 15
    assert payload['last_success']


# ---------------------------------------------------------------------------
# Test Connection
# ---------------------------------------------------------------------------

def test_test_connection_requires_authentication(client, app):
    host = _host()
    assert client.post(f'/api/hosts/{host.id}/test').status_code == 401


def test_local_test_reports_each_stage_separately(auth_client, app):
    """A single "connection failed" is not actionable; stages must be distinct."""
    host = _host(collection_method=COLLECT_LOCAL)

    response = auth_client.post(f'/api/hosts/{host.id}/test')
    payload = response.get_json()

    assert response.status_code == 200
    names = [check['name'] for check in payload['checks']]
    assert 'Target is this machine' in names
    assert any('elevated' in name for name in names)
    assert any('Security log' in name for name in names)
    assert 'latency_ms' in payload


def test_an_unreachable_remote_host_fails_the_reachability_check(auth_client, app):
    """Uses a reserved documentation address, which never routes anywhere."""
    host = _host(
        hostname='Lab-PC', ip_address='203.0.113.9',
        collection_method=COLLECT_WINRM, remote_user='admin',
    )

    payload = auth_client.post(f'/api/hosts/{host.id}/test').get_json()

    assert payload['ok'] is False
    first = payload['checks'][0]
    assert first['ok'] is False
    assert 'Enable-PSRemoting' in first['detail']


def test_a_failed_test_marks_the_host_unhealthy(auth_client, app):
    host = _host(
        hostname='Lab-PC', ip_address='203.0.113.9',
        collection_method=COLLECT_WINRM, remote_user='admin',
    )

    auth_client.post(f'/api/hosts/{host.id}/test')
    db.session.refresh(host)

    assert host.health() in (HOST_OFFLINE, HOST_DEGRADED)
    assert host.last_error


def test_a_test_does_not_create_events_or_alerts(auth_client, app):
    """Testing connectivity must not pollute the evidence record."""
    host = _host(
        hostname='Lab-PC', ip_address='203.0.113.9',
        collection_method=COLLECT_WINRM, remote_user='admin',
    )

    auth_client.post(f'/api/hosts/{host.id}/test')

    assert host.events.count() == 0
    assert host.alerts.count() == 0


# ---------------------------------------------------------------------------
# Rules R-05 to R-08
# ---------------------------------------------------------------------------

def _ingest(host, event_type, user='student'):
    return LogAnalyzer.ingest(
        [{
            'timestamp': utcnow(),
            'alert_type': event_type,
            'source_ip': 'LOCAL_CONSOLE',
            'user': user,
            'message': f'test {event_type}',
            'raw_log': '{}',
        }],
        host.id,
        origin='COLLECTED',
    )


def test_r05_fires_on_a_cleared_audit_log(app):
    result = _ingest(_host(), EVT_AUDIT_LOG_CLEARED)
    assert result['alerts']['R-05'] == 1


def test_r05_is_high_severity(app):
    from app.models import Alert, SEVERITY_HIGH

    _ingest(_host(), EVT_AUDIT_LOG_CLEARED)
    alert = Alert.query.filter_by(rule_id='R-05').first()
    assert alert.severity == SEVERITY_HIGH


@pytest.mark.parametrize('event_type', [EVT_ACCOUNT_CREATED, EVT_ACCOUNT_DELETED])
def test_r06_fires_on_account_changes(app, event_type):
    result = _ingest(_host(), event_type)
    assert result['alerts']['R-06'] == 1


@pytest.mark.parametrize('event_type', [EVT_GROUP_MEMBER_ADDED, EVT_PASSWORD_RESET])
def test_r07_fires_on_privilege_changes(app, event_type):
    result = _ingest(_host(), event_type)
    assert result['alerts']['R-07'] == 1


def test_r07_ignores_ordinary_administrative_logons(app):
    """
    4672 fires every time an administrator signs in normally. Alerting on it
    would train the operator to ignore the rule.
    """
    result = _ingest(_host(), EVT_ADMIN_LOGON)
    assert result['alerts']['R-07'] == 0


def test_r08_fires_on_an_account_lockout(app):
    result = _ingest(_host(), EVT_ACCOUNT_LOCKOUT)
    assert result['alerts']['R-08'] == 1


def test_a_lockout_does_not_also_count_towards_r01(app):
    """The lockout is the consequence of failures R-01 has already counted."""
    result = _ingest(_host(), EVT_ACCOUNT_LOCKOUT)
    assert result['alerts']['R-01'] == 0


def test_the_new_rules_are_idempotent(app):
    host = _host()
    _ingest(host, EVT_AUDIT_LOG_CLEARED)

    from app.services.detection import DetectionEngine

    second = DetectionEngine.run()
    assert second['R-05'] == 0


def test_a_successful_login_raises_no_alert_at_all(app):
    """Normal activity must stay silent, or the alert list becomes useless."""
    from app.models import EVT_SUCCESSFUL_LOGIN

    result = _ingest(_host(), EVT_SUCCESSFUL_LOGIN)
    assert result['alerts']['total'] == 0


# ---------------------------------------------------------------------------
# Process events
# ---------------------------------------------------------------------------

def test_process_events_are_not_collected_by_default(app):
    """4688 fires thousands of times an hour and would bury the real signal."""
    assert '4688' not in LogCollector.build_windows_query()


def test_process_events_can_be_enabled(app):
    app.config['WINDOWS_COLLECT_PROCESS_EVENTS'] = True
    assert '4688' in LogCollector.build_windows_query()


def test_a_process_event_is_classified_and_named(app):
    parsed = LogCollector.parse_windows_event({
        'Timestamp': '2026-08-15 10:00:00',
        'EventId': 4688,
        'TargetUserName': '',
        'SubjectUserName': 'student',
        'NewProcessName': 'C:\\Windows\\System32\\cmd.exe',
        'ParentProcessName': 'C:\\Windows\\explorer.exe',
    })

    assert parsed['alert_type'] == EVT_PROCESS_CREATED
    assert 'cmd.exe' in parsed['message']
    assert 'explorer.exe' in parsed['message']


def test_command_lines_are_never_collected(app):
    """
    Command lines routinely contain passwords and tokens. A security tool
    must not become the place they are archived.
    """
    cmd = LogCollector.build_windows_query()
    assert 'CommandLine' not in cmd


# ---------------------------------------------------------------------------
# Plug and Play auditing status (USB detection readiness)
# ---------------------------------------------------------------------------

# Verbatim auditpol output, so the parser is tested against the real shape of
# the command's table rather than an idealised version of it.
AUDITPOL_DISABLED = """System audit policy
Category/Subcategory                      Setting
Detailed Tracking
  Plug and Play Events                    No Auditing
"""

AUDITPOL_ENABLED = """System audit policy
Category/Subcategory                      Setting
Detailed Tracking
  Plug and Play Events                    Success
"""

AUDITPOL_DENIED = """Error 0x00000522 occurred:
A required privilege is not held by the client.
"""


def test_audit_output_reporting_no_auditing_is_disabled():
    from app.services.win_client import _classify_audit_output

    state, detail = _classify_audit_output(AUDITPOL_DISABLED, '')

    assert state == USB_AUDIT_DISABLED
    assert 'No Auditing' in detail


def test_audit_output_reporting_success_is_enabled():
    from app.services.win_client import _classify_audit_output

    state, _ = _classify_audit_output(AUDITPOL_ENABLED, '')
    assert state == USB_AUDIT_ENABLED


def test_a_privilege_error_is_unknown_not_disabled():
    """
    An unprivileged probe cannot see the policy at all. Reporting that as
    DISABLED would send the operator to fix the wrong thing — they would run
    auditpol, find it already correct, and stop trusting the badge.
    """
    from app.services.win_client import _classify_audit_output

    state, detail = _classify_audit_output(AUDITPOL_DENIED, '')

    assert state == USB_AUDIT_UNKNOWN
    assert 'privilege' in detail.lower()
    # The reason must survive as one line, fit for a table cell and a VARCHAR.
    assert '\n' not in detail


def test_empty_audit_output_is_unknown():
    from app.services.win_client import _classify_audit_output

    state, _ = _classify_audit_output('', '')
    assert state == USB_AUDIT_UNKNOWN


def test_audit_error_on_stderr_is_still_recognised():
    """auditpol writes its privilege failure to either stream."""
    from app.services.win_client import _classify_audit_output

    state, detail = _classify_audit_output('', AUDITPOL_DENIED)

    assert state == USB_AUDIT_UNKNOWN
    assert '\n' not in detail


def test_a_host_defaults_to_unknown_auditing(app):
    """A host nobody has probed must not claim to know its own audit policy."""
    host = _host()

    assert host.usb_audit_status is None
    assert host.to_dict()['usb_audit_status'] == USB_AUDIT_UNKNOWN


def test_the_host_stats_endpoint_reports_audit_status(auth_client, app):
    """The dashboard host overview reads this straight from /api/stats/hosts."""
    host = _host()
    host.usb_audit_status = USB_AUDIT_ENABLED
    db.session.commit()

    rows = auth_client.get('/api/stats/hosts').get_json()

    assert rows[0]['usb_audit_status'] == USB_AUDIT_ENABLED


def test_host_stats_reports_unknown_for_an_unprobed_host(auth_client, app):
    _host()

    rows = auth_client.get('/api/stats/hosts').get_json()
    assert rows[0]['usb_audit_status'] == USB_AUDIT_UNKNOWN


def test_the_local_test_reports_usb_auditing_as_advisory(auth_client, app):
    """
    USB detection is optional. The check is reported, but a host with the
    auditing off still collects logs correctly and must not be called broken.
    """
    host = _host(collection_method=COLLECT_LOCAL)

    payload = auth_client.post(f'/api/hosts/{host.id}/test').get_json()

    usb = [check for check in payload['checks'] if 'USB' in check['name']]
    assert len(usb) == 1
    assert usb[0]['advisory'] is True


def test_required_checks_are_still_marked_non_advisory(auth_client, app):
    """Prerequisites must keep deciding the verdict."""
    host = _host(collection_method=COLLECT_LOCAL)

    payload = auth_client.post(f'/api/hosts/{host.id}/test').get_json()

    required = [c for c in payload['checks'] if not c['advisory']]
    assert any('Security log' in c['name'] for c in required)
    assert all(c['advisory'] is False for c in required)


def test_a_probe_failure_cannot_break_collection(app):
    """
    The audit probe is a diagnostic. A client that cannot answer must cost
    the badge, never the logs.
    """
    from app.blueprints.api.hosts import _probe_usb_auditing

    class NoProbe:
        pass

    class ExplodingProbe:
        def pnp_audit_status(self):
            raise RuntimeError('powershell exploded')

    assert _probe_usb_auditing(NoProbe()) is None
    assert _probe_usb_auditing(ExplodingProbe()) is None


def test_a_successful_probe_returns_the_state(app):
    from app.blueprints.api.hosts import _probe_usb_auditing

    class WorkingProbe:
        def pnp_audit_status(self):
            return USB_AUDIT_ENABLED, 'Plug and Play Events: Success.'

    assert _probe_usb_auditing(WorkingProbe()) == USB_AUDIT_ENABLED


def test_a_winrm_test_reports_usb_auditing_when_the_account_works(auth_client, app, monkeypatch):
    """
    Remote hosts get the same advisory check as local ones, so the dashboard
    badge is meaningful for every Windows host rather than only the console.
    """
    import app.blueprints.api.hosts as hosts_module

    host = _host(
        hostname='Abdul-Fatah-PC', ip_address='10.0.0.5',
        collection_method=COLLECT_WINRM, remote_user='admin',
    )

    class WorkingRemote:
        username = 'admin'

        def security_log_status(self):
            return True, 'READABLE'

        def pnp_audit_status(self):
            return USB_AUDIT_ENABLED, 'Plug and Play Events: Success.'

    monkeypatch.setattr(hosts_module, '_port_is_open', lambda *a, **k: True)
    monkeypatch.setattr(hosts_module, '_winrm_for', lambda h: WorkingRemote())

    payload = auth_client.post(f'/api/hosts/{host.id}/test').get_json()

    usb = [c for c in payload['checks'] if 'USB' in c['name']]
    assert len(usb) == 1
    assert usb[0]['advisory'] is True
    assert usb[0]['ok'] is True
    assert payload['ok'] is True

    db.session.refresh(host)
    assert host.usb_audit_status == USB_AUDIT_ENABLED


def test_auditing_off_on_a_remote_host_does_not_fail_the_test(auth_client, app, monkeypatch):
    """A remote host that collects logs fine must not be called broken."""
    import app.blueprints.api.hosts as hosts_module

    host = _host(
        hostname='Abdul-Fatah-PC', ip_address='10.0.0.5',
        collection_method=COLLECT_WINRM, remote_user='admin',
    )

    class NoAuditing:
        username = 'admin'

        def security_log_status(self):
            return True, 'READABLE'

        def pnp_audit_status(self):
            return USB_AUDIT_DISABLED, 'Plug and Play Events: No Auditing.'

    monkeypatch.setattr(hosts_module, '_port_is_open', lambda *a, **k: True)
    monkeypatch.setattr(hosts_module, '_winrm_for', lambda h: NoAuditing())

    payload = auth_client.post(f'/api/hosts/{host.id}/test').get_json()

    usb = [c for c in payload['checks'] if 'USB' in c['name']][0]
    assert usb['ok'] is False        # reported honestly
    assert usb['advisory'] is True
    assert payload['ok'] is True     # but the host is not broken

    db.session.refresh(host)
    assert host.usb_audit_status == USB_AUDIT_DISABLED
