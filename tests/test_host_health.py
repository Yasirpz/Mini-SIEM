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
