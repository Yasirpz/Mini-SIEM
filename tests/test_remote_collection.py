"""
Remote log collection from another machine.

Covers routing a host to the right collector, the WinRM client's command
construction, credential handling, and the requirement that a password never
reaches the database or a process command line.
"""
import pytest

from app.extensions import db
from app.models import (
    COLLECT_LOCAL,
    COLLECT_SSH,
    COLLECT_WINRM,
    Host,
)
from app.services.win_client import PowerShellError, RemoteWinClient
from app.validators import ValidationError, validate_collection_method


# ---------------------------------------------------------------------------
# Choosing a collection method
# ---------------------------------------------------------------------------

def test_linux_hosts_default_to_ssh(app):
    host = Host(hostname='Lab-Server', ip_address='192.168.56.10', os_type='LINUX')
    assert host.effective_collection_method() == COLLECT_SSH


def test_windows_hosts_default_to_local(app):
    """Hosts created before this feature existed must keep working unchanged."""
    host = Host(hostname='Yasir', ip_address='192.168.100.68', os_type='WINDOWS')
    assert host.effective_collection_method() == COLLECT_LOCAL


def test_an_explicit_method_wins(app):
    host = Host(
        hostname='Lab-PC', ip_address='192.168.100.70', os_type='WINDOWS',
        collection_method=COLLECT_WINRM,
    )
    assert host.effective_collection_method() == COLLECT_WINRM


def test_an_unknown_stored_method_falls_back_safely(app):
    host = Host(
        hostname='Odd', ip_address='192.168.100.71', os_type='WINDOWS',
        collection_method='TELEPATHY',
    )
    assert host.effective_collection_method() == COLLECT_LOCAL


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def test_blank_method_means_automatic():
    assert validate_collection_method('', 'WINDOWS') is None
    assert validate_collection_method(None, 'LINUX') is None


def test_method_is_normalized():
    assert validate_collection_method('winrm', 'WINDOWS') == COLLECT_WINRM


def test_unknown_method_is_rejected():
    with pytest.raises(ValidationError, match='collection_method'):
        validate_collection_method('CARRIER_PIGEON', 'WINDOWS')


def test_ssh_against_windows_is_rejected():
    """Caught when saving, rather than as a puzzling failure at collection time."""
    with pytest.raises(ValidationError, match='not SSH'):
        validate_collection_method(COLLECT_SSH, 'WINDOWS')


def test_winrm_against_linux_is_rejected():
    with pytest.raises(ValidationError, match='Windows hosts only'):
        validate_collection_method(COLLECT_WINRM, 'LINUX')


# ---------------------------------------------------------------------------
# RemoteWinClient construction
# ---------------------------------------------------------------------------

def test_missing_password_is_reported_clearly():
    with pytest.raises(PowerShellError, match='MINISIEM_WINRM_PASSWORD'):
        RemoteWinClient(computer='192.168.100.70', username='admin', password='')


def test_missing_username_is_reported_clearly():
    with pytest.raises(PowerShellError, match='username'):
        RemoteWinClient(computer='192.168.100.70', username='', password='secret')


def test_missing_address_is_reported_clearly():
    with pytest.raises(PowerShellError, match='address'):
        RemoteWinClient(computer='', username='admin', password='secret')


def test_the_query_is_wrapped_for_the_remote_machine():
    client = RemoteWinClient(
        computer='192.168.100.70', username='LAB-PC\\Administrator', password='secret',
    )
    wrapped = client._wrap("Get-WinEvent -LogName Security")

    assert 'Invoke-Command' in wrapped
    assert "-ComputerName '192.168.100.70'" in wrapped
    assert 'Get-WinEvent -LogName Security' in wrapped


def test_the_password_never_appears_in_the_command():
    """
    Process command lines are readable by other accounts on Windows, so the
    credential must travel through the environment instead.
    """
    client = RemoteWinClient(
        computer='192.168.100.70', username='admin', password='hunter2-secret',
    )
    wrapped = client._wrap('whatever')

    assert 'hunter2-secret' not in wrapped
    assert f'$env:{RemoteWinClient.PASSWORD_ENV_VAR}' in wrapped


def test_a_quote_in_the_username_cannot_break_out_of_the_string():
    client = RemoteWinClient(
        computer='192.168.100.70', username="ev'il", password='secret',
    )
    assert "'ev''il'" in client._wrap('whatever')


def test_optional_connection_settings_are_applied():
    client = RemoteWinClient(
        computer='10.0.0.5', username='admin', password='secret',
        port=5986, use_ssl=True, authentication='Negotiate',
    )
    wrapped = client._wrap('whatever')

    assert '-Port 5986' in wrapped
    assert '-UseSSL' in wrapped
    assert '-Authentication' in wrapped


def test_remote_status_reports_a_readable_log():
    class OkClient(RemoteWinClient):
        def run_ps_raw(self, cmd, timeout=120):
            return 'READABLE', '', 0

    client = OkClient(computer='10.0.0.5', username='admin', password='secret')
    ok, _ = client.security_log_status()
    assert ok is True


def test_a_missing_winrm_listener_is_explained():
    class NoListener(RemoteWinClient):
        def run_ps_raw(self, cmd, timeout=120):
            return 'ERROR: WinRM cannot complete the operation.', '', 0

    client = NoListener(computer='10.0.0.5', username='admin', password='secret')
    ok, detail = client.security_log_status()

    assert ok is False
    assert 'Enable-PSRemoting' in detail


def test_a_rejected_account_is_explained():
    class Denied(RemoteWinClient):
        def run_ps_raw(self, cmd, timeout=120):
            return 'ERROR: Access is denied.', '', 0

    client = Denied(computer='10.0.0.5', username='admin', password='secret')
    ok, detail = client.security_log_status()

    assert ok is False
    assert 'local Administrator' in detail


def test_a_trustedhosts_problem_names_the_fix():
    class Untrusted(RemoteWinClient):
        def run_ps_raw(self, cmd, timeout=120):
            return 'ERROR: the TrustedHosts list must be configured.', '', 0

    client = Untrusted(computer='10.0.0.5', username='admin', password='secret')
    ok, detail = client.security_log_status()

    assert ok is False
    assert 'TrustedHosts' in detail


# ---------------------------------------------------------------------------
# The API
# ---------------------------------------------------------------------------

def test_a_remote_host_can_be_created(auth_client, app):
    response = auth_client.post('/api/hosts', json={
        'hostname': 'Lab-PC',
        'ip_address': '192.168.100.70',
        'os_type': 'WINDOWS',
        'collection_method': 'WINRM',
        'remote_user': 'LAB-PC\\Administrator',
    })

    assert response.status_code == 201
    payload = response.get_json()
    assert payload['collection_method'] == 'WINRM'
    assert payload['remote_user'] == 'LAB-PC\\Administrator'


def test_no_password_field_is_ever_persisted(auth_client, app):
    """Credentials belong in .env; the API must not accept or return one."""
    auth_client.post('/api/hosts', json={
        'hostname': 'Lab-PC',
        'ip_address': '192.168.100.70',
        'os_type': 'WINDOWS',
        'collection_method': 'WINRM',
        'remote_user': 'admin',
        'password': 'should-be-ignored',
    })

    host = Host.query.filter_by(ip_address='192.168.100.70').first()
    assert not hasattr(host, 'password')
    assert not hasattr(host, 'remote_password')
    assert 'should-be-ignored' not in str(host.to_dict())


def test_collection_without_credentials_explains_what_is_missing(auth_client, app):
    host = Host(
        hostname='Lab-PC', ip_address='192.168.100.70', os_type='WINDOWS',
        collection_method=COLLECT_WINRM, remote_user='admin',
    )
    db.session.add(host)
    db.session.commit()

    app.config['WINRM_PASSWORD'] = ''

    response = auth_client.post(f'/api/hosts/{host.id}/logs')
    payload = response.get_json()

    assert response.status_code == 400
    assert 'MINISIEM_WINRM_PASSWORD' in payload['detail']


def test_an_unreachable_remote_host_reports_the_reason(auth_client, app, monkeypatch):
    host = Host(
        hostname='Lab-PC', ip_address='192.168.100.70', os_type='WINDOWS',
        collection_method=COLLECT_WINRM, remote_user='admin',
    )
    db.session.add(host)
    db.session.commit()

    from app.blueprints.api import hosts as hosts_api

    class Unreachable:
        def security_log_status(self):
            return False, 'WinRM cannot complete the operation.'

    monkeypatch.setattr(hosts_api, '_winrm_for', lambda h: Unreachable())

    response = auth_client.post(f'/api/hosts/{host.id}/logs')
    payload = response.get_json()

    assert response.status_code == 502
    assert 'WinRM' in payload['detail']
    assert 'Enable-PSRemoting' in payload['hint']


def test_a_linux_host_still_uses_ssh(auth_client, app, monkeypatch):
    """Adding remote Windows collection must not disturb Linux hosts."""
    host = Host(hostname='Lab-Server', ip_address='192.168.56.10', os_type='LINUX')
    db.session.add(host)
    db.session.commit()

    from app.blueprints.api import hosts as hosts_api

    called = {}

    def fake_ssh(h):
        called['host'] = h.hostname
        raise RuntimeError('connection refused')

    monkeypatch.setattr(hosts_api, '_ssh_for', fake_ssh)

    response = auth_client.post(f'/api/hosts/{host.id}/logs')

    assert called['host'] == 'Lab-Server'
    assert response.status_code == 502
