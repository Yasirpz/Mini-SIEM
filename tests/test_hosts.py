"""
TC-03 Host Management Test (proposal Section 15).

Covers FR-03: add, view, update and delete monitored hosts.
"""
from app.models import Host


def test_add_host(auth_client):
    response = auth_client.post('/api/hosts', json={
        'hostname': 'Lab-PC',
        'ip_address': '127.0.0.1',
        'os_type': 'LINUX',
        'description': 'Lab workstation',
    })
    assert response.status_code == 201

    body = response.get_json()
    assert body['hostname'] == 'Lab-PC'
    assert body['ip_address'] == '127.0.0.1'
    assert body['description'] == 'Lab workstation'


def test_added_host_appears_in_the_list(auth_client):
    auth_client.post('/api/hosts', json={
        'hostname': 'Lab-PC', 'ip_address': '127.0.0.1', 'os_type': 'LINUX',
    })

    hosts = auth_client.get('/api/hosts').get_json()
    assert len(hosts) == 1
    assert hosts[0]['hostname'] == 'Lab-PC'


def test_update_host(auth_client, host):
    response = auth_client.put(f'/api/hosts/{host.id}', json={
        'hostname': 'Renamed-PC',
        'os_type': 'WINDOWS',
    })
    assert response.status_code == 200

    body = response.get_json()
    assert body['hostname'] == 'Renamed-PC'
    assert body['os_type'] == 'WINDOWS'
    # Untouched fields keep their value.
    assert body['ip_address'] == '127.0.0.1'


def test_delete_host(auth_client, host):
    assert auth_client.delete(f'/api/hosts/{host.id}').status_code == 200
    assert auth_client.get('/api/hosts').get_json() == []


def test_duplicate_ip_is_rejected(auth_client, host):
    """IP addresses identify a host, so they must stay unique."""
    response = auth_client.post('/api/hosts', json={
        'hostname': 'Another-PC', 'ip_address': '127.0.0.1', 'os_type': 'LINUX',
    })
    assert response.status_code == 409
    assert 'already exists' in response.get_json()['error']


def test_update_to_an_ip_owned_by_another_host_is_rejected(auth_client, two_hosts):
    first, second = two_hosts
    response = auth_client.put(f'/api/hosts/{second.id}', json={
        'ip_address': first.ip_address,
    })
    assert response.status_code == 409


# ---------------------------------------------------------------- validation

def test_invalid_ip_is_rejected(auth_client):
    response = auth_client.post('/api/hosts', json={
        'hostname': 'Bad-PC', 'ip_address': '999.999.1.1', 'os_type': 'LINUX',
    })
    assert response.status_code == 400
    assert 'not a valid' in response.get_json()['error']


def test_invalid_os_type_is_rejected(auth_client):
    response = auth_client.post('/api/hosts', json={
        'hostname': 'Bad-PC', 'ip_address': '10.0.0.5', 'os_type': 'SOLARIS',
    })
    assert response.status_code == 400


def test_missing_hostname_is_rejected(auth_client):
    response = auth_client.post('/api/hosts', json={
        'ip_address': '10.0.0.6', 'os_type': 'LINUX',
    })
    assert response.status_code == 400


def test_hostname_with_markup_is_rejected(auth_client):
    """Reject characters that have no place in a hostname."""
    response = auth_client.post('/api/hosts', json={
        'hostname': '<script>alert(1)</script>',
        'ip_address': '10.0.0.7',
        'os_type': 'LINUX',
    })
    assert response.status_code == 400


def test_deleting_a_host_removes_its_events_and_alerts(auth_client, host, app):
    """Cascade delete keeps orphaned events out of the database."""
    from app.services.log_analyzer import LogAnalyzer
    from app.services.sample_loader import SampleLoader
    from app.models import Alert, Event

    LogAnalyzer.ingest(SampleLoader.generate_synthetic(), host.id, archive=False)
    assert Event.query.count() > 0

    auth_client.delete(f'/api/hosts/{host.id}')

    assert Event.query.count() == 0
    assert Alert.query.count() == 0
    assert Host.query.count() == 0
