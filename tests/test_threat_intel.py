"""
TC-04 Threat IP Test (proposal Section 15).

Covers FR-04: add and manage suspicious IP addresses in the threat registry.
The demonstration address 203.0.113.50 is from the RFC 5737 documentation
range, so it never routes to a real machine.
"""
TEST_IP = '203.0.113.50'


def test_add_ip_to_registry(auth_client):
    response = auth_client.post('/api/ips', json={
        'ip_address': TEST_IP,
        'status': 'UNKNOWN',
        'source': 'Manual entry',
        'notes': 'Seen probing the lab server',
    })
    assert response.status_code == 201

    body = response.get_json()
    assert body['ip_address'] == TEST_IP
    assert body['status'] == 'UNKNOWN'
    assert body['notes'] == 'Seen probing the lab server'
    assert body['date_added'] is not None


def test_registered_ip_appears_in_the_registry(auth_client):
    auth_client.post('/api/ips', json={'ip_address': TEST_IP, 'status': 'UNKNOWN'})

    entries = auth_client.get('/api/ips').get_json()
    assert len(entries) == 1
    assert entries[0]['ip_address'] == TEST_IP


def test_update_ip_status_to_banned(auth_client, banned_ip):
    response = auth_client.put(f'/api/ips/{banned_ip.id}', json={'status': 'TRUSTED'})
    assert response.status_code == 200
    assert response.get_json()['status'] == 'TRUSTED'


def test_delete_ip(auth_client, banned_ip):
    assert auth_client.delete(f'/api/ips/{banned_ip.id}').status_code == 200
    assert auth_client.get('/api/ips').get_json() == []


def test_filter_registry_by_status(auth_client, banned_ip):
    auth_client.post('/api/ips', json={'ip_address': '198.51.100.23', 'status': 'TRUSTED'})

    banned = auth_client.get('/api/ips?status=BANNED').get_json()
    assert len(banned) == 1
    assert banned[0]['ip_address'] == TEST_IP


def test_duplicate_ip_is_rejected(auth_client, banned_ip):
    response = auth_client.post('/api/ips', json={'ip_address': TEST_IP})
    assert response.status_code == 409


def test_invalid_ip_is_rejected(auth_client):
    response = auth_client.post('/api/ips', json={'ip_address': 'not-an-ip'})
    assert response.status_code == 400


def test_invalid_status_is_rejected(auth_client):
    response = auth_client.post('/api/ips', json={
        'ip_address': '198.51.100.99', 'status': 'SUSPICIOUS',
    })
    assert response.status_code == 400


def test_ipv6_address_is_accepted(auth_client):
    response = auth_client.post('/api/ips', json={'ip_address': '2001:db8::1'})
    assert response.status_code == 201
