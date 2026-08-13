"""
Sample log parsing and import (FR-05, proposal Section 14).

Verifies that each supported log format is parsed into the same normalized
event structure, and that importing through the API produces alerts.
"""
from pathlib import Path

from app.models import Alert, Event
from app.services.sample_loader import SampleLoader

SAMPLES = Path(__file__).resolve().parent.parent / 'samples'


# ---------------------------------------------------------------- Linux auth.log

def test_parses_failed_password_lines():
    line = 'Aug 12 09:14:02 lab-server sshd[2841]: Failed password for root from 203.0.113.50 port 51422 ssh2'
    events = SampleLoader.parse_auth_log(line)

    assert len(events) == 1
    assert events[0]['alert_type'] == 'FAILED_LOGIN'
    assert events[0]['source_ip'] == '203.0.113.50'
    assert events[0]['user'] == 'root'


def test_parses_invalid_user_lines():
    line = 'Aug 12 09:15:01 lab-server sshd[2847]: Invalid user test from 203.0.113.50 port 51425'
    events = SampleLoader.parse_auth_log(line)

    assert events[0]['alert_type'] == 'INVALID_USER'
    assert events[0]['user'] == 'test'


def test_failed_password_for_invalid_user_is_classified_as_invalid_user():
    """The more specific pattern must win over the generic failed-password one."""
    line = 'Aug 12 09:15:02 lab-server sshd[2847]: Failed password for invalid user test from 203.0.113.50 port 51425 ssh2'
    events = SampleLoader.parse_auth_log(line)

    assert events[0]['alert_type'] == 'INVALID_USER'


def test_parses_successful_logins():
    line = 'Aug 12 09:21:15 lab-server sshd[2870]: Accepted password for labadmin from 192.168.1.20 port 51500 ssh2'
    events = SampleLoader.parse_auth_log(line)

    assert events[0]['alert_type'] == 'SUCCESSFUL_LOGIN'
    assert events[0]['user'] == 'labadmin'


def test_comments_and_blank_lines_are_skipped():
    text = '# a comment\n\n   \n'
    assert SampleLoader.parse_auth_log(text) == []


def test_unrecognised_lines_are_skipped_without_raising():
    text = 'Aug 12 09:14:02 lab-server systemd[1]: Started Daily apt upgrade.\n'
    assert SampleLoader.parse_auth_log(text) == []


def test_syslog_timestamps_are_parsed():
    line = 'Aug 12 09:14:02 lab-server sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2'
    events = SampleLoader.parse_auth_log(line)

    timestamp = events[0]['timestamp']
    assert (timestamp.month, timestamp.day, timestamp.hour) == (8, 12, 9)


def test_iso_timestamps_are_parsed():
    line = '2026-08-12 09:14:02 lab-server sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2'
    events = SampleLoader.parse_auth_log(line)

    assert events[0]['timestamp'].year == 2026


# ---------------------------------------------------------------- Windows CSV

def test_parses_windows_security_csv():
    csv_text = (
        'TimeCreated,EventId,TargetUserName,IpAddress,WorkstationName\n'
        '2026-08-12 09:31:04,4625,administrator,203.0.113.50,WS-LAB-01\n'
    )
    events = SampleLoader.parse_windows_csv(csv_text)

    assert len(events) == 1
    assert events[0]['alert_type'] == 'WIN_FAILED_LOGIN'
    assert events[0]['source_ip'] == '203.0.113.50'
    assert events[0]['user'] == 'administrator'


def test_windows_event_4624_is_a_successful_logon():
    csv_text = (
        'TimeCreated,EventId,TargetUserName,IpAddress\n'
        '2026-08-12 09:44:38,4624,labadmin,192.168.1.20\n'
    )
    events = SampleLoader.parse_windows_csv(csv_text)

    assert events[0]['alert_type'] == 'SUCCESSFUL_LOGIN'


def test_windows_blank_ip_becomes_a_local_console_marker():
    csv_text = 'TimeCreated,EventId,TargetUserName,IpAddress\n2026-08-12 09:40:12,4625,svc,-\n'
    events = SampleLoader.parse_windows_csv(csv_text)

    assert events[0]['source_ip'] == 'LOCAL_CONSOLE'


# ---------------------------------------------------------------- JSON

def test_parses_normalized_json():
    text = '[{"timestamp": "2026-08-12 14:02:11", "alert_type": "FAILED_LOGIN", ' \
           '"source_ip": "203.0.113.50", "user": "root", "message": "test"}]'
    events = SampleLoader.parse_json(text)

    assert len(events) == 1
    assert events[0]['source_ip'] == '203.0.113.50'


def test_malformed_json_returns_no_events_rather_than_raising():
    assert SampleLoader.parse_json('{not json') == []


# ---------------------------------------------------------------- format detection

def test_format_is_detected_from_content():
    _, linux = SampleLoader.parse(
        'Aug 12 09:14:02 h sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2')
    _, csv_fmt = SampleLoader.parse('TimeCreated,EventId,TargetUserName,IpAddress\n')
    _, json_fmt = SampleLoader.parse('[]')

    assert linux == 'linux-auth'
    assert csv_fmt == 'windows-csv'
    assert json_fmt == 'json'


# ---------------------------------------------------------------- bundled files

def test_bundled_linux_sample_parses():
    events, fmt = SampleLoader.parse(
        (SAMPLES / 'linux_auth_sample.log').read_text(encoding='utf-8'),
        filename='linux_auth_sample.log',
    )

    assert fmt == 'linux-auth'
    assert len(events) >= 15
    assert any(e['alert_type'] == 'INVALID_USER' for e in events)
    assert any(e['alert_type'] == 'SUCCESSFUL_LOGIN' for e in events)


def test_bundled_windows_sample_parses():
    events, fmt = SampleLoader.parse(
        (SAMPLES / 'windows_security_sample.csv').read_text(encoding='utf-8'),
        filename='windows_security_sample.csv',
    )

    assert fmt == 'windows-csv'
    assert len(events) == 10


def test_bundled_json_sample_parses():
    events, fmt = SampleLoader.parse(
        (SAMPLES / 'normalized_events_sample.json').read_text(encoding='utf-8'),
        filename='normalized_events_sample.json',
    )

    assert fmt == 'json'
    assert len(events) == 7


# ---------------------------------------------------------------- import API

def test_import_pasted_log_creates_events_and_alerts(auth_client, host):
    content = (SAMPLES / 'linux_auth_sample.log').read_text(encoding='utf-8')

    response = auth_client.post('/api/events/import', json={
        'host_id': host.id, 'content': content,
    })

    assert response.status_code == 200
    body = response.get_json()
    assert body['events_stored'] > 0
    assert body['alerts']['R-01'] >= 1   # the six-failure burst on root
    assert body['alerts']['R-02'] >= 1   # the invalid users
    assert Event.query.count() == body['events_stored']


def test_import_bundled_sample_by_name(auth_client, host):
    response = auth_client.post(
        '/api/events/samples/linux_auth_sample.log', json={'host_id': host.id})

    assert response.status_code == 200
    assert response.get_json()['events_stored'] > 0


def test_bundled_sample_names_cannot_escape_the_samples_folder(auth_client, host):
    """A traversal attempt must be refused, not read from disk."""
    response = auth_client.post(
        '/api/events/samples/..%2f..%2fconfig.py', json={'host_id': host.id})

    assert response.status_code in (400, 404)


def test_upload_import_creates_events(auth_client, host):
    import io

    data = {
        'host_id': str(host.id),
        'file': (io.BytesIO(
            b'Aug 12 09:14:02 lab sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2\n'
        ), 'auth.log'),
    }
    response = auth_client.post(
        '/api/events/import', data=data, content_type='multipart/form-data')

    assert response.status_code == 200
    assert response.get_json()['events_stored'] == 1


def test_generate_creates_a_burst_that_triggers_r01(auth_client, host):
    response = auth_client.post('/api/events/import', json={
        'host_id': host.id, 'generate': True, 'attempts': 8,
    })

    assert response.status_code == 200
    assert response.get_json()['alerts']['R-01'] == 1


def test_import_without_a_host_is_rejected(auth_client):
    response = auth_client.post('/api/events/import', json={'content': 'anything'})
    assert response.status_code == 400


def test_import_of_unparseable_content_is_rejected(auth_client, host):
    response = auth_client.post('/api/events/import', json={
        'host_id': host.id, 'content': 'this is not a log file',
    })
    assert response.status_code == 400


def test_listing_bundled_samples(auth_client):
    samples = auth_client.get('/api/events/samples').get_json()
    names = [s['name'] for s in samples]

    assert 'linux_auth_sample.log' in names
    assert 'windows_security_sample.csv' in names


# ---------------------------------------------------------------- event browsing

def test_events_can_be_filtered_by_type(auth_client, host):
    auth_client.post('/api/events/import', json={'host_id': host.id, 'generate': True})

    data = auth_client.get('/api/events?event_type=INVALID_USER').get_json()

    assert data['total'] > 0
    assert all(e['event_type'] == 'INVALID_USER' for e in data['events'])


def test_clearing_events_also_removes_their_alerts(auth_client, host):
    auth_client.post('/api/events/import', json={'host_id': host.id, 'generate': True})
    assert Alert.query.count() > 0

    auth_client.delete('/api/events')

    assert Event.query.count() == 0
    assert Alert.query.count() == 0
