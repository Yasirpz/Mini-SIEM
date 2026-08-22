"""
File Integrity Monitoring (rule R-10).

The scanner is exercised against real files on disk through the LOCAL
collection method, so what is tested is the actual hashing and comparison
rather than a mock of it. The behaviours that matter are: the first scan
establishes a baseline silently, later scans report modifications, additions
and deletions, an unchanged file produces nothing at all, and a legitimate
re-baseline is possible without acknowledging a flood of alerts.
"""
import pytest

from app.extensions import db
from app.models import (
    COLLECT_LOCAL,
    EVT_FILE_ADDED,
    EVT_FILE_DELETED,
    EVT_FILE_MODIFIED,
    Alert,
    Event,
    FileBaseline,
    Host,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    WatchedPath,
)
from app.services.file_integrity import scan_host


@pytest.fixture
def host(app):
    entry = Host(
        hostname='Lab-PC', ip_address='192.168.100.60', os_type='WINDOWS',
        collection_method=COLLECT_LOCAL, fim_enabled=True,
    )
    db.session.add(entry)
    db.session.commit()
    return entry


@pytest.fixture
def watched_dir(tmp_path, host):
    """A directory with two files in it, watched non-recursively."""
    (tmp_path / 'config.ini').write_text('setting=1\n', encoding='utf-8')
    (tmp_path / 'startup.bat').write_text('echo hello\n', encoding='utf-8')

    db.session.add(WatchedPath(host_id=host.id, path=str(tmp_path)))
    db.session.commit()
    return tmp_path


def _events(host, event_type=None):
    query = Event.query.filter_by(host_id=host.id)
    if event_type:
        query = query.filter_by(event_type=event_type)
    return query.all()


# ---------------------------------------------------------------------------
# The baseline
# ---------------------------------------------------------------------------

def test_the_first_scan_records_a_baseline_and_reports_nothing(app, host, watched_dir):
    """
    Switching monitoring on for a directory of existing files must not report
    every one of them as a finding. An operator who is shown four hundred
    alerts on day one learns to ignore the panel.
    """
    payload, status = scan_host(host)

    assert status == 200
    assert payload['baseline_established'] is True
    assert payload['files_checked'] == 2
    assert payload['changes'] == []
    assert FileBaseline.query.filter_by(host_id=host.id).count() == 2
    assert _events(host) == []


def test_the_baseline_records_a_real_hash(app, host, watched_dir):
    """
    The stored hash must be the SHA-256 of the file's actual bytes, not of
    what the test thought it wrote — Windows translates newlines on the way
    to disk, so the expectation is read back from the file itself.
    """
    import hashlib

    scan_host(host)

    target = watched_dir / 'config.ini'
    row = FileBaseline.query.filter_by(host_id=host.id, path=str(target)).one()

    raw = target.read_bytes()
    assert row.sha256 == hashlib.sha256(raw).hexdigest()
    assert row.size_bytes == len(raw)
    # Never tampered with, so there is no "last changed" moment to report.
    assert row.last_changed is None


def test_a_second_scan_with_nothing_changed_reports_nothing(app, host, watched_dir):
    scan_host(host)
    payload, status = scan_host(host)

    assert status == 200
    assert payload['baseline_established'] is False
    assert payload['changes'] == []
    assert _events(host) == []


# ---------------------------------------------------------------------------
# Detecting change
# ---------------------------------------------------------------------------

def test_a_modified_file_is_detected(app, host, watched_dir):
    scan_host(host)
    (watched_dir / 'config.ini').write_text('setting=666\n', encoding='utf-8')

    payload, _ = scan_host(host)

    assert len(payload['changes']) == 1
    assert payload['changes'][0]['event_type'] == EVT_FILE_MODIFIED
    assert 'config.ini' in payload['changes'][0]['path']

    events = _events(host, EVT_FILE_MODIFIED)
    assert len(events) == 1
    assert events[0].file_path == str(watched_dir / 'config.ini')


def test_a_modification_updates_the_baseline_so_it_is_not_reported_twice(app, host, watched_dir):
    """
    The new state becomes the state being compared against. Reporting the same
    change on every subsequent scan would bury any later, different change.
    """
    scan_host(host)
    (watched_dir / 'config.ini').write_text('setting=666\n', encoding='utf-8')

    scan_host(host)
    payload, _ = scan_host(host)

    assert payload['changes'] == []
    assert len(_events(host, EVT_FILE_MODIFIED)) == 1

    row = FileBaseline.query.filter_by(path=str(watched_dir / 'config.ini')).one()
    assert row.last_changed is not None


def test_a_new_file_is_detected(app, host, watched_dir):
    scan_host(host)
    (watched_dir / 'payload.exe').write_text('malware', encoding='utf-8')

    payload, _ = scan_host(host)

    assert len(payload['changes']) == 1
    assert payload['changes'][0]['event_type'] == EVT_FILE_ADDED
    assert 'payload.exe' in payload['changes'][0]['path']


def test_a_deleted_file_is_detected(app, host, watched_dir):
    scan_host(host)
    (watched_dir / 'startup.bat').unlink()

    payload, _ = scan_host(host)

    assert len(payload['changes']) == 1
    assert payload['changes'][0]['event_type'] == EVT_FILE_DELETED
    # The baseline row goes with it; there is nothing left to compare against.
    assert FileBaseline.query.filter_by(
        path=str(watched_dir / 'startup.bat')
    ).count() == 0


def test_several_files_changing_at_once_are_separate_findings(app, host, watched_dir):
    """
    The de-duplication key had to learn about file paths for this. Two files
    changing in the same second are two findings, not one repeated one.
    """
    scan_host(host)
    (watched_dir / 'config.ini').write_text('changed\n', encoding='utf-8')
    (watched_dir / 'startup.bat').write_text('changed too\n', encoding='utf-8')

    payload, _ = scan_host(host)

    assert len(payload['changes']) == 2
    assert len(_events(host, EVT_FILE_MODIFIED)) == 2


def test_a_watched_single_file_is_supported(app, host, tmp_path):
    target = tmp_path / 'hosts'
    target.write_text('127.0.0.1 localhost\n', encoding='utf-8')
    db.session.add(WatchedPath(host_id=host.id, path=str(target)))
    db.session.commit()

    scan_host(host)
    target.write_text('127.0.0.1 evil.example\n', encoding='utf-8')
    payload, _ = scan_host(host)

    assert len(payload['changes']) == 1
    assert payload['changes'][0]['event_type'] == EVT_FILE_MODIFIED


def test_a_non_recursive_watch_ignores_subdirectories(app, host, watched_dir):
    nested = watched_dir / 'sub'
    nested.mkdir()
    (nested / 'deep.txt').write_text('hidden', encoding='utf-8')

    payload, _ = scan_host(host)

    # Only the two files at the top level.
    assert payload['files_checked'] == 2


def test_a_recursive_watch_includes_subdirectories(app, host, tmp_path):
    (tmp_path / 'top.txt').write_text('a', encoding='utf-8')
    nested = tmp_path / 'sub'
    nested.mkdir()
    (nested / 'deep.txt').write_text('b', encoding='utf-8')

    db.session.add(WatchedPath(host_id=host.id, path=str(tmp_path), recursive=True))
    db.session.commit()

    payload, _ = scan_host(host)
    assert payload['files_checked'] == 2


def test_a_path_that_does_not_exist_is_not_an_error(app, host, tmp_path):
    """
    Watching a path before anything is there is legitimate: a file appearing
    where none should be is exactly what this feature is for.
    """
    db.session.add(WatchedPath(host_id=host.id, path=str(tmp_path / 'not-yet')))
    db.session.commit()

    payload, status = scan_host(host)

    assert status == 200
    assert payload['files_checked'] == 0


def test_a_host_with_nothing_watched_says_so(app, host):
    payload, status = scan_host(host)

    assert status == 200
    assert payload['watched_paths'] == 0
    assert 'No paths are being watched' in payload['message']


# ---------------------------------------------------------------------------
# R-10
# ---------------------------------------------------------------------------

def test_r10_raises_a_high_alert_for_a_modified_file(app, host, watched_dir):
    scan_host(host)
    (watched_dir / 'config.ini').write_text('tampered\n', encoding='utf-8')
    scan_host(host)

    alerts = Alert.query.filter_by(rule_id='R-10').all()
    assert len(alerts) == 1
    assert alerts[0].severity == SEVERITY_HIGH
    assert alerts[0].alert_type == 'FILE_INTEGRITY'
    assert 'config.ini' in alerts[0].message


def test_r10_raises_a_medium_alert_for_a_new_file(app, host, watched_dir):
    """
    A directory legitimately gains files during ordinary use, so a new file is
    worth looking at rather than critical. Treating it as HIGH would train the
    operator to dismiss the rule.
    """
    scan_host(host)
    (watched_dir / 'dropped.exe').write_text('x', encoding='utf-8')
    scan_host(host)

    alert = Alert.query.filter_by(rule_id='R-10').one()
    assert alert.severity == SEVERITY_MEDIUM


def test_r10_raises_a_high_alert_for_a_deleted_file(app, host, watched_dir):
    scan_host(host)
    (watched_dir / 'startup.bat').unlink()
    scan_host(host)

    alert = Alert.query.filter_by(rule_id='R-10').one()
    assert alert.severity == SEVERITY_HIGH


def test_an_integrity_event_does_not_feed_the_brute_force_rule(app, host, watched_dir):
    """A file changing is not an authentication attempt."""
    scan_host(host)
    for index in range(6):
        (watched_dir / 'config.ini').write_text(f'change {index}\n', encoding='utf-8')
        scan_host(host)

    assert Alert.query.filter_by(rule_id='R-01').count() == 0


def test_an_integrity_event_does_not_pollute_the_threat_registry(app, host, watched_dir):
    from app.models import IPRegistry

    scan_host(host)
    (watched_dir / 'config.ini').write_text('changed\n', encoding='utf-8')
    scan_host(host)

    assert IPRegistry.query.filter_by(ip_address='LOCAL_CONSOLE').count() == 0


# ---------------------------------------------------------------------------
# The API
# ---------------------------------------------------------------------------

def test_a_watched_path_can_be_added_and_removed(auth_client, app, host, tmp_path):
    response = auth_client.post(
        f'/api/hosts/{host.id}/watched-paths',
        json={'path': str(tmp_path), 'recursive': True, 'description': 'Lab config'},
    )
    assert response.status_code == 201
    path_id = response.get_json()['id']

    listing = auth_client.get(f'/api/hosts/{host.id}/watched-paths').get_json()
    assert len(listing) == 1
    assert listing[0]['recursive'] is True

    removed = auth_client.delete(f'/api/watched-paths/{path_id}')
    assert removed.status_code == 200
    assert WatchedPath.query.count() == 0


def test_the_same_path_cannot_be_watched_twice_on_one_host(auth_client, app, host, tmp_path):
    payload = {'path': str(tmp_path)}
    auth_client.post(f'/api/hosts/{host.id}/watched-paths', json=payload)
    duplicate = auth_client.post(f'/api/hosts/{host.id}/watched-paths', json=payload)

    assert duplicate.status_code == 409


def test_a_path_containing_a_line_break_is_rejected(auth_client, app, host):
    response = auth_client.post(
        f'/api/hosts/{host.id}/watched-paths',
        json={'path': 'C:\\lab\nrm -rf /'},
    )

    assert response.status_code == 400
    assert 'line breaks' in response.get_json()['error']


def test_an_empty_path_is_rejected(auth_client, app, host):
    response = auth_client.post(
        f'/api/hosts/{host.id}/watched-paths', json={'path': '   '}
    )
    assert response.status_code == 400


def test_removing_a_watched_path_removes_its_baselines(auth_client, app, host, watched_dir):
    scan_host(host)
    assert FileBaseline.query.count() == 2

    entry = WatchedPath.query.one()
    response = auth_client.delete(f'/api/watched-paths/{entry.id}')

    assert response.get_json()['baselines_removed'] == 2
    assert FileBaseline.query.count() == 0


def test_the_scan_endpoint_reports_changes(auth_client, app, host, watched_dir):
    auth_client.post(f'/api/hosts/{host.id}/integrity-scan')
    (watched_dir / 'config.ini').write_text('tampered\n', encoding='utf-8')

    response = auth_client.post(f'/api/hosts/{host.id}/integrity-scan')

    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload['changes']) == 1
    assert payload['alerts']['R-10'] == 1


def test_the_baseline_can_be_inspected(auth_client, app, host, watched_dir):
    scan_host(host)

    payload = auth_client.get(f'/api/hosts/{host.id}/baselines').get_json()

    assert payload['total'] == 2
    assert all(len(row['sha256']) == 64 for row in payload['baselines'])


def test_the_baseline_can_be_reset_after_a_legitimate_change(auth_client, app, host, watched_dir):
    """
    A software update rewrites many files at once. Without a reset the only
    options would be to acknowledge every alert or stop watching the path.
    """
    scan_host(host)
    (watched_dir / 'config.ini').write_text('updated by vendor\n', encoding='utf-8')

    response = auth_client.delete(f'/api/hosts/{host.id}/baselines')
    assert response.status_code == 200
    assert response.get_json()['baselines_removed'] == 2

    payload, _ = scan_host(host)
    assert payload['baseline_established'] is True
    assert payload['changes'] == []


def test_integrity_endpoints_need_a_login(client, app, host):
    assert client.get(f'/api/hosts/{host.id}/watched-paths').status_code == 401
    assert client.post(f'/api/hosts/{host.id}/integrity-scan').status_code == 401
    assert client.get(f'/api/hosts/{host.id}/baselines').status_code == 401


# ---------------------------------------------------------------------------
# Scheduler integration
# ---------------------------------------------------------------------------

def test_the_scheduler_scans_files_for_a_host_that_asked_for_it(app, host, watched_dir, monkeypatch):
    from app.services.scheduler import CollectionScheduler
    import app.services.collection as collection_service

    host.polling_enabled = True
    db.session.commit()

    monkeypatch.setattr(collection_service, 'collect_host',
                        lambda h: ({'message': 'ok'}, 200))

    scheduler = CollectionScheduler(app)
    scheduler.run_once()

    assert FileBaseline.query.filter_by(host_id=host.id).count() == 2
    assert scheduler.integrity_scans == 1


def test_the_scheduler_skips_hosts_that_did_not_ask_for_it(app, host, watched_dir, monkeypatch):
    from app.services.scheduler import CollectionScheduler
    import app.services.collection as collection_service

    host.polling_enabled = True
    host.fim_enabled = False
    db.session.commit()

    monkeypatch.setattr(collection_service, 'collect_host',
                        lambda h: ({'message': 'ok'}, 200))

    scheduler = CollectionScheduler(app)
    scheduler.run_once()

    assert FileBaseline.query.count() == 0
    assert scheduler.integrity_scans == 0


def test_a_failing_scan_does_not_cost_the_collection(app, host, watched_dir, monkeypatch):
    """
    An integrity scan is an addition to log collection, never a precondition.
    The logs are already stored by the time the scan runs.
    """
    from app.services.scheduler import CollectionScheduler
    import app.services.collection as collection_service
    import app.services.file_integrity as fim

    host.polling_enabled = True
    db.session.commit()

    collected = []
    monkeypatch.setattr(collection_service, 'collect_host',
                        lambda h: (collected.append(h.hostname), ({'message': 'ok'}, 200))[1])
    monkeypatch.setattr(fim, 'scan_host', lambda h: (_ for _ in ()).throw(RuntimeError('boom')))

    scheduler = CollectionScheduler(app)
    result = scheduler.run_once()

    assert collected == ['Lab-PC']
    assert result == ['Lab-PC']
    assert scheduler.integrity_scans == 0


# ---------------------------------------------------------------------------
# The dashboard's view of a finding
# ---------------------------------------------------------------------------
#
# "Watched file was modified" is an assertion; a pair of hashes is evidence.
# The panel on the dashboard has to be able to show both, and the hashes live
# in the event's raw record rather than in a column -- so a dedicated endpoint
# lifts them out. These tests are what stop that endpoint quietly losing them.

def test_recent_changes_carry_both_hashes(auth_client, app, host, watched_dir):
    scan_host(host)
    (watched_dir / 'config.ini').write_text('setting=2\n', encoding='utf-8')
    scan_host(host)

    data = auth_client.get('/api/integrity/changes').get_json()

    assert len(data['changes']) == 1
    change = data['changes'][0]
    assert change['event_type'] == EVT_FILE_MODIFIED
    assert change['file_path'].endswith('config.ini')
    # Both digests are full SHA-256 values, and they differ -- that pair is
    # the whole evidence for the finding.
    assert len(change['sha256']) == 64
    assert len(change['previous_sha256']) == 64
    assert change['sha256'] != change['previous_sha256']


def test_a_new_file_has_no_previous_hash(auth_client, app, host, watched_dir):
    """
    A file that has just appeared never had a baseline, so there is nothing to
    compare against. Reporting a previous hash here would be inventing one.
    """
    scan_host(host)
    (watched_dir / 'dropped.txt').write_text('new\n', encoding='utf-8')
    scan_host(host)

    change = auth_client.get('/api/integrity/changes').get_json()['changes'][0]

    assert change['event_type'] == EVT_FILE_ADDED
    assert change['previous_sha256'] is None
    assert len(change['sha256']) == 64


def test_recent_changes_report_how_many_paths_are_watched(auth_client, app, host,
                                                          watched_dir):
    """
    An empty panel means one thing when forty paths are watched and something
    else entirely when none are, so the count travels with the (empty) list
    rather than needing a second request to disambiguate it.
    """
    scan_host(host)

    data = auth_client.get('/api/integrity/changes').get_json()

    assert data['changes'] == []
    assert data['watched_paths'] == 1


def test_a_malformed_raw_record_does_not_break_the_panel(auth_client, app, host,
                                                          watched_dir):
    """
    The finding is real even if its corroboration cannot be read back. Losing
    the hashes is acceptable; losing the row, or the page, is not.
    """
    scan_host(host)
    (watched_dir / 'config.ini').write_text('setting=3\n', encoding='utf-8')
    scan_host(host)

    event = Event.query.filter_by(event_type=EVT_FILE_MODIFIED).first()
    event.raw_log = 'not json at all'
    db.session.commit()

    change = auth_client.get('/api/integrity/changes').get_json()['changes'][0]

    assert change['file_path'].endswith('config.ini')
    assert change['sha256'] is None
    assert change['previous_sha256'] is None


def test_recent_changes_require_a_session(client):
    response = client.get('/api/integrity/changes')

    assert response.status_code == 401
