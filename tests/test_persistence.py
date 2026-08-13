"""
TC-08 Persistence Test (proposal Section 15).

Saved hosts, threat IPs, events and alerts must survive a restart of the
application. The test simulates a restart by disposing of the SQLAlchemy
session and re-querying through a fresh one against the same database file.
"""
import pytest

from app import create_app
from app.extensions import db
from app.models import Alert, Event, Host, IPRegistry, User
from app.services.log_analyzer import LogAnalyzer
from app.services.sample_loader import SampleLoader
from config import TestConfig


@pytest.fixture
def file_app(tmp_path):
    """
    An app backed by a real SQLite file rather than an in-memory database.

    An in-memory database disappears when the connection closes, so it cannot
    demonstrate persistence — this fixture uses a file so a second app
    instance can reopen the same data.
    """
    db_path = tmp_path / 'persistence_test.db'

    class FileConfig(TestConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{db_path}"
        STORAGE_FOLDER = tmp_path / 'storage'

    yield FileConfig

    # Tear down whatever the last app instance left registered.
    application = create_app(FileConfig)
    with application.app_context():
        db.session.remove()
        db.drop_all()


def test_records_survive_a_restart(file_app):
    # --- First run: create data, then "shut down". ---
    first = create_app(file_app)
    with first.app_context():
        user = User(username='persistadmin')
        user.set_password('password-123')

        host = Host(hostname='Lab-PC', ip_address='127.0.0.1', os_type='LINUX')
        registry = IPRegistry(ip_address='203.0.113.50', status='BANNED')

        db.session.add_all([user, host, registry])
        db.session.commit()

        LogAnalyzer.ingest(
            SampleLoader.generate_synthetic(attempts=8), host.id, archive=False)

        expected = {
            'events': Event.query.count(),
            'alerts': Alert.query.count(),
        }
        assert expected['events'] > 0
        assert expected['alerts'] > 0

        db.session.remove()

    # --- Second run: a fresh app against the same database file. ---
    second = create_app(file_app)
    with second.app_context():
        assert User.query.filter_by(username='persistadmin').first() is not None

        host = Host.query.filter_by(ip_address='127.0.0.1').first()
        assert host is not None
        assert host.hostname == 'Lab-PC'

        registry = IPRegistry.query.filter_by(ip_address='203.0.113.50').first()
        assert registry is not None
        assert registry.status == 'BANNED'

        assert Event.query.count() == expected['events']
        assert Alert.query.count() == expected['alerts']


def test_login_still_works_after_a_restart(file_app):
    first = create_app(file_app)
    with first.app_context():
        user = User(username='persistadmin')
        user.set_password('password-123')
        db.session.add(user)
        db.session.commit()
        db.session.remove()

    second = create_app(file_app)
    client = second.test_client()

    response = client.post(
        '/login',
        data={'username': 'persistadmin', 'password': 'password-123'},
        follow_redirects=True,
    )
    assert b'Logged in successfully' in response.data


def test_archived_parquet_files_outlive_a_database_reset(file_app, tmp_path):
    """
    Forensic retention: clearing alerts must not destroy the evidence they
    were derived from.
    """
    from app.services.data_manager import DataManager

    application = create_app(file_app)
    with application.app_context():
        host = Host(hostname='Lab-PC', ip_address='127.0.0.1', os_type='LINUX')
        db.session.add(host)
        db.session.commit()

        events = SampleLoader.generate_synthetic(attempts=6)
        result = LogAnalyzer.ingest(events, host.id, archive=True)
        archive_path = DataManager.storage_dir() / result['archive_file']
        assert archive_path.exists()

        Alert.query.delete()
        Event.query.delete()
        db.session.commit()

        assert Event.query.count() == 0
        assert archive_path.exists()

        # The retained copy is still readable and complete.
        assert len(DataManager.load_logs(result['archive_file'])) == len(events)
