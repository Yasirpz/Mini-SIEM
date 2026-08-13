"""
Shared pytest fixtures.

Each test gets a fresh in-memory database and a temporary storage folder, so
tests never touch the real instance/ database or leave Parquet files behind.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app  # noqa: E402
from app.extensions import db  # noqa: E402
from app.models import Host, IPRegistry, User, utcnow  # noqa: E402
from config import TestConfig  # noqa: E402

ADMIN_USERNAME = 'testadmin'
ADMIN_PASSWORD = 'test-password-123'


@pytest.fixture
def app(tmp_path):
    """A Flask app bound to an in-memory database and a temp storage folder."""

    class IsolatedConfig(TestConfig):
        STORAGE_FOLDER = tmp_path / 'storage'
        SAMPLES_FOLDER = Path(__file__).resolve().parent.parent / 'samples'

    application = create_app(IsolatedConfig)

    with application.app_context():
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin(app):
    """An administrator account for login tests."""
    user = User(username=ADMIN_USERNAME)
    user.set_password(ADMIN_PASSWORD)
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def auth_client(client, admin):
    """A test client with an authenticated session."""
    client.post(
        '/login',
        data={'username': ADMIN_USERNAME, 'password': ADMIN_PASSWORD},
        follow_redirects=True,
    )
    return client


@pytest.fixture
def host(app):
    """A single monitored host."""
    entry = Host(
        hostname='Lab-PC',
        ip_address='127.0.0.1',
        os_type='LINUX',
        description='Test host',
    )
    db.session.add(entry)
    db.session.commit()
    return entry


@pytest.fixture
def two_hosts(app):
    """Two monitored hosts, needed to exercise rule R-04."""
    first = Host(hostname='Lab-PC', ip_address='127.0.0.1', os_type='LINUX')
    second = Host(hostname='Lab-Server', ip_address='192.168.56.10', os_type='LINUX')
    db.session.add_all([first, second])
    db.session.commit()
    return first, second


@pytest.fixture
def banned_ip(app):
    """A source address marked BANNED, so rule R-03 can fire."""
    entry = IPRegistry(
        ip_address='203.0.113.50',
        status='BANNED',
        source='test fixture',
        date_added=utcnow(),
        last_seen=utcnow(),
    )
    db.session.add(entry)
    db.session.commit()
    return entry
