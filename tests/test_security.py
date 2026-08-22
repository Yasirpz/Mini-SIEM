"""
Security defaults that must not quietly regress.

These are not tests of the detection engine; they are tests of the things a
security tool has to get right about *itself*. Two of them exist because the
project was shipping the wrong default and nothing said so.
"""
import logging
from pathlib import Path

import pytest

from app import create_app
from config import Config, TestConfig

PROJECT_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Debug mode
# ---------------------------------------------------------------------------

def test_debug_mode_is_off_by_default():
    """
    .flaskenv used to ship FLASK_DEBUG=1, so the documented way to start the
    application started it with Werkzeug's debugger enabled. That debugger
    turns any unhandled exception into an interactive Python console in the
    browser and prints source and local variables into the traceback -- on a
    process that is reading Windows Security logs and holding an
    administrator session.
    """
    flaskenv = (PROJECT_ROOT / '.flaskenv').read_text(encoding='utf-8')

    assert 'FLASK_DEBUG=0' in flaskenv
    assert 'FLASK_DEBUG=1' not in flaskenv.replace('#     set FLASK_DEBUG=1', '') \
        .replace('#     $env:FLASK_DEBUG=1', '') \
        .replace('#     FLASK_DEBUG=1', '')


# ---------------------------------------------------------------------------
# Secret key
# ---------------------------------------------------------------------------

def test_the_default_secret_key_is_a_named_constant():
    """
    The application has to be able to recognise its own default in order to
    warn about it, which it cannot do if the value is only a literal buried in
    a call to os.getenv.
    """
    assert Config.DEFAULT_SECRET_KEY == 'dev-key-change-me'


def test_starting_on_the_default_secret_key_logs_a_warning(tmp_path, caplog):
    """
    The session cookie is signed with SECRET_KEY. If it is the value published
    in this repository, anyone who knows it can mint a cookie for the
    administrator account -- and every other control in the application sits
    downstream of that. It is not worth refusing to start over, because a
    student following the README should get a working application; it is
    worth saying out loud.
    """

    class DefaultKeyConfig(TestConfig):
        TESTING = False          # the warning is deliberately skipped in tests
        SECRET_KEY = Config.DEFAULT_SECRET_KEY
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'warn.db'}"
        STORAGE_FOLDER = tmp_path / 'storage'
        SAMPLES_FOLDER = PROJECT_ROOT / 'samples'
        SCHEDULER_ENABLED = False

    with caplog.at_level(logging.WARNING):
        create_app(DefaultKeyConfig)

    assert any('SECRET_KEY' in record.message for record in caplog.records)


def test_a_configured_secret_key_produces_no_warning(tmp_path, caplog):
    """The warning must be about the default, not about starting up at all."""

    class RealKeyConfig(TestConfig):
        TESTING = False
        SECRET_KEY = 'a-genuinely-configured-value-8f2c1d'
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'quiet.db'}"
        STORAGE_FOLDER = tmp_path / 'storage'
        SAMPLES_FOLDER = PROJECT_ROOT / 'samples'
        SCHEDULER_ENABLED = False

    with caplog.at_level(logging.WARNING):
        create_app(RealKeyConfig)

    assert not any('SECRET_KEY' in record.message for record in caplog.records)


# ---------------------------------------------------------------------------
# Route protection
# ---------------------------------------------------------------------------

def test_every_route_except_login_requires_a_session(app):
    """
    FR-02. Checked over the URL map rather than page by page, so a route added
    later without @login_required is caught here instead of being found by
    whoever tries it.
    """
    unprotected = []

    for rule in app.url_map.iter_rules():
        if rule.endpoint in ('static', 'auth.login'):
            continue
        view = app.view_functions[rule.endpoint]
        # flask_login's decorator wraps the view; an undecorated one does not
        # carry __wrapped__.
        if not hasattr(view, '__wrapped__'):
            unprotected.append(f'{rule.endpoint} ({rule.rule})')

    assert unprotected == [], f'routes reachable without logging in: {unprotected}'


@pytest.mark.parametrize('path', [
    '/', '/alerts', '/events', '/config',
    '/api/hosts', '/api/alerts', '/api/events', '/api/stats/summary',
    '/api/stats/attack', '/api/integrity/changes', '/api/scheduler',
])
def test_protected_paths_reject_an_anonymous_caller(client, path):
    response = client.get(path)

    if path.startswith('/api/'):
        assert response.status_code == 401
        assert response.get_json()['error'] == 'Authentication required'
    else:
        # Pages redirect to the login form rather than answering with JSON.
        assert response.status_code == 302
        assert '/login' in response.headers['Location']


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------

def test_a_watched_path_cannot_carry_a_line_break_into_a_shell():
    """
    Watched paths are interpolated into a PowerShell script and an SSH command
    line. Both quote the value, but a newline would end the quoted string on
    the far side, so it is refused at the boundary rather than relied upon to
    be harmless later.
    """
    from app.validators import ValidationError, validate_watched_path

    for bad in ('C:\\lab\nwhoami', 'C:\\lab\r\nrm -rf /', 'C:\\lab\x00'):
        with pytest.raises(ValidationError):
            validate_watched_path(bad)


def test_a_quote_in_a_watched_path_is_escaped_for_powershell(app):
    """
    A single quote is legal in a Windows filename, so it cannot simply be
    rejected -- it has to be escaped. PowerShell escapes a quote inside a
    single-quoted string by doubling it.
    """
    from app.services.file_integrity import _windows_hash_script

    class FakeEntry:
        path = "C:\\lab\\it's here"
        recursive = False

    script = _windows_hash_script(FakeEntry())

    assert "$target = 'C:\\lab\\it''s here';" in script
    # -LiteralPath throughout, so a name containing wildcards is read as a
    # name rather than expanded into a pattern.
    assert '-LiteralPath' in script
    assert 'Get-ChildItem -Path' not in script
