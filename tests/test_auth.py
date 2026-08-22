"""
TC-01 Login Test and TC-02 Protected Page Test (proposal Section 15).

Covers FR-01 (secure administrator login) and FR-02 (protected routes).
"""
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME

PROTECTED_PAGES = ['/', '/alerts', '/events', '/config']
PROTECTED_APIS = ['/api/hosts', '/api/ips', '/api/alerts', '/api/events', '/api/stats/summary']


# ---------------------------------------------------------------- TC-01

def test_login_rejects_wrong_password(client, admin):
    """Wrong credentials must not create a session."""
    response = client.post(
        '/login',
        data={'username': ADMIN_USERNAME, 'password': 'wrong-password'},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b'Login failed' in response.data

    # Still unauthenticated: a protected page must redirect to the login form.
    assert client.get('/').status_code == 302


def test_login_rejects_unknown_user(client, admin):
    response = client.post(
        '/login',
        data={'username': 'nobody', 'password': ADMIN_PASSWORD},
        follow_redirects=True,
    )
    assert b'Login failed' in response.data


def test_login_error_message_does_not_reveal_which_field_was_wrong(client, admin):
    """A generic failure message avoids confirming that a username exists."""
    wrong_password = client.post(
        '/login',
        data={'username': ADMIN_USERNAME, 'password': 'nope'},
        follow_redirects=True,
    )
    unknown_user = client.post(
        '/login',
        data={'username': 'ghost', 'password': 'nope'},
        follow_redirects=True,
    )
    assert b'Login failed' in wrong_password.data
    assert b'Login failed' in unknown_user.data


def test_login_accepts_valid_credentials(client, admin):
    """Correct credentials log the administrator in and reach the dashboard."""
    response = client.post(
        '/login',
        data={'username': ADMIN_USERNAME, 'password': ADMIN_PASSWORD},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b'Logged in successfully' in response.data
    assert b'Security Operations' in response.data


def test_password_is_stored_hashed(admin):
    """Passwords must never be readable in the database."""
    assert admin.password_hash is not None
    assert ADMIN_PASSWORD not in admin.password_hash
    assert admin.check_password(ADMIN_PASSWORD) is True
    assert admin.check_password('something else') is False


# ---------------------------------------------------------------- TC-02

def test_protected_pages_redirect_when_logged_out(client):
    """Every page requires a session (FR-02)."""
    for page in PROTECTED_PAGES:
        response = client.get(page)
        assert response.status_code == 302, f"{page} was reachable while logged out"
        assert '/login' in response.headers['Location']


def test_protected_apis_return_401_when_logged_out(client):
    """API calls answer with JSON 401 rather than an HTML redirect."""
    for endpoint in PROTECTED_APIS:
        response = client.get(endpoint)
        assert response.status_code == 401, f"{endpoint} was reachable while logged out"
        assert response.get_json()['error'] == 'Authentication required'


def test_pages_are_reachable_once_logged_in(auth_client):
    for page in PROTECTED_PAGES:
        assert auth_client.get(page).status_code == 200


def test_logout_ends_the_session(auth_client):
    """After logout, protected pages must be blocked again."""
    assert auth_client.get('/').status_code == 200

    auth_client.get('/logout', follow_redirects=True)

    response = auth_client.get('/')
    assert response.status_code == 302
    assert '/login' in response.headers['Location']


def test_login_does_not_follow_an_external_next_target(client, admin):
    """The ?next= parameter must not be usable as an open redirect."""
    response = client.post(
        '/login?next=https://example.com/phish',
        data={'username': ADMIN_USERNAME, 'password': ADMIN_PASSWORD},
    )
    assert response.status_code == 302
    assert 'example.com' not in response.headers['Location']
