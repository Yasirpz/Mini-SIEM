import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent


class Config:
    """Application configuration for the Mini-SIEM Flask app.

    Values are read from environment variables (see .env.example) so that
    secrets are never committed to the repository.
    """

    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-me')

    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'SQLALCHEMY_DATABASE_URI',
        f"sqlite:///{BASE_DIR / 'instance' / 'mini_siem.db'}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session cookie hardening (NFR: Security)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    # Enable only when the app is served over HTTPS, otherwise login breaks.
    SESSION_COOKIE_SECURE = os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'

    # SSH configuration (used for optional live Linux log collection)
    SSH_DEFAULT_HOST = os.getenv('SSH_DEFAULT_HOST', '127.0.0.1')
    SSH_DEFAULT_USER = os.getenv('SSH_DEFAULT_USER', 'siem-admin')
    SSH_DEFAULT_PORT = int(os.getenv('SSH_DEFAULT_PORT', 2222))
    SSH_KEY_FILE = os.getenv('SSH_KEY_FILE', '')
    SSH_PWD = os.getenv('SSH_PASSWORD', '')

    # Windows Security log collection.
    # How many raw records to pull per run before interactive-logon filtering.
    WINDOWS_MAX_EVENTS = int(os.getenv('WINDOWS_MAX_EVENTS', 200))

    # Event 4688 (process creation) fires thousands of times an hour on a
    # normal desktop and would bury the authentication events this project is
    # about, so it is off unless explicitly enabled. Command lines are never
    # collected either way — they routinely contain passwords and tokens.
    WINDOWS_COLLECT_PROCESS_EVENTS = (
        os.getenv('WINDOWS_COLLECT_PROCESS_EVENTS', 'false').lower() == 'true'
    )

    # Remote Windows collection over PowerShell remoting (WinRM).
    # The password lives here, read from .env — never in the database, where
    # it would leak into backups and exports. A per-host override can be set
    # as MINISIEM_WINRM_PASSWORD_<HOSTNAME> (uppercased, non-alphanumerics
    # replaced with underscores).
    WINRM_DEFAULT_USER = os.getenv('MINISIEM_WINRM_USER', '')
    WINRM_PASSWORD = os.getenv('MINISIEM_WINRM_PASSWORD', '')
    WINRM_PORT = int(os.getenv('MINISIEM_WINRM_PORT', 0)) or None
    WINRM_USE_SSL = os.getenv('MINISIEM_WINRM_USE_SSL', 'false').lower() == 'true'
    WINRM_AUTH = os.getenv('MINISIEM_WINRM_AUTH', 'Default')

    # Folder used to store raw collected logs (Parquet) for forensic retention
    STORAGE_FOLDER = BASE_DIR / 'storage'

    # Folder holding the sample log files shipped with the project (D-05)
    SAMPLES_FOLDER = BASE_DIR / 'samples'

    # --- Detection rule thresholds (proposal Section 10.2) ---
    # R-01: this many auth failures for the same user/IP inside the window.
    DETECTION_FAILED_LOGIN_THRESHOLD = int(os.getenv('DETECTION_FAILED_LOGIN_THRESHOLD', 5))
    DETECTION_FAILED_LOGIN_WINDOW_MINUTES = int(
        os.getenv('DETECTION_FAILED_LOGIN_WINDOW_MINUTES', 10)
    )
    # R-04: this many distinct hosts attacked by one source IP.
    DETECTION_MULTI_HOST_THRESHOLD = int(os.getenv('DETECTION_MULTI_HOST_THRESHOLD', 2))

    # Cap on uploaded sample log files (2 MB is ample for demonstration data).
    MAX_CONTENT_LENGTH = int(os.getenv('MAX_UPLOAD_BYTES', 2 * 1024 * 1024))

    # --- Automatic collection (background scheduler) ---
    # The scheduler thread polls every host that has polling switched on. It
    # is on by default because a SIEM that only collects when a button is
    # pressed is not monitoring anything -- but note that no *host* polls
    # until it is individually enabled, so a fresh install still does nothing
    # on its own.
    SCHEDULER_ENABLED = os.getenv('SCHEDULER_ENABLED', 'true').lower() == 'true'
    # How often the scheduler wakes to ask which hosts are due. This is not
    # the collection interval -- that is set per host -- only the resolution
    # at which due times are noticed.
    # Five seconds, because that is the shortest collection interval a host
    # may be set to and a tick coarser than the interval would silently round
    # every host up to the tick.
    SCHEDULER_TICK_SECONDS = int(os.getenv('SCHEDULER_TICK_SECONDS', 5))

    # --- How times are displayed ------------------------------------------
    # Everything is *stored* in UTC. This only decides which wall clock the
    # dashboard renders it against.
    #
    # Pinned to Pakistan Standard Time (UTC+05:00) rather than left to the
    # viewing machine, because the lab, the monitored hosts and the people
    # reading the dashboard are all in Pakistan, and "whatever this browser
    # thinks" is not a defensible answer when an operator has to state when an
    # incident happened. A machine whose clock is set to the wrong region --
    # a fresh Windows install often is -- would otherwise silently relabel
    # every event on screen.
    #
    # Set MINISIEM_DISPLAY_TIMEZONE to another IANA zone name to move the
    # display, or to the literal word "local" to go back to using whatever
    # timezone the viewing machine is configured for.
    #
    # An *empty* value falls back to the default rather than meaning "use the
    # browser's zone". That matters because .env.example ships the key with no
    # value, so the usual "copy the example to .env" would otherwise switch
    # Pakistan time off for everyone who followed the instructions.
    DISPLAY_TIMEZONE = (
        os.getenv('MINISIEM_DISPLAY_TIMEZONE', '').strip() or 'Asia/Karachi'
    )
    if DISPLAY_TIMEZONE.lower() == 'local':
        DISPLAY_TIMEZONE = ''


class TestConfig(Config):
    """Configuration used by the automated test suite."""

    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SECRET_KEY = 'test-secret-key'
    # No background thread during tests. Each test gets its own in-memory
    # database that is dropped when the fixture ends, and a scheduler tick
    # arriving mid-teardown would work against a database that no longer
    # exists. Tests that cover the scheduler drive it explicitly instead.
    SCHEDULER_ENABLED = False
