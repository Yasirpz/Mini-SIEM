"""
Database models for Mini-SIEM.

Covers deliverable D-04: schema for users, hosts, threat IPs, events and alerts.
"""
from datetime import datetime, timedelta, timezone

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from .extensions import db


def utcnow():
    """
    Current UTC time as a naive datetime.

    SQLite drops tzinfo when storing a DateTime column, so values read back
    are always naive. Storing naive UTC everywhere keeps in-memory values and
    database values directly comparable — important for the time-window
    arithmetic in the detection rules.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


# Severity levels used across the detection engine and the dashboard.
# The proposal (Section 6.1) specifies Low / Medium / High.
SEVERITY_LOW = 'LOW'
SEVERITY_MEDIUM = 'MEDIUM'
SEVERITY_HIGH = 'HIGH'
SEVERITIES = (SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH)

# Ordering helper so "most severe first" sorting is unambiguous.
SEVERITY_RANK = {SEVERITY_LOW: 1, SEVERITY_MEDIUM: 2, SEVERITY_HIGH: 3}

# How a host's logs are reached.
#   LOCAL — read the Security log of the machine running Mini-SIEM
#   WINRM — run the query on a remote Windows PC over PowerShell remoting
#   SSH   — run the query on a remote Linux host over SSH
COLLECT_LOCAL = 'LOCAL'
COLLECT_WINRM = 'WINRM'
COLLECT_SSH = 'SSH'
COLLECTION_METHODS = (COLLECT_LOCAL, COLLECT_WINRM, COLLECT_SSH)

# Host health, derived from what collection actually did — never from the
# host merely existing in the database.
HOST_ONLINE = 'ONLINE'        # last attempt succeeded, and it was recent
HOST_DEGRADED = 'DEGRADED'    # has worked before, but the last attempt failed
HOST_OFFLINE = 'OFFLINE'      # failing, and no recent success
HOST_UNKNOWN = 'UNKNOWN'      # never contacted
HOST_STATUSES = (HOST_ONLINE, HOST_DEGRADED, HOST_OFFLINE, HOST_UNKNOWN)

# A host whose last success is older than this is no longer counted online,
# even if nothing has failed since — silence is not the same as health.
HOST_STALE_AFTER_MINUTES = 60

# How often a host is collected from automatically when polling is switched
# on for it. Five minutes is a compromise: short enough that a USB drive
# plugged in during a demonstration appears while the observer is still
# watching, long enough that a lab of hosts is not hammered continuously.
DEFAULT_POLL_INTERVAL_SECONDS = 300

# The shortest interval a host may be set to. Each poll opens a PowerShell
# session or an SSH connection, which takes seconds on a real network, so an
# interval below this would start the next collection before the previous one
# had finished and achieve nothing but load.
MIN_POLL_INTERVAL_SECONDS = 30

# Whether a host is actually capable of reporting USB devices, which depends
# on Plug and Play auditing being switched on there (it is off by default).
# Without this the "Recent USB Devices" panel is ambiguous: an empty panel
# could mean nothing was plugged in, or that the host would never have told
# us either way. Recording the difference is the same reasoning that makes an
# uncontacted host UNKNOWN rather than optimistically ONLINE.
USB_AUDIT_ENABLED = 'ENABLED'      # auditpol reports Success for the subcategory
USB_AUDIT_DISABLED = 'DISABLED'    # explicitly "No Auditing"
USB_AUDIT_UNKNOWN = 'UNKNOWN'      # never probed, or the probe itself failed
USB_AUDIT_STATES = (USB_AUDIT_ENABLED, USB_AUDIT_DISABLED, USB_AUDIT_UNKNOWN)

# Threat Intelligence registry statuses.
IP_UNKNOWN = 'UNKNOWN'
IP_TRUSTED = 'TRUSTED'
IP_BANNED = 'BANNED'
IP_STATUSES = (IP_UNKNOWN, IP_TRUSTED, IP_BANNED)

# Normalized event types produced by the collectors and sample importers.
EVT_FAILED_LOGIN = 'FAILED_LOGIN'
EVT_INVALID_USER = 'INVALID_USER'
EVT_WIN_FAILED_LOGIN = 'WIN_FAILED_LOGIN'
EVT_SUCCESSFUL_LOGIN = 'SUCCESSFUL_LOGIN'
EVT_SUDO_USAGE = 'SUDO_USAGE'

# Wider Windows Security activity, beyond plain logon success and failure.
# These describe the *consequences* of an attack and the actions an intruder
# takes afterwards, so they give the dashboard a fuller picture than
# authentication attempts alone.
EVT_ACCOUNT_LOCKOUT = 'ACCOUNT_LOCKOUT'              # 4740
EVT_EXPLICIT_CREDENTIALS = 'EXPLICIT_CREDENTIALS'    # 4648
EVT_ADMIN_LOGON = 'ADMIN_LOGON'                      # 4672
EVT_ACCOUNT_CREATED = 'ACCOUNT_CREATED'              # 4720
EVT_ACCOUNT_ENABLED = 'ACCOUNT_ENABLED'              # 4722
EVT_GROUP_MEMBER_ADDED = 'GROUP_MEMBER_ADDED'        # 4732
EVT_PASSWORD_RESET = 'PASSWORD_RESET'                # 4724
EVT_AUDIT_LOG_CLEARED = 'AUDIT_LOG_CLEARED'          # 1102
EVT_ACCOUNT_DELETED = 'ACCOUNT_DELETED'              # 4726
EVT_PROCESS_CREATED = 'PROCESS_CREATED'              # 4688

# Physical activity at the machine itself, rather than over the network.
# A removable drive is how data leaves an organisation and how malware
# arrives, so it belongs in the same picture as the network-borne events
# even though no source address is involved.
EVT_USB_DEVICE_CONNECTED = 'USB_DEVICE_CONNECTED'    # 6416

# File Integrity Monitoring. Windows and Linux both log who signed in, but
# neither logs that a file quietly changed -- and altering a binary, a
# configuration file or a startup script is how an intruder persists after
# the logon that let them in has scrolled out of view. These events are
# produced by comparing a fresh hash against a stored baseline rather than by
# reading any log, which is why they have no event ID.
EVT_FILE_MODIFIED = 'FILE_MODIFIED'
EVT_FILE_ADDED = 'FILE_ADDED'
EVT_FILE_DELETED = 'FILE_DELETED'
FILE_INTEGRITY_EVENT_TYPES = (EVT_FILE_MODIFIED, EVT_FILE_ADDED, EVT_FILE_DELETED)

# How many files one watched path may contribute to a single scan. A path
# pointed at a whole system directory could otherwise ask the host to hash
# tens of thousands of files, which on a remote machine means a scan that
# never finishes. Reaching the cap is reported rather than silently truncated,
# because a partial scan that looks complete is worse than no scan.
FIM_MAX_FILES_PER_PATH = 500

# Event types that the detection rules treat as authentication failures.
# Deliberately unchanged: rule R-01 counts login *attempts*, so a lockout
# (the result of failures already counted) must not inflate it, and a
# successful logon must never contribute to a brute-force score.
FAILURE_EVENT_TYPES = (EVT_FAILED_LOGIN, EVT_INVALID_USER, EVT_WIN_FAILED_LOGIN)

# Activity that is not an attack in itself but is worth surfacing, because it
# is what an intruder does once inside: gaining privilege, creating accounts,
# widening group membership, or erasing the evidence.
SENSITIVE_EVENT_TYPES = (
    EVT_FILE_MODIFIED,
    EVT_FILE_ADDED,
    EVT_FILE_DELETED,
    EVT_ACCOUNT_LOCKOUT,
    EVT_EXPLICIT_CREDENTIALS,
    EVT_ACCOUNT_CREATED,
    EVT_ACCOUNT_DELETED,
    EVT_ACCOUNT_ENABLED,
    EVT_GROUP_MEMBER_ADDED,
    EVT_PASSWORD_RESET,
    EVT_AUDIT_LOG_CLEARED,
    EVT_USB_DEVICE_CONNECTED,
)


# === USER MODEL (Administrator accounts) ===
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(256))
    created_at = db.Column(db.DateTime, default=utcnow)

    def set_password(self, password):
        """Hash and store the given plain-text password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Return True if the given plain-text password matches the stored hash."""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)


# === MONITORED HOST ===
class Host(db.Model):
    __tablename__ = 'hosts'
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    os_type = db.Column(db.String(20))  # LINUX, WINDOWS
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=utcnow)

    # How to reach this host's logs. Defaults are inferred from os_type when
    # the column is empty, so hosts created before this field existed keep
    # behaving exactly as they did.
    collection_method = db.Column(db.String(20))
    # Username used for remote authentication. Deliberately *not* accompanied
    # by a password column: secrets belong in .env, never in the database,
    # where they would end up in backups and Parquet exports.
    remote_user = db.Column(db.String(100))

    # --- Collection health -------------------------------------------------
    # Recorded from real collection outcomes so the dashboard reports what the
    # system actually observed rather than what it hopes is true.
    last_attempt = db.Column(db.DateTime)
    last_success = db.Column(db.DateTime)
    last_error = db.Column(db.String(500))
    last_latency_ms = db.Column(db.Integer)

    # Last observed Plug and Play auditing state on this host. Stored rather
    # than probed on every dashboard load, because running auditpol per host
    # on each refresh would make the page pay for information that changes
    # only when someone deliberately alters the audit policy.
    usb_audit_status = db.Column(db.String(20))

    # --- Automatic collection ----------------------------------------------
    # Whether the background scheduler collects from this host on a timer.
    # Off by default, and deliberately so: enabling it starts repeated
    # authenticated connections to a machine, which is not something an
    # upgrade should begin doing to an existing installation on its own.
    polling_enabled = db.Column(db.Boolean, default=False, nullable=False,
                                server_default='0')
    # Per-host override of DEFAULT_POLL_INTERVAL_SECONDS. NULL means "use the
    # default", so changing the default later moves every host that never
    # asked for something specific.
    poll_interval_seconds = db.Column(db.Integer)
    # When the scheduler last ran a collection for this host. Kept separate
    # from last_attempt, which a manual Collect or a connection test also
    # writes: mixing them would let clicking Test quietly postpone the next
    # automatic collection.
    last_poll = db.Column(db.DateTime)

    # --- File Integrity Monitoring -----------------------------------------
    # Off by default, like polling and for the same reason: hashing files on a
    # remote machine is real work done to somebody else's computer, and an
    # upgrade should not start doing it uninvited.
    fim_enabled = db.Column(db.Boolean, default=False, nullable=False,
                            server_default='0')
    last_integrity_scan = db.Column(db.DateTime)
    last_integrity_error = db.Column(db.String(500))

    log_sources = db.relationship(
        'LogSource', backref='host', lazy='dynamic', cascade='all, delete-orphan'
    )
    alerts = db.relationship(
        'Alert', backref='host', lazy='dynamic', cascade='all, delete-orphan'
    )
    events = db.relationship(
        'Event', backref='host', lazy='dynamic', cascade='all, delete-orphan'
    )
    archives = db.relationship(
        'LogArchive', backref='host', lazy='dynamic', cascade='all, delete-orphan'
    )
    watched_paths = db.relationship(
        'WatchedPath', backref='host', lazy='dynamic', cascade='all, delete-orphan'
    )
    file_baselines = db.relationship(
        'FileBaseline', backref='host', lazy='dynamic', cascade='all, delete-orphan'
    )

    def effective_collection_method(self):
        """
        How this host should be collected from.

        Falls back to the historical behaviour when unset: Linux hosts over
        SSH, Windows hosts read locally.
        """
        if self.collection_method in COLLECTION_METHODS:
            return self.collection_method
        return COLLECT_SSH if self.os_type == 'LINUX' else COLLECT_LOCAL

    def health(self):
        """
        Derive the host's status from real collection outcomes.

        A host is ONLINE only when a collection actually succeeded recently.
        Having a row in the database proves nothing about reachability, so
        an uncontacted host is UNKNOWN rather than optimistically ONLINE.
        """
        if self.last_attempt is None:
            return HOST_UNKNOWN

        succeeded_last = (
            self.last_success is not None
            and (self.last_error is None or self.last_success >= self.last_attempt)
        )

        fresh = (
            self.last_success is not None
            and (utcnow() - self.last_success).total_seconds()
            < HOST_STALE_AFTER_MINUTES * 60
        )

        if succeeded_last:
            return HOST_ONLINE if fresh else HOST_DEGRADED

        # The last attempt failed. If it has worked at some point, treat it as
        # degraded rather than offline so a single blip is not alarming.
        return HOST_DEGRADED if fresh else HOST_OFFLINE

    def effective_poll_interval(self):
        """
        How many seconds should pass between automatic collections.

        Falls back to the shared default when the host has no preference, and
        never returns anything below MIN_POLL_INTERVAL_SECONDS — a value that
        small can only have arrived from a hand-edited database, and honouring
        it would put the scheduler into a connect loop.
        """
        interval = self.poll_interval_seconds or DEFAULT_POLL_INTERVAL_SECONDS
        return max(int(interval), MIN_POLL_INTERVAL_SECONDS)

    def next_poll_at(self):
        """
        When this host is next due to be collected from, or None if polling
        is off. A host that has never been polled is due immediately, which
        is what makes switching the toggle on produce a visible result.
        """
        if not self.polling_enabled:
            return None
        if self.last_poll is None:
            return utcnow()
        return self.last_poll + timedelta(seconds=self.effective_poll_interval())

    def poll_due(self, now=None):
        """True if the scheduler should collect from this host right now."""
        due = self.next_poll_at()
        return due is not None and due <= (now or utcnow())

    def record_attempt(self, success, error=None, latency_ms=None):
        """Record the outcome of a collection or connection test."""
        now = utcnow()
        self.last_attempt = now
        self.last_latency_ms = latency_ms

        if success:
            self.last_success = now
            self.last_error = None
        else:
            self.last_error = (error or 'Unknown error')[:500]

    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'os_type': self.os_type,
            'description': self.description or '',
            'collection_method': self.effective_collection_method(),
            'remote_user': self.remote_user or '',
            'event_count': self.events.count(),
            'alert_count': self.alerts.count(),
            'status': self.health(),
            'last_attempt': _fmt(self.last_attempt),
            'last_success': _fmt(self.last_success),
            'last_error': self.last_error,
            'last_latency_ms': self.last_latency_ms,
            'usb_audit_status': self.usb_audit_status or USB_AUDIT_UNKNOWN,
            'polling_enabled': bool(self.polling_enabled),
            # The stored preference and the value actually used are reported
            # separately. Collapsing them would make the interface write the
            # current default back as an explicit setting the moment anyone
            # saved a host, quietly pinning every host to today's default.
            'poll_interval_seconds': self.poll_interval_seconds,
            'poll_interval_effective': self.effective_poll_interval(),
            'last_poll': _fmt(self.last_poll),
            'next_poll': _fmt(self.next_poll_at()),
            'fim_enabled': bool(self.fim_enabled),
            'watched_path_count': self.watched_paths.count(),
            'baseline_file_count': self.file_baselines.count(),
            'last_integrity_scan': _fmt(self.last_integrity_scan),
            'last_integrity_error': self.last_integrity_error,
        }


# === LOG SOURCE STATE (tracks incremental log collection per host) ===
class LogSource(db.Model):
    __tablename__ = 'log_sources'
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    log_type = db.Column(db.String(50), default='auth')
    last_fetch = db.Column(db.DateTime)


# === LOG ARCHIVE (Parquet forensic retention index) ===
class LogArchive(db.Model):
    __tablename__ = 'log_archives'
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=utcnow)
    filename = db.Column(db.String(200), nullable=False)
    record_count = db.Column(db.Integer, default=0)
    origin = db.Column(db.String(30), default='COLLECTED')  # COLLECTED / IMPORTED / SYNTHETIC


# === THREAT INTELLIGENCE IP REGISTRY ===
class IPRegistry(db.Model):
    __tablename__ = 'ip_registry'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    status = db.Column(db.String(20), default=IP_UNKNOWN)
    source = db.Column(db.String(100), default='Manual entry')
    notes = db.Column(db.String(255))
    date_added = db.Column(db.DateTime, default=utcnow)
    last_seen = db.Column(db.DateTime, default=utcnow)
    hit_count = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'status': self.status,
            'source': self.source or '',
            'notes': self.notes or '',
            'date_added': _fmt(self.date_added),
            'last_seen': _fmt(self.last_seen),
            'hit_count': self.hit_count or 0,
        }


# === NORMALIZED SECURITY EVENT ===
class Event(db.Model):
    """
    A single normalized security event extracted from a log source.

    Events are the raw material the detection rules run over. They are stored
    separately from Alerts so that the dashboard can show "events seen" versus
    "alerts raised", and so rules can be re-run without re-collecting logs.
    """
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=utcnow, index=True)
    event_type = db.Column(db.String(50), index=True)
    source_ip = db.Column(db.String(45), index=True)
    username = db.Column(db.String(100))
    message = db.Column(db.Text)
    raw_log = db.Column(db.Text)
    origin = db.Column(db.String(30), default='COLLECTED')
    ingested_at = db.Column(db.DateTime, default=utcnow)

    # Only removable-media events populate this. It is a separate column
    # rather than something parsed back out of `message`, so the dashboard can
    # show the device name without re-parsing prose that was written for a
    # human reader.
    device_name = db.Column(db.String(200))

    # Only file-integrity events supply this. Unlike device_name it *is* part
    # of the de-duplication key, because two different files changing in the
    # same second are two findings, not one repeated one.
    file_path = db.Column(db.String(500))

    alerts = db.relationship(
        'Alert', backref='event', lazy='dynamic', cascade='all, delete-orphan'
    )

    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'host_name': self.host.hostname if self.host else 'Unknown Host',
            'timestamp': _fmt(self.timestamp),
            'event_type': self.event_type,
            'source_ip': self.source_ip,
            'username': self.username,
            'message': self.message,
            'device_name': self.device_name,
            'file_path': self.file_path,
            'origin': self.origin,
        }


# === ALERT (output of the detection engine) ===
class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=True, index=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=utcnow, index=True)
    rule_id = db.Column(db.String(10), index=True)  # R-01 .. R-04
    alert_type = db.Column(db.String(50))
    message = db.Column(db.Text)
    severity = db.Column(db.String(20), default=SEVERITY_MEDIUM, index=True)
    source_ip = db.Column(db.String(45), index=True)
    acknowledged = db.Column(db.Boolean, default=False, index=True)

    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'host_name': self.host.hostname if self.host else 'Unknown Host',
            'timestamp': _fmt(self.timestamp),
            'rule_id': self.rule_id,
            'alert_type': self.alert_type,
            'message': self.message,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'acknowledged': bool(self.acknowledged),
        }


# === FILE INTEGRITY MONITORING ===
#
# Two tables, because they answer two different questions. WatchedPath is what
# the operator asked to be watched and is edited by hand; FileBaseline is what
# was actually found there and is written only by the scanner. Keeping them
# apart means deleting a watched path cannot destroy the evidence of what its
# files used to look like until the operator says so, and it means the
# interface never has to show a list of four hundred hashes to explain that
# one directory is being watched.
class WatchedPath(db.Model):
    """A file or directory whose contents are checked for tampering."""

    __tablename__ = 'watched_paths'
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False, index=True)
    path = db.Column(db.String(500), nullable=False)
    # Directories are walked one level deep unless this is set. Recursion is
    # opt-in because pointing a recursive watch at a system directory is the
    # easy way to ask a host to hash a hundred thousand files.
    recursive = db.Column(db.Boolean, default=False, nullable=False, server_default='0')
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=utcnow)

    __table_args__ = (
        db.UniqueConstraint('host_id', 'path', name='uq_watched_path_per_host'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'path': self.path,
            'recursive': bool(self.recursive),
            'description': self.description or '',
            'created_at': _fmt(self.created_at),
            'file_count': FileBaseline.query.filter_by(
                host_id=self.host_id, watched_path_id=self.id
            ).count(),
        }


class FileBaseline(db.Model):
    """
    The last known good state of one file.

    The hash is what the comparison actually turns on. Size and modification
    time are stored alongside it as corroboration for the human reading the
    alert -- a file whose hash changed but whose size did not is a different
    story from one that grew by two megabytes.
    """

    __tablename__ = 'file_baselines'
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False, index=True)
    watched_path_id = db.Column(
        db.Integer, db.ForeignKey('watched_paths.id', ondelete='CASCADE'), index=True
    )
    path = db.Column(db.String(500), nullable=False, index=True)
    sha256 = db.Column(db.String(64), nullable=False)
    size_bytes = db.Column(db.Integer)
    modified_at = db.Column(db.DateTime)

    first_seen = db.Column(db.DateTime, default=utcnow)
    # Refreshed on every scan that still finds the file, so a baseline row that
    # has stopped being touched is visibly stale rather than silently so.
    last_seen = db.Column(db.DateTime, default=utcnow)
    # Only moves when the hash actually changed, which makes it the answer to
    # "when was this file last tampered with".
    last_changed = db.Column(db.DateTime)

    __table_args__ = (
        db.UniqueConstraint('host_id', 'path', name='uq_file_baseline_per_host'),
    )

    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'watched_path_id': self.watched_path_id,
            'path': self.path,
            'sha256': self.sha256,
            'size_bytes': self.size_bytes,
            'modified_at': _fmt(self.modified_at),
            'first_seen': _fmt(self.first_seen),
            'last_seen': _fmt(self.last_seen),
            'last_changed': _fmt(self.last_changed),
        }


def _fmt(value):
    """Render a datetime for the JSON API, tolerating NULL columns."""
    if not value:
        return None
    return value.strftime('%Y-%m-%d %H:%M:%S')
