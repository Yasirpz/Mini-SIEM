"""
Database models for Mini-SIEM.

Covers deliverable D-04: schema for users, hosts, threat IPs, events and alerts.
"""
from datetime import datetime, timezone

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

# Event types that the detection rules treat as authentication failures.
FAILURE_EVENT_TYPES = (EVT_FAILED_LOGIN, EVT_INVALID_USER, EVT_WIN_FAILED_LOGIN)


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

    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'os_type': self.os_type,
            'description': self.description or '',
            'event_count': self.events.count(),
            'alert_count': self.alerts.count(),
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


def _fmt(value):
    """Render a datetime for the JSON API, tolerating NULL columns."""
    if not value:
        return None
    return value.strftime('%Y-%m-%d %H:%M:%S')
