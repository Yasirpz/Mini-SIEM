from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from .extensions import db, login_manager


# === USER MODEL (Administrator accounts) ===
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(256))

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
    ip_address = db.Column(db.String(15), unique=True, nullable=False)
    os_type = db.Column(db.String(20))  # LINUX, WINDOWS

    logs_sources = db.relationship('LogSource', backref='host', lazy='dynamic', cascade="all, delete-orphan")
    alerts = db.relationship('Alert', backref='host', lazy='dynamic', cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'os_type': self.os_type,
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
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    filename = db.Column(db.String(200), nullable=False)
    record_count = db.Column(db.Integer, default=0)


# === THREAT INTELLIGENCE IP REGISTRY ===
class IPRegistry(db.Model):
    __tablename__ = 'ip_registry'
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False)
    status = db.Column(db.String(20), default='UNKNOWN')  # TRUSTED, BANNED, UNKNOWN
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


# === ALERT (output of the detection engine) ===
class Alert(db.Model):
    __tablename__ = 'alerts'
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    alert_type = db.Column(db.String(50))
    message = db.Column(db.Text)
    severity = db.Column(db.String(20), default='WARNING')
    source_ip = db.Column(db.String(50))

    def to_dict(self):
        return {
            'id': self.id,
            'host_id': self.host_id,
            'host_name': self.host.hostname if self.host else "Unknown Host",
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'alert_type': self.alert_type,
            'message': self.message,
            'severity': self.severity,
            'source_ip': self.source_ip,
        }
