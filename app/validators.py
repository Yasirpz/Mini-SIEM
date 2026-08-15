"""
Server-side input validation for the JSON API.

The browser forms do some checking of their own, but the API is reachable
directly, so every value that reaches the database is validated here as well.
"""
import ipaddress
import re

from app.models import (
    COLLECT_LOCAL,
    COLLECT_SSH,
    COLLECT_WINRM,
    COLLECTION_METHODS,
    IP_STATUSES,
)

HOSTNAME_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._-]{0,99}$')

VALID_OS_TYPES = ('LINUX', 'WINDOWS')

MAX_NOTE_LENGTH = 255
MAX_DESCRIPTION_LENGTH = 255


class ValidationError(ValueError):
    """Raised when a submitted field fails validation."""


def validate_ip(value, field='ip_address'):
    """Return a normalized IP address string, or raise ValidationError."""
    if not value or not str(value).strip():
        raise ValidationError(f"{field} is required")

    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        raise ValidationError(f"'{value}' is not a valid IPv4 or IPv6 address")


def validate_hostname(value):
    """Return a cleaned hostname, or raise ValidationError."""
    if not value or not str(value).strip():
        raise ValidationError('hostname is required')

    hostname = str(value).strip()
    if not HOSTNAME_PATTERN.match(hostname):
        raise ValidationError(
            'hostname may only contain letters, numbers, spaces, dots, '
            'hyphens and underscores (max 100 characters)'
        )
    return hostname


def validate_os_type(value):
    """Return a normalized OS type, or raise ValidationError."""
    os_type = str(value or '').strip().upper()
    if os_type not in VALID_OS_TYPES:
        raise ValidationError(f"os_type must be one of {', '.join(VALID_OS_TYPES)}")
    return os_type


def validate_ip_status(value):
    """Return a normalized threat-registry status, or raise ValidationError."""
    status = str(value or '').strip().upper()
    if status not in IP_STATUSES:
        raise ValidationError(f"status must be one of {', '.join(IP_STATUSES)}")
    return status


def validate_collection_method(value, os_type=None):
    """
    Return a normalized collection method, or raise ValidationError.

    Rejects combinations that cannot work — SSH against Windows, or WinRM
    against Linux — so the error appears when the host is saved rather than
    as a puzzling failure at collection time.
    """
    if value is None or not str(value).strip():
        return None

    method = str(value).strip().upper()
    if method not in COLLECTION_METHODS:
        raise ValidationError(
            f"collection_method must be one of {', '.join(COLLECTION_METHODS)}"
        )

    if os_type == 'LINUX' and method in (COLLECT_WINRM, COLLECT_LOCAL):
        raise ValidationError(
            'Linux hosts are collected over SSH; WinRM and local collection '
            'apply to Windows hosts only'
        )
    if os_type == 'WINDOWS' and method == COLLECT_SSH:
        raise ValidationError(
            'Windows hosts are collected locally or over WinRM, not SSH'
        )

    return method


def validate_text(value, field, max_length):
    """Return a trimmed optional text field, or raise ValidationError if too long."""
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None
    if len(text) > max_length:
        raise ValidationError(f"{field} must be {max_length} characters or fewer")
    return text
