"""
Sample log ingestion (proposal FR-05 and Section 14).

Parses the log formats used for development and demonstration into the same
normalized event dicts the live collectors produce:

    {timestamp, alert_type, source_ip, user, message, raw_log}

Three input formats are recognised automatically:

  * Linux ``auth.log`` / journald text  — the classic sshd authentication lines
  * Windows Security log CSV            — exported Event ID 4625 records
  * JSON                                — a list of already-normalized events

A synthetic generator is also provided so a demonstration can be run without
any input file at all.
"""
import csv
import io
import json
import random
import re
from datetime import datetime, timedelta

from app.models import (
    EVT_FAILED_LOGIN,
    EVT_INVALID_USER,
    EVT_SUCCESSFUL_LOGIN,
    EVT_SUDO_USAGE,
    EVT_WIN_FAILED_LOGIN,
)

# Syslog-style month names, for "Nov 12 10:31:22" timestamps.
MONTHS = {
    'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
    'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12,
}

# Timestamp at the start of a log line, in either syslog or ISO form.
SYSLOG_TS = re.compile(r'^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+')
ISO_TS = re.compile(r'^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})')

# sshd message patterns. Ordered most specific first: "Failed password for
# invalid user bob" must be classified as an invalid user, not a failed password.
LINE_PATTERNS = (
    (
        EVT_INVALID_USER,
        re.compile(r'Failed password for invalid user (?P<user>[\w.$-]+) from (?P<ip>[\d.a-fA-F:]+)'),
    ),
    (
        EVT_INVALID_USER,
        re.compile(r'Invalid user (?P<user>[\w.$-]+) from (?P<ip>[\d.a-fA-F:]+)'),
    ),
    (
        EVT_FAILED_LOGIN,
        re.compile(r'Failed password for (?P<user>[\w.$-]+) from (?P<ip>[\d.a-fA-F:]+)'),
    ),
    (
        EVT_FAILED_LOGIN,
        re.compile(r'authentication failure.*ruser=(?P<user>[\w.$-]*).*rhost=(?P<ip>[\d.a-fA-F:]+)'),
    ),
    (
        EVT_SUCCESSFUL_LOGIN,
        re.compile(r'Accepted (?:password|publickey) for (?P<user>[\w.$-]+) from (?P<ip>[\d.a-fA-F:]+)'),
    ),
    (
        EVT_SUDO_USAGE,
        re.compile(r'sudo:\s+(?P<user>[\w.$-]+)\s*:.*COMMAND='),
    ),
)


class SampleLoader:
    """Parses sample/imported log content into normalized event dicts."""

    @staticmethod
    def parse(content, filename=''):
        """
        Detect the format of ``content`` and parse it.

        Returns (events, format_name). Unrecognised lines are skipped rather
        than raising, so a partially malformed sample file still imports the
        records it can.
        """
        text = content.decode('utf-8', errors='replace') if isinstance(content, bytes) else content
        stripped = text.strip()

        if not stripped:
            return [], 'empty'

        name = (filename or '').lower()

        if stripped[0] in '[{' or name.endswith('.json'):
            return SampleLoader.parse_json(stripped), 'json'

        if name.endswith('.csv') or SampleLoader._looks_like_csv(stripped):
            return SampleLoader.parse_windows_csv(stripped), 'windows-csv'

        return SampleLoader.parse_auth_log(stripped), 'linux-auth'

    # ------------------------------------------------------------------
    # Linux auth.log / journald text
    # ------------------------------------------------------------------

    @staticmethod
    def parse_auth_log(text, reference=None):
        """Parse Linux SSH authentication log lines."""
        reference = reference or datetime.now()
        events = []

        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            timestamp, remainder = SampleLoader._extract_timestamp(line, reference)

            for event_type, pattern in LINE_PATTERNS:
                match = pattern.search(remainder)
                if not match:
                    continue

                groups = match.groupdict()
                events.append({
                    'timestamp': timestamp,
                    'alert_type': event_type,
                    'source_ip': groups.get('ip') or 'LOCAL',
                    'user': groups.get('user') or 'unknown',
                    'message': remainder,
                    'raw_log': line,
                })
                break

        return events

    # ------------------------------------------------------------------
    # Windows Security log CSV
    # ------------------------------------------------------------------

    @staticmethod
    def parse_windows_csv(text):
        """
        Parse an exported Windows Security log CSV.

        Column names are matched case-insensitively and several common export
        spellings are accepted, since the exact headers differ between
        ``Get-WinEvent`` exports and Event Viewer exports.
        """
        events = []
        reader = csv.DictReader(io.StringIO(text))

        for row in reader:
            values = {
                (key or '').strip().lower(): (value or '').strip()
                for key, value in row.items()
            }

            timestamp = SampleLoader._parse_any_datetime(
                _first(values, 'timecreated', 'timestamp', 'time', 'date')
            )
            event_id = _first(values, 'eventid', 'id', 'event_id')
            user = _first(values, 'targetusername', 'user', 'username', 'account') or 'unknown'
            source_ip = _first(values, 'ipaddress', 'source_ip', 'sourceip', 'ip') or 'LOCAL_CONSOLE'

            if source_ip in ('-', '::1', '127.0.0.1'):
                source_ip = 'LOCAL_CONSOLE'

            # 4624 is a successful logon; anything else in a Security export
            # that reaches here is treated as a failure (4625 and friends).
            if event_id == '4624':
                event_type = EVT_SUCCESSFUL_LOGIN
                message = f"Windows successful logon for user: {user} (Event 4624)"
            else:
                event_type = EVT_WIN_FAILED_LOGIN
                message = f"Windows logon failure for user: {user} (Event {event_id or '4625'})"

            events.append({
                'timestamp': timestamp,
                'alert_type': event_type,
                'source_ip': source_ip,
                'user': user,
                'message': message,
                'raw_log': json.dumps(values),
            })

        return events

    # ------------------------------------------------------------------
    # Pre-normalized JSON
    # ------------------------------------------------------------------

    @staticmethod
    def parse_json(text):
        """Parse a JSON list (or single object) of already-normalized events."""
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return []

        records = [data] if isinstance(data, dict) else data
        events = []

        for record in records:
            if not isinstance(record, dict):
                continue

            event_type = (
                record.get('alert_type')
                or record.get('event_type')
                or EVT_FAILED_LOGIN
            )
            events.append({
                'timestamp': SampleLoader._parse_any_datetime(record.get('timestamp')),
                'alert_type': event_type,
                'source_ip': record.get('source_ip') or record.get('ip') or 'LOCAL',
                'user': record.get('user') or record.get('username') or 'unknown',
                'message': record.get('message') or f"{event_type} event",
                'raw_log': json.dumps(record),
            })

        return events

    # ------------------------------------------------------------------
    # Synthetic generator (no input file needed)
    # ------------------------------------------------------------------

    @staticmethod
    def generate_synthetic(source_ip='203.0.113.50', attempts=8, include_success=True):
        """
        Build a realistic burst of failed logins from one source IP.

        Defaults are chosen to cross the R-01 threshold, so a demonstration
        reliably produces alerts. The default address is from the RFC 5737
        documentation range, which never routes to a real machine.
        """
        now = datetime.now().replace(microsecond=0)
        usernames = ['root', 'admin', 'test', 'oracle', 'postgres']
        events = []

        for index in range(attempts):
            timestamp = now - timedelta(minutes=(attempts - index))

            # Roughly a third of the attempts target users that do not exist,
            # so both R-01 and R-02 have something to match.
            if index % 3 == 2:
                user = random.choice(usernames[2:])
                events.append({
                    'timestamp': timestamp,
                    'alert_type': EVT_INVALID_USER,
                    'source_ip': source_ip,
                    'user': user,
                    'message': f"Invalid user {user} from {source_ip}",
                    'raw_log': f"sshd[{2800 + index}]: Invalid user {user} from {source_ip} port {51400 + index}",
                })
            else:
                events.append({
                    'timestamp': timestamp,
                    'alert_type': EVT_FAILED_LOGIN,
                    'source_ip': source_ip,
                    'user': 'root',
                    'message': f"Failed password for root from {source_ip}",
                    'raw_log': f"sshd[{2800 + index}]: Failed password for root from {source_ip} port {51400 + index} ssh2",
                })

        if include_success:
            events.append({
                'timestamp': now,
                'alert_type': EVT_SUCCESSFUL_LOGIN,
                'source_ip': '192.168.1.20',
                'user': 'labadmin',
                'message': 'Accepted password for labadmin from 192.168.1.20',
                'raw_log': 'sshd[2900]: Accepted password for labadmin from 192.168.1.20 port 51500 ssh2',
            })

        return events

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_csv(text):
        """A CSV sample is recognised by a comma-separated header row."""
        first_line = text.splitlines()[0].lower()
        return ',' in first_line and any(
            column in first_line
            for column in ('timecreated', 'eventid', 'targetusername', 'ipaddress', 'timestamp')
        )

    @staticmethod
    def _extract_timestamp(line, reference):
        """
        Pull a leading timestamp off a log line.

        Returns (timestamp, remainder). Lines without a recognisable timestamp
        fall back to the reference time so they are still imported.
        """
        match = ISO_TS.match(line)
        if match:
            timestamp = datetime.fromisoformat(f"{match.group(1)} {match.group(2)}")
            return timestamp, line[match.end():].strip()

        match = SYSLOG_TS.match(line)
        if match:
            month = MONTHS.get(match.group(1).lower())
            if month:
                # Syslog omits the year. Assume the most recent occurrence:
                # a date more than a day ahead of "now" must be last year's.
                timestamp = datetime(
                    reference.year, month, int(match.group(2)),
                    int(match.group(3)), int(match.group(4)), int(match.group(5)),
                )
                if timestamp > reference + timedelta(days=1):
                    timestamp = timestamp.replace(year=reference.year - 1)
                return timestamp, line[match.end():].strip()

        return reference, line

    @staticmethod
    def _parse_any_datetime(value):
        """Best-effort datetime parsing across the formats these samples use."""
        if isinstance(value, datetime):
            return value
        if not value:
            return datetime.now().replace(microsecond=0)

        text = str(value).strip().replace('/', '-')
        formats = (
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M',
            '%d-%m-%Y %H:%M:%S',
            '%m-%d-%Y %H:%M:%S',
            '%Y-%m-%d',
        )
        for fmt in formats:
            try:
                return datetime.strptime(text, fmt)
            except ValueError:
                continue

        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return datetime.now().replace(microsecond=0)


def _first(values, *keys):
    """Return the first non-empty value among the given dictionary keys."""
    for key in keys:
        value = values.get(key)
        if value:
            return value
    return ''
