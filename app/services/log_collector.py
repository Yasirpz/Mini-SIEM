"""
Collects and normalizes authentication logs from Linux and Windows hosts
into a common event format:
    {timestamp, alert_type, source_ip, user, message, raw_log}
"""
import re
import json
from datetime import datetime

from flask import current_app

from app.models import (
    EVT_FAILED_LOGIN,
    EVT_INVALID_USER,
    EVT_SUCCESSFUL_LOGIN,
    EVT_SUDO_USAGE,
    EVT_WIN_FAILED_LOGIN,
)

# --- Windows Security log tuning -------------------------------------------

# 4625 = an account failed to log on.  4624 = an account logged on successfully.
WIN_EVENT_FAILED_LOGON = 4625
WIN_EVENT_SUCCESSFUL_LOGON = 4624

# Windows records a successful logon (4624) for a great deal of routine
# machine activity — services starting, scheduled tasks, the window manager.
# Only these logon types represent a person actually authenticating, so the
# rest are filtered out at the PowerShell stage. Without this the Events page
# fills with noise and the real demonstration is impossible to see.
#   2  Interactive          (signed in at the keyboard)
#   7  Unlock               (unlocked the workstation)
#   10 RemoteInteractive    (RDP)
#   11 CachedInteractive    (signed in with cached domain credentials)
WIN_INTERACTIVE_LOGON_TYPES = ('2', '7', '10', '11')

# Built-in accounts that generate constant background logons.
WIN_IGNORED_ACCOUNTS = ('SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', 'ANONYMOUS LOGON')

# How many raw records to pull on a first run, before filtering.
WIN_DEFAULT_MAX_EVENTS = 200

LOGON_TYPE_LABELS = {
    '2': 'interactive',
    '3': 'network',
    '4': 'batch',
    '5': 'service',
    '7': 'unlock',
    '8': 'network cleartext',
    '9': 'new credentials',
    '10': 'remote interactive',
    '11': 'cached interactive',
}


def _config(key, default):
    """Read a tuning value from Flask config, falling back outside an app context."""
    try:
        return current_app.config.get(key, default)
    except RuntimeError:
        return default


class LogCollector:

    # --- Linux (journalctl / sshd message parsing) ---
    LINUX_PATTERNS = {
        'failed_password': re.compile(r"Failed password for (?:invalid user )?([\w.-]+) from ([\d.]+)"),
        'invalid_user': re.compile(r"Invalid user ([\w.-]+) from ([\d.]+)"),
        'sudo': re.compile(r"sudo:\s+([a-zA-Z0-9._-]+)\s*:"),
    }

    # =====================================================================
    # LINUX (SSH + journalctl + regex parsing)
    # =====================================================================
    @staticmethod
    def get_linux_logs(ssh_client, last_fetch_time=None):
        logs = []

        cmd = "sudo journalctl -u ssh -o json --no-pager"

        if last_fetch_time:
            since_str = last_fetch_time.strftime("%Y-%m-%d %H:%M:%S")
            cmd += f' --since "{since_str}"'
        else:
            cmd += ' --since "7 days ago"'  # default range on first run

        print(f"DEBUG [Linux]: Executing {cmd}")

        try:
            stdout, stderr = ssh_client.run(cmd)

            if not stdout:
                return []

            for line in stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    message = entry.get('MESSAGE', '')

                    ts_micro = int(entry.get('__REALTIME_TIMESTAMP', 0))
                    timestamp = datetime.fromtimestamp(ts_micro / 1_000_000)

                    parsed = LogCollector._parse_linux_message(message, timestamp)
                    if parsed:
                        logs.append(parsed)

                except json.JSONDecodeError:
                    continue

        except Exception as e:
            print(f"Error collecting Linux logs: {e}")
            # Don't re-raise: a failure on one host shouldn't stop the batch
            return []

        return logs

    @staticmethod
    def _parse_linux_message(message, timestamp):
        match = LogCollector.LINUX_PATTERNS['failed_password'].search(message)
        if match:
            return {
                'timestamp': timestamp,
                'alert_type': EVT_FAILED_LOGIN,
                'source_ip': match.group(2),
                'user': match.group(1),
                'message': message,
                'raw_log': message,
            }

        match = LogCollector.LINUX_PATTERNS['invalid_user'].search(message)
        if match:
            return {
                'timestamp': timestamp,
                'alert_type': EVT_INVALID_USER,
                'source_ip': match.group(2),
                'user': match.group(1),
                'message': message,
                'raw_log': message,
            }

        match = LogCollector.LINUX_PATTERNS['sudo'].search(message)
        if match:
            return {
                'timestamp': timestamp,
                'alert_type': EVT_SUDO_USAGE,
                'source_ip': 'LOCAL',
                'user': match.group(1),
                'message': message,
                'raw_log': message,
            }
        return None

    # =====================================================================
    # WINDOWS (PowerShell + XML parsing, Event IDs 4625 and 4624)
    # =====================================================================
    @staticmethod
    def build_windows_query(last_fetch_time=None, max_events=None):
        """
        Build the PowerShell command that reads the Security log.

        Both failed (4625) and successful (4624) logons are requested, but
        successful logons are filtered down to genuine interactive sign-ins
        inside PowerShell — filtering there rather than in Python means the
        noise never crosses the process boundary.

        Each record is emitted as its own single-line JSON object (NDJSON)
        rather than one JSON document for the whole batch. `ConvertTo-Json`
        renders a lone object as `{...}` but several as `[...]`, so a batch
        that happens to contain exactly one event would otherwise parse
        differently from every other batch. One object per line removes that
        ambiguity entirely.

        "No events were found" is caught and treated as an empty result, since
        Get-WinEvent reports an empty match as an error.
        """
        max_events = max_events or _config('WINDOWS_MAX_EVENTS', WIN_DEFAULT_MAX_EVENTS)
        ids = f"{WIN_EVENT_FAILED_LOGON},{WIN_EVENT_SUCCESSFUL_LOGON}"

        if last_fetch_time:
            ts_str = last_fetch_time.strftime('%Y-%m-%d %H:%M:%S')
            filter_script = (
                f"@{{LogName='Security'; Id={ids}; StartTime=[datetime]'{ts_str}'}}"
            )
        else:
            filter_script = f"@{{LogName='Security'; Id={ids}}}"

        logon_types = ','.join(f"'{t}'" for t in WIN_INTERACTIVE_LOGON_TYPES)
        ignored = ','.join(f"'{a}'" for a in WIN_IGNORED_ACCOUNTS)

        return (
            "$ErrorActionPreference='Stop'; "
            "$records = @(); "
            "try { "
            f"  $records = @(Get-WinEvent -FilterHashtable {filter_script} "
            f"    -MaxEvents {max_events} -ErrorAction Stop) "
            "} catch { "
            # An empty match is normal; anything else must reach the caller.
            f"  if ($_.Exception.Message -notmatch 'No events were found') {{ "
            "     [Console]::Error.WriteLine($_.Exception.Message); exit 2 "
            "  } "
            "} "
            "foreach ($rec in $records) { "
            "   $xml = [xml]$rec.ToXml(); "
            "   $data = @{}; "
            "   foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }; "
            "   $logonType = [string]$data['LogonType']; "
            "   $account = [string]$data['TargetUserName']; "
            f"   $keep = $rec.Id -eq {WIN_EVENT_FAILED_LOGON}; "
            "   if (-not $keep) { "
            f"      $keep = ($logonType -in @({logon_types})) -and "
            f"              ($account -notin @({ignored})) -and "
            "              (-not $account.EndsWith('$')) "
            "   } "
            "   if ($keep) { "
            "      [PSCustomObject]@{ "
            "         Timestamp = $rec.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); "
            "         EventId = $rec.Id; "
            "         TargetUserName = $account; "
            "         IpAddress = [string]$data['IpAddress']; "
            "         LogonType = $logonType; "
            "         WorkstationName = [string]$data['WorkstationName']; "
            "      } | ConvertTo-Json -Compress "
            "   } "
            "} "
            "exit 0"
        )

    @staticmethod
    def get_windows_logs(win_client, last_fetch_time=None):
        """
        Collect and normalize Windows Security logon events.

        Raises PowerShellError (via the client) when the command genuinely
        fails, so the API can report the real reason rather than silently
        returning an empty list.
        """
        ps_cmd = LogCollector.build_windows_query(last_fetch_time)
        stdout = win_client.run_ps(ps_cmd)

        logs = LogCollector.parse_windows_ndjson(stdout)
        print(f"DEBUG [Windows]: Collected {len(logs)} events.")
        return logs

    @staticmethod
    def parse_windows_ndjson(stdout):
        """
        Parse newline-delimited JSON records into normalized events.

        A malformed line is skipped rather than aborting the batch, so one bad
        record cannot cost the operator every other event in the collection.
        """
        if not stdout:
            return []

        logs = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                print(f"WinLog: skipping unparseable record: {line[:120]}")
                continue

            # Tolerate a whole-batch array, in case ConvertTo-Json is ever
            # called without -Compress and wraps the output differently.
            candidates = entry if isinstance(entry, list) else [entry]
            for candidate in candidates:
                parsed = LogCollector.parse_windows_event(candidate)
                if parsed:
                    logs.append(parsed)

        return logs

    @staticmethod
    def parse_windows_event(entry):
        """
        Turn one Windows Security record into a normalized event.

        Returns None for records that are neither 4624 nor 4625, so an
        unexpected event ID is skipped rather than mislabelled.
        """
        if not isinstance(entry, dict):
            return None

        try:
            event_id = int(entry.get('EventId'))
        except (TypeError, ValueError):
            return None

        if event_id == WIN_EVENT_FAILED_LOGON:
            alert_type = EVT_WIN_FAILED_LOGIN
            outcome = 'logon failure'
        elif event_id == WIN_EVENT_SUCCESSFUL_LOGON:
            alert_type = EVT_SUCCESSFUL_LOGIN
            outcome = 'successful logon'
        else:
            return None

        user = (entry.get('TargetUserName') or '').strip() or 'UNKNOWN'
        ip = (entry.get('IpAddress') or '').strip()
        workstation = (entry.get('WorkstationName') or '').strip()
        logon_type = (entry.get('LogonType') or '').strip()

        # Windows writes "-" or "::1" for a sign-in at the physical keyboard.
        # LOCAL_CONSOLE is the marker the detection engine already treats as
        # non-routable, so a local sign-in never looks like a remote attacker.
        if not ip or ip in ('-', '::1', '127.0.0.1'):
            ip = 'LOCAL_CONSOLE'

        timestamp = LogCollector._parse_windows_timestamp(entry.get('Timestamp'))

        descriptor = LOGON_TYPE_LABELS.get(logon_type)
        detail = f" via {descriptor}" if descriptor else ''
        origin = f" from {workstation}" if workstation and workstation != '-' else ''

        return {
            'timestamp': timestamp,
            'alert_type': alert_type,
            'source_ip': ip,
            'user': user,
            'message': (
                f"Windows {outcome} for user '{user}'{detail}{origin} "
                f"(Event {event_id})"
            ),
            'raw_log': json.dumps(entry, sort_keys=True),
        }

    @staticmethod
    def _parse_windows_timestamp(value):
        """Parse the PowerShell-formatted timestamp, falling back to now."""
        try:
            return datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            return datetime.now().replace(microsecond=0)
