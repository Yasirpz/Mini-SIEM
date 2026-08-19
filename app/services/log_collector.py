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
    EVT_ACCOUNT_CREATED,
    EVT_ACCOUNT_DELETED,
    EVT_ACCOUNT_ENABLED,
    EVT_ACCOUNT_LOCKOUT,
    EVT_PROCESS_CREATED,
    EVT_ADMIN_LOGON,
    EVT_AUDIT_LOG_CLEARED,
    EVT_EXPLICIT_CREDENTIALS,
    EVT_FAILED_LOGIN,
    EVT_GROUP_MEMBER_ADDED,
    EVT_INVALID_USER,
    EVT_PASSWORD_RESET,
    EVT_SUCCESSFUL_LOGIN,
    EVT_SUDO_USAGE,
    EVT_USB_DEVICE_CONNECTED,
    EVT_WIN_FAILED_LOGIN,
)

# --- Windows Security log tuning -------------------------------------------

# 4625 = an account failed to log on.  4624 = an account logged on successfully.
WIN_EVENT_FAILED_LOGON = 4625
WIN_EVENT_SUCCESSFUL_LOGON = 4624

# Every Windows Security event the collector understands, and the normalized
# type each becomes. Anything not listed here is skipped rather than guessed
# at, so an unfamiliar event can never be mislabelled.
WIN_EVENT_TYPES = {
    4625: EVT_WIN_FAILED_LOGIN,       # account failed to log on
    4624: EVT_SUCCESSFUL_LOGIN,       # account logged on
    4740: EVT_ACCOUNT_LOCKOUT,        # account locked out after repeated failures
    4648: EVT_EXPLICIT_CREDENTIALS,   # logon using explicit credentials (runas)
    4672: EVT_ADMIN_LOGON,            # special privileges assigned to a new logon
    4720: EVT_ACCOUNT_CREATED,        # a user account was created
    4722: EVT_ACCOUNT_ENABLED,        # a user account was enabled
    4724: EVT_PASSWORD_RESET,         # an attempt was made to reset a password
    4726: EVT_ACCOUNT_DELETED,        # a user account was deleted
    4732: EVT_GROUP_MEMBER_ADDED,     # member added to a security-enabled local group
    4688: EVT_PROCESS_CREATED,        # a new process was created
    1102: EVT_AUDIT_LOG_CLEARED,      # the audit log was cleared
    6416: EVT_USB_DEVICE_CONNECTED,   # an external device was recognised
}

# Human-readable summary per event id, used in the stored message.
WIN_EVENT_DESCRIPTIONS = {
    4625: 'logon failure',
    4624: 'successful logon',
    4740: 'account locked out',
    4648: 'logon with explicit credentials',
    4672: 'administrative privileges assigned',
    4720: 'user account created',
    4722: 'user account enabled',
    4724: 'password reset attempt',
    4726: 'user account deleted',
    4732: 'added to a security group',
    4688: 'process created',
    1102: 'AUDIT LOG CLEARED',
    6416: 'external device connected',
}

# Events that describe a person signing in, and therefore need the
# interactive-logon-type filter to keep service noise out. The rest describe
# discrete administrative actions that are always worth recording.
WIN_LOGON_EVENTS = (4624, 4672)

# Plug-and-play auditing (6416) fires for *every* device Windows recognises,
# including the internal disk, keyboard and network card enumerated at every
# boot. Only removable storage is interesting here, and a USB device always
# declares itself in VendorIds or CompatibleIds, so those are matched to
# separate the handful of real events from the boot-time flood.
WIN_DEVICE_EVENTS = (6416,)
WIN_USB_ID_MARKER = 'USB'

# Process creation (4688) fires for *every* process the machine starts, which
# on a normal desktop is thousands per hour. Collecting it by default would
# bury the authentication events this project exists to show, so it is
# opt-in via WINDOWS_COLLECT_PROCESS_EVENTS.
WIN_NOISY_EVENTS = (4688,)

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
        noise never crosses the process boundary. Device events (6416) are
        narrowed the same way, to the ones whose hardware IDs say USB.

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

        wanted = [
            event_id for event_id in WIN_EVENT_TYPES
            if event_id not in WIN_NOISY_EVENTS
            or _config('WINDOWS_COLLECT_PROCESS_EVENTS', False)
        ]
        ids = ','.join(str(i) for i in wanted)

        if last_fetch_time:
            ts_str = last_fetch_time.strftime('%Y-%m-%d %H:%M:%S')
            filter_script = (
                f"@{{LogName='Security'; Id={ids}; StartTime=[datetime]'{ts_str}'}}"
            )
        else:
            filter_script = f"@{{LogName='Security'; Id={ids}}}"

        logon_types = ','.join(f"'{t}'" for t in WIN_INTERACTIVE_LOGON_TYPES)
        ignored = ','.join(f"'{a}'" for a in WIN_IGNORED_ACCOUNTS)
        device_ids = ','.join(str(i) for i in WIN_DEVICE_EVENTS)

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
            "   if (-not $account) { $account = [string]$data['SubjectUserName'] } "
            "   $vendorIds = [string]$data['VendorIds']; "
            "   $compatibleIds = [string]$data['CompatibleIds']; "
            # Sign-in events need the interactive filter to keep service noise
            # out; administrative actions are always kept.
            f"   if ($rec.Id -in @({','.join(str(i) for i in WIN_LOGON_EVENTS)})) {{ "
            f"      $keep = ($logonType -in @({logon_types})) -and "
            f"              ($account -notin @({ignored})) -and "
            "              (-not $account.EndsWith('$')) "
            # Every device the machine has ever seen is announced here at boot,
            # so discard anything that is not removable before it is emitted.
            f"   }} elseif ($rec.Id -in @({device_ids})) {{ "
            f"      $keep = ($vendorIds -like '*{WIN_USB_ID_MARKER}*') -or "
            f"              ($compatibleIds -like '*{WIN_USB_ID_MARKER}*') "
            "   } else { $keep = $true } "
            "   if ($keep) { "
            "      [PSCustomObject]@{ "
            "         Timestamp = $rec.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); "
            "         EventId = $rec.Id; "
            "         TargetUserName = $account; "
            "         SubjectUserName = [string]$data['SubjectUserName']; "
            # Carried so the dashboard can name the drive that was plugged in;
            # the hardware IDs travel with it as the evidence for why the
            # record was kept.
            "         DeviceDescription = [string]$data['DeviceDescription']; "
            "         VendorIds = $vendorIds; "
            "         CompatibleIds = $compatibleIds; "
            # Process name only. CommandLine is deliberately not collected:
            # command lines routinely contain passwords and tokens, and a
            # security tool must not become the place they are archived.
            "         NewProcessName = [string]$data['NewProcessName']; "
            "         ParentProcessName = [string]$data['ParentProcessName']; "
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

        alert_type = WIN_EVENT_TYPES.get(event_id)
        if alert_type is None:
            return None

        outcome = WIN_EVENT_DESCRIPTIONS.get(event_id, f'event {event_id}')

        # Account-management events name the affected account in
        # TargetUserName and the actor in SubjectUserName; fall back so the
        # event is never stored with an empty user.
        user = (
            (entry.get('TargetUserName') or '').strip()
            or (entry.get('SubjectUserName') or '').strip()
            or 'UNKNOWN'
        )

        # A device event has no target account at all — the only person it
        # names is the one who was signed in when the device appeared, so
        # SubjectUserName is read directly rather than through the fallback.
        if alert_type == EVT_USB_DEVICE_CONNECTED:
            user = (entry.get('SubjectUserName') or '').strip() or 'UNKNOWN'

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

        device_name = None

        if alert_type == EVT_PROCESS_CREATED:
            process = (entry.get('NewProcessName') or '').strip() or 'unknown process'
            parent = (entry.get('ParentProcessName') or '').strip()
            parentage = f" (parent: {parent})" if parent else ''
            message = f"Process started by '{user}': {process}{parentage}"
        elif alert_type == EVT_USB_DEVICE_CONNECTED:
            device_name = (entry.get('DeviceDescription') or '').strip() or 'Unknown device'
            # Plugging a drive in happens at the machine itself, so there is no
            # remote address to report. LOCAL_CONSOLE is the marker the
            # detection engine already treats as non-routable, which keeps the
            # event out of the brute-force and threat-IP correlations.
            ip = 'LOCAL_CONSOLE'
            message = f"USB device connected: {device_name} by user '{user}'"
        else:
            message = (
                f"Windows {outcome} for user '{user}'{detail}{origin} "
                f"(Event {event_id})"
            )

        return {
            'timestamp': timestamp,
            'alert_type': alert_type,
            'source_ip': ip,
            'user': user,
            'message': message,
            'device_name': device_name,
            'raw_log': json.dumps(entry, sort_keys=True),
        }

    @staticmethod
    def _parse_windows_timestamp(value):
        """Parse the PowerShell-formatted timestamp, falling back to now."""
        try:
            return datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            return datetime.now().replace(microsecond=0)
