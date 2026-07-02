"""
Collects and normalizes authentication logs from Linux and Windows hosts
into a common event format:
    {timestamp, alert_type, source_ip, user, message, raw_log}
"""
import re
import json
from datetime import datetime


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
                'alert_type': 'FAILED_LOGIN',
                'source_ip': match.group(2),
                'user': match.group(1),
                'message': message,
                'raw_log': message,
            }

        match = LogCollector.LINUX_PATTERNS['invalid_user'].search(message)
        if match:
            return {
                'timestamp': timestamp,
                'alert_type': 'INVALID_USER',
                'source_ip': match.group(2),
                'user': match.group(1),
                'message': message,
                'raw_log': message,
            }

        match = LogCollector.LINUX_PATTERNS['sudo'].search(message)
        if match:
            return {
                'timestamp': timestamp,
                'alert_type': 'SUDO_USAGE',
                'source_ip': 'LOCAL',
                'user': match.group(1),
                'message': message,
                'raw_log': message,
            }
        return None

    # =====================================================================
    # WINDOWS (PowerShell + XML parsing, Event ID 4625)
    # =====================================================================
    @staticmethod
    def get_windows_logs(win_client, last_fetch_time=None):
        logs = []

        if last_fetch_time:
            ts_str = last_fetch_time.strftime('%Y-%m-%d %H:%M:%S')
            filter_script = f"@{{LogName='Security'; Id=4625; StartTime=[datetime]'{ts_str}'}}"
            params = ""  # fetch everything since that date
        else:
            filter_script = "@{LogName='Security'; Id=4625}"
            params = "-MaxEvents 20"  # default cap on first run

        ps_cmd = (
            f"Get-WinEvent -FilterHashtable {filter_script} {params} -ErrorAction SilentlyContinue | "
            "ForEach-Object { "
            "   $xml = [xml]$_.ToXml(); "
            "   $data = @{}; "
            "   $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }; "
            "   [PSCustomObject]@{ "
            "       Timestamp = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); "
            "       IpAddress = $data['IpAddress']; "
            "       TargetUserName = $data['TargetUserName']; "
            "       EventId = $_.Id "
            "   } "
            "} | ConvertTo-Json -Compress"
        )

        print(f"DEBUG [Windows]: Executing PS with filter: {filter_script}")

        try:
            stdout = win_client.run_ps(ps_cmd)

            if not stdout:
                return []

            try:
                data = json.loads(stdout)
            except json.JSONDecodeError:
                print("WinLog Error: invalid JSON output from PowerShell")
                return []

            # PowerShell returns a dict for a single result, a list for many
            entries = [data] if isinstance(data, dict) else data

            for entry in entries:
                ip = entry.get('IpAddress', '-')
                user = entry.get('TargetUserName', 'UNKNOWN')
                ts_str = entry.get('Timestamp')

                try:
                    timestamp = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                except (ValueError, TypeError):
                    timestamp = datetime.now()

                if not ip or ip == '-':
                    ip = 'LOCAL_CONSOLE'

                logs.append({
                    'timestamp': timestamp,
                    'alert_type': 'WIN_FAILED_LOGIN',
                    'source_ip': ip,
                    'user': user,
                    'message': f"Windows logon failure for user: {user} (Event 4625)",
                    'raw_log': json.dumps(entry),
                })
            print(f"DEBUG [Windows]: Collected {len(logs)} logs.")
        except Exception as e:
            print(f"Error collecting Windows logs: {e}")
            return []

        return logs
