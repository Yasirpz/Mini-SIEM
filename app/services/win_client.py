"""Wrapper around subprocess for running PowerShell locally, kept API-compatible with RemoteClient."""
import subprocess


class WinClient:

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def run_ps(self, cmd):
        """Run a PowerShell command and return its stdout."""
        full_cmd = ['powershell', '-NoProfile', '-NonInteractive', '-Command', cmd]

        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            encoding='oem',
            timeout=120,
        )
        if result.returncode != 0:
            raise Exception(f"PowerShell error: {result.stderr.strip()}")

        return result.stdout.strip()

    def can_read_security_log(self):
        """
        Report whether the Security event log is readable.

        Reading it requires an elevated process. Checking explicitly lets the
        API return "run as Administrator" rather than the indistinguishable
        "no new log entries" that a silent permission failure would produce.
        """
        probe = (
            "try { Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop | "
            "Out-Null; 'OK' } catch { 'DENIED' }"
        )
        try:
            return self.run_ps(probe).strip().endswith('OK')
        except Exception:
            return False

    def get_logs_json(self, log_name, limit=10):
        """Fetch a Windows event log as JSON."""
        ps_cmd = f"Get-WinEvent -LogName '{log_name}' -MaxEvents {limit} | Select-Object TimeCreated, Id, Message | ConvertTo-Json"
        return self.run_ps(ps_cmd)
