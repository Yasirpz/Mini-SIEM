"""
Local Windows command execution for reading the Security event log.

Kept API-compatible with RemoteClient so the collection endpoint can treat
Linux and Windows hosts the same way.

Reading the Security log requires the *Flask process itself* to be elevated —
not merely the terminal a developer happens to have open. This module reports
that condition explicitly, because a non-elevated read fails in a way that is
otherwise indistinguishable from "there were no events".
"""
import ctypes
import subprocess

# Get-WinEvent says this when the filter matched nothing. It exits non-zero
# and writes to stderr, but it is a normal empty result, not a failure.
NO_EVENTS_MARKER = 'No events were found'


class PowerShellError(RuntimeError):
    """Raised when PowerShell fails in a way the caller should surface."""


class WinClient:

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    # ------------------------------------------------------------------
    # Process elevation
    # ------------------------------------------------------------------

    @staticmethod
    def is_elevated():
        """
        True when the current process holds an elevated token.

        This checks the Flask process, which is what actually matters — an
        Administrator terminal does not help if the server was started
        somewhere else.
        """
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    # ------------------------------------------------------------------
    # PowerShell execution
    # ------------------------------------------------------------------

    def run_ps(self, cmd, timeout=120):
        """
        Run a PowerShell command and return stdout.

        Raises PowerShellError carrying the real stderr text when the command
        genuinely fails. A non-zero exit code with usable stdout is *not*
        treated as a failure: PowerShell exits non-zero for a pipeline that
        merely produced nothing, which would otherwise mask real results.
        """
        stdout, stderr, returncode = self.run_ps_raw(cmd, timeout=timeout)

        if stdout:
            return stdout

        if returncode != 0 and stderr and NO_EVENTS_MARKER not in stderr:
            raise PowerShellError(stderr.strip())

        return stdout

    def run_ps_raw(self, cmd, timeout=120):
        """
        Execute PowerShell and return (stdout, stderr, returncode) verbatim.

        Output is decoded as UTF-8 with replacement rather than the OEM code
        page: the previous OEM decoding could raise on non-ASCII usernames and
        take down the whole collection.
        """
        try:
            result = subprocess.run(
                [
                    'powershell',
                    '-NoProfile',
                    '-NonInteractive',
                    '-ExecutionPolicy', 'Bypass',
                    '-Command', cmd,
                ],
                capture_output=True,
                timeout=timeout,
            )
        except FileNotFoundError as exc:
            raise PowerShellError('powershell.exe was not found on PATH.') from exc
        except subprocess.TimeoutExpired as exc:
            raise PowerShellError(f'PowerShell timed out after {timeout}s.') from exc

        stdout = result.stdout.decode('utf-8', errors='replace').strip()
        stderr = result.stderr.decode('utf-8', errors='replace').strip()
        return stdout, stderr, result.returncode

    # ------------------------------------------------------------------
    # Security log availability
    # ------------------------------------------------------------------

    def security_log_status(self):
        """
        Report whether the Security log can be read.

        Returns (ok, detail). `ok` is False only when the log is genuinely
        unreadable; an empty log counts as readable. `detail` carries the
        underlying reason so the API can show something actionable instead of
        a blanket "run as Administrator".
        """
        probe = (
            "$ErrorActionPreference='Stop'; "
            "try { "
            "  $null = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop; "
            "  'READABLE' "
            "} catch { "
            f"  if ($_.Exception.Message -match '{NO_EVENTS_MARKER}') {{ 'EMPTY' }} "
            "  else { 'ERROR: ' + $_.Exception.Message } "
            "}"
        )

        try:
            stdout, stderr, _ = self.run_ps_raw(probe, timeout=60)
        except PowerShellError as exc:
            return False, str(exc)

        text = (stdout or stderr or '').strip()

        if text.endswith('READABLE') or text.endswith('EMPTY'):
            return True, text

        if not text:
            return False, 'PowerShell produced no output when probing the Security log.'

        return False, text.replace('ERROR: ', '', 1)

    def can_read_security_log(self):
        """Backwards-compatible boolean form of security_log_status()."""
        ok, _ = self.security_log_status()
        return ok

    def get_logs_json(self, log_name, limit=10):
        """Fetch a Windows event log as JSON (kept for ad-hoc inspection)."""
        ps_cmd = (
            f"Get-WinEvent -LogName '{log_name}' -MaxEvents {limit} | "
            "Select-Object TimeCreated, Id, Message | ConvertTo-Json"
        )
        return self.run_ps(ps_cmd)
