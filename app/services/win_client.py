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

from app.models import USB_AUDIT_DISABLED, USB_AUDIT_ENABLED, USB_AUDIT_UNKNOWN

# Get-WinEvent says this when the filter matched nothing. It exits non-zero
# and writes to stderr, but it is a normal empty result, not a failure.
NO_EVENTS_MARKER = 'No events were found'

# The audit subcategory that has to be switched on before Windows will record
# a connected device as Event 6416. Named here so the probe, the API and the
# documentation cannot drift apart.
PNP_AUDIT_SUBCATEGORY = 'Plug and Play Events'


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

    # ------------------------------------------------------------------
    # Plug and Play auditing (required for USB detection)
    # ------------------------------------------------------------------

    def pnp_audit_status(self):
        """
        Report whether this machine audits Plug and Play events.

        Returns (state, detail) where state is one of the USB_AUDIT_* values.
        The distinction between DISABLED and UNKNOWN matters: "switched off"
        is something the operator can fix with one command, whereas "we could
        not tell" usually means the process is not elevated. Reporting both as
        a bare False would send them looking for the wrong problem.

        Reading the audit policy needs an elevated token, exactly as reading
        the Security log does, so an unprivileged probe yields UNKNOWN rather
        than a misleading DISABLED.
        """
        probe = (
            f'& auditpol.exe "/get" "/subcategory:{PNP_AUDIT_SUBCATEGORY}"'
        )

        try:
            stdout, stderr, _ = self.run_ps_raw(probe, timeout=60)
        except PowerShellError as exc:
            return USB_AUDIT_UNKNOWN, str(exc)

        return _classify_audit_output(stdout, stderr)

    def get_logs_json(self, log_name, limit=10):
        """Fetch a Windows event log as JSON (kept for ad-hoc inspection)."""
        ps_cmd = (
            f"Get-WinEvent -LogName '{log_name}' -MaxEvents {limit} | "
            "Select-Object TimeCreated, Id, Message | ConvertTo-Json"
        )
        return self.run_ps(ps_cmd)


class RemoteWinClient(WinClient):
    """
    Runs the same Security-log queries on another Windows PC over PowerShell
    remoting (WinRM).

    The password is passed to PowerShell through an environment variable
    rather than embedded in the command string. Process command lines are
    readable by other accounts on Windows, so interpolating a credential into
    one would expose it to anybody able to list processes.
    """

    PASSWORD_ENV_VAR = 'MINISIEM_REMOTE_PASSWORD'

    def __init__(self, computer, username, password, port=None, use_ssl=False,
                 authentication='Default'):
        if not computer:
            raise PowerShellError('No address configured for the remote host.')
        if not username:
            raise PowerShellError(
                'No remote username configured. Set one on the host in the '
                'Configuration page.'
            )
        if not password:
            raise PowerShellError(
                'No remote password configured. Set MINISIEM_WINRM_PASSWORD in '
                '.env — credentials are deliberately never stored in the database.'
            )

        self.computer = computer
        self.username = username
        self._password = password
        self.port = port
        self.use_ssl = use_ssl
        self.authentication = authentication

    # ------------------------------------------------------------------

    def _wrap(self, inner_script):
        """Wrap a script so it executes on the remote computer."""
        options = [
            f"-ComputerName '{_ps_quote(self.computer)}'",
            '-Credential $cred',
            '-ErrorAction Stop',
        ]
        if self.port:
            options.append(f'-Port {int(self.port)}')
        if self.use_ssl:
            options.append('-UseSSL')
        if self.authentication and self.authentication != 'Default':
            options.append(f"-Authentication {_ps_quote(self.authentication)}")

        return (
            f"$secure = ConvertTo-SecureString $env:{self.PASSWORD_ENV_VAR} "
            "-AsPlainText -Force; "
            "$cred = New-Object System.Management.Automation.PSCredential("
            f"'{_ps_quote(self.username)}', $secure); "
            "try { "
            f"  Invoke-Command {' '.join(options)} -ScriptBlock {{ {inner_script} }} "
            "} catch { "
            "  [Console]::Error.WriteLine($_.Exception.Message); exit 3 "
            "}"
        )

    def run_ps_raw(self, cmd, timeout=120):
        """Execute a script on the remote machine, keeping the password out of argv."""
        import os
        import subprocess

        env = os.environ.copy()
        env[self.PASSWORD_ENV_VAR] = self._password

        try:
            result = subprocess.run(
                [
                    'powershell',
                    '-NoProfile',
                    '-NonInteractive',
                    '-ExecutionPolicy', 'Bypass',
                    '-Command', self._wrap(cmd),
                ],
                capture_output=True,
                timeout=timeout,
                env=env,
            )
        except FileNotFoundError as exc:
            raise PowerShellError('powershell.exe was not found on PATH.') from exc
        except subprocess.TimeoutExpired as exc:
            raise PowerShellError(
                f'Connection to {self.computer} timed out after {timeout}s. '
                'Check that WinRM is enabled and reachable.'
            ) from exc

        stdout = result.stdout.decode('utf-8', errors='replace').strip()
        stderr = result.stderr.decode('utf-8', errors='replace').strip()
        return stdout, stderr, result.returncode

    def security_log_status(self):
        """Probe the remote Security log, translating common WinRM failures."""
        probe = (
            "try { "
            "  $null = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop; "
            "  'READABLE' "
            "} catch { "
            f"  if ($_.Exception.Message -match '{NO_EVENTS_MARKER}') {{ 'EMPTY' }} "
            "  else { 'ERROR: ' + $_.Exception.Message } "
            "}"
        )

        try:
            stdout, stderr, _ = self.run_ps_raw(probe, timeout=90)
        except PowerShellError as exc:
            return False, str(exc)

        text = (stdout or stderr or '').strip()

        if text.endswith('READABLE') or text.endswith('EMPTY'):
            return True, text
        if not text:
            return False, f'No response from {self.computer}.'

        return False, _explain_winrm_failure(text.replace('ERROR: ', '', 1), self.computer)

    @staticmethod
    def is_elevated():
        """Local elevation is irrelevant when querying another machine."""
        return True


def _one_line(text):
    """Collapse multi-line command output into a single readable line."""
    return ' '.join(part.strip() for part in (text or '').split()) or ''


def _classify_audit_output(stdout, stderr):
    """
    Turn auditpol's tabular output into a USB_AUDIT_* state.

    auditpol prints a table whose last column is the setting, e.g.
        Plug and Play Events                    No Auditing
    and writes an "Error 0x00000522" line instead when the caller lacks the
    privilege to read the policy at all.
    """
    text = (stdout or '').strip()
    problem = (stderr or '').strip()

    # auditpol splits its privilege error across two lines and may put it on
    # either stream. Flatten it so the reason fits a table cell and a
    # VARCHAR column rather than arriving with embedded newlines.
    if not text:
        return USB_AUDIT_UNKNOWN, _one_line(problem) or 'auditpol produced no output.'

    # A privilege failure is reported on stdout by auditpol, not stderr, so it
    # has to be recognised here rather than inferred from the exit code.
    if 'required privilege' in text.lower() or 'error 0x' in text.lower():
        return USB_AUDIT_UNKNOWN, _one_line(text)

    for line in text.splitlines():
        if PNP_AUDIT_SUBCATEGORY.lower() not in line.lower():
            continue

        setting = line.lower().split(PNP_AUDIT_SUBCATEGORY.lower(), 1)[1].strip()
        if 'no auditing' in setting:
            return USB_AUDIT_DISABLED, (
                f'{PNP_AUDIT_SUBCATEGORY}: No Auditing. USB devices will not be '
                f'recorded until this is enabled.'
            )
        if 'success' in setting:
            return USB_AUDIT_ENABLED, f'{PNP_AUDIT_SUBCATEGORY}: {setting.title()}.'
        return USB_AUDIT_UNKNOWN, f'Unrecognised audit setting: {setting!r}'

    return USB_AUDIT_UNKNOWN, f'Could not find "{PNP_AUDIT_SUBCATEGORY}" in the audit policy.'


def _ps_quote(value):
    """Escape a value for use inside a single-quoted PowerShell string."""
    return str(value).replace("'", "''")


def _explain_winrm_failure(message, computer):
    """Add a concrete remedy to the most common WinRM errors."""
    lowered = message.lower()

    if 'cannot find the computer' in lowered or 'winrm cannot complete' in lowered:
        return (
            f"{message} — WinRM does not appear to be listening on {computer}. "
            "On that PC, run 'Enable-PSRemoting -Force' from an Administrator "
            "PowerShell."
        )
    if 'access is denied' in lowered:
        return (
            f"{message} — the account was rejected by {computer}. It must be a "
            "local Administrator there, and for a workgroup (non-domain) PC the "
            "username usually needs the form COMPUTERNAME\\\\User."
        )
    if 'trustedhosts' in lowered:
        return (
            f"{message} — on this machine run: Set-Item "
            f"WSMan:\\localhost\\Client\\TrustedHosts -Value '{computer}' -Force"
        )
    return message
