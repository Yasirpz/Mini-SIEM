"""
The log-collection pipeline, independent of what triggered it.

This module exists because collection acquired a second caller. The whole
pipeline used to live inside the `/api/hosts/<id>/logs` view, which meant it
could only run when a person pressed a button: the logic was welded to a
request, a session and a JSON response. A system that looks only when it is
asked to is a log viewer rather than a monitor, so `collect_host` lifts that
logic out and returns plain data instead of a Flask response.

The route now translates that data into JSON, and the background scheduler in
`app.services.scheduler` calls the same function on a timer. Both paths share
one implementation, so automatic collection cannot drift away from the manual
one -- there is only one of them to drift.

Everything here needs an application context, for `current_app.config` and the
database session, but never a *request* context.
"""
import logging
import os
import re
import time

from flask import current_app

from app.extensions import db
from app.models import COLLECT_LOCAL, COLLECT_SSH, COLLECT_WINRM, LogSource, utcnow
from app.services.log_analyzer import LogAnalyzer
from app.services.log_collector import LogCollector
from app.services.remote_client import RemoteClient
from app.services.win_client import PowerShellError, RemoteWinClient, WinClient

log = logging.getLogger(__name__)


def collect_host(host):
    """
    Collect logs for one host, archive them, and run the detection rules.

    Returns `(payload, status)` -- a JSON-serialisable dict and an HTTP status
    code -- rather than a Flask response, so a caller with no request in
    flight can use it too. 200 means the host was reached; any other status
    carries an `error` key describing what failed, and by then the failure has
    already been recorded against the host.

    Collection is incremental: `LogSource.last_fetch` means a repeated call
    only pulls records that appeared since the previous run. That is what
    makes it safe to call on a short timer -- polling a quiet host costs one
    round trip and stores nothing.
    """

    log_source = LogSource.query.filter_by(host_id=host.id).first()
    if not log_source:
        log_source = LogSource(host_id=host.id, log_type='security', last_fetch=None)
        db.session.add(log_source)
        db.session.commit()

    method = host.effective_collection_method()
    started = time.monotonic()

    def elapsed_ms():
        return int((time.monotonic() - started) * 1000)

    def fail(status, message, **extra):
        """Record the failure against the host, then return the payload."""
        detail = extra.get('detail') or message
        host.record_attempt(False, error=detail, latency_ms=elapsed_ms())
        db.session.commit()
        log.warning('Collection failed for %s (%s): %s', host.hostname, method, detail)
        return {'error': message, **extra}, status

    log.info('Starting collection for %s via %s', host.hostname, method)

    if method == COLLECT_SSH:
        try:
            with _ssh_for(host) as remote:
                logs = LogCollector.get_linux_logs(remote, last_fetch_time=log_source.last_fetch)
        except Exception as exc:
            return fail(502, f"SSH connection to {host.ip_address} failed.", detail=str(exc))

    elif method == COLLECT_WINRM:
        try:
            win = _winrm_for(host)
        except PowerShellError as exc:
            return fail(
                400,
                'Remote collection is not configured for this host.',
                detail=str(exc),
            )

        readable, detail = win.security_log_status()
        if not readable:
            return fail(
                502,
                f"Cannot read the Security log on {host.ip_address}.",
                detail=detail,
                hint=(
                    'On the target PC, run "Enable-PSRemoting -Force" from an '
                    'Administrator PowerShell, and make sure the account you '
                    'configured is a local Administrator there.'
                ),
            )

        # Same best-effort refresh as the local path. A remote probe crosses
        # the network and so has more ways to fail, which makes it all the
        # more important that it cannot cost the operator their logs.
        host.usb_audit_status = _probe_usb_auditing(win) or host.usb_audit_status

        try:
            logs = LogCollector.get_windows_logs(win, last_fetch_time=log_source.last_fetch)
        except PowerShellError as exc:
            return fail(
                502,
                f"Remote collection from {host.ip_address} failed.",
                detail=str(exc),
            )

    elif method == COLLECT_LOCAL:
        try:
            with WinClient() as win:
                # A process without an elevated token cannot read the Security
                # log, and Get-WinEvent reports that indistinguishably from an
                # empty result. Probe first, and report what actually went
                # wrong — including whether *this server process* is elevated,
                # which is what matters rather than the terminal being used.
                readable, detail = win.security_log_status()
                if not readable:
                    return fail(
                        403,
                        'Cannot read the Windows Security log.',
                        detail=detail,
                        server_is_elevated=win.is_elevated(),
                        hint=(
                            'Stop Flask and restart it from a PowerShell window opened '
                            'with "Run as Administrator". The Flask process itself must '
                            'be elevated — an Administrator terminal does not help if the '
                            'server was started elsewhere.'
                        ),
                    )

                # Refresh the recorded auditing state on the way past. Most
                # operators press Collect far more often than Test, so tying
                # this only to the connection test would leave the dashboard
                # showing UNKNOWN indefinitely.
                #
                # Deliberately best-effort: this is an optional diagnostic,
                # and it must never be able to fail a collection that would
                # otherwise have succeeded. Losing the badge is a far smaller
                # problem than losing the logs.
                host.usb_audit_status = (
                    _probe_usb_auditing(win) or host.usb_audit_status
                )

                logs = LogCollector.get_windows_logs(win, last_fetch_time=log_source.last_fetch)
        except PowerShellError as exc:
            return fail(
                500,
                'Windows log collection failed.',
                detail=str(exc),
                server_is_elevated=WinClient.is_elevated(),
            )
        except Exception as exc:
            return fail(500, 'Windows collection error.', detail=str(exc))

    else:
        return fail(400, f"Unsupported collection method: {method}")

    # Reaching a host and finding nothing new is a *successful* collection.
    # Recording it as such is what stops a quiet host from drifting OFFLINE.
    if not logs:
        host.record_attempt(True, latency_ms=elapsed_ms())
        db.session.commit()
        log.info('No new entries for %s', host.hostname)
        return {
            'message': 'Connected successfully. No new log entries since the last collection.',
            'events_received': 0,
            'events_stored': 0,
            'duplicates_skipped': 0,
            'alerts': {'total': 0},
            'status': host.health(),
        }, 200

    try:
        result = LogAnalyzer.ingest(logs, host.id, origin='COLLECTED')
    except Exception as exc:
        return fail(500, 'Storing the collected events failed.', detail=str(exc))

    # UTC, like every other datetime in the database. The next collection
    # turns this back into the monitored host's local time when it builds the
    # query, so the watermark means the same thing on every machine.
    log_source.last_fetch = utcnow()
    host.record_attempt(True, latency_ms=elapsed_ms())
    db.session.commit()

    log.info(
        'Collected %s entries from %s: %s new, %s duplicates, %s alerts',
        result['events_received'], host.hostname, result['events_stored'],
        result['duplicates_skipped'], result['alerts']['total'],
    )

    return {
        'message': (
            f"Received {result['events_received']}, "
            f"stored {result['events_stored']} new, "
            f"ignored {result['duplicates_skipped']} duplicates"
        ),
        'file': result['archive_file'],
        'status': host.health(),
        **result,
    }, 200


# ------------------------------------------------------------------
# Connection helpers
#
# These live beside the pipeline rather than beside the routes because the
# scheduler needs them without going through the HTTP layer at all.
# ------------------------------------------------------------------


def _probe_usb_auditing(win):
    """
    Best-effort read of a host's Plug and Play auditing state.

    Returns None when the state cannot be determined, which leaves whatever
    was previously recorded in place rather than overwriting a known value
    with a guess.
    """
    probe = getattr(win, 'pnp_audit_status', None)
    if probe is None:
        return None

    try:
        state, _ = probe()
        return state
    except Exception:
        log.warning('Could not read the Plug and Play audit policy', exc_info=True)
        return None


def _ssh_for(host):
    """Build a RemoteClient for a host using the configured SSH credentials."""
    return RemoteClient(
        host=host.ip_address,
        user=host.remote_user or current_app.config.get('SSH_DEFAULT_USER', 'siem-admin'),
        port=current_app.config.get('SSH_DEFAULT_PORT', 2222),
        password=current_app.config.get('SSH_PWD'),
        key_file=current_app.config.get('SSH_KEY_FILE') or None,
    )


def _winrm_for(host):
    """
    Build a RemoteWinClient for a host.

    The username may be stored per host, but the password is only ever read
    from the environment. A per-host password can be supplied as
    MINISIEM_WINRM_PASSWORD_<HOSTNAME>; otherwise the shared
    MINISIEM_WINRM_PASSWORD is used.
    """
    suffix = re.sub(r'[^A-Z0-9]', '_', (host.hostname or '').upper())
    password = (
        os.getenv(f'MINISIEM_WINRM_PASSWORD_{suffix}')
        or current_app.config.get('WINRM_PASSWORD')
    )

    return RemoteWinClient(
        computer=host.ip_address,
        username=host.remote_user or current_app.config.get('WINRM_DEFAULT_USER'),
        password=password,
        port=current_app.config.get('WINRM_PORT'),
        use_ssl=current_app.config.get('WINRM_USE_SSL', False),
        authentication=current_app.config.get('WINRM_AUTH', 'Default'),
    )
