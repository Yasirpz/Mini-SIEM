"""Host Management Module API: CRUD, live telemetry and log collection."""
import logging
import socket
import time
from datetime import datetime

from flask import current_app, jsonify, request
from flask_login import login_required

from app.blueprints.api import api_bp
from app.extensions import db
from app.models import (
    COLLECT_LOCAL,
    COLLECT_SSH,
    COLLECT_WINRM,
    Host,
    USB_AUDIT_ENABLED,
)
# The collection pipeline and the connection helpers live in the service
# layer so the background scheduler can reach them without an HTTP request.
# They are imported here because these routes are their other caller.
from app.services.collection import (
    _probe_usb_auditing,
    _ssh_for,
    _winrm_for,
    collect_host,
)
from app.services.win_client import PowerShellError, WinClient
from app.validators import (
    MAX_DESCRIPTION_LENGTH,
    ValidationError,
    validate_bool,
    validate_collection_method,
    validate_hostname,
    validate_ip,
    validate_os_type,
    validate_poll_interval,
    validate_text,
)

log = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Host management (CRUD) — FR-03
# ------------------------------------------------------------------

@api_bp.route('/hosts', methods=['GET'])
@login_required
def get_hosts():
    hosts = Host.query.order_by(Host.hostname.asc()).all()
    return jsonify([h.to_dict() for h in hosts])


@api_bp.route('/hosts', methods=['POST'])
@login_required
def add_host():
    data = request.get_json(silent=True) or {}

    hostname = validate_hostname(data.get('hostname'))
    ip_address = validate_ip(data.get('ip_address'))
    os_type = validate_os_type(data.get('os_type'))
    description = validate_text(data.get('description'), 'description', MAX_DESCRIPTION_LENGTH)

    if Host.query.filter_by(ip_address=ip_address).first():
        return jsonify({'error': f"A host with IP {ip_address} already exists"}), 409

    host = Host(
        hostname=hostname,
        ip_address=ip_address,
        os_type=os_type,
        description=description,
        collection_method=validate_collection_method(data.get('collection_method'), os_type),
        remote_user=validate_text(data.get('remote_user'), 'remote user', 100),
        polling_enabled=validate_bool(data.get('polling_enabled', False), 'polling_enabled'),
        poll_interval_seconds=validate_poll_interval(data.get('poll_interval_seconds')),
        fim_enabled=validate_bool(data.get('fim_enabled', False), 'fim_enabled'),
    )
    db.session.add(host)
    db.session.commit()
    return jsonify(host.to_dict()), 201


@api_bp.route('/hosts/<int:host_id>', methods=['PUT'])
@login_required
def update_host(host_id):
    host = Host.query.get_or_404(host_id)
    data = request.get_json(silent=True) or {}

    if 'hostname' in data:
        host.hostname = validate_hostname(data['hostname'])

    if 'ip_address' in data:
        ip_address = validate_ip(data['ip_address'])
        clash = Host.query.filter(
            Host.ip_address == ip_address, Host.id != host.id
        ).first()
        if clash:
            return jsonify({'error': f"A host with IP {ip_address} already exists"}), 409
        host.ip_address = ip_address

    if 'os_type' in data:
        host.os_type = validate_os_type(data['os_type'])

    if 'description' in data:
        host.description = validate_text(
            data['description'], 'description', MAX_DESCRIPTION_LENGTH
        )

    if 'collection_method' in data:
        host.collection_method = validate_collection_method(
            data['collection_method'], host.os_type
        )

    if 'remote_user' in data:
        host.remote_user = validate_text(data['remote_user'], 'remote user', 100)

    if 'polling_enabled' in data:
        enabled = validate_bool(data['polling_enabled'], 'polling_enabled')
        # Switching polling on makes the host due immediately rather than one
        # interval from now. Someone who has just enabled it is watching for
        # something to happen, and making them wait five minutes to find out
        # whether it works is a poor way to report success.
        if enabled and not host.polling_enabled:
            host.last_poll = None
        host.polling_enabled = enabled

    if 'poll_interval_seconds' in data:
        host.poll_interval_seconds = validate_poll_interval(data['poll_interval_seconds'])

    if 'fim_enabled' in data:
        host.fim_enabled = validate_bool(data['fim_enabled'], 'fim_enabled')

    db.session.commit()
    return jsonify(host.to_dict()), 200


@api_bp.route('/hosts/<int:host_id>', methods=['DELETE'])
@login_required
def delete_host(host_id):
    host = Host.query.get_or_404(host_id)
    db.session.delete(host)
    db.session.commit()
    return jsonify({'message': 'Host removed'}), 200


# ------------------------------------------------------------------
# Live host telemetry (RAM / CPU / disk / uptime)
# ------------------------------------------------------------------

@api_bp.route('/hosts/<int:host_id>/ssh-info', methods=['GET'])
@login_required
def get_ssh_info(host_id):
    host = Host.query.get_or_404(host_id)

    try:
        with _ssh_for(host) as remote:
            ram_out, _ = remote.run("free -m | grep Mem | awk '{print $7}'")
            disk_percentage, _ = remote.run("df -h | grep '/$' | awk '{print $5}'")
            if not disk_percentage:
                disk_percentage, _ = remote.run("df -h | grep '/dev/sda1' | awk '{print $5}'")
            disk_total, _ = remote.run("df -h | grep '/dev/sda1' | awk '{print $2}'")
            cpu_load, _ = remote.run("uptime | awk -F'load average:' '{ print $2 }' | cut -d',' -f1")
            uptime_seconds_str, _ = remote.run("cat /proc/uptime | awk '{print $1}'")

            uptime_formatted = 'N/A'
            try:
                total_seconds = float(uptime_seconds_str)
                hours = int(total_seconds // 3600)
                minutes = int((total_seconds % 3600) // 60)
                uptime_formatted = f"{hours}h {minutes}m"
            except (ValueError, TypeError):
                pass

            return jsonify({
                'free_ram_mb': ram_out.strip(),
                'disk_info': disk_percentage.strip(),
                'disk_total': disk_total.strip(),
                'cpu_load': cpu_load.strip(),
                'uptime_hours': uptime_formatted,
            }), 200
    except Exception as exc:
        return jsonify({'error': f"Connection error: {exc}"}), 502


@api_bp.route('/hosts/<int:host_id>/windows-info', methods=['GET'])
@login_required
def get_windows_info(host_id):
    import psutil

    host = Host.query.get_or_404(host_id)
    if host.os_type != 'WINDOWS':
        return jsonify({'error': 'Host is not marked as WINDOWS'}), 400

    try:
        mem = psutil.virtual_memory()
        free_ram_mb = str(round(mem.available / (1024 * 1024)))
        cpu_load = f"{psutil.cpu_percent(interval=0.1)}%"

        try:
            usage = psutil.disk_usage('C:\\')
            disk_percentage = f"{usage.percent}%"
            disk_total = f"{round(usage.total / (1024 ** 3), 1)}GB"
        except OSError:
            disk_percentage, disk_total = 'N/A', '?'

        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime_seconds = (datetime.now() - boot_time).total_seconds()
        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)

        return jsonify({
            'free_ram_mb': free_ram_mb,
            'disk_info': disk_percentage,
            'disk_total': disk_total,
            'cpu_load': cpu_load,
            'uptime_hours': f"{hours}h {minutes}m",
        }), 200
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


# ------------------------------------------------------------------
# Log collection + detection (core SIEM workflow)
# ------------------------------------------------------------------

@api_bp.route('/hosts/<int:host_id>/logs', methods=['POST'])
@login_required
def fetch_logs(host_id):
    """
    Collect authentication logs for a host and run them through the analysis
    pipeline: archive to Parquet, store as events, apply the detection rules.

    The work itself lives in `app.services.collection` so that the background
    scheduler can perform an identical collection without a request. This view
    only resolves the host and turns the result into JSON.
    """
    host = Host.query.get_or_404(host_id)
    payload, status = collect_host(host)
    return jsonify(payload), status


@api_bp.route('/hosts/<int:host_id>/test', methods=['POST'])
@login_required
def test_connection(host_id):
    """
    Check a host stage by stage and report each one separately.

    "Connection failed" is not actionable — it could mean the PC is off, the
    password is wrong, or the account lacks permission, and those have
    completely different fixes. Each stage is therefore reported on its own.
    """
    host = Host.query.get_or_404(host_id)
    method = host.effective_collection_method()
    started = time.monotonic()

    checks = []

    def add(name, ok, detail='', advisory=False):
        """
        Record one stage of the test.

        An advisory check reports an optional capability rather than a
        prerequisite. It is shown to the operator but deliberately excluded
        from the overall verdict, so a host that collects logs perfectly well
        is not reported as broken merely because an optional feature is off.
        """
        checks.append({'name': name, 'ok': ok, 'detail': detail, 'advisory': advisory})
        return ok

    log.info('Testing connection to %s via %s', host.hostname, method)

    if method == COLLECT_LOCAL:
        add('Target is this machine', True, 'No network connection required.')

        elevated = WinClient.is_elevated()
        add(
            'Flask process is elevated',
            elevated,
            'Running with an elevated token.' if elevated else
            'The Flask process is not elevated. Restart it from a PowerShell '
            'window opened with "Run as Administrator".',
        )

        readable, detail = WinClient().security_log_status()
        add('Security log is readable', readable, detail)

        # USB detection is optional, so this is advisory: a host with Plug and
        # Play auditing off still collects everything else correctly.
        audit_state, audit_detail = WinClient().pnp_audit_status()
        host.usb_audit_status = audit_state or host.usb_audit_status
        add(
            'USB device auditing enabled',
            audit_state == USB_AUDIT_ENABLED,
            audit_detail,
            advisory=True,
        )

    elif method == COLLECT_WINRM:
        port = current_app.config.get('WINRM_PORT') or 5985
        reachable = _port_is_open(host.ip_address, port)
        add(
            f'Host reachable on port {port}',
            reachable,
            f'{host.ip_address}:{port} accepted a connection.' if reachable else
            f'Nothing is listening on {host.ip_address}:{port}. Check the PC is '
            'on, and run "Enable-PSRemoting -Force" there.',
        )

        if reachable:
            try:
                win = _winrm_for(host)
            except PowerShellError as exc:
                add('Credentials configured', False, str(exc))
                win = None
            else:
                add('Credentials configured', True,
                    f'Using account "{win.username}".')

            if win is not None:
                readable, detail = win.security_log_status()
                # A rejected account and a permission problem look different
                # to the operator, so separate them.
                if readable:
                    add('Authentication successful', True, 'The account was accepted.')
                    add('Security log accessible', True, detail)

                    # Only worth asking once the account has been accepted —
                    # probing first would just report the authentication
                    # failure a second time under a misleading name.
                    audit_state, audit_detail = win.pnp_audit_status()
                    host.usb_audit_status = audit_state or host.usb_audit_status
                    add(
                        'USB device auditing enabled',
                        audit_state == USB_AUDIT_ENABLED,
                        audit_detail,
                        advisory=True,
                    )
                elif 'denied' in detail.lower() or 'credential' in detail.lower():
                    add('Authentication successful', False, detail)
                else:
                    add('Authentication successful', True,
                        'Reached the remote host.')
                    add('Security log accessible', False, detail)

    elif method == COLLECT_SSH:
        port = current_app.config.get('SSH_DEFAULT_PORT', 22)
        reachable = _port_is_open(host.ip_address, port)
        add(
            f'Host reachable on port {port}',
            reachable,
            f'{host.ip_address}:{port} accepted a connection.' if reachable else
            f'Nothing is listening on {host.ip_address}:{port}. Check the host '
            'is on and sshd is running.',
        )

        if reachable:
            try:
                with _ssh_for(host) as remote:
                    add('Authentication successful', True, 'SSH login accepted.')
                    out, _ = remote.run('test -r /var/log/auth.log && echo auth.log '
                                        '|| (test -r /var/log/secure && echo secure)')
                    found = (out or '').strip()
                    add(
                        'Authentication log readable',
                        bool(found),
                        f'Found /var/log/{found}.' if found else
                        'Neither /var/log/auth.log nor /var/log/secure is readable '
                        'by this account.',
                    )
            except Exception as exc:
                add('Authentication successful', False, str(exc))

    latency = int((time.monotonic() - started) * 1000)
    required = [check for check in checks if not check['advisory']]
    ok = all(check['ok'] for check in required) and bool(required)

    failure = next((c for c in required if not c['ok']), None)
    host.record_attempt(
        ok,
        error=None if ok else f"{failure['name']}: {failure['detail']}",
        latency_ms=latency,
    )
    db.session.commit()

    return jsonify({
        'ok': ok,
        'checks': checks,
        'latency_ms': latency,
        'status': host.health(),
        'collection_method': method,
    }), 200


def _port_is_open(address, port, timeout=3):
    """
    True if a TCP connection to address:port succeeds.

    A short timeout matters: without it an unreachable host would block the
    request until the operating system gave up, tying up the worker and
    making the whole dashboard feel dead.
    """
    try:
        with socket.create_connection((address, int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False
