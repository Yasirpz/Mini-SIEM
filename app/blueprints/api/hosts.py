"""Host Management Module API: CRUD, live telemetry and log collection."""
from datetime import datetime

from flask import current_app, jsonify, request
from flask_login import login_required

from app.blueprints.api import api_bp
from app.extensions import db
from app.models import Host, LogSource
from app.services.log_analyzer import LogAnalyzer
from app.services.log_collector import LogCollector
from app.services.remote_client import RemoteClient
from app.services.win_client import WinClient
from app.validators import (
    MAX_DESCRIPTION_LENGTH,
    ValidationError,
    validate_hostname,
    validate_ip,
    validate_os_type,
    validate_text,
)


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

    Collection is incremental — LogSource.last_fetch means a repeated call
    only pulls records that appeared since the previous run.
    """
    host = Host.query.get_or_404(host_id)

    log_source = LogSource.query.filter_by(host_id=host.id).first()
    if not log_source:
        log_source = LogSource(host_id=host.id, log_type='security', last_fetch=None)
        db.session.add(log_source)
        db.session.commit()

    if host.os_type == 'LINUX':
        try:
            with _ssh_for(host) as remote:
                logs = LogCollector.get_linux_logs(remote, last_fetch_time=log_source.last_fetch)
        except Exception as exc:
            return jsonify({'error': f"SSH error: {exc}"}), 502

    elif host.os_type == 'WINDOWS':
        try:
            with WinClient() as win:
                logs = LogCollector.get_windows_logs(win, last_fetch_time=log_source.last_fetch)
        except Exception as exc:
            return jsonify({'error': f"Windows collection error: {exc}"}), 500

    else:
        return jsonify({'error': f"Unsupported OS type: {host.os_type}"}), 400

    if not logs:
        return jsonify({
            'message': 'No new log entries found',
            'events_stored': 0,
            'alerts': {'total': 0},
        }), 200

    try:
        result = LogAnalyzer.ingest(logs, host.id, origin='COLLECTED')
    except Exception as exc:
        return jsonify({'error': f"Storage error: {exc}"}), 500

    log_source.last_fetch = datetime.now()
    db.session.commit()

    return jsonify({
        'message': (
            f"Collected {result['events_received']} log entries, "
            f"stored {result['events_stored']} new events"
        ),
        'file': result['archive_file'],
        **result,
    }), 200


def _ssh_for(host):
    """Build a RemoteClient for a host using the configured SSH credentials."""
    return RemoteClient(
        host=host.ip_address,
        user=current_app.config.get('SSH_DEFAULT_USER', 'siem-admin'),
        port=current_app.config.get('SSH_DEFAULT_PORT', 2222),
        password=current_app.config.get('SSH_PWD'),
        key_file=current_app.config.get('SSH_KEY_FILE') or None,
    )
