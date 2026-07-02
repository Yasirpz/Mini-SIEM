from flask import Blueprint, jsonify, request, current_app
from flask_login import login_required
from datetime import datetime

from app.models import Host, LogSource, LogArchive, Alert, IPRegistry
from app.services.remote_client import RemoteClient
from app.services.win_client import WinClient
from app.services.log_collector import LogCollector
from app.services.data_manager import DataManager
from app.services.log_analyzer import LogAnalyzer
from app.extensions import db

api_bp = Blueprint("api_hosts", __name__)

# ------------------------------------------------------------------
# Host management (CRUD)
# ------------------------------------------------------------------

@api_bp.route("/hosts", methods=["GET"])
@login_required
def get_hosts():
    hosts = Host.query.all()
    return jsonify([h.to_dict() for h in hosts])


@api_bp.route("/hosts", methods=["POST"])
@login_required
def add_host():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    if Host.query.filter_by(ip_address=data.get("ip_address")).first():
        return jsonify({"error": "IP address must be unique"}), 409
    new_host = Host(
        hostname=data.get("hostname"),
        ip_address=data.get("ip_address"),
        os_type=data.get("os_type"),
    )
    db.session.add(new_host)
    db.session.commit()
    return jsonify(new_host.to_dict()), 201


@api_bp.route("/hosts/<int:host_id>", methods=["DELETE"])
@login_required
def delete_host(host_id):
    host = Host.query.get_or_404(host_id)
    db.session.delete(host)
    db.session.commit()
    return jsonify({"message": "Host removed"}), 200


@api_bp.route("/hosts/<int:host_id>", methods=["PUT"])
@login_required
def update_host(host_id):
    host = Host.query.get_or_404(host_id)
    data = request.get_json()
    if 'hostname' in data:
        host.hostname = data['hostname']
    if 'ip_address' in data:
        host.ip_address = data['ip_address']
    if 'os_type' in data:
        host.os_type = data['os_type']
    db.session.commit()
    return jsonify(host.to_dict()), 200


# ------------------------------------------------------------------
# Live host telemetry (RAM / CPU / disk / uptime)
# ------------------------------------------------------------------

@api_bp.route("/hosts/<int:host_id>/ssh-info", methods=["GET"])
@login_required
def get_ssh_info(host_id):
    host = Host.query.get_or_404(host_id)
    ssh_user = current_app.config.get("SSH_DEFAULT_USER", "siem-admin")
    ssh_port = current_app.config.get("SSH_DEFAULT_PORT", 2222)
    ssh_key = current_app.config.get("SSH_KEY_FILE") or None
    ssh_password = current_app.config.get("SSH_PWD")
    try:
        with RemoteClient(host=host.ip_address, user=ssh_user, port=ssh_port,
                           password=ssh_password, key_file=ssh_key) as remote:
            ram_out, _ = remote.run("free -m | grep Mem | awk '{print $7}'")
            disk_percentage, _ = remote.run("df -h | grep '/$' | awk '{print $5}'")
            if not disk_percentage:
                disk_percentage, _ = remote.run("df -h | grep '/dev/sda1' | awk '{print $5}'")
            disk_total, _ = remote.run("df -h | grep '/dev/sda1' | awk '{print $2}'")
            cpu_load, _ = remote.run("uptime | awk -F'load average:' '{ print $2 }' | cut -d',' -f1")
            uptime_seconds_str, _ = remote.run("cat /proc/uptime | awk '{print $1}'")
            uptime_formatted = "N/A"
            try:
                total_seconds = float(uptime_seconds_str)
                hours = int(total_seconds // 3600)
                minutes = int((total_seconds % 3600) // 60)
                uptime_formatted = f"{hours}h {minutes}m"
            except (ValueError, TypeError):
                pass

            return jsonify({
                "free_ram_mb": ram_out.strip(), "disk_info": disk_percentage.strip(),
                "disk_total": disk_total.strip(), "cpu_load": cpu_load.strip(),
                "uptime_hours": uptime_formatted,
            }), 200
    except Exception as e:
        return jsonify({"error": f"Connection error: {str(e)}"}), 500


@api_bp.route("/hosts/<int:host_id>/windows-info", methods=["GET"])
@login_required
def get_windows_info(host_id):
    import psutil
    host = Host.query.get_or_404(host_id)
    if host.os_type != "WINDOWS":
        return jsonify({"error": "Host is not marked as WINDOWS"}), 400
    try:
        mem = psutil.virtual_memory()
        free_ram_mb = str(round(mem.available / (1024 * 1024)))
        cpu_load = f"{psutil.cpu_percent(interval=0.1)}%"
        try:
            usage = psutil.disk_usage("C:\\")
            disk_percentage = f"{usage.percent}%"
            disk_total = f"{round(usage.total / (1024**3), 1)}GB"
        except OSError:
            disk_percentage, disk_total = "N/A", "?"
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime_seconds = (datetime.now() - boot_time).total_seconds()
        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        return jsonify({
            "free_ram_mb": free_ram_mb, "disk_info": disk_percentage,
            "disk_total": disk_total, "cpu_load": cpu_load,
            "uptime_hours": f"{hours}h {minutes}m",
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ------------------------------------------------------------------
# Log collection + detection (core SIEM workflow)
# ------------------------------------------------------------------

@api_bp.route("/hosts/<int:host_id>/logs", methods=["POST"])
@login_required
def fetch_logs(host_id):
    """
    Collects authentication logs for a host, archives them to Parquet for
    forensic retention, then runs the detection engine to raise alerts.
    Uses an incremental fetch based on LogSource.last_fetch so repeated
    calls only process new events.
    """
    host = Host.query.get_or_404(host_id)

    log_source = LogSource.query.filter_by(host_id=host.id).first()
    if not log_source:
        log_source = LogSource(host_id=host.id, log_type='security', last_fetch=None)
        db.session.add(log_source)
        db.session.commit()

    logs = []

    if host.os_type == 'LINUX':
        ssh_user = current_app.config.get("SSH_DEFAULT_USER", "siem-admin")
        ssh_port = current_app.config.get("SSH_DEFAULT_PORT", 2222)
        ssh_key = current_app.config.get("SSH_KEY_FILE") or None
        ssh_password = current_app.config.get("SSH_PWD")

        try:
            with RemoteClient(host=host.ip_address, user=ssh_user, port=ssh_port,
                               password=ssh_password, key_file=ssh_key) as remote:
                logs = LogCollector.get_linux_logs(remote, last_fetch_time=log_source.last_fetch)
        except Exception as e:
            return jsonify({"error": f"SSH error: {str(e)}"}), 500

    elif host.os_type == 'WINDOWS':
        try:
            with WinClient() as win:
                logs = LogCollector.get_windows_logs(win, last_fetch_time=log_source.last_fetch)
        except Exception as e:
            return jsonify({"error": f"Windows collection error: {str(e)}"}), 500

    if not logs:
        return jsonify({"message": "No new logs", "alerts": 0}), 200

    try:
        filename, count = DataManager.save_logs_to_parquet(logs, host.id)
    except Exception as e:
        return jsonify({"error": f"Storage error: {str(e)}"}), 500

    log_source.last_fetch = datetime.now()
    archive = LogArchive(host_id=host.id, filename=filename, record_count=count)
    db.session.add(archive)
    db.session.commit()

    alerts_count = LogAnalyzer.analyze_parquet(filename, host.id)

    return jsonify({
        "message": f"Collected {count} log entries",
        "file": filename,
        "alerts": alerts_count,
    }), 200


# ------------------------------------------------------------------
# Threat Intelligence IP registry
# ------------------------------------------------------------------

@api_bp.route("/ips", methods=["GET"])
@login_required
def get_ips():
    ips = IPRegistry.query.order_by(IPRegistry.last_seen.desc()).all()
    return jsonify([{
        'id': ip.id,
        'ip_address': ip.ip_address,
        'status': ip.status,
        'last_seen': ip.last_seen.strftime('%Y-%m-%d %H:%M:%S'),
    } for ip in ips])


@api_bp.route("/ips", methods=["POST"])
@login_required
def add_ip():
    data = request.get_json()
    if not data or 'ip_address' not in data:
        return jsonify({"error": "IP address is required"}), 400

    if IPRegistry.query.filter_by(ip_address=data['ip_address']).first():
        return jsonify({"error": "IP address already exists"}), 409

    new_ip = IPRegistry(
        ip_address=data['ip_address'],
        status=data.get('status', 'UNKNOWN'),
    )
    db.session.add(new_ip)
    db.session.commit()
    return jsonify({"message": "IP address added", "id": new_ip.id}), 201


@api_bp.route("/ips/<int:ip_id>", methods=["PUT"])
@login_required
def update_ip(ip_id):
    ip_entry = IPRegistry.query.get_or_404(ip_id)
    data = request.get_json()

    if 'status' in data:
        ip_entry.status = data['status']

    db.session.commit()
    return jsonify({"message": "IP status updated"}), 200


@api_bp.route("/ips/<int:ip_id>", methods=["DELETE"])
@login_required
def delete_ip(ip_id):
    ip_entry = IPRegistry.query.get_or_404(ip_id)
    db.session.delete(ip_entry)
    db.session.commit()
    return jsonify({"message": "IP address removed"}), 200


@api_bp.route("/alerts", methods=["GET"])
@login_required
def get_recent_alerts():
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(20).all()
    return jsonify([a.to_dict() for a in alerts])
