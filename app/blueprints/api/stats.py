"""
Dashboard Module API: summary statistics and chart data (FR-08).

Feeds the stat cards and the two Chart.js charts on the dashboard.
"""
from collections import Counter
from datetime import timedelta

from flask import jsonify, request
from flask_login import login_required
from sqlalchemy import func

from app.blueprints.api import api_bp
from app.extensions import db
from app.models import (
    Alert,
    Event,
    Host,
    IPRegistry,
    EVT_SUCCESSFUL_LOGIN,
    FAILURE_EVENT_TYPES,
    HOST_DEGRADED,
    HOST_OFFLINE,
    HOST_ONLINE,
    HOST_UNKNOWN,
    IP_BANNED,
    SEVERITIES,
    SEVERITY_HIGH,
    USB_AUDIT_UNKNOWN,
    utcnow,
)

RULE_NAMES = {
    'R-01': 'Failed Login',
    'R-02': 'Invalid User',
    'R-03': 'Threat IP Match',
    'R-04': 'Multiple Host Attempt',
    'R-05': 'Audit Log Cleared',
    'R-06': 'Account Created/Deleted',
    'R-07': 'Privilege Change',
    'R-08': 'Account Lockout',
    'R-09': 'External Device Connected',
}


@api_bp.route('/stats/summary', methods=['GET'])
@login_required
def stats_summary():
    """Headline counts for the dashboard stat cards."""
    day_ago = utcnow() - timedelta(hours=24)

    hosts = Host.query.all()
    by_status = Counter(host.health() for host in hosts)

    return jsonify({
        'hosts': len(hosts),
        # Health comes from real collection outcomes, so these counts reflect
        # what the system has actually observed rather than what is configured.
        'hosts_online': by_status.get(HOST_ONLINE, 0),
        'hosts_degraded': by_status.get(HOST_DEGRADED, 0),
        'hosts_offline': by_status.get(HOST_OFFLINE, 0),
        'hosts_unknown': by_status.get(HOST_UNKNOWN, 0),
        'events': Event.query.count(),
        'events_24h': Event.query.filter(Event.timestamp >= day_ago).count(),
        'failed_logins': Event.query.filter(
            Event.event_type.in_(FAILURE_EVENT_TYPES)
        ).count(),
        'successful_logins': Event.query.filter(
            Event.event_type == EVT_SUCCESSFUL_LOGIN
        ).count(),
        'alerts': Alert.query.count(),
        'high_alerts': Alert.query.filter_by(severity=SEVERITY_HIGH).count(),
        'unacknowledged': Alert.query.filter_by(acknowledged=False).count(),
        'alerts_24h': Alert.query.filter(Alert.timestamp >= day_ago).count(),
        'threat_ips': IPRegistry.query.count(),
        'banned_ips': IPRegistry.query.filter_by(status=IP_BANNED).count(),
    })


@api_bp.route('/stats/hosts', methods=['GET'])
@login_required
def stats_hosts():
    """Per-host event and alert counts, for the events-by-host chart."""
    hosts = Host.query.order_by(Host.hostname.asc()).all()
    return jsonify([
        {
            'hostname': host.hostname,
            'status': host.health(),
            'os_type': host.os_type,
            'collection_method': host.effective_collection_method(),
            'events': host.events.count(),
            'alerts': host.alerts.count(),
            # Whether this host can report USB devices at all. Read from the
            # last probe rather than measured here, so a dashboard refresh
            # never pays for a per-host auditpol call.
            'usb_audit_status': host.usb_audit_status or USB_AUDIT_UNKNOWN,
            'last_success': host.last_success.strftime('%Y-%m-%d %H:%M:%S')
            if host.last_success else None,
        }
        for host in hosts
    ])


@api_bp.route('/stats/severity', methods=['GET'])
@login_required
def stats_severity():
    """Alert counts grouped by severity — drives the doughnut chart."""
    rows = dict(
        db.session.query(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
        .all()
    )
    return jsonify({
        'labels': list(SEVERITIES),
        'counts': [rows.get(level, 0) for level in SEVERITIES],
    })


@api_bp.route('/stats/rules', methods=['GET'])
@login_required
def stats_rules():
    """Alert counts grouped by detection rule."""
    rows = dict(
        db.session.query(Alert.rule_id, func.count(Alert.id))
        .group_by(Alert.rule_id)
        .all()
    )
    rule_ids = sorted(RULE_NAMES)
    return jsonify({
        'labels': [f"{rid} {RULE_NAMES[rid]}" for rid in rule_ids],
        'counts': [rows.get(rid, 0) for rid in rule_ids],
    })


@api_bp.route('/stats/timeline', methods=['GET'])
@login_required
def stats_timeline():
    """
    Authentication failures per day — drives the failed-login trend chart.

    Days with no activity are filled in with zero so the line chart shows a
    continuous axis rather than skipping empty dates.
    """
    days = min(max(request.args.get('days', 7, type=int), 1), 90)
    start = (utcnow() - timedelta(days=days - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0
    )

    rows = (
        db.session.query(
            func.date(Event.timestamp).label('day'),
            func.count(Event.id),
        )
        .filter(Event.timestamp >= start)
        .filter(Event.event_type.in_(FAILURE_EVENT_TYPES))
        .group_by('day')
        .all()
    )
    counts_by_day = {str(day): count for day, count in rows}

    labels = []
    counts = []
    for offset in range(days):
        day = (start + timedelta(days=offset)).date()
        labels.append(day.isoformat())
        counts.append(counts_by_day.get(day.isoformat(), 0))

    return jsonify({'labels': labels, 'counts': counts})


@api_bp.route('/stats/top-sources', methods=['GET'])
@login_required
def stats_top_sources():
    """The busiest attacking source IPs, with their registry status."""
    limit = min(max(request.args.get('limit', 5, type=int), 1), 25)

    rows = (
        db.session.query(Event.source_ip, func.count(Event.id).label('hits'))
        .filter(Event.event_type.in_(FAILURE_EVENT_TYPES))
        .filter(Event.source_ip.isnot(None))
        .filter(~Event.source_ip.in_(('LOCAL', 'LOCAL_CONSOLE')))
        .group_by(Event.source_ip)
        .order_by(func.count(Event.id).desc())
        .limit(limit)
        .all()
    )

    statuses = dict(
        db.session.query(IPRegistry.ip_address, IPRegistry.status)
        .filter(IPRegistry.ip_address.in_([ip for ip, _ in rows]))
        .all()
    ) if rows else {}

    return jsonify([
        {'source_ip': ip, 'hits': hits, 'status': statuses.get(ip, 'UNKNOWN')}
        for ip, hits in rows
    ])
