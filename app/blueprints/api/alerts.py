"""Alert Module API: listing, filtering and acknowledging alerts (FR-07)."""
from flask import jsonify, request
from flask_login import login_required

from app.blueprints.api import api_bp
from app.extensions import db
from app.models import Alert, SEVERITIES
from app.validators import ValidationError

MAX_PAGE_SIZE = 200


@api_bp.route('/alerts', methods=['GET'])
@login_required
def get_alerts():
    """
    List alerts, newest first.

    Supported filters: severity, host_id, rule_id, source_ip and acknowledged.
    """
    query = Alert.query

    severity = request.args.get('severity')
    if severity:
        severity = severity.upper()
        if severity not in SEVERITIES:
            raise ValidationError(f"severity must be one of {', '.join(SEVERITIES)}")
        query = query.filter(Alert.severity == severity)

    host_id = request.args.get('host_id', type=int)
    if host_id:
        query = query.filter(Alert.host_id == host_id)

    rule_id = request.args.get('rule_id')
    if rule_id:
        query = query.filter(Alert.rule_id == rule_id.upper())

    source_ip = request.args.get('source_ip')
    if source_ip:
        query = query.filter(Alert.source_ip == source_ip)

    acknowledged = request.args.get('acknowledged')
    if acknowledged is not None and acknowledged != '':
        query = query.filter(Alert.acknowledged == (acknowledged.lower() == 'true'))

    limit = min(request.args.get('limit', 20, type=int), MAX_PAGE_SIZE)
    offset = max(request.args.get('offset', 0, type=int), 0)

    total = query.count()
    alerts = query.order_by(Alert.timestamp.desc(), Alert.id.desc()) \
                  .offset(offset).limit(limit).all()

    payload = [alert.to_dict() for alert in alerts]

    # The dashboard consumes a bare list; the alerts page asks for the
    # paginated envelope by passing ?paginated=true.
    if request.args.get('paginated', '').lower() == 'true':
        return jsonify({
            'total': total,
            'limit': limit,
            'offset': offset,
            'alerts': payload,
        })

    return jsonify(payload)


@api_bp.route('/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@login_required
def acknowledge_alert(alert_id):
    """Mark an alert as reviewed, or clear that flag."""
    alert = Alert.query.get_or_404(alert_id)
    data = request.get_json(silent=True) or {}

    alert.acknowledged = bool(data.get('acknowledged', True))
    db.session.commit()
    return jsonify(alert.to_dict()), 200


@api_bp.route('/alerts/<int:alert_id>', methods=['DELETE'])
@login_required
def delete_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    db.session.delete(alert)
    db.session.commit()
    return jsonify({'message': 'Alert removed'}), 200
