"""Threat Intelligence Module API: the suspicious IP registry (FR-04)."""
from flask import jsonify, request
from flask_login import login_required

from app.blueprints.api import api_bp
from app.extensions import db
from app.models import IPRegistry, utcnow
from app.validators import (
    MAX_NOTE_LENGTH,
    validate_ip,
    validate_ip_status,
    validate_text,
)


@api_bp.route('/ips', methods=['GET'])
@login_required
def get_ips():
    status = request.args.get('status')

    query = IPRegistry.query
    if status:
        query = query.filter_by(status=validate_ip_status(status))

    entries = query.order_by(IPRegistry.last_seen.desc()).all()
    return jsonify([entry.to_dict() for entry in entries])


@api_bp.route('/ips', methods=['POST'])
@login_required
def add_ip():
    data = request.get_json(silent=True) or {}

    ip_address = validate_ip(data.get('ip_address'))
    status = validate_ip_status(data.get('status', 'UNKNOWN'))
    source = validate_text(data.get('source'), 'source', 100) or 'Manual entry'
    notes = validate_text(data.get('notes'), 'notes', MAX_NOTE_LENGTH)

    if IPRegistry.query.filter_by(ip_address=ip_address).first():
        return jsonify({'error': f"{ip_address} is already in the registry"}), 409

    entry = IPRegistry(
        ip_address=ip_address,
        status=status,
        source=source,
        notes=notes,
        date_added=utcnow(),
        last_seen=utcnow(),
    )
    db.session.add(entry)
    db.session.commit()
    return jsonify(entry.to_dict()), 201


@api_bp.route('/ips/<int:ip_id>', methods=['PUT'])
@login_required
def update_ip(ip_id):
    entry = IPRegistry.query.get_or_404(ip_id)
    data = request.get_json(silent=True) or {}

    if 'ip_address' in data:
        ip_address = validate_ip(data['ip_address'])
        clash = IPRegistry.query.filter(
            IPRegistry.ip_address == ip_address, IPRegistry.id != entry.id
        ).first()
        if clash:
            return jsonify({'error': f"{ip_address} is already in the registry"}), 409
        entry.ip_address = ip_address

    if 'status' in data:
        entry.status = validate_ip_status(data['status'])

    if 'source' in data:
        entry.source = validate_text(data['source'], 'source', 100)

    if 'notes' in data:
        entry.notes = validate_text(data['notes'], 'notes', MAX_NOTE_LENGTH)

    db.session.commit()
    return jsonify(entry.to_dict()), 200


@api_bp.route('/ips/<int:ip_id>', methods=['DELETE'])
@login_required
def delete_ip(ip_id):
    entry = IPRegistry.query.get_or_404(ip_id)
    db.session.delete(entry)
    db.session.commit()
    return jsonify({'message': 'IP address removed'}), 200
