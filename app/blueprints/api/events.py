"""
Log Analysis Module API: browsing stored events and importing sample logs.

Covers FR-05 (sample log/event input for testing and demonstration) and the
event half of FR-06.
"""
from flask import current_app, jsonify, request
from flask_login import login_required

from app.blueprints.api import api_bp
from app.extensions import db
from app.models import Event, Host
from app.services.detection import DetectionEngine
from app.services.log_analyzer import LogAnalyzer
from app.services.sample_loader import SampleLoader

MAX_PAGE_SIZE = 200


@api_bp.route('/events', methods=['GET'])
@login_required
def get_events():
    """List stored events, newest first, with optional filters."""
    query = Event.query

    host_id = request.args.get('host_id', type=int)
    if host_id:
        query = query.filter(Event.host_id == host_id)

    event_type = request.args.get('event_type')
    if event_type:
        query = query.filter(Event.event_type == event_type.upper())

    source_ip = request.args.get('source_ip')
    if source_ip:
        query = query.filter(Event.source_ip == source_ip)

    limit = min(request.args.get('limit', 50, type=int), MAX_PAGE_SIZE)
    offset = max(request.args.get('offset', 0, type=int), 0)

    total = query.count()
    events = query.order_by(Event.timestamp.desc()).offset(offset).limit(limit).all()

    return jsonify({
        'total': total,
        'limit': limit,
        'offset': offset,
        'events': [event.to_dict() for event in events],
    })


@api_bp.route('/events/import', methods=['POST'])
@login_required
def import_events():
    """
    Import sample log data for a host.

    Accepts three input modes:
      * multipart file upload  — field ``file`` plus ``host_id``
      * JSON {host_id, content}       — pasted raw log text
      * JSON {host_id, generate: true} — built-in synthetic generator

    Whatever the input, the parsed events go through the same pipeline the
    live collectors use, so the resulting alerts are identical.
    """
    if request.files.get('file'):
        upload = request.files['file']
        host_id = request.form.get('host_id', type=int)
        raw = upload.read()
        source_name = upload.filename or 'upload'
    else:
        data = request.get_json(silent=True) or {}
        host_id = data.get('host_id')
        if data.get('generate'):
            return _import_synthetic(host_id, data)
        raw = data.get('content') or ''
        source_name = data.get('filename', 'pasted-input')

    host = _require_host(host_id)
    if isinstance(host, tuple):
        return host

    events, detected_format = SampleLoader.parse(raw, filename=source_name)
    if not events:
        return jsonify({
            'error': 'No recognisable security events were found in that input',
            'format': detected_format,
        }), 400

    result = LogAnalyzer.ingest(events, host.id, origin='IMPORTED')
    result['format'] = detected_format
    result['source'] = source_name
    result['message'] = (
        f"Parsed {len(events)} events from {source_name} ({detected_format}); "
        f"stored {result['events_stored']} new, "
        f"skipped {result['duplicates_skipped']} duplicate(s)."
    )
    return jsonify(result), 200


@api_bp.route('/events/samples', methods=['GET'])
@login_required
def list_samples():
    """List the sample log files shipped with the project (D-05)."""
    folder = current_app.config.get('SAMPLES_FOLDER')
    if not folder or not folder.exists():
        return jsonify([])

    files = [
        {'name': path.name, 'size': path.stat().st_size}
        for path in sorted(folder.iterdir())
        if path.is_file() and path.suffix.lower() in ('.log', '.csv', '.json')
    ]
    return jsonify(files)


@api_bp.route('/events/samples/<path:name>', methods=['POST'])
@login_required
def import_bundled_sample(name):
    """Import one of the bundled sample files by name."""
    folder = current_app.config.get('SAMPLES_FOLDER')
    if not folder:
        return jsonify({'error': 'Sample folder is not configured'}), 500

    # Resolve and confirm the path stays inside the samples folder, so a
    # crafted name like ../../config.py cannot read arbitrary files.
    target = (folder / name).resolve()
    try:
        target.relative_to(folder.resolve())
    except ValueError:
        return jsonify({'error': 'Invalid sample name'}), 400

    if not target.is_file():
        return jsonify({'error': f"Sample '{name}' not found"}), 404

    data = request.get_json(silent=True) or {}
    host = _require_host(data.get('host_id'))
    if isinstance(host, tuple):
        return host

    events, detected_format = SampleLoader.parse(
        target.read_text(encoding='utf-8', errors='replace'), filename=target.name
    )
    if not events:
        return jsonify({'error': f"No events could be parsed from {name}"}), 400

    result = LogAnalyzer.ingest(events, host.id, origin='IMPORTED')
    result['format'] = detected_format
    result['source'] = target.name
    result['message'] = (
        f"Imported {result['events_stored']} new events from {target.name}; "
        f"{result['alerts']['total']} alert(s) raised."
    )
    return jsonify(result), 200


@api_bp.route('/detection/run', methods=['POST'])
@login_required
def run_detection():
    """
    Re-apply the detection rules to events already in the database.

    This is what makes the threat-registry demonstration work: import logs,
    mark a source IP as BANNED, re-run, and watch R-03 escalate the severity
    without re-collecting anything.
    """
    data = request.get_json(silent=True) or {}
    host_id = data.get('host_id')

    if host_id:
        host = _require_host(host_id)
        if isinstance(host, tuple):
            return host
        host_id = host.id

    alerts = DetectionEngine.run(host_id=host_id)
    return jsonify({
        'message': f"Detection complete: {alerts['total']} new alert(s).",
        'alerts': alerts,
    }), 200


@api_bp.route('/events', methods=['DELETE'])
@login_required
def clear_events():
    """Delete stored events (and their alerts). Used to reset a demonstration."""
    host_id = request.args.get('host_id', type=int)

    query = Event.query
    if host_id:
        query = query.filter(Event.host_id == host_id)

    removed = query.count()
    # Deleting through the ORM lets the Alert cascade fire.
    for event in query.all():
        db.session.delete(event)
    db.session.commit()

    return jsonify({'message': f"Removed {removed} event(s)", 'removed': removed}), 200


def _import_synthetic(host_id, data):
    """Generate a synthetic failed-login burst and run it through the pipeline."""
    host = _require_host(host_id)
    if isinstance(host, tuple):
        return host

    events = SampleLoader.generate_synthetic(
        source_ip=data.get('source_ip', '203.0.113.50'),
        attempts=int(data.get('attempts', 8)),
    )
    result = LogAnalyzer.ingest(events, host.id, origin='SYNTHETIC')
    result['format'] = 'synthetic'
    result['source'] = 'built-in generator'
    result['message'] = (
        f"Generated {len(events)} synthetic events; "
        f"stored {result['events_stored']} new, "
        f"{result['alerts']['total']} alert(s) raised."
    )
    return jsonify(result), 200


def _require_host(host_id):
    """Resolve a host id, or return a JSON error response tuple."""
    if not host_id:
        return jsonify({'error': 'host_id is required'}), 400

    host = Host.query.get(host_id)
    if not host:
        return jsonify({'error': f"No host with id {host_id}"}), 404
    return host
