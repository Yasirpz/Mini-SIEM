"""File Integrity Monitoring API: watched paths, baselines and scanning."""
import logging

from flask import jsonify, request
from flask_login import login_required

from app.blueprints.api import api_bp
from app.extensions import db
from app.models import FileBaseline, Host, WatchedPath
from app.services.file_integrity import scan_host
from app.validators import (
    MAX_DESCRIPTION_LENGTH,
    validate_bool,
    validate_text,
    validate_watched_path,
)

log = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Watched paths
# ------------------------------------------------------------------

@api_bp.route('/hosts/<int:host_id>/watched-paths', methods=['GET'])
@login_required
def get_watched_paths(host_id):
    host = Host.query.get_or_404(host_id)
    paths = WatchedPath.query.filter_by(host_id=host.id).order_by(
        WatchedPath.path.asc()
    ).all()
    return jsonify([p.to_dict() for p in paths]), 200


@api_bp.route('/hosts/<int:host_id>/watched-paths', methods=['POST'])
@login_required
def add_watched_path(host_id):
    host = Host.query.get_or_404(host_id)
    data = request.get_json(silent=True) or {}

    path = validate_watched_path(data.get('path'))

    if WatchedPath.query.filter_by(host_id=host.id, path=path).first():
        return jsonify({'error': f'{path} is already being watched on this host'}), 409

    entry = WatchedPath(
        host_id=host.id,
        path=path,
        recursive=validate_bool(data.get('recursive', False), 'recursive'),
        description=validate_text(
            data.get('description'), 'description', MAX_DESCRIPTION_LENGTH
        ),
    )
    db.session.add(entry)
    db.session.commit()
    return jsonify(entry.to_dict()), 201


@api_bp.route('/watched-paths/<int:path_id>', methods=['DELETE'])
@login_required
def remove_watched_path(path_id):
    """
    Stop watching a path.

    The baselines recorded underneath it go too. Keeping them would leave rows
    describing files nothing is checking any more, and the next scan of a
    re-added path would compare against a baseline of unknown age — worse than
    honestly starting again.
    """
    entry = WatchedPath.query.get_or_404(path_id)

    removed = FileBaseline.query.filter_by(
        host_id=entry.host_id, watched_path_id=entry.id
    ).delete()

    db.session.delete(entry)
    db.session.commit()

    return jsonify({
        'message': f'Stopped watching {entry.path}',
        'baselines_removed': removed,
    }), 200


# ------------------------------------------------------------------
# Baselines
# ------------------------------------------------------------------

@api_bp.route('/hosts/<int:host_id>/baselines', methods=['GET'])
@login_required
def get_baselines(host_id):
    """
    The recorded state of every watched file on a host.

    This is the evidence behind an R-10 alert: an operator who is told a file
    changed should be able to see the hash it is being compared against, and
    when that hash was first recorded.
    """
    host = Host.query.get_or_404(host_id)

    try:
        limit = min(int(request.args.get('limit', 100)), 500)
    except (TypeError, ValueError):
        limit = 100

    rows = FileBaseline.query.filter_by(host_id=host.id).order_by(
        FileBaseline.last_changed.desc().nullslast(),
        FileBaseline.path.asc(),
    ).limit(limit).all()

    return jsonify({
        'host_id': host.id,
        'total': FileBaseline.query.filter_by(host_id=host.id).count(),
        'baselines': [row.to_dict() for row in rows],
    }), 200


@api_bp.route('/hosts/<int:host_id>/baselines', methods=['DELETE'])
@login_required
def reset_baseline(host_id):
    """
    Discard a host's baseline so the next scan records a fresh one.

    Needed after a legitimate change — a software update rewrites hundreds of
    files, and without this the operator's only options would be to
    acknowledge hundreds of alerts or stop watching the path. Deliberately
    explicit, never automatic: a system that quietly re-baselines after
    reporting a change would erase exactly the evidence it exists to keep.
    """
    host = Host.query.get_or_404(host_id)
    removed = FileBaseline.query.filter_by(host_id=host.id).delete()
    host.last_integrity_scan = None
    db.session.commit()

    log.info('Integrity baseline reset for %s (%s rows)', host.hostname, removed)
    return jsonify({
        'message': (
            f'Baseline cleared for {host.hostname}. The next scan will record '
            'a new one and report nothing.'
        ),
        'baselines_removed': removed,
    }), 200


# ------------------------------------------------------------------
# Scanning
# ------------------------------------------------------------------

@api_bp.route('/hosts/<int:host_id>/integrity-scan', methods=['POST'])
@login_required
def run_integrity_scan(host_id):
    """Hash every watched file on a host and report what changed."""
    host = Host.query.get_or_404(host_id)
    payload, status = scan_host(host)
    return jsonify(payload), status
