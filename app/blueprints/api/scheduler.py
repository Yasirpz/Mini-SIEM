"""Automatic collection: status and manual control of the background poller."""
from flask import current_app, jsonify
from flask_login import login_required

from app.blueprints.api import api_bp
from app.services.scheduler import get_scheduler


@api_bp.route('/scheduler', methods=['GET'])
@login_required
def scheduler_status():
    """
    Report what automatic collection is doing.

    The dashboard polls this so an operator can tell at a glance whether the
    system is collecting on its own, and when the next collection is due. A
    scheduler that has silently died must be visible as such -- that is the
    whole point of reporting `running` rather than assuming it.
    """
    scheduler = get_scheduler(current_app)
    if scheduler is None:
        return jsonify({
            'running': False,
            'enabled': False,
            'detail': 'Automatic collection is not available in this process.',
            'hosts_polled': 0,
            'hosts': [],
        }), 200

    payload = scheduler.status()
    payload['enabled'] = bool(current_app.config.get('SCHEDULER_ENABLED', False))
    if not payload['enabled']:
        payload['detail'] = (
            'Automatic collection is switched off. Set SCHEDULER_ENABLED=true '
            'in .env and restart to enable it.'
        )
    elif payload['hosts_polled'] == 0:
        payload['detail'] = (
            'No host has automatic collection switched on yet. Enable it per '
            'host on the Configuration page.'
        )
    return jsonify(payload), 200


@api_bp.route('/scheduler/run', methods=['POST'])
@login_required
def scheduler_run_now():
    """
    Run one tick immediately, without waiting for the timer.

    Useful when demonstrating the feature, and useful when debugging a host
    that is not producing anything: it separates "the schedule has not come
    round yet" from "the collection itself is failing".

    This runs in the request thread rather than signalling the background one,
    so the caller gets the actual outcome rather than an acknowledgement.
    """
    scheduler = get_scheduler(current_app)
    if scheduler is None:
        return jsonify({'error': 'Automatic collection is not available.'}), 503

    collected = scheduler.run_once()
    return jsonify({
        'message': (
            f"Collected from {len(collected)} host(s): {', '.join(collected)}"
            if collected else
            'No host was due for automatic collection.'
        ),
        'collected': collected,
    }), 200
