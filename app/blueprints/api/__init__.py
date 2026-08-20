"""
JSON API blueprint.

All routes are mounted under /api and require an authenticated session
(FR-02). The route modules are imported for their side effect of registering
handlers on the shared blueprint.
"""
from flask import Blueprint, jsonify

from app.validators import ValidationError

api_bp = Blueprint('api', __name__)


@api_bp.errorhandler(ValidationError)
def handle_validation_error(error):
    """Turn a validation failure into a 400 with a readable message."""
    return jsonify({'error': str(error)}), 400


from . import (  # noqa: E402,F401
    hosts, threat_intel, events, alerts, stats, scheduler, integrity,
)
