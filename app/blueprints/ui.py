"""Server-rendered pages. Every page requires an authenticated session (FR-02)."""
from flask import Blueprint, render_template
from flask_login import login_required

ui_bp = Blueprint('ui', __name__)


@ui_bp.route('/')
@login_required
def index():
    """Monitoring dashboard: summary statistics, charts and recent alerts."""
    return render_template('index.html')


@ui_bp.route('/alerts')
@login_required
def alerts():
    """Alert Module: full alert table with severity and rule filtering."""
    return render_template('alerts.html')


@ui_bp.route('/events')
@login_required
def events():
    """Log Analysis Module: browse stored events and import sample logs."""
    return render_template('events.html')


@ui_bp.route('/config')
@login_required
def config():
    """Administration panel: host management and the Threat Intel registry."""
    return render_template('config.html')
