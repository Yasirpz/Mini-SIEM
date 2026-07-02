from flask import Blueprint, render_template
from flask_login import login_required

ui_bp = Blueprint('ui', __name__)


@ui_bp.route('/')
@login_required
def index():
    """Monitoring dashboard: host status + recent alerts."""
    return render_template('index.html')


@ui_bp.route('/config')
@login_required
def config():
    """Administration panel: host management + Threat Intel IP registry."""
    return render_template('config.html')
