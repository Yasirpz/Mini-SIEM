from flask import Flask, jsonify, request

from config import Config

from .extensions import csrf, db, login_manager, migrate


def create_app(config_class=Config):
    """Application factory for the Mini-SIEM Flask app."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    login_manager.init_app(app)

    # LoginManager configuration
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    @login_manager.unauthorized_handler
    def unauthorized():
        """
        Answer unauthenticated API calls with 401 JSON instead of an HTML
        redirect, so the front end can report the problem properly (FR-02).
        """
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Authentication required'}), 401
        from flask import flash, redirect, url_for

        flash(login_manager.login_message, login_manager.login_message_category)
        return redirect(url_for('auth.login', next=request.path))

    # Register blueprints
    from .blueprints.api import api_bp
    from .blueprints.auth import auth_bp
    from .blueprints.ui import ui_bp

    app.register_blueprint(ui_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp, url_prefix='/api')

    _register_error_handlers(app)

    # Make sure the instance folder exists before SQLite tries to open the
    # database file inside it.
    _ensure_folders(app)

    # Auto-create tables for local/demo use (use Flask-Migrate for production)
    with app.app_context():
        db.create_all()

    return app


def _ensure_folders(app):
    """Create the instance, storage and samples folders if they are missing."""
    from pathlib import Path

    Path(app.instance_path).mkdir(parents=True, exist_ok=True)

    for key in ('STORAGE_FOLDER', 'SAMPLES_FOLDER'):
        folder = app.config.get(key)
        if folder:
            Path(folder).mkdir(parents=True, exist_ok=True)


def _register_error_handlers(app):
    """Return JSON for API errors and HTML pages for everything else."""

    def wants_json():
        return request.path.startswith('/api/')

    @app.errorhandler(404)
    def not_found(error):
        if wants_json():
            return jsonify({'error': 'Not found'}), 404
        from flask import render_template

        return render_template('error.html', code=404,
                               message='Page not found.'), 404

    @app.errorhandler(413)
    def too_large(error):
        limit = app.config.get('MAX_CONTENT_LENGTH', 0) // (1024 * 1024)
        return jsonify({'error': f"Uploaded file is too large (limit {limit} MB)"}), 413

    @app.errorhandler(500)
    def server_error(error):
        db.session.rollback()
        if wants_json():
            return jsonify({'error': 'Internal server error'}), 500
        from flask import render_template

        return render_template('error.html', code=500,
                               message='Something went wrong on the server.'), 500
