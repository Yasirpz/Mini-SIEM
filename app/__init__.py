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
        _add_missing_columns()

    return app


def _add_missing_columns():
    """
    Add columns that were introduced after a database was first created.

    db.create_all() only creates missing *tables*; it will not alter one that
    already exists. Without this, upgrading an existing installation leaves
    the schema behind the models and every query fails with "no such column".

    Deliberately narrow: it only ever adds nullable columns, never drops or
    rewrites anything, and is safe to run on every start. A production
    deployment should use Flask-Migrate instead.
    """
    from sqlalchemy import inspect, text

    additions = {
        'hosts': {
            'collection_method': 'VARCHAR(20)',
            'remote_user': 'VARCHAR(100)',
            'last_attempt': 'DATETIME',
            'last_success': 'DATETIME',
            'last_error': 'VARCHAR(500)',
            'last_latency_ms': 'INTEGER',
            'usb_audit_status': 'VARCHAR(20)',
        },
        'events': {
            'device_name': 'VARCHAR(200)',
        },
    }

    inspector = inspect(db.engine)

    for table, columns in additions.items():
        if not inspector.has_table(table):
            continue

        existing = {col['name'] for col in inspector.get_columns(table)}

        for name, column_type in columns.items():
            if name in existing:
                continue
            db.session.execute(
                text(f'ALTER TABLE {table} ADD COLUMN {name} {column_type}')
            )
            db.session.commit()


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
