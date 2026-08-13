"""Authentication Module: administrator login and logout (FR-01)."""
from urllib.parse import urlparse

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.forms import LoginForm
from app.models import User

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('ui.index'))

    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Logged in successfully.', 'success')
            return redirect(_safe_next() or url_for('ui.index'))

        # Deliberately generic: never reveal whether the username or the
        # password was the incorrect part.
        flash('Login failed. Check your username and password.', 'danger')

    return render_template('login.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))


def _safe_next():
    """
    Return the ?next= target only when it is a path on this site.

    Rejecting absolute URLs stops the login form being used as an open
    redirect into an attacker-controlled domain.
    """
    target = request.args.get('next')
    if not target:
        return None

    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith('/'):
        return None
    return target
