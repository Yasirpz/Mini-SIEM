"""
Create (or update) an administrator account for Mini-SIEM.

Usage:
    python scripts/create_admin.py                    # prompts for both fields
    python scripts/create_admin.py --username admin   # prompts for the password
    python scripts/create_admin.py --list             # show existing accounts

Passwords are hashed with Werkzeug before being stored — nothing is ever
saved in plain text. The password prompt is hidden as you type.

Avoid passing a password on the command line: it would end up in your shell
history. The prompt is the safe path.
"""
import argparse
import getpass
import sys
from pathlib import Path

# Make the project root importable when running this script directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from app.extensions import db
from app.models import User

MIN_PASSWORD_LENGTH = 8


def list_accounts():
    users = User.query.order_by(User.username).all()
    if not users:
        print('No administrator accounts exist yet.')
        return

    print(f"{len(users)} administrator account(s):")
    for user in users:
        created = user.created_at.strftime('%Y-%m-%d') if user.created_at else 'unknown'
        print(f"  - {user.username}  (created {created})")


def prompt_password():
    """Ask for a password twice and check it meets the minimum length."""
    password = getpass.getpass('Admin password: ')
    confirm = getpass.getpass('Confirm password: ')

    if password != confirm:
        print('Passwords do not match.')
        return None
    if len(password) < MIN_PASSWORD_LENGTH:
        print(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        return None
    return password


def main():
    parser = argparse.ArgumentParser(
        description='Create or update a Mini-SIEM administrator account.')
    parser.add_argument('--username', help='account name (prompted for if omitted)')
    parser.add_argument('--list', action='store_true', help='list existing accounts and exit')
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        if args.list:
            list_accounts()
            return 0

        username = (args.username or input('Admin username: ')).strip()
        if not username:
            print('Username cannot be empty.')
            return 1

        password = prompt_password()
        if password is None:
            return 1

        user = User.query.filter_by(username=username).first()
        if user:
            user.set_password(password)
            db.session.commit()
            print(f"Password updated for existing user '{username}'.")
        else:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            print(f"Admin user '{username}' created.")

        print('You can now log in at http://127.0.0.1:5000/login')
    return 0


if __name__ == '__main__':
    sys.exit(main())
