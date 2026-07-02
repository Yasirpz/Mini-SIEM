"""
Create (or update) an administrator account for Mini-SIEM.

Usage:
    python scripts/create_admin.py

You will be prompted for a username and password. Passwords are hashed
before being stored — nothing is ever saved in plain text.
"""
import getpass
import sys
from pathlib import Path

# Make the project root importable when running this script directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import create_app
from app.extensions import db
from app.models import User


def main():
    app = create_app()
    with app.app_context():
        username = input("Admin username: ").strip()
        if not username:
            print("Username cannot be empty.")
            return

        password = getpass.getpass("Admin password: ")
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.")
            return
        if len(password) < 6:
            print("Password should be at least 6 characters.")
            return

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


if __name__ == "__main__":
    main()
