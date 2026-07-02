import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Application configuration for the Mini-SIEM Flask app.

    Values are read from environment variables (see .env.example) so that
    secrets are never committed to the repository.
    """

    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-me')

    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'SQLALCHEMY_DATABASE_URI', 'sqlite:///../instance/mini_siem.db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # SSH configuration (used for optional live Linux log collection)
    SSH_DEFAULT_HOST = os.getenv('SSH_DEFAULT_HOST', '127.0.0.1')
    SSH_DEFAULT_USER = os.getenv('SSH_DEFAULT_USER', 'siem-admin')
    SSH_DEFAULT_PORT = int(os.getenv('SSH_DEFAULT_PORT', 2222))
    SSH_KEY_FILE = os.getenv('SSH_KEY_FILE', '')
    SSH_PWD = os.getenv('SSH_PASSWORD', '')

    # Folder used to store raw collected logs (Parquet) for forensic retention
    STORAGE_FOLDER = Path.cwd() / 'storage'
