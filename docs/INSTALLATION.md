# Installation Guide

Mini-SIEM — FYCP/2K26/109
IMCS, University of Sindh, Jamshoro

This guide covers installing and running Mini-SIEM on a local Windows or
Linux development machine, as described in the project's non-functional
requirement for portability.

## 1. Prerequisites

- Python 3.10 or newer
- pip
- Git

## 2. Clone the repository

```bash
git clone https://github.com/<your-username>/mini-siem.git
cd mini-siem
```

## 3. Create a virtual environment

```bash
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

## 4. Install dependencies

```bash
pip install -r requirements.txt
```

## 5. Configure environment variables

Copy the example file and edit it:

```bash
cp .env.example .env
```

Set at least `SECRET_KEY` to a random string. The default
`SQLALCHEMY_DATABASE_URI` stores the database at `instance/mini_siem.db`,
which is fine for local/demo use.

The `SSH_*` variables are only required if you want to enable live log
collection from a real Linux host over SSH. They can be left blank if you
plan to demonstrate the system using the sample data seed script instead.

## 6. Initialize the database

```bash
flask shell
```
```python
>>> from app.extensions import db
>>> db.create_all()
>>> exit()
```

## 7. Create an administrator account

```bash
python scripts/create_admin.py
```

You will be prompted for a username and password. Passwords are hashed with
`werkzeug.security` before being stored — nothing is saved in plain text.

## 8. (Optional) Load sample data for a demo

This adds a sample host, a suspicious test IP address
(`203.0.113.50`, a reserved documentation address), and generates alerts
from synthetic failed-login events — useful for a self-contained
demonstration that doesn't require a real Linux/Windows target machine.

```bash
python scripts/seed_sample_data.py
```

## 9. Run the application

```bash
flask run
```

Open `http://127.0.0.1:5000` in a browser and log in with the account
created in step 7.

## 10. Stopping / resetting

To reset the local database during testing, stop the server and delete
`instance/mini_siem.db`, then repeat steps 6–8.
