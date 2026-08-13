# Installation Guide

Mini-SIEM — FYCP/2K26/109
IMCS, University of Sindh, Jamshoro

This guide covers installing and running Mini-SIEM on a local Windows or
Linux machine, satisfying the project's non-functional requirement for
portability.

## 1. Prerequisites

- Python 3.10 or newer
- pip
- Git

Check your Python version:

```bash
python --version
```

## 2. Get the project

```bash
git clone https://github.com/<your-username>/mini-siem.git
cd mini-siem
```

## 3. Create a virtual environment

```bash
python -m venv venv
```

Activate it:

```bash
venv\Scripts\activate
```

On Linux/macOS use `source venv/bin/activate` instead. Your prompt should
now be prefixed with `(venv)`.

## 4. Install dependencies

```bash
pip install -r requirements.txt
```

## 5. Configure environment variables

Copy the example file:

```bash
copy .env.example .env
```

On Linux/macOS use `cp .env.example .env`.

Open `.env` and set `SECRET_KEY` to your own random value. Generate one with:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

`.env` is git-ignored, so your secret never reaches the repository. Every
other setting has a working default:

| Setting | Purpose | Default |
|---|---|---|
| `SQLALCHEMY_DATABASE_URI` | Database location | `instance/mini_siem.db` |
| `DETECTION_FAILED_LOGIN_THRESHOLD` | Failures needed to trigger R-01 | `5` |
| `DETECTION_FAILED_LOGIN_WINDOW_MINUTES` | R-01 time window | `10` |
| `DETECTION_MULTI_HOST_THRESHOLD` | Hosts needed to trigger R-04 | `2` |
| `SESSION_COOKIE_SECURE` | HTTPS-only session cookie | `false` |
| `MAX_UPLOAD_BYTES` | Sample log upload limit | `2097152` (2 MB) |

The `SSH_*` variables are only needed for live log collection from a real
Linux host. Leave them alone to demonstrate the system using sample data.

## 6. Initialize the database

No manual step is required — the tables are created automatically the first
time the application starts. The database file lands in `instance/`.

## 7. Create an administrator account

```bash
python scripts/create_admin.py
```

You will be prompted for a username and password. The password prompt is
hidden as you type, and the value is hashed with `werkzeug.security` before
storage — nothing is ever saved in plain text. Minimum length is 8
characters.

To list existing accounts:

```bash
python scripts/create_admin.py --list
```

## 8. (Optional) Load the demonstration dataset

This creates two monitored hosts, adds the suspicious test address
`203.0.113.50` to the registry, imports the bundled Linux sample log against
both hosts, and runs the detection engine:

```bash
python scripts/seed_sample_data.py --ban
```

| Flag | Effect |
|---|---|
| *(none)* | Seeds data, leaving `203.0.113.50` as `UNKNOWN` so you can demonstrate R-03 escalation manually. |
| `--ban` | Also marks `203.0.113.50` as `BANNED`, so rule R-03 fires immediately. |
| `--reset` | Deletes existing events and alerts before seeding. |

Importing against two hosts is what makes rule R-04 (Multiple Host Attempt)
fire, since one source IP is then seen attacking two machines.

## 9. Run the application

```bash
flask run
```

Open `http://127.0.0.1:5000` and log in with the account from step 7.

`FLASK_APP` and `FLASK_DEBUG` are already set in `.flaskenv`, so no extra
environment configuration is needed.

## 10. Run the tests

```bash
python -m pytest
```

The suite uses a temporary in-memory database, so it never touches your
`instance/mini_siem.db`.

## 11. Resetting

To clear events and alerts but keep hosts and accounts, use the **Clear
events** button on the Events page, or:

```bash
python scripts/seed_sample_data.py --reset
```

To start completely fresh, stop the server, delete `instance/mini_siem.db`
and the `storage/` folder, then repeat from step 7.

## Notes

- **Internet access.** Bootstrap 5 and Chart.js are loaded from a public CDN
  in `app/templates/base.html`. If you will demonstrate on a machine with no
  internet connection, download those two files into
  `app/static/vendor/` beforehand and update the three `<link>`/`<script>`
  tags to point at them.
- **Live Linux collection** requires an authorized host reachable over SSH
  with a user permitted to run `journalctl`. Only ever point this at a
  machine you own or have written permission to monitor.
- **Live Windows collection** reads the Security event log of the machine
  running Mini-SIEM, and needs an elevated (Administrator) shell to see
  Event ID 4625 records.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `flask: command not found` | The virtual environment is not active. Re-run the activate command from step 3. |
| Login form returns "The CSRF token is missing" | `SECRET_KEY` is unset or changed between restarts. Set it in `.env`. |
| Login succeeds but immediately redirects back | `SESSION_COOKIE_SECURE=true` while serving over plain HTTP. Set it to `false` for local use. |
| Dashboard charts are blank | No events yet, or no internet for the Chart.js CDN. Import a sample log, and check the browser console. |
| `No module named 'app'` when running a script | Run scripts from the project root, e.g. `python scripts/create_admin.py`. |
