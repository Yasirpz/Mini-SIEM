# Mini-SIEM

**A Web-Based Security Event Monitoring and Threat Detection System**

Final Year Project — `FYCP/2K26/109`
Institute of Mathematics & Computer Science (IMCS), University of Sindh, Jamshoro
BS Computer Science

| Role | Name | Roll No. |
|---|---|---|
| Group Leader | Yasir Parveez | 2K23/CSM/146 |
| Group Member | Abdul Fatah | 2K23/CSM/03 |
| Group Member | Mushahid Hussain | 2K23/CSM/100 |
| Supervisor | Mr. Danish Nazir Arain | — |

---

## Overview

Mini-SIEM is a lightweight, educational Security Information and Event
Management (SIEM) prototype. It gives a lab administrator a single web
dashboard to log in securely, manage monitored hosts, maintain a threat
intelligence IP registry, collect or import security events, and review
rule-based alerts for suspicious login activity.

It is intentionally scoped as a defensive, educational subset of what a
commercial SIEM (Splunk, Elastic, Wazuh, etc.) provides — small enough to
build and demonstrate within an FYP timeline, but built on the same core
ideas: log collection, normalization, correlation, and alerting.

## Core Features

- **Secure administrator authentication** — hashed passwords, session-based
  login, CSRF-protected forms.
- **Host management** — add, edit, and remove monitored Linux/Windows hosts.
- **Threat Intelligence IP registry** — track IP addresses as
  `UNKNOWN`, `TRUSTED`, or `BANNED`.
- **Log collection** — pull authentication logs from Linux hosts over SSH
  (`journalctl`) or from Windows hosts via PowerShell (`Get-WinEvent`,
  Event ID 4625), or feed in sample/synthetic events for a controlled demo.
- **Forensic retention** — raw collected events are archived to columnar
  Parquet files before analysis, so evidence isn't lost.
- **Rule-based detection engine** — flags failed logins, invalid users, and
  known-bad source IPs, and assigns a severity (`WARNING` / `CRITICAL`).
- **Dashboard** — live host status (RAM/CPU/disk/uptime) and a real-time
  alert table.

## Detection Rules

| Rule ID | Name | Logic |
|---|---|---|
| R-01 | Failed Login Rule | Repeated failed logins for the same user/IP within a short window raise an alert. |
| R-02 | Invalid User Rule | Invalid-user login attempts raise an alert with source IP and username. |
| R-03 | Threat IP Match Rule | An event whose source IP is marked `BANNED` in the registry raises a `CRITICAL` alert. |
| R-04 | Multiple Host Attempt Rule | The same suspicious source IP appearing across multiple hosts raises a higher-severity alert. |

## Architecture

```
Log Sources (sample logs / Linux auth.log / Windows Security log)
        │
        ▼
Log Collector (SSH / PowerShell)  ──▶  Parser & Normalization
        │                                     │
        ▼                                     ▼
  SQLite Database  ◀────────────────  Detection Rule Engine
 (Users, Hosts, IPs, Alerts)                   │
        │                                      ▼
        └──────────────────────────▶  Web Dashboard (Alerts & Reports)
```

Workflow: **collect/import logs → parse events → apply rules → store alerts
→ visualize results**.

| Module | Functionality |
|---|---|
| Authentication Module | Restricts the dashboard and admin pages to logged-in users. |
| Host Management Module | Stores hostname, IP address, and OS type. |
| Threat Intel Module | Maintains suspicious IP addresses with status and last-seen time. |
| Log Analysis Module | Processes collected/sample logs and extracts security events. |
| Alert Module | Creates alerts from detection rules and assigns severity. |
| Dashboard Module | Displays host status, alerts, and summary information. |

## Tools & Technologies

Python, Flask, Flask-Login, Flask-WTF, Flask-SQLAlchemy, SQLite, pandas +
pyarrow (Parquet storage), paramiko (SSH), psutil (Windows host telemetry),
Bootstrap 5, vanilla JavaScript.

## Project Structure

```
mini-siem/
├── app/
│   ├── blueprints/        # auth, ui, and api routes
│   ├── services/          # log collection, parsing, storage, detection
│   ├── static/             # CSS & JS
│   ├── templates/          # Jinja2 templates
│   ├── extensions.py
│   ├── forms.py
│   └── models.py
├── docs/                   # installation guide, user manual, testing report
├── scripts/                 # admin creation & sample data seeding
├── config.py
├── requirements.txt
└── .env.example
```

## Getting Started

See [`docs/INSTALLATION.md`](docs/INSTALLATION.md) for full setup
instructions. Quick start:

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env               # then edit .env with your own SECRET_KEY

flask shell
>>> from app.extensions import db
>>> db.create_all()
>>> exit()

python scripts/create_admin.py     # create your admin login
python scripts/seed_sample_data.py # optional: load demo hosts, threat IP, alerts

flask run
```

Then open `http://127.0.0.1:5000` and log in.

## Documentation

- [Installation Guide](docs/INSTALLATION.md) — environment setup and first run.
- [User Manual](docs/USER_MANUAL.md) — how to use the dashboard and admin panel.
- [Testing Report](docs/TESTING.md) — test cases and demo scenario.

## Scope

**In scope:** administrator authentication, host management, threat IP
registry, sample/imported log ingestion, rule-based detection for
failed-login/invalid-user/suspicious-IP patterns, alert generation, and
dashboard reporting.

**Out of scope:** unauthorized scanning or exploitation, enterprise-scale
real-time correlation, full malware/antivirus analysis, and monitoring of
any system the team does not have permission to access.

## Ethical Use

This project is for educational and authorized lab use only. Testing is
performed exclusively against systems owned by the team or explicitly
authorized by the supervisor/lab administrator, using synthetic or
anonymized log data. No passwords, credentials, or private data are stored
in this repository.

## License

Released under the [MIT License](LICENSE).
