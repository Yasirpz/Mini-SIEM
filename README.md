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
| Supervisor | Dr. Asadullah Burdi | — |

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
  login, CSRF-protected forms *and* CSRF-protected JSON API.
- **Host management** — add, edit, and remove monitored Linux/Windows hosts.
- **Threat Intelligence IP registry** — track addresses as `UNKNOWN`,
  `TRUSTED` or `BANNED`, with source, notes and hit counts.
- **Log collection** — pull authentication logs from Linux hosts over SSH
  (`journalctl`) or from Windows hosts via PowerShell (`Get-WinEvent`,
  Event IDs 4625, 4624, the account-management set, and 6416).
- **Sample log import** — upload or paste Linux `auth.log` text, a Windows
  Security CSV export or JSON, or generate synthetic events, so the whole
  system can be demonstrated with no target machine at all.
- **Forensic retention** — raw events are archived to columnar Parquet files
  before analysis, so evidence survives even if alerts are cleared.
- **USB device detection** — spots removable storage plugged into a monitored
  Windows host (Event ID 6416) and reports the host, device, user and time.
  Internal hardware enumerated at boot is filtered out during collection.
  The Monitored Hosts table also shows whether each host actually *audits*
  Plug and Play events, so an empty USB panel is never ambiguous.
- **Rule-based detection engine** — nine rules (R-01 … R-09) with `LOW` /
  `MEDIUM` / `HIGH` severities, re-runnable at any time over stored events.
- **Dashboard** — summary statistics, Chart.js charts (failure trend,
  severity split, alerts per rule), top attacking IPs, recent USB devices,
  live host telemetry.
- **Alert triage** — filter by severity, rule, host and review status;
  acknowledge alerts as they are handled.

## Detection Rules

Implemented in [`app/services/detection.py`](app/services/detection.py).

| Rule | Name | Logic | Severity |
|---|---|---|---|
| R-01 | Failed Login Rule | ≥ 5 auth failures for the same user + source IP within a 10-minute sliding window. One alert per burst, not per event. | `MEDIUM` |
| R-02 | Invalid User Rule | A login attempt for a user that does not exist. | `LOW` |
| R-03 | Threat IP Match Rule | The event's source IP is marked `BANNED` in the registry. | `HIGH` |
| R-04 | Multiple Host Attempt Rule | One source IP produces failures on ≥ 2 different monitored hosts. | `HIGH` |
| R-05 | Audit Log Cleared | The Windows Security log was cleared (Event 1102). No threshold — one occurrence is the whole signal. | `HIGH` |
| R-06 | Account Created / Deleted | A Windows account appeared or disappeared (4720 / 4726). | `MEDIUM` |
| R-07 | Privilege Change | An account was added to a security group, or had its password reset by someone else (4732 / 4724). | `MEDIUM` |
| R-08 | Account Lockout | Windows locked an account out after repeated failures (4740). | `MEDIUM` |
| R-09 | External Device Connected | A USB storage device was connected to a monitored host (Event 6416). No threshold — every connection is reported. | `MEDIUM` |

R-01–R-04 detect attacks in progress. R-05–R-08 cover what an intruder does
*after* getting in: escalating privilege, establishing persistence, and
erasing the evidence. R-09 covers the physical route in and out — a USB drive
carries data off a machine, and malware onto one, without touching the network
the other rules watch.

R-07 deliberately ignores ordinary administrative logons (4672) — they happen
every time an admin signs in, and alerting on them would train the operator to
ignore the rule. A lockout (R-08) does not feed R-01 either: it is the
consequence of failures that rule has already counted.

R-09 requires Plug and Play auditing to be enabled on the monitored machine
(see [`docs/REAL_WORLD_LAB_SETUP.md`](docs/REAL_WORLD_LAB_SETUP.md)). Where it
is not enabled the host simply reports no device events — collection carries
on normally rather than failing.

Thresholds are configurable in `.env` (see `.env.example`). Addresses marked
`TRUSTED` are suppressed entirely. Re-running detection never duplicates an
existing alert, so it is safe to run repeatedly during a demonstration.

## What it does, in one paragraph

Mini-SIEM acts as a centralised security monitoring platform. It collects
authentication and security events from authorised Windows and Linux hosts,
normalises the logs into a common event format, stores them, applies detection
rules, generates alerts, and presents the results through a single dashboard.

### Why each part exists

| Question | Answer |
|---|---|
| **Why a SIEM?** | Logs hold the evidence of an attack, but nobody reads them. A SIEM does the reading. |
| **Why centralised?** | An attacker probing five machines looks harmless on each one. Only a central view reveals the pattern. |
| **Why normalise?** | A Linux `auth.log` line and a Windows Event 4625 describe the same thing in different shapes. Normalising once means the rules never care about the source, and a new log type costs one parser rather than a rewrite. |
| **Why correlate?** | One failed login is noise. Five in ten minutes is an attack. Correlation is what separates them. |
| **Why rules?** | Every alert can be traced to a specific rule and a specific event. That is explainable; a machine-learning score is not. |
| **Why alerts?** | To rank what deserves attention, instead of presenting everything equally. |
| **Why multiple hosts?** | Because rule R-04 — one IP attacking several machines — cannot exist otherwise. |
| **Why source IP?** | It is what ties separate events to a single actor, and what the threat registry keys on. |
| **Why event IDs?** | They are Windows' own stable vocabulary: 4625 is a failed logon on every Windows machine ever made. |

## Multi-host monitoring

One dashboard, three collection methods:

```
                     CENTRAL MINI-SIEM
                            │
     ┌──────────────────────┼──────────────────────┐
     │                      │                      │
LOCAL (this PC)        WINRM (LAN)            SSH (LAN)
Windows Security    Windows Security      /var/log/auth.log
log, read directly  log, read remotely    read over SSH
     │                      │                      │
     └──────────────────────┼──────────────────────┘
                            ▼
                 Normalised event format
                            ▼
               Parquet archive + Event table
                            ▼
              Detection engine (R-01 … R-09)
                            ▼
                     Alerts → Dashboard
```

Each host records its own health from real collection outcomes —
`ONLINE`, `DEGRADED`, `OFFLINE` or `UNKNOWN`. A host that has never been
contacted reports `UNKNOWN`, never `ONLINE`: existing in the database proves
nothing about whether it can be reached.

**Test Connection** checks each stage separately — reachable, authenticated,
log accessible — because "connection failed" gives no clue whether the PC is
off, the password is wrong, or the account lacks permission.

See [`docs/REAL_WORLD_LAB_SETUP.md`](docs/REAL_WORLD_LAB_SETUP.md) for exact
setup and demo-day steps.

## Architecture

```
Log sources
  ├── Linux auth.log via SSH (journalctl)
  ├── Windows Security log via PowerShell (Event ID 4625)
  └── Imported sample / synthetic logs
        │
        ▼
  Parser & normalization  ──▶  Parquet archive (forensic retention)
        │
        ▼
  Event table (SQLite)
        │
        ▼
  Detection rule engine (R-01 … R-09)
        │
        ▼
  Alert table  ──▶  Web dashboard, alert triage, charts
```

Workflow: **collect/import logs → parse and normalize → store events →
apply rules → store alerts → visualize**.

| Module | Functionality | Code |
|---|---|---|
| Authentication | Restricts every page and API route to logged-in users. | `blueprints/auth.py` |
| Host Management | Hostname, IP address, OS type and description. | `blueprints/api/hosts.py` |
| Threat Intel | Suspicious IPs with status, source, notes and last-seen time. | `blueprints/api/threat_intel.py` |
| Log Analysis | Parses collected/imported logs and extracts events. | `services/log_analyzer.py`, `services/sample_loader.py` |
| Alert | Applies the detection rules and assigns severity. | `services/detection.py` |
| Dashboard | Summary counts, charts and recent activity. | `blueprints/api/stats.py` |

## Tools & Technologies

Python, Flask, Flask-Login, Flask-WTF, Flask-SQLAlchemy, SQLite, pandas +
pyarrow (Parquet retention), paramiko (SSH), psutil (Windows telemetry),
Bootstrap 5, Chart.js, vanilla JavaScript ES modules, pytest.

Bootstrap and Chart.js are bundled in `app/static/vendor/` and served
locally, so the application makes **no external network requests** and runs
fully offline.

## Project Structure

```
mini-siem/
├── app/
│   ├── blueprints/
│   │   ├── api/            # hosts, threat_intel, events, alerts, stats
│   │   ├── auth.py         # login / logout
│   │   └── ui.py           # server-rendered pages
│   ├── services/
│   │   ├── detection.py    # R-01 .. R-09 rule engine
│   │   ├── log_analyzer.py # ingestion pipeline
│   │   ├── log_collector.py# live Linux/Windows collection
│   │   ├── sample_loader.py# sample log parsers
│   │   ├── data_manager.py # Parquet retention
│   │   ├── remote_client.py# SSH wrapper
│   │   └── win_client.py   # PowerShell wrapper
│   ├── static/             # CSS & ES-module JS
│   ├── templates/          # Jinja2 templates
│   ├── models.py           # users, hosts, IPs, events, alerts
│   └── validators.py       # server-side input validation
├── docs/                   # installation, user manual, testing report
├── samples/                # sample log files (D-05)
├── scripts/                # admin creation & demo seeding
├── tests/                  # pytest suite (TC-01 .. TC-08)
├── config.py
└── requirements.txt
```

## Getting Started

See [`docs/INSTALLATION.md`](docs/INSTALLATION.md) for full setup. Quick start:

```bash
python -m venv venv
venv\Scripts\activate            # Linux/macOS: source venv/bin/activate
pip install -r requirements.txt

copy .env.example .env           # Linux/macOS: cp .env.example .env
                                 # then set your own SECRET_KEY

python scripts/create_admin.py   # create your admin login
python scripts/seed_sample_data.py --ban   # optional: load the demo dataset

flask run
```

Then open `http://127.0.0.1:5000` and log in.

## Running the tests

```bash
python -m pytest
```

236 tests cover the proposal's test cases TC-01 – TC-08, each of the nine
detection rules individually, all three sample log parsers, USB device
detection, and input validation.

## Documentation

- [Installation Guide](docs/INSTALLATION.md) — environment setup and first run.
- [User Manual](docs/USER_MANUAL.md) — how to use each module.
- [Testing Report](docs/TESTING.md) — test cases, results and the demo script.
- [Sample Logs](samples/README.md) — what each sample file demonstrates.

## Scope

**In scope:** administrator authentication, host management, threat IP
registry, sample/imported log ingestion, rule-based detection for
failed-login / invalid-user / suspicious-IP / multi-host patterns, alert
generation with severity, and dashboard reporting.

**Out of scope:** unauthorized scanning or exploitation, enterprise-scale
real-time correlation, full malware/antivirus analysis, packet-level
inspection, and monitoring of any system the team does not have permission
to access.

## Ethical Use

This project is for educational and authorized lab use only. Testing is
performed exclusively against systems owned by the team or explicitly
authorized by the supervisor/lab administrator, using synthetic or anonymized
log data. Every address in the bundled samples comes from a reserved
documentation range (RFC 5737) or private range (RFC 1918), so none of them
routes to a real machine. No passwords, credentials, or private data are
stored in this repository.

## License

Released under the [MIT License](LICENSE).
