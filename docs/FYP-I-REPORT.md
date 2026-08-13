# FYP-I Report

## Mini-SIEM: A Web-Based Security Event Monitoring and Threat Detection System

**Project ID:** FYCP/2K26/109
**Program:** BS Computer Science — Final Year
**Institute:** Institute of Mathematics & Computer Science (IMCS), University of Sindh, Jamshoro
**Supervisor:** Dr. Asadullah Burdi

| Role | Name | Roll No. |
|---|---|---|
| Group Leader | Yasir Parveez | 2K23/CSM/146 |
| Group Member | Abdul Fatah | 2K23/CSM/03 |
| Group Member | Mushahid Hussain | 2K23/CSM/100 |

**Submission date:** ______________________

> **Note for the team.** This report documents the FYP-I phase (requirement
> analysis, system design and foundation prototype). Fields left as blank
> lines are for you to complete — meeting dates, supervisor feedback and
> screenshots cannot be filled in from the source code. Verify every figure
> against your own run before submitting.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Problem Statement](#2-problem-statement)
3. [Aim and Objectives](#3-aim-and-objectives)
4. [Literature Review](#4-literature-review)
5. [Requirement Analysis](#5-requirement-analysis)
6. [System Design](#6-system-design)
7. [Database Schema](#7-database-schema)
8. [Technology Selection](#8-technology-selection)
9. [FYP-I Prototype Status](#9-fyp-i-prototype-status)
10. [Risk Assessment](#10-risk-assessment)
11. [Work Completed and Plan for FYP-II](#11-work-completed-and-plan-for-fyp-ii)
12. [References](#12-references)

---

## 1. Introduction

### 1.1 Background

Every computer system, server and web application continuously produces log
records: successful logins, failed logins, invalid user attempts, access from
unfamiliar addresses, privilege escalation, and application errors. These
records are the primary evidence available when investigating whether a
system has been attacked.

In small organisations and educational laboratories, that evidence is usually
ignored. Reading raw logs by hand is slow, requires technical skill, and does
not scale — a single Linux host can generate thousands of authentication
lines per day. As a result, indicators such as a sustained password-guessing
attack often go unnoticed until they succeed.

Security Information and Event Management (SIEM) systems solve this by
centralising logs, normalising them into a common structure, applying
detection logic, and presenting the results as prioritised alerts. Commercial
and open-source platforms — Splunk, Elastic Stack, Wazuh — do this very well,
but they demand significant configuration effort, storage and expertise. For
a university laboratory, that overhead is disproportionate.

### 1.2 Motivation

This project is motivated by the gap between "no monitoring at all" and
"enterprise SIEM". A lightweight system that demonstrates the *core ideas*
clearly — collection, normalisation, correlation, alerting — is more useful
for teaching and for a small lab than a platform nobody has time to
configure.

It also makes the concepts concrete for the team: rather than reading about
detection rules, we implement them, and discover why a naive rule produces
unusable output.

### 1.3 Scope of this Report

This report covers the FYP-I phase: understanding the problem domain,
establishing requirements, designing the system, and building the foundation
prototype. Full implementation of the detection engine, testing and
evaluation belong to FYP-II and are documented in the FYP-II report.

---

## 2. Problem Statement

Small labs, student networks and small organisations lack an affordable and
approachable security event monitoring system. Raw logs are difficult to read
manually, and basic indicators of suspicious behaviour — repeated failed
logins, invalid user attempts, access from known-bad addresses — remain
hidden inside them.

There is a need for a lightweight, web-based system that can accept log
events from multiple sources, normalise them into a common structure, analyse
them through understandable detection rules, store the results, and present
meaningful prioritised alerts to an administrator through a dashboard.

---

## 3. Aim and Objectives

### 3.1 Aim

To develop a lightweight web-based Mini-SIEM system for monitoring security
events, detecting suspicious login-related behaviour, managing monitored
hosts, maintaining a threat intelligence IP registry, and displaying alerts
through a dashboard.

### 3.2 Objectives

| # | Objective | Phase |
|---|---|---|
| O-1 | Design a secure administrator login system for controlled access. | FYP-I |
| O-2 | Develop a host management module for systems selected for monitoring. | FYP-I |
| O-3 | Implement a threat intelligence IP registry with status and notes. | FYP-I |
| O-4 | Design a log/event analysis module identifying failed logins, invalid users and repeated suspicious events. | FYP-I design, FYP-II build |
| O-5 | Generate alerts using rule-based detection and store them locally. | FYP-II |
| O-6 | Present security summaries and alerts through a web dashboard. | FYP-II |
| O-7 | Prepare testing evidence, user guidance, installation instructions and a demonstration script. | FYP-II |

---

## 4. Literature Review

### 4.1 Log Management and Security Monitoring

NIST SP 800-92, *Guide to Computer Security Log Management*, establishes the
foundation this project builds on: logs are only valuable if they are
generated consistently, retained reliably, and analysed. It stresses the
distinction between **collection** and **analysis** — many organisations
collect logs but never look at them, which is precisely the failure mode
observed in small labs.

NIST SP 800-94, *Guide to Intrusion Detection and Prevention Systems*,
distinguishes signature-based detection from anomaly-based detection. This
project uses the signature/rule-based approach: it is deterministic,
explainable and appropriate for a system that must be defensible in a viva.
Anomaly detection requires a training baseline that a lab prototype cannot
realistically establish.

The NIST Cybersecurity Framework 2.0 organises security work into Govern,
Identify, Protect, **Detect**, Respond and Recover. Mini-SIEM sits squarely
in *Detect* — specifically the "Adverse Event Analysis" category.

### 4.2 Comparison of Existing Approaches

| Approach | Strengths | Limitations | How Mini-SIEM addresses it |
|---|---|---|---|
| Manual log inspection | No cost, no setup | Slow, error-prone, does not scale, misses patterns spread across files | Automates parsing and correlation; presents results as a ranked list |
| Enterprise SIEM (Splunk, Elastic, Wazuh) | Powerful, scalable, mature | Costly, complex to configure, heavy infrastructure, steep learning curve | Implements a feasible educational subset with the same conceptual pipeline |
| Basic monitoring dashboard | Visualises data clearly | Displays only; cannot detect patterns or raise alerts | Adds a rule engine and persistent alert storage |
| Antivirus / anti-malware | Effective against known malware | Focused on files and processes, not authentication behaviour | Focuses specifically on log-based authentication events |

### 4.3 Positioning

Mini-SIEM deliberately implements a narrow but complete vertical slice:
authentication events only, four detection rules, one dashboard. This is a
better fit for an FYP than a broad but shallow imitation of a commercial
product, because every part of the pipeline can be fully implemented,
explained and tested.

---

## 5. Requirement Analysis

### 5.1 Stakeholders

| Stakeholder | Need |
|---|---|
| Lab / system administrator | See which hosts are being attacked, and how seriously, without reading raw logs |
| Cybersecurity students | Understand how detection rules and alerting actually work |
| Small offices | Evaluate the concept before investing in a larger platform |
| FYP evaluators | Verify functionality through a repeatable demonstration |

### 5.2 Functional Requirements

| ID | Requirement | Priority |
|---|---|---|
| FR-01 | The system shall allow an administrator to log in securely. | Must |
| FR-02 | The system shall restrict dashboard, host, threat IP and alert pages to authenticated users. | Must |
| FR-03 | The system shall allow the administrator to add, view, update and delete monitored hosts. | Must |
| FR-04 | The system shall allow management of suspicious IP addresses in a threat registry. | Must |
| FR-05 | The system shall support sample log/event input for testing and demonstration. | Must |
| FR-06 | The system shall detect failed login, invalid user and suspicious IP patterns. | Must |
| FR-07 | The system shall generate alerts with severity, timestamp, host and source IP. | Must |
| FR-08 | The system shall display alerts and summary statistics on a web dashboard. | Must |
| FR-09 | The system shall provide a repeatable demo workflow for FYP evaluation. | Must |

### 5.3 Non-Functional Requirements

| Attribute | Requirement | Design consequence |
|---|---|---|
| Usability | Understandable by students and lab administrators | Bootstrap UI, plain-language alert messages, no command line needed for normal use |
| Security | Administrative access protected by login and session management | Hashed passwords, session cookies, CSRF protection on forms *and* API, server-side validation |
| Performance | Sample logs processed within a reasonable time during a demonstration | In-process analysis, indexed database columns, bulk queries rather than per-row lookups |
| Maintainability | Code organised into models, routes, services, templates, static files | Application factory, blueprints, service layer separated from HTTP layer |
| Portability | Runs on local Windows or Linux with Python and Flask | SQLite (no server), pure-Python dependencies, no OS-specific build step |
| Ethical compliance | Only sample logs or authorised systems | Sample data confined to reserved address ranges; no scanning capability implemented |

### 5.4 Use Cases

**UC-01 Authenticate**
Actor: Administrator. The administrator submits credentials; the system
verifies them against a stored hash and establishes a session. On failure a
deliberately generic message is shown so that valid usernames are not
revealed.

**UC-02 Manage monitored hosts**
The administrator adds a host with hostname, IP address, OS type and optional
description. The system validates the address and rejects duplicates.

**UC-03 Maintain threat intelligence**
The administrator records an address as `UNKNOWN`, `TRUSTED` or `BANNED`.
Status directly changes detection behaviour.

**UC-04 Ingest logs**
The administrator either triggers collection from a monitored host or imports
a sample log file. The system parses records into normalised events, archives
the raw batch, and stores the events.

**UC-05 Review alerts**
The administrator opens the dashboard, reviews alerts ranked by severity,
filters them, and marks handled ones as reviewed.

---

## 6. System Design

### 6.1 Architectural Overview

```
                        ┌──────────────────────────┐
   Log sources          │  Linux host (SSH)        │
                        │  Windows Security log    │
                        │  Sample / synthetic logs │
                        └────────────┬─────────────┘
                                     │
                        ┌────────────▼─────────────┐
   Normalisation        │  Parsers                 │
                        │  → common event format   │
                        └────────────┬─────────────┘
                                     │
                   ┌─────────────────┼─────────────────┐
                   │                                   │
        ┌──────────▼──────────┐            ┌───────────▼──────────┐
        │  Parquet archive    │            │  Event table         │
        │  (forensic copy)    │            │  (SQLite)            │
        └─────────────────────┘            └───────────┬──────────┘
                                                       │
                                           ┌───────────▼──────────┐
        Detection                          │  Rule engine         │
                                           │  R-01 … R-04         │
                                           └───────────┬──────────┘
                                                       │
                                           ┌───────────▼──────────┐
                                           │  Alert table         │
                                           └───────────┬──────────┘
                                                       │
                                           ┌───────────▼──────────┐
        Presentation                       │  Web dashboard       │
                                           │  charts, triage      │
                                           └──────────────────────┘
```

**Figure 1: Mini-SIEM architecture.**

A key design decision is that events are stored **separately from** alerts.
Storing only alerts would mean the detection rules could never be re-applied
without re-collecting logs. Because events persist, rules can be re-run at
any time — which is what allows a change in threat intelligence to
retroactively escalate the severity of evidence already gathered.

### 6.2 Module Decomposition

| Module | Responsibility | Implementation |
|---|---|---|
| Authentication | Session establishment and route protection | `app/blueprints/auth.py` |
| Host Management | CRUD for monitored hosts, live telemetry | `app/blueprints/api/hosts.py` |
| Threat Intelligence | Suspicious IP registry | `app/blueprints/api/threat_intel.py` |
| Log Collection | Retrieval from Linux/Windows hosts | `app/services/log_collector.py` |
| Log Parsing | Format detection and normalisation | `app/services/sample_loader.py` |
| Log Analysis | Ingestion pipeline: archive → store → detect | `app/services/log_analyzer.py` |
| Detection | The four rules and severity assignment | `app/services/detection.py` |
| Retention | Parquet archival | `app/services/data_manager.py` |
| Dashboard | Summary statistics and chart data | `app/blueprints/api/stats.py` |
| Validation | Server-side input checking | `app/validators.py` |

### 6.3 The Normalised Event Format

Every log source, regardless of origin, is reduced to one structure:

```python
{
    'timestamp':  datetime,   # when the event occurred (naive UTC)
    'alert_type': str,        # FAILED_LOGIN, INVALID_USER, ...
    'source_ip':  str,        # originating address, or a LOCAL marker
    'user':       str,        # targeted username
    'message':    str,        # human-readable description
    'raw_log':    str,        # original line, retained for evidence
}
```

This is the single most important design decision in the project. Because
normalisation happens at the boundary, the detection rules never need to know
whether an event came from a Linux `auth.log`, a Windows Security export or a
synthetic generator. Adding a new log source in future means writing one
parser, not touching the rule engine at all.

### 6.4 Detection Rule Design

| Rule | Name | Detection logic | Severity |
|---|---|---|---|
| R-01 | Failed Login | ≥ N authentication failures for the same username *and* source IP within a sliding time window | `MEDIUM` |
| R-02 | Invalid User | An authentication attempt for a username that does not exist | `LOW` |
| R-03 | Threat IP Match | The event's source IP is marked `BANNED` in the registry | `HIGH` |
| R-04 | Multiple Host Attempt | One source IP produces failures against ≥ M distinct monitored hosts | `HIGH` |

**Design rationale for R-01.** The obvious implementation — raise an alert on
every failed login — was rejected during design. A user who mistypes a
password three times would generate three alerts identical in form to a
brute-force attack, making the alert list useless. Requiring a threshold
*within a bounded window* distinguishes a burst from occasional human error.
A sliding window is used rather than fixed buckets so an attack straddling a
boundary is still caught.

**Design rationale for R-04.** One address failing against several machines
is qualitatively different from one address failing repeatedly against one
machine: it indicates scanning or credential spraying rather than a forgotten
password. This justifies the higher severity.

**Severity scheme.** `LOW` / `MEDIUM` / `HIGH`, as specified in the proposal.
Severity reflects *confidence combined with impact*: a single invalid-user
probe is common background noise (`LOW`), a sustained burst is deliberate
(`MEDIUM`), and confirmed-bad or multi-host activity warrants attention now
(`HIGH`).

### 6.5 Trust Model

The registry status of a source address changes detection behaviour directly:

| Status | Effect |
|---|---|
| `UNKNOWN` | Default. Tracked with a hit count; ordinary rules apply. |
| `TRUSTED` | All alerts suppressed. Prevents a known scanner or admin jump box flooding the list. |
| `BANNED` | Any event escalates to `HIGH` via R-03. |

Addresses observed in failure events are auto-registered as `UNKNOWN`, so the
registry populates itself and the administrator only decides which entries to
promote.

---

## 7. Database Schema

Six tables, corresponding to deliverable D-04.

```
users                    hosts                       log_sources
─────                    ─────                       ───────────
id            PK         id              PK          id           PK
username      UNIQUE     hostname                    host_id      FK → hosts
password_hash            ip_address      UNIQUE      log_type
created_at               os_type                     last_fetch
                         description
                         created_at

ip_registry              events                      alerts
───────────              ──────                      ──────
id            PK         id            PK            id           PK
ip_address    UNIQUE     host_id       FK → hosts    host_id      FK → hosts
status                   timestamp     INDEX         event_id     FK → events
source                   event_type    INDEX         timestamp    INDEX
notes                    source_ip     INDEX         rule_id      INDEX
date_added               username                    alert_type
last_seen                message                     message
hit_count                raw_log                     severity     INDEX
                         origin                      source_ip    INDEX
                         ingested_at                 acknowledged INDEX

log_archives
────────────
id            PK
host_id       FK → hosts
timestamp
filename
record_count
origin
```

**Figure 2: Entity relationships.**

### 7.1 Design Notes

**Why `events` and `alerts` are separate.** An event is an observation; an
alert is a judgement about one or more observations. Keeping them apart lets
the dashboard report "events seen" against "alerts raised", and permits rules
to be re-applied without re-collection.

**Why `alerts.event_id` exists.** Each alert is anchored to the event that
triggered it. This provides traceability from a judgement back to its
evidence, and gives the engine a natural de-duplication key: an alert is only
created if no alert with the same `(rule_id, event_id)` pair already exists.
Re-running detection is therefore safe.

**Why `log_archives` indexes files rather than storing content.** Raw batches
are written to Parquet on disk. The table records what was written and when,
so evidence remains discoverable while the database stays small.

**Timestamp handling.** SQLite discards timezone information on storage, so
all datetimes are stored as naive UTC. Mixing aware and naive values would
break the time-window arithmetic in R-01, so a single helper produces every
default timestamp.

**Indexing.** Columns used by rule queries and dashboard filters
(`timestamp`, `event_type`, `source_ip`, `severity`, `rule_id`) are indexed.

---

## 8. Technology Selection

| Layer | Choice | Justification | Alternatives considered |
|---|---|---|---|
| Language | Python 3.10+ | Strong text-processing and data libraries; team familiarity | — |
| Web framework | Flask | Minimal, explicit, easy to explain in a viva | Django — too much implicit machinery for a project this size |
| ORM | SQLAlchemy (via Flask-SQLAlchemy) | Portable schema definition, protects against SQL injection | Raw `sqlite3` — more error-prone |
| Database | SQLite | Zero configuration, single file, adequate for lab scale | PostgreSQL — needs a server, disproportionate here |
| Authentication | Flask-Login | Session management with a small API surface | Hand-rolled sessions — unnecessary security risk |
| Forms / CSRF | Flask-WTF | Validation and CSRF tokens together | Manual token handling — easy to get wrong |
| Retention | pandas + pyarrow (Parquet) | Columnar, compressed, fast to filter when replaying | Plain CSV — larger and slower; raw JSON — no schema |
| SSH | paramiko | Pure-Python SSH, no external binary | Shelling out to `ssh` — poor error handling |
| Front-end | Bootstrap 5 + vanilla ES modules | No build step; readable by examiners | React — build tooling adds no value at this scale |
| Charts | Chart.js | Lightweight, declarative | D3 — far more power than needed |
| Testing | pytest | Concise tests, strong fixture model | `unittest` — more boilerplate |

**Note on the front end.** Avoiding a JavaScript build pipeline was a
deliberate choice: the entire system can be read and run directly from the
repository, which matters for a project that must be inspected and defended.

---

## 9. FYP-I Prototype Status

By the end of FYP-I the foundation was working end to end.

| Area | Status at end of FYP-I |
|---|---|
| Python virtual environment | Complete and documented |
| Dependency installation | Complete; `requirements.txt` finalised |
| Flask application factory | Complete; blueprints registered |
| Login page and authentication | Complete; passwords hashed, CSRF protected |
| Administrator account creation | Complete via `scripts/create_admin.py` |
| Host management module | Complete; CRUD with validation |
| Threat IP registry | Complete; status, source, notes |
| Database schema | Complete; six tables |
| Log collection (Linux/Windows) | Working; incremental fetch implemented |
| Parquet retention | Working |
| Detection rules | **Design complete; R-01 and R-04 implementation deferred to FYP-II** |
| Dashboard | Basic host list and alert table; charts deferred to FYP-II |
| Sample log import | Design complete; implementation deferred to FYP-II |
| Automated tests | Deferred to FYP-II |

**Screenshots.** Insert the FYP-I prototype screenshots here:

- Figure 3: Login page — _____________________
- Figure 4: Host management — _____________________
- Figure 5: Threat IP registry — _____________________

*(Ensure no real password, token or private address is visible.)*

---

## 10. Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Detection rules produce unusable volumes of alerts | High | High | Threshold-and-window design for R-01; de-duplication; `TRUSTED` suppression |
| No access to a real Linux host for demonstration | Medium | High | Sample log import and a synthetic generator, so the demo needs no target machine |
| Live log collection fails during the viva | Medium | High | Demonstration path built entirely on imported sample data |
| Demonstration machine has no internet | Medium | Medium | Identified: Bootstrap and Chart.js load from a CDN; vendor them locally before the viva |
| Team member unavailable near submission | Low | Medium | All members maintain working knowledge of the whole system; contributions tracked via Git |
| Scope expanding beyond available time | Medium | Medium | Out-of-scope list agreed in the proposal and adhered to |
| Accidental exposure of real data in screenshots | Low | High | Only synthetic data and reserved address ranges used throughout |

---

## 11. Work Completed and Plan for FYP-II

### 11.1 FYP-I Completed

| Week | Task | Status |
|---|---|---|
| 1 | Finalise title, Project ID, team roles, supervisor feedback | Complete |
| 2 | Study SIEM concepts, log types, detection rules, ethical requirements | Complete |
| 3 | Requirement analysis, scope, functional and non-functional requirements | Complete |
| 4 | Database schema, architecture diagram, module workflow | Complete |
| 5–6 | Authentication, dashboard layout, host module, threat IP registry | Complete |
| 7 | Sample logs and initial parser/detection proof of concept | Complete |
| 8 | FYP-I prototype, proposal defence material, progress log | Complete |

### 11.2 Planned for FYP-II

| Week | Task |
|---|---|
| 1–3 | Complete the log analysis module, the full rule engine (R-01 … R-04) and alert storage |
| 4–5 | Dashboard charts, severity handling, alert filtering and acknowledgement |
| 6 | Module testing and integration testing |
| 7 | User manual, installation guide, testing report |
| 8 | Final report, slides, poster, repository finalisation, demo video |

### 11.3 Known Gaps Entering FYP-II

Identified honestly at the end of FYP-I:

1. R-01 alerted on every failed login rather than applying a threshold — the
   most important correctness gap.
2. R-04 was designed but not implemented.
3. Events existed only inside Parquet archives, so rules could not be re-run.
4. Severity used `WARNING`/`CRITICAL` rather than the specified
   `LOW`/`MEDIUM`/`HIGH`.
5. No sample log import interface (FR-05 unmet).
6. No summary statistics or charts (FR-08 partially unmet).
7. No automated tests.
8. The JSON API was exempt from CSRF protection.

All eight were addressed in FYP-II; see the FYP-II report.

---

## 12. References

1. National Institute of Standards and Technology. (2006). *Guide to Computer Security Log Management*. NIST Special Publication 800-92.
2. Scarfone, K., & Mell, P. (2007). *Guide to Intrusion Detection and Prevention Systems (IDPS)*. NIST Special Publication 800-94.
3. National Institute of Standards and Technology. (2024). *The NIST Cybersecurity Framework (CSF) 2.0*.
4. OWASP Foundation. (2021). *OWASP Top 10 Web Application Security Risks*.
5. Pallets Projects. (n.d.). *Flask Documentation*.
6. SQLAlchemy Project. (n.d.). *SQLAlchemy ORM Documentation*.
7. Python Software Foundation. (n.d.). *Python Documentation*.
8. Stallings, W., & Brown, L. (2018). *Computer Security: Principles and Practice*. Pearson.
9. Arkko, J., Cotton, M., & Vegoda, L. (2010). *IPv4 Address Blocks Reserved for Documentation*. RFC 5737.

---

**Supervisor's remarks**

_______________________________________________________________________

_______________________________________________________________________

Supervisor signature: ____________________  Date: ______________
