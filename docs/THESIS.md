# Mini-SIEM

## A Web-Based Security Event Monitoring and Threat Detection System

**Project ID:** FYCP/2K26/109

**Submitted in partial fulfilment of the requirements for the degree of**
**Bachelor of Science in Computer Science**

**Submitted by**

| Name | Roll Number |
|---|---|
| Yasir Parveez *(Group Leader)* | 2K23/CSM/146 |
| Abdul Fatah | 2K23/CSM/03 |
| Mushahid Hussain | 2K23/CSM/100 |

**Supervised by**

Dr. Asadullah Burdi

**Institute of Mathematics & Computer Science**
**University of Sindh, Jamshoro**

Session ______________  ·  Submitted ______________

<div class="pagebreak"></div>

## Certificate of Approval

This is to certify that the work presented in this thesis, entitled
**"Mini-SIEM: A Web-Based Security Event Monitoring and Threat Detection
System"**, submitted by **Yasir Parveez (2K23/CSM/146)**, **Abdul Fatah
(2K23/CSM/03)** and **Mushahid Hussain (2K23/CSM/100)**, has been carried out
under my supervision at the Institute of Mathematics & Computer Science,
University of Sindh, Jamshoro. This work is original and has not been
submitted elsewhere for any other degree.

I recommend that it be accepted in partial fulfilment of the requirements for
the degree of Bachelor of Science in Computer Science.

&nbsp;

**Supervisor**

Dr. Asadullah Burdi

Signature: ______________________  Date: ______________

&nbsp;

**Director / Head of Institute**

Signature: ______________________  Date: ______________

&nbsp;

**External Examiner**

Signature: ______________________  Date: ______________

<div class="pagebreak"></div>

## Declaration of Originality

We declare that this thesis, and the software system it describes, are our
own work. All sources of information have been acknowledged, and all external
libraries and frameworks used are credited in Chapter 5 and the References.

We further declare that this work has not been submitted, in whole or in
part, for any other degree or qualification.

Any use of artificial intelligence tools during this project is declared
separately in the AI Use Declaration accompanying this submission.

| Name | Roll Number | Signature | Date |
|---|---|---|---|
| Yasir Parveez | 2K23/CSM/146 | ________________ | __________ |
| Abdul Fatah | 2K23/CSM/03 | ________________ | __________ |
| Mushahid Hussain | 2K23/CSM/100 | ________________ | __________ |

<div class="pagebreak"></div>

## Acknowledgements

We wish to thank our supervisor, Dr. Asadullah Burdi, for his guidance
throughout this project.

_(Add your own acknowledgements here — faculty, lab staff, family, anyone who
helped. Keep it brief and sincere.)_

_______________________________________________________________________

_______________________________________________________________________

_______________________________________________________________________

<div class="pagebreak"></div>

## Abstract

Computer systems generate large volumes of security-relevant log records, but
in small organisations and educational laboratories these records are rarely
examined. Reading them manually is slow and does not scale, so indicators of
attack — repeated failed logins, probing for non-existent accounts, activity
from known-hostile addresses — frequently go unnoticed. Commercial Security
Information and Event Management (SIEM) platforms address this problem, but
their cost, configuration burden and infrastructure requirements make them
impractical at laboratory scale.

This thesis presents Mini-SIEM, a lightweight web-based security event
monitoring and threat detection system built for educational and small-lab
use. The system collects authentication logs from Linux hosts over SSH and
from Windows Security event logs, or imports sample logs in three different
formats. All sources are reduced to a single normalised event structure,
archived to compressed columnar Parquet files for forensic retention, stored
in a relational database, and analysed by a rule-based detection engine
implementing four documented rules. Alerts are assigned Low, Medium or High
severity and presented through a web dashboard providing summary statistics,
charts, filtering and acknowledgement.

The delivered system comprises approximately 5,200 lines of code and is
verified by 95 automated tests covering every detection rule, all three log
parsers, the complete access-control surface and a set of security checks.

Two results are of particular note. First, redesigning the failed-login rule
from a per-event trigger to a threshold within a sliding time window was
necessary to make its output usable: the naive form could not distinguish a
user mistyping a password from a brute-force attack. Second, because
normalised events are stored independently of alerts, the detection rules can
be re-applied to evidence already collected. Marking a single address as
hostile and re-running detection raised total alerts from 13 to 31, and
high-severity alerts from 3 to 21, without re-reading a single log line. This
capacity to reinterpret stored evidence as knowledge improves is the
essential characteristic distinguishing a SIEM from a log viewer, and the
system reproduces it faithfully at laboratory scale.

**Keywords:** SIEM, security monitoring, log analysis, intrusion detection,
failed login detection, threat intelligence, event correlation, Flask, Python

<div class="pagebreak"></div>

## Table of Contents

**1. Introduction**
 1.1 Background
 1.2 Motivation
 1.3 Problem Statement
 1.4 Aim and Objectives
 1.5 Scope
 1.6 Thesis Organisation

**2. Literature Review**
 2.1 Security Log Management
 2.2 Intrusion Detection Approaches
 2.3 The NIST Cybersecurity Framework
 2.4 Existing Systems
 2.5 Research Gap

**3. Requirement Analysis and Methodology**
 3.1 Stakeholders
 3.2 Functional Requirements
 3.3 Non-Functional Requirements
 3.4 Use Cases
 3.5 Development Methodology

**4. System Design**
 4.1 Architecture
 4.2 Module Decomposition
 4.3 The Normalised Event Format
 4.4 Database Design
 4.5 Detection Rule Design
 4.6 Trust Model

**5. Implementation**
 5.1 Technology Selection
 5.2 Code Organisation
 5.3 Authentication
 5.4 Log Collection
 5.5 Log Parsing
 5.6 Forensic Retention
 5.7 The Detection Engine
 5.8 Dashboard and Triage
 5.9 Security Implementation

**6. Testing and Results**
 6.1 Testing Strategy
 6.2 Test Suite
 6.3 Detection Rule Verification
 6.4 Proposal Test Cases
 6.5 Reference Dataset Results
 6.6 Performance

**7. Evaluation and Discussion**
 7.1 Requirements Evaluation
 7.2 Comparison with Existing Systems
 7.3 Design Decisions in Retrospect
 7.4 Limitations

**8. Conclusion and Future Work**
 8.1 Conclusion
 8.2 Future Work

**References**

**Appendices**

<div class="pagebreak"></div>

# Chapter 1 — Introduction

## 1.1 Background

Every computer system, server and web application continuously produces log
records. Authentication subsystems record who attempted to log in, from
where, and whether they succeeded. Operating systems record privilege
escalation and configuration changes. Applications record errors. Together
these records constitute the primary evidence available when determining
whether a system has been attacked, and how.

The volume is substantial. A single internet-facing Linux host commonly
generates thousands of authentication records per day, the majority of them
routine. Buried among them may be a handful of records indicating a genuine
attack — a sustained sequence of failed passwords against a privileged
account, or repeated probing for usernames that do not exist.

Security Information and Event Management (SIEM) systems exist to solve this
problem. A SIEM centralises log records from multiple sources, normalises
them into a consistent structure, applies detection logic to identify
patterns of concern, and presents prioritised alerts to an administrator.
The pipeline — collect, normalise, correlate, alert — is common to every
implementation regardless of scale.

## 1.2 Motivation

In small organisations and educational laboratories, logs are typically
collected but never examined. The obstacle is not unwillingness but
practicality: manual inspection requires time and technical skill
proportional to the volume of data, and neither is usually available. The
consequence is that attacks are discovered after they succeed, rather than
while they are in progress.

Commercial and mature open-source SIEM platforms — Splunk, Elastic Stack,
Wazuh — address this capably, but they impose costs disproportionate to a
laboratory setting: licensing or infrastructure expenditure, substantial
configuration effort, storage provisioning, and specialist expertise to tune.
A platform that is never properly configured provides no protection.

This project is motivated by the gap between no monitoring at all and
enterprise SIEM deployment. A system that implements the core concepts
clearly, at a scale that a small laboratory can actually operate, has value
both operationally and pedagogically.

There is also a learning motivation. Implementing detection rules — rather
than reading about them — surfaces problems that are not obvious in the
abstract. As Chapter 6 documents, the project's first working detection rule
was technically correct and practically useless, and understanding why was
the most instructive part of the work.

## 1.3 Problem Statement

Small laboratories, student networks and small organisations lack an
affordable and approachable security event monitoring system. Raw logs are
difficult to read manually, and basic indicators of suspicious behaviour —
repeated failed logins, invalid user attempts, and access from addresses
already identified as hostile — remain hidden within them.

There is a need for a lightweight, web-based system that can accept log
events from multiple sources, normalise them into a common structure, analyse
them through understandable detection rules, store the results durably, and
present meaningful prioritised alerts through a dashboard.

## 1.4 Aim and Objectives

### Aim

To develop a lightweight web-based Mini-SIEM system for monitoring security
events, detecting suspicious login-related behaviour, managing monitored
hosts, maintaining a threat intelligence IP registry, and displaying alerts
through a dashboard.

### Objectives

1. To design a secure administrator login system for controlled access to the
   Mini-SIEM dashboard.
2. To develop a host management module for adding and viewing systems
   selected for monitoring.
3. To implement a threat intelligence IP registry where suspicious addresses
   can be stored with status and notes.
4. To design a log and event analysis module capable of identifying failed
   login attempts, invalid user activity and repeated suspicious events.
5. To generate alerts using rule-based detection and store them in a local
   database for review.
6. To present security summaries, alerts and monitoring information through a
   web dashboard.
7. To prepare testing evidence, user guidance, installation instructions and
   a demonstration script suitable for project evaluation.

## 1.5 Scope

### In Scope

- Administrator authentication and protected routes
- Host entry and management
- Threat intelligence IP registry with status labels and notes
- Sample log import and synthetic event generation
- Rule-based detection for failed login, invalid user and suspicious IP
  patterns
- Alert generation with Low, Medium and High severity levels
- Dashboard display of alerts, event counts, host records and charts
- Testing using sample logs, reserved test addresses and authorised local
  systems

### Out of Scope

- Unauthorised scanning, exploitation, password cracking or credential
  collection
- Enterprise-scale real-time correlation across large networks
- Malware analysis, antivirus functionality or packet-level inspection
- Monitoring of systems for which permission has not been granted
- Behavioural or machine-learning-based anomaly detection

### Ethical Position

This project is defensive throughout. The system implements no offensive
capability. All development and testing used synthetic data and addresses
drawn from ranges reserved for documentation purposes. Live collection is
restricted by design to hosts for which the operator supplies their own
credentials.

## 1.6 Thesis Organisation

Chapter 2 reviews the literature on log management and intrusion detection,
and compares existing systems. Chapter 3 establishes requirements and
describes the development methodology. Chapter 4 presents the system design,
including the database schema and detection rule logic. Chapter 5 documents
implementation. Chapter 6 presents testing and measured results. Chapter 7
evaluates the system against its requirements and discusses design decisions
in retrospect. Chapter 8 concludes and identifies future work.

<div class="pagebreak"></div>

# Chapter 2 — Literature Review

## 2.1 Security Log Management

NIST Special Publication 800-92, *Guide to Computer Security Log Management*,
provides the foundational treatment of the subject. It establishes that log
data has value only when it is generated consistently, retained reliably, and
actually analysed — and observes that many organisations perform the first
two while omitting the third.

The distinction between collection and analysis is directly relevant to this
project. It is straightforward to gather log records; the difficulty lies in
extracting meaning from them. SP 800-92 also emphasises log retention for
forensic purposes: evidence must survive the incident it documents. This
principle motivated the archival design described in Section 5.6, where raw
log batches are written to durable storage before any analysis takes place,
and are not deleted when the analytical database is cleared.

## 2.2 Intrusion Detection Approaches

NIST SP 800-94, *Guide to Intrusion Detection and Prevention Systems*,
classifies detection methodologies into three categories:

**Signature-based detection** compares observed activity against patterns of
known attacks. It is precise and produces explainable results, but detects
only what it has been told to look for.

**Anomaly-based detection** establishes a statistical baseline of normal
behaviour and flags deviations. It can identify previously unknown attacks
but requires a substantial training period and tends toward false positives.

**Stateful protocol analysis** compares observed activity against vendor
profiles of correct protocol behaviour.

This project adopts the signature-based approach, implemented as explicit
rules. The choice was deliberate. Anomaly detection requires a baseline of
normal traffic that a laboratory prototype cannot realistically establish,
and its outputs are difficult to explain — a significant drawback for a
system that must be defended in an academic examination. Rule-based detection
produces results whose derivation can be traced precisely from evidence to
conclusion.

SP 800-94 also discusses alert tuning and the operational cost of false
positives. This informed the threshold design described in Section 4.5: an
alert that fires indiscriminately imposes a cost on the administrator without
providing corresponding value.

## 2.3 The NIST Cybersecurity Framework

The NIST Cybersecurity Framework 2.0 organises cybersecurity activity into
six functions: Govern, Identify, Protect, Detect, Respond and Recover.

Mini-SIEM operates within **Detect**, and specifically within the *Adverse
Event Analysis* category — determining whether observed activity indicates an
attack. It touches **Respond** only insofar as alerts can be acknowledged;
automated response is out of scope. Positioning the system explicitly within
a recognised framework clarifies both what it does and, equally importantly,
what it does not attempt.

## 2.4 Existing Systems

| System | Type | Strengths | Limitations for this context |
|---|---|---|---|
| **Splunk** | Commercial SIEM | Mature, scalable, powerful query language, extensive integrations | Licensing cost; substantial infrastructure; steep learning curve |
| **Elastic Stack** | Open-source | Flexible, strong visualisation, large ecosystem | Multi-component deployment; significant memory and storage; considerable configuration |
| **Wazuh** | Open-source SIEM/HIDS | Free; agent-based; file integrity monitoring; compliance reporting | Agent deployment on every host; complex initial setup |
| **OSSEC** | Host IDS | Lightweight; established | Limited visualisation; primarily host-focused |
| **Manual inspection** | — | No cost or setup | Slow; error-prone; does not scale; cannot correlate across sources |

Each of these platforms is technically superior to the system presented here
in capability and scale. The relevant question for this project is not which
is most capable, but which approach is appropriate for a small laboratory
that needs monitoring it can actually deploy and understand.

## 2.5 Research Gap

The gap this project addresses is one of *appropriate scale*, not of
capability. Enterprise platforms are over-provisioned for a laboratory
environment; manual inspection is under-provisioned. Between them lies a need
for a system that implements the complete SIEM pipeline — collection,
normalisation, correlation, alerting, presentation — narrowly enough that it
can be deployed in minutes and understood in full.

Mini-SIEM therefore implements a deliberately narrow but complete vertical
slice: authentication events only, four detection rules, one dashboard. Every
stage of the pipeline is present and functional. This is a more instructive
and more defensible construction for a final year project than a broad but
shallow imitation of a commercial product, because each component can be
fully implemented, tested and explained.

<div class="pagebreak"></div>

# Chapter 3 — Requirement Analysis and Methodology

## 3.1 Stakeholders

| Stakeholder | Need |
|---|---|
| Laboratory / system administrator | To see which monitored hosts are under attack, and how seriously, without reading raw logs |
| Cybersecurity students | To understand how detection rules, correlation and alerting operate in practice |
| Small offices | To evaluate the monitoring concept before committing to a larger platform |
| Project evaluators | To verify functionality through a repeatable demonstration |

## 3.2 Functional Requirements

| ID | Requirement | Priority |
|---|---|---|
| FR-01 | The system shall allow an administrator to log in securely. | Must |
| FR-02 | The system shall restrict dashboard, host, threat IP and alert pages to authenticated users. | Must |
| FR-03 | The system shall allow the administrator to add, view, update and delete monitored hosts. | Must |
| FR-04 | The system shall allow the administrator to add and manage suspicious IP addresses in a threat registry. | Must |
| FR-05 | The system shall support sample log and event input for testing and demonstration. | Must |
| FR-06 | The system shall detect failed login, invalid user and suspicious IP patterns from logs and events. | Must |
| FR-07 | The system shall generate alerts with severity, timestamp, host and source IP where available. | Must |
| FR-08 | The system shall display alerts and summary statistics on a web dashboard. | Must |
| FR-09 | The system shall provide a repeatable demonstration workflow for evaluation. | Must |

## 3.3 Non-Functional Requirements

| Attribute | Requirement | Design consequence |
|---|---|---|
| Usability | Comprehensible to students and laboratory administrators | Bootstrap interface; plain-language alert messages; no command line required for normal operation |
| Security | Administrative access protected by login and session management | Hashed passwords; CSRF protection on forms and API; server-side validation |
| Performance | Sample logs processed within reasonable time during demonstration | In-process analysis; indexed database columns; bulk queries in place of per-row lookups |
| Maintainability | Code organised into models, routes, services, templates and static files | Application factory; blueprints; service layer separated from HTTP layer |
| Portability | Runs on local Windows or Linux with Python and Flask | SQLite requiring no server; pure-Python dependencies; no build step |
| Ethical compliance | Only sample logs or authorised systems | Synthetic data confined to reserved address ranges; no scanning capability |

## 3.4 Use Cases

**UC-01 — Authenticate.** The administrator submits credentials. The system
verifies them against a stored hash and establishes a session. On failure a
deliberately generic message is displayed so that valid usernames cannot be
enumerated.

**UC-02 — Manage monitored hosts.** The administrator records a host with
hostname, IP address, operating system type and optional description. The
system validates the address format and rejects duplicates.

**UC-03 — Maintain threat intelligence.** The administrator records an
address as `UNKNOWN`, `TRUSTED` or `BANNED`, optionally with a source and
notes. The recorded status directly modifies detection behaviour.

**UC-04 — Ingest logs.** The administrator triggers collection from a
monitored host, or imports a sample log file. The system parses records into
normalised events, archives the raw batch, and stores the events.

**UC-05 — Review alerts.** The administrator opens the dashboard, reviews
alerts ranked by severity, applies filters, and acknowledges those that have
been handled.

## 3.5 Development Methodology

An incremental approach was adopted, structured around the two project
phases.

| Phase | Activity | Outcome |
|---|---|---|
| Requirement analysis | Identify core functions needed for approval and demonstration | Requirements in Sections 3.2 and 3.3 |
| System design | Design modules, schema, detection rules and dashboard workflow | Chapter 4 |
| Implementation | Develop routes, models, forms, parsers and detection logic | Chapter 5 |
| Testing | Verify login, protected pages, data entry, parsing, detection and display | Chapter 6 |
| Documentation | Prepare report, manual, installation guide and demonstration script | Accompanying documents |

The incremental structure proved valuable in one specific respect. The
initial detection implementation was completed early enough for its
inadequacy to become apparent during the first phase, leaving time for a
redesign in the second. Had detection been implemented late, the flawed
version would have been submitted.

<div class="pagebreak"></div>

# Chapter 4 — System Design

## 4.1 Architecture

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

**Figure 4.1 — Mini-SIEM system architecture.**

Data flows in one direction: sources are parsed, evidence is retained,
events are stored, rules are applied, alerts are produced, and results are
presented. Two properties of this arrangement matter.

First, archival occurs *before* analysis. If the detection logic is later
found to be defective, the original evidence remains intact and can be
re-processed.

Second, events are stored *separately* from alerts. This is the single most
consequential design decision in the project, and Section 4.4 examines its
implications.

## 4.2 Module Decomposition

| Module | Responsibility | Implementation |
|---|---|---|
| Authentication | Session establishment and route protection | `app/blueprints/auth.py` |
| Host Management | CRUD for monitored hosts; live telemetry | `app/blueprints/api/hosts.py` |
| Threat Intelligence | Suspicious IP registry | `app/blueprints/api/threat_intel.py` |
| Log Collection | Retrieval from Linux and Windows hosts | `app/services/log_collector.py` |
| Log Parsing | Format detection and normalisation | `app/services/sample_loader.py` |
| Log Analysis | Ingestion pipeline: archive, store, detect | `app/services/log_analyzer.py` |
| Detection | The four rules and severity assignment | `app/services/detection.py` |
| Retention | Parquet archival | `app/services/data_manager.py` |
| Dashboard | Summary statistics and chart data | `app/blueprints/api/stats.py` |
| Validation | Server-side input checking | `app/validators.py` |

## 4.3 The Normalised Event Format

Every log source, irrespective of origin, is reduced to a single structure:

```python
{
    'timestamp':  datetime,   # when the event occurred (naive UTC)
    'alert_type': str,        # FAILED_LOGIN, INVALID_USER, ...
    'source_ip':  str,        # originating address, or a LOCAL marker
    'user':       str,        # targeted username
    'message':    str,        # human-readable description
    'raw_log':    str,        # original line, retained as evidence
}
```

Because normalisation occurs at the system boundary, the detection rules
never need to determine whether an event originated from a Linux `auth.log`
file, a Windows Security export, or a synthetic generator. The rules operate
on a uniform structure.

The practical consequence is extensibility. Supporting an additional log
source — a web server access log, a firewall log — requires writing one
parser that emits this structure. The detection engine requires no
modification whatsoever.

## 4.4 Database Design

Six tables implement the persistent model.

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

**Figure 4.2 — Entity relationship diagram.**

### Separation of Events and Alerts

An **event** is an observation: something occurred and was recorded. An
**alert** is a judgement: an event, or a pattern of events, is considered
worthy of attention.

Storing only alerts — as the initial prototype did — makes the judgement
permanent and the evidence disposable. The detection rules could never be
re-applied without contacting every monitored host again and re-reading its
logs, which may no longer contain the relevant records.

Storing events independently makes analysis repeatable. Rules can be
re-executed at any time against evidence already gathered. This enables the
behaviour demonstrated in Section 6.5: when an administrator marks an address
as hostile, the system re-evaluates evidence collected days earlier and
raises its assessed severity accordingly. Without this separation, that
capability would not exist.

### Alert-to-Event Anchoring

Each alert records the `event_id` that triggered it. This serves two
purposes. It provides traceability from a judgement back to the specific
evidence supporting it. It also supplies a natural de-duplication key: an
alert is created only if no alert with the same `(rule_id, event_id)` pair
already exists, which makes repeated execution of the detection engine
idempotent.

### Timestamp Handling

SQLite discards timezone information when storing datetime values, so all
timestamps are stored as naive UTC. Mixing timezone-aware and naive values
would produce incorrect results in the time-window arithmetic of rule R-01;
a single helper function therefore produces every default timestamp in the
system.

## 4.5 Detection Rule Design

| Rule | Name | Logic | Severity |
|---|---|---|---|
| R-01 | Failed Login | ≥ N authentication failures for the same username and source IP within a sliding time window | Medium |
| R-02 | Invalid User | An authentication attempt for a username that does not exist | Low |
| R-03 | Threat IP Match | The event's source IP is marked `BANNED` in the registry | High |
| R-04 | Multiple Host Attempt | One source IP produces failures against ≥ M distinct monitored hosts | High |

### Rationale for R-01

The obvious implementation — raise an alert for every failed login — was
implemented first and subsequently rejected. A user mistyping a password
three times generates three alerts identical in form to those produced by a
brute-force attack. The administrator is presented with a list in which
routine error and genuine attack are indistinguishable, which conveys no more
information than the raw log did.

Requiring a threshold *within a bounded time window* distinguishes a burst
from occasional human error. A sliding window is used rather than fixed
buckets so that an attack spanning a boundary is still detected.

### Rationale for R-02 Severity

A single probe for a non-existent account is ordinary background noise on any
internet-facing host. It is recorded because a *pattern* of such probes is
meaningful, but an individual occurrence does not warrant urgency. Assigning
it higher severity would dilute the high-severity category and obscure
genuinely serious alerts.

### Rationale for R-04

An address producing failures against several distinct machines is
qualitatively different from one producing failures against a single machine.
The former indicates scanning or credential spraying; the latter is
consistent with a forgotten password. This difference in kind justifies the
difference in assigned severity.

### Severity Semantics

Severity reflects confidence combined with impact:

- **Low** — activity consistent with background noise; recorded for pattern
  analysis
- **Medium** — activity indicating deliberate action against one target
- **High** — activity confirmed hostile by human classification, or exhibiting
  a pattern characteristic of scanning

## 4.6 Trust Model

The registry status of a source address modifies detection behaviour
directly:

| Status | Effect |
|---|---|
| `UNKNOWN` | Default. Tracked with a hit count; ordinary rules apply. |
| `TRUSTED` | All alerts suppressed. Prevents a known scanner or administrative jump host from flooding the alert list. |
| `BANNED` | Any event escalates to High severity via R-03. |

Addresses observed in failure events are automatically registered as
`UNKNOWN`, so the registry populates itself from observed activity. The
administrator's task is reduced to deciding which entries to promote or
demote, rather than entering addresses manually.

<div class="pagebreak"></div>

# Chapter 5 — Implementation

## 5.1 Technology Selection

| Layer | Choice | Justification | Alternatives considered |
|---|---|---|---|
| Language | Python 3.10+ | Strong text-processing and data libraries; team familiarity | — |
| Web framework | Flask | Minimal and explicit; readable in full | Django — excessive implicit machinery for this scale |
| ORM | SQLAlchemy | Portable schema definition; protects against SQL injection | Raw `sqlite3` — more error-prone |
| Database | SQLite | Zero configuration; single file; adequate for laboratory scale | PostgreSQL — requires a server |
| Authentication | Flask-Login | Session management with a small API surface | Custom implementation — unnecessary security risk |
| Forms and CSRF | Flask-WTF | Validation and CSRF tokens together | Manual token handling — error-prone |
| Retention | pandas + pyarrow | Columnar, compressed, efficient to filter | CSV — larger and slower; JSON — no schema |
| SSH | paramiko | Pure-Python SSH; no external binary | Shelling out to `ssh` — poor error handling |
| Front-end | Bootstrap 5 + ES modules | No build step; directly readable | React — build tooling adds no value here |
| Charts | Chart.js | Lightweight and declarative | D3 — greater power than required |
| Testing | pytest | Concise tests; strong fixture model | `unittest` — more boilerplate |

Avoiding a JavaScript build pipeline was deliberate: the entire system can be
read and executed directly from the repository, which matters for work that
must be inspected and defended.

Bootstrap and Chart.js are served from `app/static/vendor/` rather than a
content delivery network, so the system makes no external network requests
and functions without internet connectivity.

## 5.2 Code Organisation

```
mini-siem/
├── app/
│   ├── blueprints/
│   │   ├── api/
│   │   │   ├── hosts.py          200 lines
│   │   │   ├── events.py         187 lines
│   │   │   ├── stats.py          123 lines
│   │   │   ├── threat_intel.py    70 lines
│   │   │   └── alerts.py          66 lines
│   │   ├── auth.py                41 lines
│   │   └── ui.py                  24 lines
│   ├── services/
│   │   ├── detection.py          334 lines
│   │   ├── sample_loader.py      296 lines
│   │   ├── log_analyzer.py       151 lines
│   │   ├── log_collector.py      145 lines
│   │   ├── data_manager.py        81 lines
│   │   ├── remote_client.py       58 lines
│   │   └── win_client.py          23 lines
│   ├── models.py                 187 lines
│   ├── validators.py              55 lines
│   ├── static/js/               1,142 lines
│   └── templates/                 692 lines
├── tests/                          905 lines
├── scripts/                        223 lines
└── samples/
```

Approximate totals: 2,205 lines of application Python, 905 lines of tests,
1,142 lines of JavaScript and 692 lines of templates — approximately 5,200
lines in total.

## 5.3 Authentication

Passwords are hashed using `werkzeug.security`, which applies scrypt with
per-password salting. The plain-text value is never stored, and cannot be
recovered from the database.

Login failures produce a deliberately generic message that does not indicate
whether the username or the password was incorrect, preventing username
enumeration. Session cookies are marked `HttpOnly` with `SameSite=Lax`, and
the `Secure` flag is configurable for HTTPS deployment. The post-login
redirect target is accepted only if it is a relative path within the
application, preventing an open-redirect vulnerability.

## 5.4 Log Collection

**Linux.** Collection uses `paramiko` to establish an SSH connection and
execute `journalctl` with JSON output, restricted to records since the last
successful fetch. Incremental collection avoids repeatedly transferring and
re-parsing the same records.

**Windows.** Collection invokes PowerShell's `Get-WinEvent` filtered to
Security event ID 4625 (failed logon), converting each record to JSON. This
reads the Security log of the machine on which Mini-SIEM runs and requires an
elevated shell; it is not a remote agent.

Collection failure on one host does not abort the batch. A host that is
unreachable is reported and skipped, and other hosts continue to be
processed.

## 5.5 Log Parsing

Three parsers and a synthetic generator produce the normalised event
structure.

| Format | Source | Parser |
|---|---|---|
| Linux `auth.log` / journald text | SSH collection or file import | `parse_auth_log` |
| Windows Security CSV | Event Viewer export | `parse_windows_csv` |
| Normalised JSON | Programmatic input | `parse_json` |
| Synthetic | Built-in generator | `generate_synthetic` |

Three implementation details merit note.

**Pattern ordering.** The line `Failed password for invalid user bob from
198.51.100.4` matches both the invalid-user pattern and the failed-password
pattern. Patterns are evaluated most-specific-first, so the line is correctly
classified as `INVALID_USER` rather than `FAILED_LOGIN`.

**Year inference.** Syslog timestamps such as `Aug 12 09:14:02` omit the
year. The parser assumes the most recent occurrence: if applying the current
year places the date more than one day in the future, the previous year is
used instead.

**Malformed input.** Unrecognised lines are skipped rather than guessed at. A
partially malformed file still imports the records that can be parsed
correctly. Fabricating event data would undermine the evidential value of the
entire system, so no attempt is made to infer missing fields.

## 5.6 Forensic Retention

Each collected or imported batch is written to a timestamped Parquet file
before analysis begins. Parquet is columnar and compressed, which keeps
retained logs small and efficient to filter during replay.

Critically, clearing events and alerts from the database does not delete
these archives. This is verified by test: after the database is wiped, the
archived file remains present, readable and complete. This satisfies the
retention principle set out in NIST SP 800-92 — evidence survives the
analytical system built on top of it.

## 5.7 The Detection Engine

Implemented in `app/services/detection.py`, 334 lines. This is the core
contribution of the project.

### Execution Model

`DetectionEngine.run()` performs four steps:

1. Load candidate events, optionally scoped to one host or a time range.
2. Refresh the threat registry, recording every routable source address
   observed in a failure event together with a hit count.
3. Evaluate each rule, producing *candidate* alerts rather than writing
   directly to the database.
4. Persist candidates, discarding duplicates and suppressing any originating
   from a `TRUSTED` address.

Separating evaluation from persistence keeps each rule a pure function of the
events supplied to it. Rules can therefore be tested independently, with both
positive and negative cases, without database interaction.

### R-01 — Failed Login

Authentication failures are grouped by `(host, source IP, username)`. Within
each group a sliding window advances through the events; when the count
within the window reaches the threshold — five failures within ten minutes by
default — a single alert is raised, anchored to the event that completed the
burst.

Grouping by username as well as address means that five failures against
`root` and five against `admin` from one address constitute two distinct
attempts and produce two alerts.

An early implementation raised an alert for every event once the threshold
was exceeded, so a ten-event burst produced five alerts describing one
incident. Anchoring to a single event and terminating the scan for that group
produces exactly one alert per burst.

### R-02 — Invalid User

Any event of type `INVALID_USER` produces a Low severity alert naming the
attempted username and source address.

### R-03 — Threat IP Match

Any event whose source address is marked `BANNED` produces a High severity
alert. This rule is applied per event and is intentionally the most prolific:
an address confirmed hostile justifies recording every interaction it has
with the monitored estate.

### R-04 — Multiple Host Attempt

Failures are grouped by source address across all hosts. An address producing
failures against at least two distinct hosts raises a High severity alert
anchored to the most recent such event.

When analysis is scoped to a single host, this rule nonetheless examines
events from every host, since cross-machine correlation is its entire
purpose.

### De-duplication and Idempotence

An alert is written only when no existing alert shares the same
`(rule_id, event_id)` pair. Existing pairs are retrieved in a single query
rather than one query per candidate.

Consequently, repeated execution of the detection engine is idempotent: the
first run creates alerts and subsequent runs create none. This has practical
value during demonstration, where rules may be re-applied several times.

### Configurable Thresholds

| Setting | Default | Rule |
|---|---|---|
| `DETECTION_FAILED_LOGIN_THRESHOLD` | 5 | R-01 |
| `DETECTION_FAILED_LOGIN_WINDOW_MINUTES` | 10 | R-01 |
| `DETECTION_MULTI_HOST_THRESHOLD` | 2 | R-04 |

Exposing these values acknowledges that appropriate thresholds depend on the
environment. A busy shared server requires a higher threshold than a
single-user workstation.

## 5.8 Dashboard and Triage

| Page | Purpose |
|---|---|
| `/login` | Authentication |
| `/` | Dashboard: statistics, charts, host status, recent alerts |
| `/alerts` | Full alert table with filtering, pagination and acknowledgement |
| `/events` | Event browsing and sample log import |
| `/config` | Host management and threat intelligence registry |

The dashboard presents four summary cards and three charts: authentication
failures over seven days (identifying *when* activity occurred), alerts by
severity (the triage picture), and alerts by detection rule (indicating *what
kind* of attack is in progress). A ranked list of the most active source
addresses, annotated with registry status, supports the decision of which
addresses to ban.

All dynamic content is inserted using `textContent` rather than `innerHTML`.
Since displayed values include usernames and log messages originating from
untrusted input, this eliminates a cross-site scripting vector by
construction rather than by escaping.

## 5.9 Security Implementation

Because the system is itself a security tool, its own security was treated as
a requirement rather than an afterthought.

| Area | Measure |
|---|---|
| Password storage | scrypt hashing with per-password salt |
| Username enumeration | Generic failure message |
| Session cookies | `HttpOnly`, `SameSite=Lax`, configurable `Secure` |
| Open redirect | Post-login target restricted to relative paths |
| CSRF | Token required on forms *and* JSON API; sent as `X-CSRFToken` header |
| SQL injection | All access through the ORM; no string-concatenated SQL |
| Cross-site scripting | All dynamic content set via `textContent` |
| Path traversal | Sample filenames resolved and confirmed within the samples directory |
| Upload size | Capped at 2 MB by `MAX_CONTENT_LENGTH` |
| Input validation | Server-side validation of addresses, hostnames and enumerated values |
| Secrets | Read from `.env`, which is excluded from version control |

The CSRF measure warrants specific comment. The initial prototype exempted
the entire JSON API from CSRF protection for convenience. This was a genuine
vulnerability: any website visited by an authenticated administrator could
have issued state-changing requests against the application. The exemption
was removed and the front end modified to transmit the token as a header.

<div class="pagebreak"></div>

# Chapter 6 — Testing and Results

## 6.1 Testing Strategy

Testing addresses three questions. Does each component behave correctly in
isolation? Do components function correctly together? And — most importantly
for a detection system — do the rules refrain from firing when they should
not?

The third question received particular attention. A detection rule that fires
on everything is trivially "correct" in the sense that it never misses an
attack, while being operationally worthless. Negative test cases are
therefore treated as first-class evidence throughout.

Tests execute against a temporary in-memory database and a temporary storage
directory, leaving the development database untouched.

## 6.2 Test Suite

```
python -m pytest
```

**Result: 95 passed.**

| File | Tests | Coverage |
|---|---|---|
| `test_detection.py` | 21 | All four rules, positive and negative cases |
| `test_sample_import.py` | 27 | Three parsers, import API, bundled files |
| `test_dashboard.py` | 14 | Statistics endpoints, alert listing, filtering |
| `test_hosts.py` | 11 | Host CRUD, validation, cascade deletion |
| `test_auth.py` | 10 | Login, route protection, session handling |
| `test_threat_intel.py` | 9 | Registry CRUD, status filtering, validation |
| `test_persistence.py` | 3 | Restart survival, archive retention |

## 6.3 Detection Rule Verification

| Rule | Positive case | Negative case |
|---|---|---|
| R-01 | 6 failures within 3 minutes → 1 alert | 4 failures (below threshold) → none; 6 failures across 6 hours (outside window) → none |
| R-02 | Invalid-user event → 1 alert | Ordinary failed login → none |
| R-03 | Event from `BANNED` address → 1 alert | Event from unlisted address → none |
| R-04 | Same address on 2 hosts → 1 alert | Same address on 1 host → none |

Additional properties verified: R-01 produces one alert per burst rather than
one per event; R-01 distinguishes different usernames from the same address;
R-04 correlates across hosts even when analysis is scoped to one host;
repeated execution produces no duplicate alerts; events from local console
markers do not enter the threat registry.

## 6.4 Proposal Test Cases

| ID | Test Case | Expected Result | Status |
|---|---|---|---|
| TC-01 | Login Test | Wrong credentials rejected; valid accepted | Pass |
| TC-02 | Protected Page Test | Redirect to login; API returns 401 | Pass |
| TC-03 | Host Management Test | Host appears and persists | Pass |
| TC-04 | Threat IP Test | Address appears in registry | Pass |
| TC-05 | Log Analysis Test | Events extracted, stored and archived | Pass |
| TC-06 | Alert Test | Alerts carry timestamp, address, host and severity | Pass |
| TC-07 | Dashboard Test | Alerts, counts and summaries displayed | Pass |
| TC-08 | Persistence Test | Records survive restart | Pass |

## 6.5 Reference Dataset Results

The following is reproducible with:

```
python scripts/seed_sample_data.py --reset-registry
```

Two hosts are created and `samples/linux_auth_sample.log` is imported against
both.

**Before any address is marked hostile:**

```
Events in database : 34
Alerts in database : 13

  R-01 Failed Login          :  2    (one burst per host)
  R-02 Invalid User          :  8    (4 invalid users × 2 hosts)
  R-03 Threat IP Match       :  0    (nothing banned yet)
  R-04 Multiple Host Attempt :  3    (3 addresses seen on both hosts)

  Severity:  High 3  |  Medium 2  |  Low 8
```

**After marking `203.0.113.50` as `BANNED` and re-running detection:**

```
R-03 raised 18 new alerts

  Total alerts   : 31
  High severity  : 21
  Banned IPs     : 1
```

### Interpretation

This is the central result of the project. A single item of threat
intelligence changed the system's assessment of evidence that had *already
been collected*. No host was contacted; no log file was re-read. Total alerts
increased from 13 to 31, and high-severity alerts from 3 to 21, solely
because a human classified one address as hostile.

This behaviour is what distinguishes a SIEM from a log viewer. A log viewer
displays what was recorded. A SIEM re-evaluates what was recorded as
understanding improves. The architectural precondition is the separation of
events from alerts described in Section 4.4; without it, the only way to
obtain this result would be to re-collect logs that may no longer exist.

Most active source addresses in the reference dataset:

| Source IP | Failure events | Registry status |
|---|---|---|
| `203.0.113.50` | 18 | `BANNED` |
| `198.51.100.23` | 6 | `UNKNOWN` |
| `192.0.2.77` | 6 | `UNKNOWN` |

The failures attributed to `192.0.2.77` are deliberately distributed across
ninety minutes in the sample data, keeping them below the R-01 window
threshold. This demonstrates the rule correctly distinguishing a slow trickle
from a burst — the behaviour that the redesign was undertaken to achieve.

## 6.6 Performance

The reference dataset of 34 events is parsed, archived, stored and analysed
in well under one second on a standard laptop. Database columns used by rule
queries and dashboard filters are indexed, and the detection engine retrieves
existing alert keys in a single bulk query rather than issuing one query per
candidate alert.

This performance is adequate for the intended scale and satisfies the
non-functional requirement. It should not be extrapolated to enterprise event
volumes; see Section 7.4.

<div class="pagebreak"></div>

# Chapter 7 — Evaluation and Discussion

## 7.1 Requirements Evaluation

| ID | Requirement | Status | Evidence |
|---|---|---|---|
| FR-01 | Secure administrator login | Met | `test_auth.py` |
| FR-02 | Protected pages restricted | Met | 4 pages and 5 API endpoints tested |
| FR-03 | Host add/view/update/delete | Met | `test_hosts.py` |
| FR-04 | Threat IP registry management | Met | `test_threat_intel.py` |
| FR-05 | Sample log and event input | Met | 3 formats plus generator, 27 tests |
| FR-06 | Detect failed login, invalid user, suspicious IP | Met | 4 rules, 21 tests |
| FR-07 | Alerts with severity, timestamp, host, source IP | Met | Field-completeness test |
| FR-08 | Dashboard alerts and summary statistics | Met | 5 endpoints, 3 charts, 14 tests |
| FR-09 | Repeatable demonstration workflow | Met | Seed script and documented walkthrough |

| Non-functional attribute | Assessment |
|---|---|
| Usability | Five pages; no command line required for normal operation |
| Security | Hashing, CSRF on forms and API, validation, path-traversal protection |
| Performance | Reference dataset processed in under one second |
| Maintainability | Service layer separated from HTTP layer; rules are pure functions; 95 regression tests |
| Portability | Runs on Windows and Linux; no database server; no build step; no internet requirement |
| Ethical compliance | Synthetic data and reserved address ranges only; no offensive capability |

All nine functional requirements and all six non-functional attributes are
satisfied.

## 7.2 Comparison with Existing Systems

| Capability | Splunk | Elastic | Wazuh | Mini-SIEM |
|---|---|---|---|---|
| Log collection | Extensive | Extensive | Extensive | SSH and Windows Security log |
| Normalisation | Yes | Yes | Yes | Yes |
| Correlation rules | Advanced | Advanced | Advanced | Four documented rules |
| Threat intelligence | Yes | Yes | Yes | Manual registry with auto-population |
| Dashboard | Advanced | Advanced | Yes | Statistics and three charts |
| Setup time | Days | Days | Hours | Minutes |
| Cost | Licensed | Free (infrastructure cost) | Free | Free |
| Comprehensible in full | No | No | No | Yes |

The final row is the relevant one for this project's purpose. The
established platforms exceed Mini-SIEM in every capability dimension. What
Mini-SIEM offers is a complete pipeline that can be read, understood, modified
and explained in its entirety — which is precisely what an educational
prototype requires.

## 7.3 Design Decisions in Retrospect

**Separating events from alerts** was correct, and its value exceeded initial
expectations. It was adopted to permit rule re-execution; it turned out to
enable the retrospective re-evaluation demonstrated in Section 6.5, which
became the project's most significant result.

**Rule-based rather than anomaly-based detection** was correct for this
context. Every alert can be traced to the specific evidence and the specific
rule that produced it, which is essential both for defending the work and for
teaching the concepts.

**The R-01 redesign** was the most instructive episode in the project. The
original implementation satisfied a literal reading of the requirement —
"detect failed logins" — while producing output no administrator could act
upon. The lesson is that correctness and usefulness are distinct properties,
and that for detection systems the harder question is not *what to detect*
but *what not to report*.

**Not using a JavaScript build pipeline** was correct. The absence of a build
step means the system runs directly from a checkout, which repeatedly proved
valuable during development and will matter during examination.

**Vendoring the front-end libraries** was correct and should have been done
earlier. The dependency on a content delivery network was a latent failure
mode that would have manifested only during a demonstration in a venue
without internet access.

## 7.4 Limitations

1. **Detection scope.** Authentication events only. No process monitoring,
   file integrity checking, network flow analysis or malware detection.
   Behavioural and anomaly-based detection are absent.

2. **Log format dependency.** Alert accuracy depends entirely on input
   conforming to recognised formats. Unrecognised lines are skipped silently;
   a non-standard SSH configuration could emit records the parsers do not
   match.

3. **Windows collection is local only.** It reads the Security log of the
   host on which the application runs and requires an elevated shell.
   Monitoring multiple Windows machines would require an agent architecture
   that has not been implemented.

4. **Scale.** SQLite and synchronous in-process collection are appropriate to
   laboratory volumes. Enterprise event rates would require a different
   storage engine and asynchronous ingestion.

5. **No real-time streaming.** Collection is triggered manually or by
   re-execution. No scheduler is implemented.

6. **Single-user model.** One administrator role. No per-user permissions, no
   audit trail of administrator actions, no multi-tenancy.

7. **Static thresholds.** Detection thresholds do not adapt to a host's
   normal traffic level; appropriate values must be chosen by the
   administrator.

<div class="pagebreak"></div>

# Chapter 8 — Conclusion and Future Work

## 8.1 Conclusion

This project set out to develop a lightweight web-based security event
monitoring system for educational and small-laboratory use. All nine
functional requirements and all six non-functional attributes defined in
Chapter 3 have been satisfied.

The delivered system collects authentication logs from Linux hosts over SSH
and from Windows Security event logs, or imports sample logs in three
formats. It normalises all sources into a single event structure, retains raw
evidence in compressed columnar archives that survive database reset, applies
four documented detection rules with graded severity, and presents results
through a dashboard providing statistics, charts, filtering and
acknowledgement. The implementation comprises approximately 5,200 lines of
code and is verified by 95 automated tests, all of which pass.

Two outcomes are of particular significance.

The first concerns detection quality. The project's initial detection
implementation raised an alert for every failed login. It was technically
functional and operationally useless: an administrator presented with a wall
of identical alerts possesses no more information than they had reading the
raw log. Redesigning the rule around a threshold within a sliding time window
— and verifying explicitly that it does *not* fire on four attempts, or on
six attempts distributed across six hours — converted a log echo into a
detection rule. The negative test cases proved more instructive than the
positive ones, and the episode illustrates that in detection systems the
difficult question is not what to detect but what to refrain from reporting.

The second concerns architecture. By storing normalised events separately
from the alerts derived from them, the system can re-evaluate evidence when
knowledge changes. Marking a single address as hostile raised high-severity
alerts from three to twenty-one across data already resident on disk, with no
host contacted and no log re-read. This capacity to reinterpret the past as
understanding improves is the essential characteristic of security
information and event management, and the project reproduces it faithfully at
laboratory scale.

The system remains a deliberately bounded educational prototype. It does not
replace an enterprise SIEM platform and was never intended to. Within its
stated scope it is complete, tested, documented and demonstrable.

## 8.2 Future Work

Ordered by the ratio of value delivered to effort required:

| Enhancement | Rationale |
|---|---|
| Scheduled automatic collection | Converts the system from on-demand to continuous monitoring |
| PDF and Excel export of alert reports | Supports incident record-keeping |
| Email or SMS notification for High severity alerts | Closes the loop between detection and response |
| Additional log formats | The normalised event structure is designed for this; each addition requires one parser |
| Alert comments and assignment | Supports triage by more than one person |
| Per-host adaptive thresholds | Reduces false positives on busy hosts |
| Geolocation and ASN enrichment | Adds context to threat intelligence decisions |
| Windows agent for remote collection | Removes the local-only limitation |
| Role-based access control | Separates viewing from administration |
| Log integrity verification | Cryptographic hashing of archives to detect tampering |

<div class="pagebreak"></div>

# References

1. National Institute of Standards and Technology. (2006). *Guide to Computer Security Log Management*. NIST Special Publication 800-92.

2. Scarfone, K., & Mell, P. (2007). *Guide to Intrusion Detection and Prevention Systems (IDPS)*. NIST Special Publication 800-94.

3. National Institute of Standards and Technology. (2024). *The NIST Cybersecurity Framework (CSF) 2.0*. NIST CSWP 29.

4. OWASP Foundation. (2021). *OWASP Top 10 Web Application Security Risks*.

5. Stallings, W., & Brown, L. (2018). *Computer Security: Principles and Practice* (4th ed.). Pearson.

6. Arkko, J., Cotton, M., & Vegoda, L. (2010). *IPv4 Address Blocks Reserved for Documentation*. RFC 5737. Internet Engineering Task Force.

7. Rekhter, Y., Moskowitz, B., Karrenberg, D., de Groot, G. J., & Lear, E. (1996). *Address Allocation for Private Internets*. RFC 1918. Internet Engineering Task Force.

8. Pallets Projects. (n.d.). *Flask Documentation*. https://flask.palletsprojects.com/

9. SQLAlchemy Project. (n.d.). *SQLAlchemy ORM Documentation*. https://docs.sqlalchemy.org/

10. Python Software Foundation. (n.d.). *Python Documentation*. https://docs.python.org/3/

11. Apache Software Foundation. (n.d.). *Apache Parquet Documentation*. https://parquet.apache.org/

12. Percival, C. (2009). *Stronger Key Derivation via Sequential Memory-Hard Functions*. BSDCan.

<div class="pagebreak"></div>

# Appendices

## Appendix A — Installation and Reproduction

```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
python scripts/create_admin.py
python scripts/seed_sample_data.py --reset-registry
python -m pytest
flask run
```

The application is then available at `http://127.0.0.1:5000`.

## Appendix B — Demonstration Script

1. Log in as administrator.
2. Configuration → add two monitored hosts.
3. Configuration → add `203.0.113.50` to the registry as `UNKNOWN`.
4. Events → import `linux_auth_sample.log` against both hosts.
5. Observe: R-01 fires once per burst; R-02 for each invalid user; R-04
   because one address reached two hosts. R-03 remains at zero.
6. Configuration → mark `203.0.113.50` as `BANNED`.
7. Alerts → re-run detection. R-03 fires and severity escalates.
8. Dashboard → statistics and charts reflect the revised totals.
9. Alerts → filter to High severity; acknowledge one alert.
10. Log out; confirm protected pages are inaccessible.

## Appendix C — Detection Rule Summary

| Rule | Trigger | Threshold | Severity |
|---|---|---|---|
| R-01 | Repeated authentication failures, same user and source | 5 within 10 minutes | Medium |
| R-02 | Authentication attempt for non-existent user | 1 occurrence | Low |
| R-03 | Source address marked `BANNED` | 1 occurrence | High |
| R-04 | One source address failing against multiple hosts | 2 distinct hosts | High |

## Appendix D — Team Contributions

| Member | Roll No. | Contribution |
|---|---|---|
| Yasir Parveez | 2K23/CSM/146 | Group leader; Flask architecture, authentication, system integration, supervisor liaison, documentation management |
| Abdul Fatah | 2K23/CSM/03 | Database design, host management module, threat intelligence registry, test data preparation, repository organisation |
| Mushahid Hussain | 2K23/CSM/100 | Log parsers, detection rules, dashboard interface and charts, alert presentation, testing evidence, demonstration preparation |

Individual contribution evidence is maintained through version control
history, meeting records and the project progress log.

## Appendix E — Ethical Statement

All development and testing used synthetic log data and addresses drawn from
ranges reserved for documentation (RFC 5737: `192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`) or private use (RFC 1918). No test data
refers to any real system.

No unauthorised scanning, exploitation, password cracking or credential
collection was performed at any stage. The system implements no offensive
capability. Live log collection is restricted by design to hosts for which
the operator supplies their own credentials, and the accompanying
documentation states that it must be directed only at systems the operator
owns or has written permission to monitor.

No password, token, private address or personal data appears in the source
repository, this thesis, or any accompanying screenshot.

## Appendix F — Screenshots

*(Insert demonstration screenshots here. Confirm no credential or private
address is visible in any image.)*

- Figure F.1 — Login page
- Figure F.2 — Dashboard with summary statistics and charts
- Figure F.3 — Alerts page filtered to High severity
- Figure F.4 — Events page following sample import
- Figure F.5 — Threat intelligence registry
- Figure F.6 — Test suite execution showing 95 passing tests
