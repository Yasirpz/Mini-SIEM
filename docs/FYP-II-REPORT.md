# FYP-II Final Report

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

> **Note for the team.** Every measured figure in this report comes from an
> actual run of the delivered system and is reproducible with the commands
> given in Section 6. Re-run them before submission and confirm the numbers
> match. Blank lines are for content only you can supply — screenshots,
> supervisor feedback and meeting records.

---

## Abstract

This project delivers Mini-SIEM, a lightweight web-based Security Information
and Event Management prototype for educational and small-laboratory use. The
system collects authentication logs from Linux hosts over SSH and from
Windows Security event logs, or imports sample logs in three formats,
normalises them into a common event structure, archives the raw evidence to
columnar Parquet files, and applies four rule-based detection rules to
identify suspicious login behaviour. Alerts are assigned `LOW`, `MEDIUM` or
`HIGH` severity and presented through a web dashboard with summary
statistics, charts and filtering.

The delivered system comprises approximately 5,200 lines of code across
Python, JavaScript and templates, and is verified by 95 automated tests
covering the proposal's eight test cases, all four detection rules
individually, three log parsers, and a set of security checks. A key result
is that changing an address's threat-intelligence status retroactively
escalates the severity of evidence already collected: in the reference
dataset, marking one address as banned raised total alerts from 13 to 31 and
high-severity alerts from 3 to 21, without re-collecting a single log line.

**Keywords:** SIEM, security monitoring, log analysis, intrusion detection,
failed login detection, threat intelligence, Flask, Python

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [System Implementation](#2-system-implementation)
3. [The Detection Engine](#3-the-detection-engine)
4. [Log Ingestion Pipeline](#4-log-ingestion-pipeline)
5. [User Interface](#5-user-interface)
6. [Testing and Results](#6-testing-and-results)
7. [Security Implementation](#7-security-implementation)
8. [Evaluation Against Requirements](#8-evaluation-against-requirements)
9. [Limitations](#9-limitations)
10. [Future Enhancements](#10-future-enhancements)
11. [Conclusion](#11-conclusion)
12. [References](#12-references)
13. [Appendices](#13-appendices)

---

## 1. Introduction

### 1.1 Purpose

This report documents the FYP-II phase: completing the detection engine,
building the dashboard and triage interface, testing the system, and
evaluating it against the requirements set out in the proposal. The FYP-I
report covers requirement analysis and system design and is not repeated
here.

### 1.2 Gaps Carried Forward from FYP-I

FYP-I closed with eight known gaps. Each was resolved in FYP-II:

| # | Gap at end of FYP-I | Resolution |
|---|---|---|
| 1 | R-01 alerted on every failed login, with no threshold | Rewritten as a sliding-window threshold rule (§3.2) |
| 2 | R-04 designed but not implemented | Implemented as cross-host correlation (§3.5) |
| 3 | Events existed only in Parquet; rules could not be re-run | `Event` table added; rules operate on stored events (§2.2) |
| 4 | Severity used `WARNING`/`CRITICAL` | Changed to `LOW`/`MEDIUM`/`HIGH` per proposal §6.1 |
| 5 | No sample log import (FR-05 unmet) | Three parsers plus a synthetic generator (§4) |
| 6 | No summary statistics or charts (FR-08 partial) | Five statistics endpoints and three charts (§5.2) |
| 7 | No automated tests | 95-test pytest suite (§6) |
| 8 | JSON API exempt from CSRF | Exemption removed; token sent as a header (§7.2) |

---

## 2. System Implementation

### 2.1 Code Structure and Size

```
mini-siem/
├── app/
│   ├── blueprints/
│   │   ├── api/
│   │   │   ├── hosts.py          200 lines   host CRUD, telemetry, collection
│   │   │   ├── events.py         187 lines   event browsing and import
│   │   │   ├── stats.py          123 lines   dashboard statistics
│   │   │   ├── threat_intel.py    70 lines   IP registry
│   │   │   └── alerts.py          66 lines   alert listing and triage
│   │   ├── auth.py                41 lines   login / logout
│   │   └── ui.py                  24 lines   page routes
│   ├── services/
│   │   ├── detection.py          334 lines   the four detection rules
│   │   ├── sample_loader.py      296 lines   three log parsers + generator
│   │   ├── log_analyzer.py       151 lines   ingestion pipeline
│   │   ├── log_collector.py      145 lines   live Linux/Windows collection
│   │   ├── data_manager.py        81 lines   Parquet retention
│   │   ├── remote_client.py       58 lines   SSH wrapper
│   │   └── win_client.py          23 lines   PowerShell wrapper
│   ├── models.py                 187 lines   six database models
│   ├── validators.py              55 lines   server-side validation
│   ├── static/js/               1,142 lines  ES modules
│   └── templates/                 692 lines  Jinja2 templates
├── tests/                          905 lines  95 tests
├── scripts/                        223 lines  admin creation, demo seeding
└── samples/                                   three sample log files
```

Approximate totals: **2,205 lines** of application Python, **905 lines** of
tests, **1,142 lines** of JavaScript, **692 lines** of templates — around
**5,200 lines** overall.

### 2.2 Data Model

Six tables implement deliverable D-04: `users`, `hosts`, `log_sources`,
`log_archives`, `ip_registry`, `events` and `alerts`. The schema is given in
the FYP-I report §7.

The decision with the greatest consequence was separating **events** from
**alerts**. Because normalised events persist independently, the detection
rules can be re-applied at any moment without contacting a host again. This
single choice is what makes the threat-intelligence demonstration in §6.4
possible.

Each alert stores the `event_id` that triggered it. This gives traceability
from a judgement back to its evidence, and provides the de-duplication key
described in §3.6.

---

## 3. The Detection Engine

Implemented in `app/services/detection.py` (334 lines). This is the core
contribution of the project.

### 3.1 Execution Model

`DetectionEngine.run()` performs the following:

1. Load candidate events, optionally scoped to one host or a time range.
2. Refresh the threat registry — record every routable source address seen in
   a failure event, with a hit count.
3. Evaluate each rule, producing *candidate* alerts rather than writing them
   directly.
4. Persist candidates, discarding duplicates and suppressing anything from a
   `TRUSTED` address.

Separating evaluation from persistence keeps each rule a pure function of the
events it receives, which makes the rules independently testable — every rule
has both positive and negative unit tests (§6.2).

### 3.2 R-01 — Failed Login Rule

**Logic.** Group authentication failures by `(host, source IP, username)`.
Within each group, advance a sliding window; when the number of failures
inside the window reaches the threshold (default 5 within 10 minutes), raise
one alert anchored to the event that completed the burst.

**Severity:** `MEDIUM`.

**Why a sliding window rather than a simple count.** Counting failures
without regard to time would treat six failures spread over six hours — a
user repeatedly mistyping a password across a working day — identically to
six failures in ninety seconds. The window makes the rule specific to bursts.
A *sliding* window is used rather than fixed buckets so that an attack
straddling a bucket boundary is still detected.

**Why one alert per burst.** An early implementation raised an alert for
every event once the threshold was crossed, so a ten-event burst produced
five alerts describing the same incident. Anchoring to a single event and
stopping the scan for that group produces one alert per burst. This is
verified by `test_r01_raises_one_alert_per_burst_not_per_event`.

**Grouping by username as well as IP.** Five failures against `root` and five
against `admin` from the same address are two distinct attempts and produce
two alerts, verified by `test_r01_separates_different_usernames`.

### 3.3 R-02 — Invalid User Rule

**Logic.** Any event of type `INVALID_USER` raises an alert naming the
attempted username and source address.

**Severity:** `LOW`. A single probe for a non-existent account is common
background noise on any internet-facing host. It is recorded because a
*pattern* of such probes is meaningful, but an individual occurrence does not
warrant urgency. Rating it higher would drown the genuinely serious alerts.

### 3.4 R-03 — Threat IP Match Rule

**Logic.** Any event whose source address is marked `BANNED` raises a `HIGH`
severity alert.

Applied per event, matching the proposal's wording ("if an event source IP
matches an IP stored in the threat registry"). This is intentionally the
noisiest rule: an address confirmed hostile justifies recording every
interaction it has with the monitored estate.

**Severity:** `HIGH` — confidence is maximal, because a human has explicitly
classified the source.

### 3.5 R-04 — Multiple Host Attempt Rule

**Logic.** Group failures by source address across *all* hosts. If one
address has produced failures against at least the threshold number of
distinct hosts (default 2), raise a `HIGH` alert anchored to the most recent
event.

**Severity:** `HIGH`. An address failing against several machines indicates
scanning or credential spraying rather than a forgotten password.

**Implementation note.** When analysis is scoped to a single host, R-04 still
examines events from every host — correlating across machines is the entire
purpose of the rule. Verified by
`test_r04_still_correlates_when_analysis_is_scoped_to_one_host`.

### 3.6 De-duplication and Idempotence

An alert is written only when no existing alert shares the same
`(rule_id, event_id)` pair. Existing pairs are fetched in a single query
rather than one query per candidate.

The consequence is that **re-running detection is idempotent**: the first run
creates alerts, subsequent runs create none. This matters practically —
during a live demonstration the rules can be re-applied repeatedly without
corrupting the dashboard. Verified by
`test_r01_is_idempotent_across_repeated_runs`.

### 3.7 Noise Suppression

Two mechanisms prevent the alert list becoming unusable:

- **Trusted addresses.** Any address marked `TRUSTED` is suppressed entirely.
- **Non-routable markers.** Local console markers (`LOCAL`,
  `LOCAL_CONSOLE`, `-`) never trigger remote-attacker rules and are never
  added to the registry, verified by
  `test_local_console_events_do_not_pollute_the_registry`.

### 3.8 Configurable Thresholds

| Setting | Default | Rule |
|---|---|---|
| `DETECTION_FAILED_LOGIN_THRESHOLD` | 5 | R-01 |
| `DETECTION_FAILED_LOGIN_WINDOW_MINUTES` | 10 | R-01 |
| `DETECTION_MULTI_HOST_THRESHOLD` | 2 | R-04 |

Set in `.env`. Exposing them acknowledges that appropriate values depend on
the environment: a busy shared server needs a higher threshold than a
single-user workstation.

---

## 4. Log Ingestion Pipeline

### 4.1 Unified Pipeline

Every source — live collection, file upload, pasted text, bundled sample or
synthetic generation — passes through the same three stages in
`app/services/log_analyzer.py`:

```
normalised events → Parquet archive → Event rows → detection rules
```

Because the pipeline is shared, an imported sample file produces exactly the
same alerts a live collection would. This is what makes a laboratory
demonstration a faithful representation of real operation.

### 4.2 Supported Formats

| Format | Source | Parser |
|---|---|---|
| Linux `auth.log` / journald text | SSH collection or file import | `parse_auth_log` |
| Windows Security CSV | Event Viewer / `Get-WinEvent` export | `parse_windows_csv` |
| Normalised JSON | Programmatic input | `parse_json` |
| Synthetic | Built-in generator | `generate_synthetic` |

Format is detected automatically from content and filename.

### 4.3 Parsing Details

**Pattern ordering matters.** `Failed password for invalid user bob from …`
matches both the invalid-user and the failed-password patterns. Patterns are
ordered most-specific-first so the line is correctly classified as
`INVALID_USER`. Verified by
`test_failed_password_for_invalid_user_is_classified_as_invalid_user`.

**Syslog timestamps omit the year.** `Aug 12 09:14:02` carries no year. The
parser assumes the most recent occurrence: if applying the current year
places the date more than a day in the future, the previous year is used.

**Malformed input is skipped, not guessed at.** Unrecognised lines are
ignored rather than coerced into a fabricated event. A partially malformed
file still imports the records it can. Inventing event data would undermine
the evidential value of the whole system.

### 4.4 De-duplication

Collectors fetch by time window, so the same line can legitimately arrive
twice. Events are de-duplicated on
`(host, timestamp, event_type, source_ip, username)`. Sub-second precision is
dropped so keys survive a Parquet round-trip. Verified by
`test_reingesting_the_same_logs_does_not_duplicate_events`.

### 4.5 Forensic Retention

Each batch is written to a timestamped Parquet file before analysis. Parquet
is columnar and compressed, keeping retained logs small and quick to filter.

Critically, clearing events and alerts from the database does **not** delete
the archives. Verified by
`test_archived_parquet_files_outlive_a_database_reset`: after wiping the
database, the archived file remains readable and complete.

---

## 5. User Interface

### 5.1 Pages

| Page | Purpose |
|---|---|
| `/login` | Authentication |
| `/` | Dashboard: statistics, charts, host status, recent alerts |
| `/alerts` | Full alert table with filtering, pagination, acknowledgement |
| `/events` | Event browsing and sample log import |
| `/config` | Host management and threat intelligence registry |

### 5.2 Dashboard

Four summary cards (hosts, events, alerts with unreviewed count, high
severity with banned-IP count) and three charts:

- **Authentication failures over 7 days** (line) — identifies *when* an
  attack occurred. Days with no activity are filled with zero so the axis
  stays continuous.
- **Alerts by severity** (doughnut) — the triage picture at a glance.
- **Alerts by detection rule** (horizontal bar) — which rule is firing, and
  therefore what kind of attack is in progress.

A "top attacking source IPs" panel ranks addresses by failure count with
their registry status, so the administrator can decide what to ban.

### 5.3 Alert Triage

Filtering by severity, rule, host and review status, with 25-per-page
pagination. Alerts can be acknowledged, dimming the row and removing it from
the "unreviewed" filter. A "re-run detection" control re-applies the rules to
stored events.

### 5.4 Front-End Design Notes

All dynamic content is inserted using `textContent`, never `innerHTML`. Since
the displayed values include usernames and log messages originating from
untrusted input, this eliminates a cross-site scripting route by
construction.

No JavaScript build step is used; the browser loads ES modules directly. The
entire system can therefore be read and run straight from the repository.

---

## 6. Testing and Results

### 6.1 Test Suite

```bash
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

Tests run against a temporary in-memory database and a temporary storage
folder, so the development database is never touched.

### 6.2 Proposal Test Cases

| ID | Test Case | Expected Result | Status |
|---|---|---|---|
| TC-01 | Login Test | Wrong credentials rejected, valid accepted | Pass |
| TC-02 | Protected Page Test | Redirect to login; API returns 401 | Pass |
| TC-03 | Host Management Test | Host appears and persists | Pass |
| TC-04 | Threat IP Test | IP appears in registry | Pass |
| TC-05 | Log Analysis Test | Events extracted, stored, archived | Pass |
| TC-06 | Alert Test | Alerts with timestamp, IP, host, severity | Pass |
| TC-07 | Dashboard Test | Alerts, counts and summaries displayed | Pass |
| TC-08 | Persistence Test | Records survive restart | Pass |

### 6.3 Detection Rule Verification

Each rule is verified both for firing correctly and — equally important — for
*not* firing when it should not.

| Rule | Positive case | Negative case |
|---|---|---|
| R-01 | 6 failures in 3 minutes → 1 alert | 4 failures (below threshold) → none; 6 failures over 6 hours (outside window) → none |
| R-02 | Invalid-user event → 1 alert | Ordinary failed login → none |
| R-03 | Event from `BANNED` IP → 1 alert | Event from unlisted IP → none |
| R-04 | Same IP on 2 hosts → 1 alert | Same IP on 1 host → none |

The negative cases carry the real weight. They demonstrate the rules are
*selective* rather than merely reactive — the difference between a detection
engine and a log viewer that shouts at everything.

### 6.4 Reference Dataset Results

Reproduce with:

```bash
python scripts/seed_sample_data.py --reset-registry
```

This creates two hosts, imports `samples/linux_auth_sample.log` against both,
and runs detection.

`--reset-registry` is used rather than `--reset` because the plain reset
deliberately preserves the Threat Intelligence registry — it holds an
administrator's decisions, not collected data. If an address were left marked
`BANNED` from an earlier run, R-03 would fire immediately and the
"before banning" figures below could not be observed.

**Before any address is banned:**

```
Events in database : 34
Alerts in database : 13

  R-01 Failed Login          :  2    (one burst per host)
  R-02 Invalid User          :  8    (4 invalid users × 2 hosts)
  R-03 Threat IP Match       :  0    (nothing banned yet)
  R-04 Multiple Host Attempt :  3    (3 addresses seen on both hosts)

  Severity:  HIGH 3  |  MEDIUM 2  |  LOW 8
```

**After marking `203.0.113.50` as `BANNED` and re-running detection:**

```
R-03 raised 18 new alerts

  Total alerts   : 31
  High severity  : 21
  Banned IPs     : 1
```

**Interpretation.** This is the central result of the project. Threat
intelligence changed the assessment of evidence that had *already been
collected* — no host was contacted, no log re-read. Total alerts rose from 13
to 31 and high-severity alerts from 3 to 21, purely because a human
classified one address as hostile. This is precisely the behaviour that
distinguishes a SIEM from a log viewer.

Top attacking sources in the reference dataset:

| Source IP | Failure events | Registry status |
|---|---|---|
| `203.0.113.50` | 18 | `BANNED` |
| `198.51.100.23` | 6 | `UNKNOWN` |
| `192.0.2.77` | 6 | `UNKNOWN` |

Note that `192.0.2.77`'s failures are deliberately spread across 90 minutes
in the sample data, so they stay *below* the R-01 window threshold. This
demonstrates the rule distinguishing a slow trickle from a burst.

### 6.5 Screenshots

Insert demonstration screenshots here:

- Figure 1: Dashboard with charts — _____________________
- Figure 2: Alerts page filtered to HIGH — _____________________
- Figure 3: Events page after import — _____________________
- Figure 4: Threat registry — _____________________

*(Confirm no real credential or private address is visible.)*

---

## 7. Security Implementation

Because the project is itself a security tool, its own security was treated
as a requirement rather than an afterthought.

### 7.1 Authentication

- Passwords hashed with `werkzeug.security`; the plain value is never stored.
  Verified by `test_password_is_stored_hashed`.
- Login failures return a deliberately generic message so valid usernames
  cannot be enumerated. Verified by
  `test_login_error_message_does_not_reveal_which_field_was_wrong`.
- Session cookies are `HttpOnly` with `SameSite=Lax`; the `Secure` flag is
  configurable for HTTPS deployment.
- The `?next=` redirect target is accepted only if it is a relative path on
  this site, closing an open-redirect route. Verified by
  `test_login_does_not_follow_an_external_next_target`.

### 7.2 CSRF Protection

The FYP-I prototype exempted the entire JSON API from CSRF protection. This
was a genuine vulnerability: any site the administrator visited while logged
in could have issued authenticated state-changing requests.

The exemption was removed. The token is published in a `<meta>` tag and sent
by the front end as an `X-CSRFToken` header on every non-GET request.
Verified end to end: `POST /api/hosts` without a token returns `400`; with a
valid token it returns `201`.

### 7.3 Input Validation

All validation is server-side in `app/validators.py`, since the API is
reachable directly.

| Field | Rule |
|---|---|
| IP addresses | Parsed with `ipaddress`; IPv4 and IPv6 accepted, anything else rejected |
| Hostnames | Restricted character set, maximum 100 characters |
| OS type | Must be `LINUX` or `WINDOWS` |
| Registry status | Must be `UNKNOWN`, `TRUSTED` or `BANNED` |
| Severity filter | Must be `LOW`, `MEDIUM` or `HIGH` |
| Text fields | Length-bounded |

### 7.4 Other Measures

- **Path traversal.** Bundled sample names are resolved and confirmed to
  remain inside the samples folder, so a crafted name cannot read arbitrary
  files. Verified by
  `test_bundled_sample_names_cannot_escape_the_samples_folder`.
- **Upload limits.** `MAX_CONTENT_LENGTH` caps imports at 2 MB by default.
- **SQL injection.** All access goes through the SQLAlchemy ORM; no string
  concatenation of SQL.
- **XSS.** All dynamic content is set via `textContent`.
- **Secrets.** `SECRET_KEY` and SSH credentials are read from `.env`, which
  is git-ignored. No credential appears in the repository.

---

## 8. Evaluation Against Requirements

### 8.1 Functional Requirements

| ID | Requirement | Status | Evidence |
|---|---|---|---|
| FR-01 | Secure administrator login | Met | `test_auth.py` |
| FR-02 | Protected pages restricted | Met | 4 pages + 5 API endpoints tested |
| FR-03 | Host add/view/update/delete | Met | `test_hosts.py` |
| FR-04 | Threat IP registry management | Met | `test_threat_intel.py` |
| FR-05 | Sample log/event input | Met | 3 formats + generator, 27 tests |
| FR-06 | Detect failed login, invalid user, suspicious IP | Met | 4 rules, 21 tests |
| FR-07 | Alerts with severity, timestamp, host, source IP | Met | `test_alerts_carry_every_required_field` |
| FR-08 | Dashboard alerts and summary statistics | Met | 5 endpoints, 3 charts, 14 tests |
| FR-09 | Repeatable demo workflow | Met | Seed script + documented walkthrough |

### 8.2 Non-Functional Requirements

| Attribute | Assessment |
|---|---|
| Usability | Five pages, no command line needed for normal operation; plain-language alert messages |
| Security | Hashed passwords, CSRF on forms and API, server-side validation, path-traversal protection |
| Performance | 34 events processed and analysed in well under a second; bulk queries used rather than per-row lookups |
| Maintainability | Service layer separated from HTTP layer; rules are pure functions; 95 tests guard against regression |
| Portability | Runs on Windows and Linux; SQLite requires no server; developed and tested on Windows 11 with Python 3.14 |
| Ethical compliance | Only synthetic data and reserved address ranges; no scanning capability implemented |

### 8.3 Deliverables

| ID | Deliverable | Status |
|---|---|---|
| D-01 | Approved FYP proposal | Complete |
| D-02 | Working prototype | Complete |
| D-03 | Source code repository | Complete — `github.com/Yasirpz/Mini-SIEM` |
| D-04 | Database schema/models | Complete — six tables |
| D-05 | Sample logs | Complete — three files in `samples/` |
| D-06 | Testing report | Complete — `docs/TESTING.md` |
| D-07 | Installation guide | Complete — `docs/INSTALLATION.md` |
| D-08 | User manual | Complete — `docs/USER_MANUAL.md` |
| D-09 | Final report and slides | This report + `docs/PRESENTATION-OUTLINE.md` |
| D-10 | Poster / summary | Outline provided in the presentation document |
| D-11 | Similarity report and AI-use declaration | `docs/AI-USE-DECLARATION.md` — to be completed by the team |

---

## 9. Limitations

Stated honestly, consistent with proposal §21.1.

1. **Scope of detection.** Only authentication events. No process, file
   integrity, network flow or malware analysis. Behavioural and anomaly-based
   detection are out of scope.

2. **Log format dependency.** Alert accuracy depends entirely on input
   format. Unrecognised lines are skipped silently; a non-standard SSH
   configuration could produce lines the parsers miss.

3. **Windows collection is local only.** It reads the Security log of the
   machine running Mini-SIEM and requires an elevated shell. It is not a
   remote agent, so monitoring several Windows hosts would need an agent
   architecture not built here.

4. **Scale.** SQLite and synchronous in-process collection suit laboratory
   volumes. Enterprise event rates would require a different storage engine
   and asynchronous ingestion.

5. **No real-time streaming.** Collection is triggered manually or by re-run,
   not continuous. There is no scheduler.

6. **Single-user model.** One administrator role; no per-user permissions,
   audit trail of administrator actions, or multi-tenancy.

7. **Detection thresholds are static.** They do not adapt to a host's normal
   traffic level; an appropriate value must be chosen by the administrator.

---

## 10. Future Enhancements

Building on proposal §21.2, ordered by ratio of value to effort:

| Enhancement | Rationale |
|---|---|
| Scheduled automatic collection | Turns the system from on-demand into continuous monitoring |
| PDF/Excel export of alert reports | Requested in the proposal; useful for incident records |
| Email/SMS notification for `HIGH` alerts | Closes the loop from detection to response |
| Additional log formats (web server, firewall, application logs) | The normalised event format is designed for this; each addition is one parser |
| Alert comments and assignment | Supports multi-person triage |
| Per-host adaptive thresholds | Reduces false positives on busy hosts |
| Geolocation / ASN enrichment of source IPs | Adds context to threat intelligence decisions |
| Windows agent for remote collection | Removes the local-only limitation |
| Role-based access control | Separates viewing from administration |

---

## 11. Conclusion

Mini-SIEM meets every functional requirement set out in the proposal. The
delivered system collects or imports authentication logs from multiple
sources, normalises them into a common event structure, retains raw evidence
in compressed columnar archives, applies four documented detection rules with
graded severity, and presents the results through a dashboard with statistics,
charts and triage tooling. All 95 automated tests pass.

The most valuable outcome was not the volume of code but a specific lesson
about detection quality. The initial implementation raised an alert for every
failed login. It was technically functional and practically useless: an
administrator facing a wall of identical alerts has no more information than
they had reading the raw log. Redesigning R-01 around a threshold within a
sliding window — and testing explicitly that it *does not* fire on four
attempts, or on six attempts spread across six hours — turned a log echo into
a detection rule. The negative test cases proved more instructive than the
positive ones.

The second significant outcome is the demonstration in §6.4. By storing
events separately from alerts, the system can re-evaluate evidence when
knowledge changes. Marking one address as hostile raised high-severity alerts
from 3 to 21 across data already on disk. That capacity — to reinterpret the
past as understanding improves — is the essential idea behind security
information and event management, and the project reproduces it faithfully at
laboratory scale.

The system remains a deliberately bounded educational prototype. It does not
replace an enterprise SIEM and was never intended to. Within its stated
scope, it is complete, tested, documented and demonstrable.

---

## 12. References

1. National Institute of Standards and Technology. (2006). *Guide to Computer Security Log Management*. NIST SP 800-92.
2. Scarfone, K., & Mell, P. (2007). *Guide to Intrusion Detection and Prevention Systems (IDPS)*. NIST SP 800-94.
3. National Institute of Standards and Technology. (2024). *The NIST Cybersecurity Framework (CSF) 2.0*.
4. OWASP Foundation. (2021). *OWASP Top 10 Web Application Security Risks*.
5. Pallets Projects. (n.d.). *Flask Documentation*.
6. SQLAlchemy Project. (n.d.). *SQLAlchemy ORM Documentation*.
7. Python Software Foundation. (n.d.). *Python Documentation*.
8. Stallings, W., & Brown, L. (2018). *Computer Security: Principles and Practice*. Pearson.
9. Arkko, J., Cotton, M., & Vegoda, L. (2010). *IPv4 Address Blocks Reserved for Documentation*. RFC 5737.
10. Apache Software Foundation. (n.d.). *Apache Parquet Documentation*.

---

## 13. Appendices

### Appendix A — Reproducing the Results

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env          # set your own SECRET_KEY
python scripts/create_admin.py
python scripts/seed_sample_data.py --reset-registry
python -m pytest
flask run
```

### Appendix B — Demonstration Script

1. Log in as administrator.
2. Configuration → add two monitored hosts.
3. Configuration → add `203.0.113.50` as `UNKNOWN`.
4. Events → import `linux_auth_sample.log` against both hosts.
5. Observe: R-01 fires once per burst, R-02 for each invalid user, R-04
   because one address hit two hosts. R-03 is zero.
6. Configuration → mark `203.0.113.50` as `BANNED`.
7. Alerts → Re-run detection. R-03 fires; severity escalates to `HIGH`.
8. Dashboard → statistics and charts reflect the new totals.
9. Alerts → filter to `HIGH`; acknowledge one alert.
10. Log out; confirm protected pages are inaccessible.

### Appendix C — Team Contributions

| Member | Roll No. | Contribution |
|---|---|---|
| Yasir Parveez | 2K23/CSM/146 | Group leader; Flask architecture, authentication, integration, supervisor liaison, documentation management |
| Abdul Fatah | 2K23/CSM/03 | Database design, host management module, threat IP registry, test data preparation, repository organisation |
| Mushahid Hussain | 2K23/CSM/100 | Log parsers, detection rules, dashboard UI and charts, alert display, testing evidence, demo preparation |

Individual contribution evidence is maintained through Git commit history,
meeting logs and the progress log in `docs/PROGRESS-LOG.md`.

### Appendix D — Ethical Statement

All development and testing used synthetic log data and addresses from ranges
reserved for documentation (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`) or private use (RFC 1918). No test traffic or test data
refers to any real system.

No unauthorised scanning, exploitation, password cracking or credential
collection was performed at any point. The system implements no offensive
capability. Live log collection is restricted by design to hosts for which
the operator supplies their own credentials, and the documentation states
explicitly that it must only be pointed at systems the operator owns or has
written permission to monitor.

No password, token, private address or personal data appears in the
repository, this report, or any screenshot.

---

**Supervisor's remarks**

_______________________________________________________________________

_______________________________________________________________________

Supervisor signature: ____________________  Date: ______________
