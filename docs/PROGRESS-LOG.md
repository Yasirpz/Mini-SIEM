# Progress Log

**Mini-SIEM** — FYCP/2K26/109
Institute of Mathematics & Computer Science, University of Sindh, Jamshoro
Supervisor: Mr. Fiaz Ahmed Memon

> **How to use this document.** This log records weekly progress and
> individual contributions, as required for FYP evaluation. The technical
> milestones below reflect what was actually built and can be cross-checked
> against the Git commit history. **Dates, meeting records and supervisor
> feedback must be filled in by the team** — they cannot be reconstructed
> from the repository, and inventing them would be dishonest.

---

## Team

| Member | Roll No. | Primary responsibility |
|---|---|---|
| Yasir Parveez | 2K23/CSM/146 | Group leader; Flask architecture, authentication, integration, supervisor liaison, documentation |
| Abdul Fatah | 2K23/CSM/03 | Database design, host management, threat IP registry, test data, repository organisation |
| Mushahid Hussain | 2K23/CSM/100 | Log parsers, detection rules, dashboard UI and charts, alert display, testing evidence, demo |

---

## FYP-I

### Week 1 — Project definition

**Dates:** ____________  **Meeting with supervisor:** ____________

| Task | Owner | Status |
|---|---|---|
| Finalise project title and Project ID | All | Complete |
| Agree team roles | All | Complete |
| Initial supervisor consultation | Yasir | Complete |

**Supervisor feedback:** _________________________________________________

---

### Week 2 — Domain study

**Dates:** ____________  **Meeting with supervisor:** ____________

| Task | Owner | Status |
|---|---|---|
| Study SIEM concepts and the collection → analysis pipeline | All | Complete |
| Review NIST SP 800-92 and SP 800-94 | Yasir, Mushahid | Complete |
| Survey log formats (Linux `auth.log`, Windows Event ID 4625) | Mushahid | Complete |
| Establish ethical boundaries for testing | All | Complete |

**Key decision:** Rule-based detection over anomaly-based — deterministic,
explainable, and does not require a training baseline a lab cannot provide.

**Supervisor feedback:** _________________________________________________

---

### Week 3 — Requirements

**Dates:** ____________  **Meeting with supervisor:** ____________

| Task | Owner | Status |
|---|---|---|
| Functional requirements FR-01 … FR-09 | Yasir | Complete |
| Non-functional requirements | Yasir, Abdul | Complete |
| Scope definition, in and out | All | Complete |
| Use case identification | Abdul | Complete |

**Key decision:** Explicit out-of-scope list agreed — no scanning, no
exploitation, no malware analysis, no monitoring without permission.

**Supervisor feedback:** _________________________________________________

---

### Week 4 — Design

**Dates:** ____________  **Meeting with supervisor:** ____________

| Task | Owner | Status |
|---|---|---|
| Database schema design | Abdul | Complete |
| Architecture diagram | Yasir | Complete |
| Module decomposition | Yasir | Complete |
| Normalised event format specification | Mushahid | Complete |
| Detection rule logic design (R-01 … R-04) | Mushahid | Complete |

**Key decision:** A single normalised event format for every log source. This
is why the detection rules never need to know a log's origin, and why adding
a source later costs one parser rather than a rule-engine change.

**Supervisor feedback:** _________________________________________________

---

### Weeks 5–6 — Foundation implementation

**Dates:** ____________  **Meeting with supervisor:** ____________

| Task | Owner | Status |
|---|---|---|
| Flask application factory and blueprints | Yasir | Complete |
| Authentication: login, logout, session handling | Yasir | Complete |
| Password hashing and admin creation script | Yasir | Complete |
| Database models | Abdul | Complete |
| Host management module (CRUD) | Abdul | Complete |
| Threat IP registry | Abdul | Complete |
| Base templates and dashboard layout | Mushahid | Complete |

**Supervisor feedback:** _________________________________________________

---

### Week 7 — Parsing proof of concept

**Dates:** ____________  **Meeting with supervisor:** ____________

| Task | Owner | Status |
|---|---|---|
| Linux `auth.log` regex patterns | Mushahid | Complete |
| Windows Event ID 4625 collection | Mushahid | Complete |
| SSH collection via paramiko | Yasir | Complete |
| Parquet retention | Abdul | Complete |
| Initial sample log data | Abdul | Complete |

**Issue identified:** the first detection implementation raised an alert for
every failed login. Recognised as unusable and scheduled for redesign in
FYP-II. *(See FYP-II Week 1–3.)*

**Supervisor feedback:** _________________________________________________

---

### Week 8 — FYP-I deliverables

**Dates:** ____________  **Meeting with supervisor:** ____________

| Task | Owner | Status |
|---|---|---|
| FYP-I prototype assembled | All | Complete |
| Proposal defence material | Yasir | Complete |
| FYP-I report | Yasir | Complete |
| Progress log started | All | Complete |

**FYP-I outcome:** Foundation working end to end — authentication, host
management, threat registry, collection and retention. Eight gaps documented
honestly and carried into FYP-II (FYP-I report §11.3).

**Supervisor feedback:** _________________________________________________

---

## FYP-II

### Weeks 1–3 — Detection engine

**Dates:** ____________  **Meeting with supervisor:** ____________

| Task | Owner | Status |
|---|---|---|
| `Event` model added; events stored in database | Abdul | Complete |
| **R-01 redesigned** with sliding-window threshold | Mushahid | Complete |
| R-02 invalid user rule | Mushahid | Complete |
| R-03 threat IP match rule | Mushahid | Complete |
| **R-04 implemented** — cross-host correlation | Mushahid | Complete |
| Severity changed to LOW/MEDIUM/HIGH | Mushahid | Complete |
| Alert de-duplication and idempotence | Yasir | Complete |
| Unified ingestion pipeline | Yasir | Complete |

**Most significant work of the project.** R-01 was rewritten from
"alert on every failure" to a threshold within a sliding window. The
rewrite was driven by the realisation that the original rule produced
output no administrator could act on.

**Supervisor feedback:** _________________________________________________

---

### Weeks 4–5 — Dashboard and triage

**Dates:** ____________  **Meeting with supervisor:** ____________

| Task | Owner | Status |
|---|---|---|
| Sample log import: three parsers plus generator | Mushahid | Complete |
| Bundled sample log files | Abdul | Complete |
| Statistics endpoints | Yasir | Complete |
| Chart.js charts: trend, severity, per-rule | Mushahid | Complete |
| Alerts page with filtering and pagination | Mushahid | Complete |
| Alert acknowledgement | Mushahid | Complete |
| Events browsing page | Mushahid | Complete |
| Host description, IP source/notes fields | Abdul | Complete |

**Supervisor feedback:** _________________________________________________

---

### Week 6 — Testing

**Dates:** ____________  **Meeting with supervisor:** ____________

| Task | Owner | Status |
|---|---|---|
| pytest fixtures and test database isolation | Yasir | Complete |
| Detection rule tests, positive and negative | Mushahid | Complete |
| Parser and import tests | Mushahid | Complete |
| Host and registry tests | Abdul | Complete |
| Authentication and access control tests | Yasir | Complete |
| Persistence and retention tests | Abdul | Complete |
| **Security hardening**: CSRF on API, validation, path traversal | Yasir | Complete |

**Result:** 95 tests, all passing. Security gap closed — the JSON API had
been exempt from CSRF protection, which would have allowed a malicious site
to issue authenticated state-changing requests.

**Supervisor feedback:** _________________________________________________

---

### Week 7 — Documentation

**Dates:** ____________  **Meeting with supervisor:** ____________

| Task | Owner | Status |
|---|---|---|
| Installation guide | Yasir | Complete |
| User manual | Yasir | Complete |
| Testing report | Mushahid | Complete |
| Sample log documentation | Abdul | Complete |
| README and repository organisation | Abdul | Complete |

**Supervisor feedback:** _________________________________________________

---

### Week 8 — Final deliverables

**Dates:** ____________  **Meeting with supervisor:** ____________

| Task | Owner | Status |
|---|---|---|
| FYP-I report | Yasir | Complete |
| FYP-II final report | Yasir | Complete |
| Presentation slides | Mushahid | ____________ |
| Poster | Mushahid | ____________ |
| Repository finalised and pushed | Abdul | Complete |
| Demo video | All | ____________ |
| Similarity report | Yasir | ____________ |
| AI use declaration | All | ____________ |

**Supervisor feedback:** _________________________________________________

---

## Milestone Summary

| Milestone | Evidence |
|---|---|
| Requirements agreed | FYP-I report §5 |
| Design complete | FYP-I report §6–7 |
| Foundation prototype | FYP-I report §9 |
| Detection engine complete | `app/services/detection.py`, 21 tests |
| Sample ingestion complete | `app/services/sample_loader.py`, 27 tests |
| Dashboard complete | `app/blueprints/api/stats.py`, 14 tests |
| Testing complete | 95 tests passing |
| Documentation complete | `docs/` |
| Repository published | `github.com/Yasirpz/Mini-SIEM` |

---

## Meeting Record

Add a row after each supervisor meeting.

| # | Date | Attendees | Topics discussed | Actions agreed |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |
| 4 | | | | |
| 5 | | | | |
| 6 | | | | |
| 7 | | | | |
| 8 | | | | |

---

## Contribution Evidence

Individual contributions are evidenced by:

1. **Git commit history** — `git log --author="<name>"`
2. **This progress log** — task ownership per week
3. **Meeting records** — the table above
4. **Viva questioning** — all members maintain working knowledge of the whole
   system, not only their own modules

> **Note.** If the Git history does not yet reflect individual authorship
> (for example if commits were made from one shared account), state that
> plainly to your supervisor rather than adjusting the history. Use this log
> and the meeting records as the contribution evidence instead.
