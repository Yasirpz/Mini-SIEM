# Presentation & Poster Outline

**Mini-SIEM** — FYCP/2K26/109
Deliverables D-09 (presentation slides) and D-10 (poster/summary)

> Build these slides in PowerPoint or Google Slides. This document gives the
> structure, the exact content for each slide, and speaker notes. Figures in
> square brackets are screenshots you need to capture from your own run.

---

## Part 1 — Presentation Slides

**Target length:** 15 slides, 12–15 minutes, leaving time for questions.

---

### Slide 1 — Title

**Mini-SIEM**
A Web-Based Security Event Monitoring and Threat Detection System

Project ID: FYCP/2K26/109
BS Computer Science — Final Year
Institute of Mathematics & Computer Science, University of Sindh, Jamshoro

Yasir Parveez (2K23/CSM/146) · Abdul Fatah (2K23/CSM/03) · Mushahid Hussain (2K23/CSM/100)
Supervisor: Dr. Asadullah Burdi

---

### Slide 2 — The Problem

**Logs contain the evidence. Nobody reads them.**

- Every server records failed logins, invalid users, unfamiliar addresses
- A single Linux host can produce thousands of authentication lines a day
- In small labs, nobody has time to read them
- Attacks are discovered *after* they succeed, not during

> **Speaker note:** Open with a concrete image — a wall of raw `auth.log`
> text. Ask the audience how long it would take to spot six failed root
> logins hidden inside it.

---

### Slide 3 — Why Not Just Use Splunk?

| | Enterprise SIEM | Manual checking | **Mini-SIEM** |
|---|---|---|---|
| Cost | High | Free | Free |
| Setup | Days | None | Minutes |
| Detects patterns | Yes | No | Yes |
| Fits a student lab | No | — | Yes |

**Our position:** a narrow but *complete* vertical slice — the same pipeline
as a commercial SIEM, small enough to build, explain and defend.

---

### Slide 4 — Aim and Objectives

**Aim:** a lightweight web-based system to monitor security events, detect
suspicious login behaviour, and present alerts through a dashboard.

**Objectives:**
1. Secure administrator authentication
2. Host management
3. Threat intelligence IP registry
4. Log/event analysis
5. Rule-based alert generation
6. Dashboard reporting
7. Testing evidence and documentation

---

### Slide 5 — Architecture

Use the diagram from the FYP-I report §6.1.

```
Log sources → Parsers → ┬→ Parquet archive (evidence)
                        └→ Event table → Rule engine → Alerts → Dashboard
```

**Key point to emphasise:** events are stored **separately** from alerts.

> **Speaker note:** This is the design decision examiners are most likely to
> probe. Storing only alerts would mean rules could never be re-applied
> without re-collecting logs. Because events persist, the system can
> re-evaluate old evidence when knowledge changes — which is Slide 11.

---

### Slide 6 — Normalisation: One Format for Everything

```python
{
  'timestamp':  datetime,
  'alert_type': 'FAILED_LOGIN',
  'source_ip':  '203.0.113.50',
  'user':       'root',
  'message':    'Failed password for root from 203.0.113.50',
  'raw_log':    '<original line>'
}
```

Linux `auth.log`, Windows Security CSV, JSON and synthetic data all reduce to
this. **The detection rules never know where an event came from.**

Adding a new log source = writing one parser. The rule engine is untouched.

---

### Slide 7 — The Four Detection Rules

| Rule | Detects | Severity |
|---|---|---|
| **R-01** Failed Login | ≥5 failures, same user + IP, within 10 minutes | MEDIUM |
| **R-02** Invalid User | Login attempt for a non-existent account | LOW |
| **R-03** Threat IP Match | Source address marked BANNED | HIGH |
| **R-04** Multiple Host | One IP failing against ≥2 hosts | HIGH |

---

### Slide 8 — The Most Important Slide: Why R-01 Is Hard

**Our first version alerted on every failed login.**

It worked. It was useless.

- A user mistyping their password 3 times → 3 alerts
- A brute-force attack → 200 alerts
- Both look identical in the list

**The fix:** a threshold *within a sliding time window*.

| Scenario | Alerts |
|---|---|
| 6 failures in 3 minutes | **1** (a burst) |
| 4 failures in 3 minutes | **0** (below threshold) |
| 6 failures over 6 hours | **0** (someone forgot their password) |

> **Speaker note:** This is your strongest slide. It shows engineering
> judgement, not just coding. The negative cases — proving the rule *doesn't*
> fire — are what make it a detection rule instead of a log echo.

---

### Slide 9 — Live Demonstration (Part 1)

**Walk through:**
1. Log in
2. Add two monitored hosts
3. Add `203.0.113.50` to the threat registry as `UNKNOWN`
4. Import `linux_auth_sample.log` against both hosts

**Result on screen:**

```
34 events → 13 alerts
R-01: 2   R-02: 8   R-03: 0   R-04: 3
HIGH 3  |  MEDIUM 2  |  LOW 8
```

[Screenshot: import result panel]

---

### Slide 10 — Live Demonstration (Part 2)

**Now mark `203.0.113.50` as BANNED → Re-run detection**

```
R-03 raises 18 new alerts

Total alerts:  13 → 31
High severity:  3 → 21
```

**No host was contacted. No log was re-read.**

[Screenshot: dashboard before and after, side by side]

---

### Slide 11 — Why That Matters

> A SIEM is not a log viewer. It **reinterprets the past as understanding
> improves.**

One human decision — "this address is hostile" — retroactively changed the
severity of evidence already on disk.

That is the difference between storing logs and doing security monitoring.

> **Speaker note:** If you only get one idea across in the whole viva, make
> it this one.

---

### Slide 12 — Dashboard

[Screenshot: full dashboard with charts]

- Summary cards: hosts, events, alerts, high severity
- Failure trend over 7 days — *when* did it happen
- Severity split — *how bad* is it
- Alerts per rule — *what kind* of attack
- Top attacking source IPs — *who* to ban next

---

### Slide 13 — Testing

**95 automated tests, all passing**

| Area | Tests |
|---|---|
| Detection rules (positive + negative) | 21 |
| Log parsing and import | 27 |
| Dashboard and statistics | 14 |
| Host management | 11 |
| Authentication and access control | 10 |
| Threat registry | 9 |
| Persistence and retention | 3 |

All eight proposal test cases (TC-01 – TC-08): **Pass**

Security checks: CSRF on API, path traversal, open redirect, input
validation, password hashing.

---

### Slide 14 — Limitations & Future Work

**Honest limitations:**
- Authentication events only — no malware or network analysis
- Windows collection is local, not a remote agent
- SQLite scale — laboratory volumes, not enterprise
- Manual collection trigger, no scheduler

**Next steps:**
- Scheduled automatic collection
- PDF/Excel alert export
- Email notification for HIGH alerts
- More log formats — one parser each, engine unchanged

> **Speaker note:** Volunteering limitations before you're asked reads as
> confidence, not weakness. Examiners will find them anyway.

---

### Slide 15 — Conclusion

**Delivered:**
- ~5,200 lines across Python, JavaScript, templates
- 4 detection rules, 6 database tables, 5 pages, 3 log parsers
- 95 tests passing
- Full documentation: installation, user manual, testing report

**Learned:**
A working rule and a *useful* rule are not the same thing.

Repository: `github.com/Yasirpz/Mini-SIEM`

**Questions?**

---

## Part 2 — Anticipated Viva Questions

Prepare answers for these. They are the questions most likely to be asked.

| Question | Where the answer is |
|---|---|
| Why not just use Wazuh or Splunk? | Slide 3 — scope, feasibility, learning value |
| How is this different from a log viewer? | Slide 11 — re-evaluation of stored evidence |
| Why store events *and* alerts separately? | FYP-II §2.2 — rules must be re-runnable |
| What stops duplicate alerts on re-run? | FYP-II §3.6 — `(rule_id, event_id)` de-duplication |
| How did you choose the threshold of 5 in 10 minutes? | Configurable in `.env`; defaults chosen so ordinary mistyping doesn't trigger. Depends on environment |
| What happens with a log line you can't parse? | Skipped, never guessed at — fabricating events would destroy evidential value |
| How do you know the rules actually work? | 21 detection tests, including negative cases |
| Is this secure itself? | FYP-II §7 — hashing, CSRF on forms *and* API, validation, path traversal |
| What was the hardest part? | R-01 — see Slide 8 |
| What would you do with six more months? | Slide 14 |
| Who did what? | FYP-II Appendix C + `docs/PROGRESS-LOG.md` + Git history |

---

## Part 3 — Poster Outline (D-10)

**Size:** A1 portrait. **Rule:** readable from two metres away.

```
┌─────────────────────────────────────────────────┐
│  MINI-SIEM                                      │
│  Security Event Monitoring & Threat Detection   │
│  FYCP/2K26/109 · IMCS, University of Sindh      │
├──────────────────────┬──────────────────────────┤
│  PROBLEM             │  ARCHITECTURE            │
│  Logs hold the       │                          │
│  evidence, nobody    │  [architecture diagram]  │
│  reads them.         │                          │
│                      │  Sources → Parse →       │
│  Enterprise SIEMs    │  Archive → Detect →      │
│  are too heavy for   │  Alert → Dashboard       │
│  a student lab.      │                          │
├──────────────────────┼──────────────────────────┤
│  DETECTION RULES     │  RESULT                  │
│                      │                          │
│  R-01 Failed login   │  34 events → 13 alerts   │
│       burst  MEDIUM  │                          │
│  R-02 Invalid user   │  Ban one address,        │
│              LOW     │  re-run detection:       │
│  R-03 Banned IP      │                          │
│              HIGH    │  13 → 31 alerts          │
│  R-04 Multi-host     │   3 → 21 high severity   │
│              HIGH    │                          │
│                      │  No host re-contacted.   │
├──────────────────────┴──────────────────────────┤
│  [DASHBOARD SCREENSHOT — largest element]       │
├─────────────────────────────────────────────────┤
│  BUILT WITH          │  VERIFIED BY             │
│  Python · Flask      │  95 automated tests      │
│  SQLite · Parquet    │  TC-01 – TC-08 all pass  │
│  Bootstrap · Chart.js│                          │
├─────────────────────────────────────────────────┤
│  Yasir Parveez · Abdul Fatah · Mushahid Hussain │
│  Supervisor: Dr. Asadullah Burdi                │
│  github.com/Yasirpz/Mini-SIEM                   │
└─────────────────────────────────────────────────┘
```

**Design guidance:**
- The dashboard screenshot is the visual anchor — make it large
- The 13 → 31 result is the headline number; set it in large type
- Keep body text minimal; the poster supports your explanation, it isn't a
  substitute for it
- Use the severity colours consistently: LOW blue, MEDIUM amber, HIGH red

---

## Part 4 — Demo Preparation Checklist

Run through this the day before.

- [ ] `python -m pytest` → confirm 95 passed
- [ ] `python scripts/seed_sample_data.py --reset-registry` → confirm 34 events / 13 alerts
- [ ] Admin account exists and the password is known
- [ ] **Vendor Bootstrap and Chart.js locally** if the venue has no internet — otherwise the charts will not render
- [ ] Browser zoom set so text is readable on a projector
- [ ] Dark mode toggle tested (looks good on a projector)
- [ ] Screenshots captured as backup in case the live demo fails
- [ ] Demo video recorded as a second fallback
- [ ] All three members can answer questions about any part of the system
- [ ] Laptop charger packed
