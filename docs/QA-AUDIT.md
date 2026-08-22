# QA Audit

**Project:** Mini-SIEM — Centralised Lab Monitoring & Security Controller
**Supervisor:** Mr. Fiaz Ahmed Memon
**Audit date:** 22 August 2026
**Automated suite at time of audit:** 370 tests, all passing (`python -m pytest`)

---

## 1. How to read this document

Every row below carries a status, and the statuses mean exactly what they say:

| Status | Meaning |
|---|---|
| **PASS** | Exercised end to end and observed working, either by an automated test or by driving the running application. |
| **PASS WITH LIMITATION** | Works, but only under a stated condition — a privilege, a credential, a configuration. The condition is named in the row. |
| **NEEDS FIX** | Known to be wrong or incomplete. |
| **NOT VERIFIED** | The code exists and is covered by automated tests against a substituted client, but it has **not** been run against real hardware in this audit. Not the same as "works". |

Nothing is marked PASS on the strength of the code existing. Where a feature
was verified by driving the running application rather than by a unit test,
the row says so, because those are different kinds of evidence.

---

## 2. Feature matrix

| Feature | Existing / New | Local | Remote | Backend | Database | API | UI | Tested | Status |
|---|---|---|---|---|---|---|---|---|---|
| Administrator authentication | Existing | ✔ | n/a | ✔ | ✔ | ✔ | ✔ | Automated + driven | **PASS** |
| Session protection on every route | Existing | ✔ | n/a | ✔ | n/a | ✔ | ✔ | Automated (URL map swept) | **PASS** |
| Host management (add / edit / delete) | Existing | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Automated + driven | **PASS** |
| Host health (online / degraded / offline / unknown) | Existing | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Automated + driven | **PASS** |
| Threat Intelligence IP registry | Existing | ✔ | n/a | ✔ | ✔ | ✔ | ✔ | Automated + driven | **PASS** |
| Sample log import (file / paste / bundled / synthetic) | Existing | ✔ | n/a | ✔ | ✔ | ✔ | ✔ | Automated + driven | **PASS** |
| Log parsing and normalisation | Existing | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Automated | **PASS** |
| Parquet forensic archive | Existing | ✔ | ✔ | ✔ | ✔ | n/a | n/a | Automated | **PASS** |
| Windows Security log collection — local | Existing | ✔ | n/a | ✔ | ✔ | ✔ | ✔ | Real events collected; see §4.1 | **PASS WITH LIMITATION** |
| Windows Security log collection — remote (WinRM) | Existing | n/a | ? | ✔ | ✔ | ✔ | ✔ | Automated against a fake client only | **NOT VERIFIED** |
| Linux collection over SSH | Existing | n/a | ? | ✔ | ✔ | ✔ | ✔ | Automated against a fake client only | **NOT VERIFIED** |
| USB device detection (Event 6416) | Existing | ✔ | ? | ✔ | ✔ | ✔ | ✔ | Automated + driven; see §4.2 | **PASS WITH LIMITATION** |
| USB audit-policy status per host | Existing | ✔ | ? | ✔ | ✔ | ✔ | ✔ | Automated | **PASS** |
| Automatic collection (background scheduler) | Existing | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Automated + driven | **PASS** |
| Detection R-01 Failed Login | Existing | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Automated + real data; see §3.1 | **PASS** |
| Detection R-02 Invalid User | Existing | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Automated + demo data | **PASS** |
| Detection R-03 Threat IP Match | Existing | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Automated + demo data | **PASS** |
| Detection R-04 Multiple Host Attempt | Existing | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Automated + demo data | **PASS** |
| Detection R-05 – R-08 (post-compromise) | Existing | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Automated only; see §4.3 | **PASS WITH LIMITATION** |
| Detection R-09 External Device | Existing | ✔ | ? | ✔ | ✔ | ✔ | ✔ | Automated + driven | **PASS** |
| Detection R-10 File Integrity | Existing | ✔ | ? | ✔ | ✔ | ✔ | ✔ | Automated + driven on real files | **PASS** |
| File Integrity Monitoring — local | Existing | ✔ | n/a | ✔ | ✔ | ✔ | ✔ | Automated + driven on real files | **PASS** |
| File Integrity Monitoring — remote | Existing | n/a | ? | ✔ | ✔ | ✔ | ✔ | Automated against a fake client only | **NOT VERIFIED** |
| FIM before/after hashes on the dashboard | **New** | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Automated + driven | **PASS** |
| Live auto-refresh (Dashboard / Alerts / Events) | **New** | ✔ | n/a | n/a | n/a | ✔ | ✔ | Driven; see §3.2 | **PASS** |
| Connection-loss and recovery reporting | **New** | ✔ | n/a | n/a | n/a | ✔ | ✔ | Driven; see §3.3 | **PASS** |
| Configurable refresh interval (2/5/10/30/off) | **New** | ✔ | n/a | n/a | n/a | n/a | ✔ | Driven | **PASS** |
| MITRE ATT&CK rule catalogue and coverage panel | **New** | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Automated + driven | **PASS** |
| Pakistan Standard Time display | **New** | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Automated + driven | **PASS** |
| UTC storage across both collectors | Existing (fixed) | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Automated | **PASS** |
| System-activity pipeline strip | **New** | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | Driven | **PASS** |
| Security operations console styling | **New** | ✔ | n/a | n/a | n/a | n/a | ✔ | Driven (both themes) | **PASS** |
| Self-contained demonstration instance | **New** | ✔ | n/a | ✔ | ✔ | ✔ | ✔ | Driven | **PASS** |

`?` means the feature is not applicable in that column, or depends on a remote
prerequisite that this audit could not exercise.

---

## 3. What was fixed during this audit

### 3.1 R-01 ignored failures typed at a monitored machine's own keyboard

**Severity: high — this was the single most consequential defect found.**

R-01 discarded every authentication failure whose source carried a `LOCAL` or
`LOCAL_CONSOLE` marker, on the reasoning that these are not attacker addresses
and would only create noise. That reasoning is correct for R-03 and R-04,
where the whole question is *which remote address* is responsible. It was
wrong for R-01.

The cost was measurable rather than theoretical. The live database on the
development machine held **87 events collected from a real Windows Security
log, 21 of them failed interactive logons, and zero alerts**. A demonstration
of "perform failed logins on a monitored Windows machine, watch R-01 fire"
would have produced nothing at all.

Re-running detection over a *copy* of that live database with the fix applied
(the live file was not modified) produces:

```
R-01 MEDIUM  Yasir  5 failed login attempts for user 'Info-Service'
                    at the machine's own console within 10 minutes.
```

The rule's shape is unchanged — same threshold, same sliding window, still one
alert per (host, source, user) burst. What the marker still suppresses is
everything that reads a source as a remote address: the threat registry, R-03,
and R-04's cross-host correlation. Two people mistyping passwords on two
different lab PCs must not correlate into one attacker, and a test asserts it.

### 3.2 R-10 alerts were stored but invisible on the rules chart

Rule names lived in a dictionary inside the stats API, and R-10 was added to
the detection engine without being added to it. File-integrity alerts were
written to the database and then silently omitted from the "Alerts by
Detection Rule" chart, and could not be filtered for on the Alerts page.

Both now read `app/rule_catalog.py`, and a test asserts that every rule id the
engine can emit is present in the catalogue, so the omission cannot recur.

### 3.3 Events were stored on the monitored machine's wall clock, not UTC

The Windows collector sent `TimeCreated` verbatim and the Linux collector read
journald's epoch through the SIEM's local clock. Events from a host in another
timezone were therefore stored hours off, which put them into the future on
the dashboard and quietly broke the ten-minute window R-01 depends on, since
two hosts' events could no longer be ordered against each other.

Conversion now happens on the machine that owns the clock.
`scripts/fix_event_timezones.py` repairs rows already stored, estimating each
host's offset from the gap between its event times and the ingestion times the
SIEM wrote itself.

### 3.4 A blank timezone setting would have disabled Pakistan time

`.env.example` ships `MINISIEM_DISPLAY_TIMEZONE=` with no value, so the
documented "copy the example to .env" set it to an empty string. Reading that
as "use the browser's zone" would have switched PKT off for exactly the people
who followed the setup instructions. An empty value now falls back to the
default.

### 3.5 An unset refresh preference read as "off"

`Number(localStorage.getItem(key))` is `0` when the key is absent, and `0` is
a legitimate stored value meaning *off*. A first-time visitor therefore got a
dashboard that never refreshed itself. Found by opening the page, not by a
test.

### 3.6 A failed refresh wiped the tables

Each panel cleared itself before fetching and drew an error row on failure, so
a dropped connection replaced the alert table, the host table and the ATT&CK
table with error messages — destroying the last known good picture at the
moment an operator most needs it. Panels now fetch first, keep their rows on
failure, and dim them to show they are no longer current.

### 3.7 `.flaskenv` shipped `FLASK_DEBUG=1`

The documented way to start the application started it with Werkzeug's
debugger enabled, which turns any unhandled exception into an interactive
Python console in the browser — on a process reading Windows Security logs and
holding an administrator session. Debug is now off by default, with
instructions for enabling it deliberately during development.

### 3.8 The default `SECRET_KEY` passed silently

Session cookies are signed with `SECRET_KEY`. If it is the value published in
this repository, anyone who knows it can forge an administrator cookie. The
application now logs a warning at startup when it is running on that default,
rather than refusing to start — a student following the README for the first
time should still get a working application.

---

## 4. Limitations that remain

### 4.1 Local Windows collection requires an elevated Flask process

Reading the Windows Security log needs Administrator. Started normally, a
collection returns HTTP 403 with an actionable message:

> Stop Flask and restart it from a PowerShell window opened with "Run as
> Administrator". The Flask process itself must be elevated — an Administrator
> terminal does not help if the server was started elsewhere.

That error path was verified in this audit. Successful collection is evidenced
by the 87 real events in the live database, collected on 19 August 2026 — but
a *successful* elevated collection was **not** re-run during this audit,
because the audit process was not elevated. Treat local Windows collection as
working-with-a-prerequisite rather than as re-verified today.

### 4.2 USB detection needs Plug and Play auditing enabled on the host

Off by default in Windows. The Monitored Hosts table reports each host's audit
state so an empty USB panel is never ambiguous, and the enabling command is in
the tooltip:

```
auditpol /set /subcategory:"Plug and Play Events" /success:enable
```

USB detection was verified through the ingestion pipeline with a normalized
event, and R-09 fired correctly. It was not verified by physically plugging a
drive into a host with auditing enabled.

### 4.3 R-05 – R-08 were exercised with synthetic events, not real ones

Clearing an audit log, creating an account, changing group membership and
locking an account out are all covered by automated tests that feed the
detection engine the corresponding normalized events. None of them was
triggered by performing the action on a real Windows machine and collecting
the resulting event. The parsing of those event IDs is separately tested
against captured event XML, so both halves are covered — but not the join
between them, end to end, on real hardware.

### 4.4 Remote collection was not exercised against a real machine

The configured remote host (`Abdul-Fatah-PC`, WinRM) has no credentials set,
and fails with a clear message:

> No remote password configured. Set `MINISIEM_WINRM_PASSWORD` in .env —
> credentials are deliberately never stored in the database.

WinRM and SSH collection, and remote file integrity scanning, are covered by
automated tests that substitute a fake client for the transport. That proves
the command construction, the parsing and the error handling; it does not
prove that a real remote host answers. **Do not claim remote collection works
in the viva without running it first.** Prerequisites are documented in
[`docs/REAL_WORLD_LAB_SETUP.md`](REAL_WORLD_LAB_SETUP.md).

### 4.5 Severity has three levels, not four

The dashboard shows `LOW` / `MEDIUM` / `HIGH`, as specified in Section 6.1 of
the project proposal. There is deliberately no `CRITICAL` level above `HIGH`:
adding one would change an existing project objective, and every stored alert
would have to be re-graded against a scale it was never assigned on.

### 4.6 Alerts do not carry a username column

Alert rows name the rule, host, source address and message; the username
appears inside the message rather than as its own field, because the `Alert`
model has no username column. Adding one would be a schema change with a
backfill for existing rows, and it was judged out of scope for an audit whose
brief was to preserve the existing objectives.

### 4.7 A credential reached the database, and how it got there

**Resolved during the audit, but the underlying lesson stands.**

A lab password had been typed into the **Remote username** field when adding
a host on the Configuration page. Every WinRM connection attempt then tried to
authenticate with the password as the account name, which is both why remote
collection never worked and how the value spread:

| Where it ended up | Why |
|---|---|
| `hosts.remote_user` | Entered directly in the Add Host form. |
| 26 `EXPLICIT_CREDENTIALS` (4648) event rows | Windows logged the attempted logon, recording the bogus account name in `TargetUserName`. Mini-SIEM collected it faithfully, into the username, the message and the raw record. |
| One Parquet forensic archive | The same events were archived before analysis, as every collected event is. |

All three were cleared: the host field emptied, the event rows deleted, and
the archive redacted in place. The archive was redacted rather than pruned
because dropping rows out of a retention file undermines the one thing it is
for, and its recorded row count would no longer match its contents.

Two points worth keeping:

1. **This is not a parser defect.** Event 4648's `TargetUserName` is whatever
   the operator typed, and Mini-SIEM recording it accurately is correct
   behaviour. No heuristic is added to guess whether a username "looks like a
   password" — it would suppress real evidence to catch an operator error.
   Process command lines are already excluded from collection for the same
   underlying reason (see `WINDOWS_COLLECT_PROCESS_EVENTS` in `config.py`).

2. **A credential that has been in a database should be treated as
   compromised and rotated**, regardless of how thoroughly it was removed
   afterwards. Deleting rows removes the copy you know about.

### 4.8 Screenshots were not captured

The audit environment could not composite browser frames, so verification was
carried out through the accessibility tree, the page text, computed styles,
console output and network activity rather than by eye. Layout was checked
structurally and by computed CSS values in both themes; it was not visually
inspected.

---

## 5. End-to-end runs performed

Each of these was carried out against a running application, not simulated.

| # | Test | Result |
|---|---|---|
| 1 | Log in, load every page (Dashboard, Alerts, Events, Configuration) | All render, no console errors |
| 2 | Import the bundled Linux auth log against two hosts, run detection | 36 events → 33 alerts; R-01, R-02, R-03, R-04 all fire |
| 3 | Baseline a watched folder, modify one file and add another, re-scan | Baseline silent on first scan; second scan reports 1 modified + 1 appeared, with correct before/after SHA-256 |
| 4 | R-10 alert generation from those findings | HIGH for modified, MEDIUM for appeared |
| 5 | Inject a USB event into the running system, do **not** touch the browser | Within 5s: event count 38 → 39, USB row appeared, ATT&CK coverage 5 → 6 techniques, Lateral Movement tactic 0 → 1, "last updated" advanced |
| 6 | Stop the server with the dashboard open | Indicator turns red, *Connection lost — retrying…*, all rows retained and dimmed, counts preserved |
| 7 | Restart the server | Returns to Live on its own, dimming cleared, timestamp advances |
| 8 | Same loss/recovery cycle without a page reload (fetch suppressed in place) | Identical behaviour, confirming recovery is the controller's, not the browser's |
| 9 | Attempt local Windows Security collection unelevated | HTTP 403 with the actionable message quoted in §4.1 |
| 10 | Re-run detection over a copy of the live database | R-01 fires on real collected data (§3.1) |
| 11 | Full automated suite | 370 passed |

---

## 6. Verdict

The pipeline **Host → Collection → Parsing → Normalisation → Database →
Detection → Alert → Dashboard** was verified working end to end for local
collection, imported logs and file integrity monitoring, with the dashboard
updating live and without manual reloading.

The two things a reader should carry away:

1. **The most important fix was not cosmetic.** R-01 was silently ignoring the
   attack scenario the project is most likely to be demonstrated with. Real
   collected data proved it, and proves the fix.
2. **Remote collection remains unproven on hardware.** It is implemented,
   tested against substituted transports, and clearly diagnosable when
   misconfigured — but it has not been run against a second physical machine
   during this audit, and should not be claimed as working until it has.
