# Development Log

**Mini-SIEM** — FYCP/2K26/109

A chronological record of how the system was built: what was added, what broke,
and why each significant decision was taken.

> **Why this document exists.** The commit history records *what* changed. This
> records *why*, including the things that went wrong. For a viva that matters
> more than the diff — an examiner asking "why does R-01 work that way?" wants
> the reasoning, and several of the most defensible answers in this project came
> from fixing something that was initially wrong.

---

## Phase 1 — Foundation (FYP-I)

The initial prototype established the Flask application factory, blueprint
layout, authentication, host management, the Threat Intelligence registry,
SSH and Windows log collection, and Parquet archival.

It closed with eight known gaps, recorded honestly rather than hidden:

1. R-01 alerted on every failed login, with no threshold.
2. R-04 was designed but not implemented.
3. Events existed only inside Parquet archives, so rules could not be re-run.
4. Severity used `WARNING`/`CRITICAL` rather than the specified levels.
5. No sample log import.
6. No summary statistics or charts.
7. No automated tests.
8. The JSON API was exempt from CSRF protection.

---

## Phase 2 — Detection engine and completion (FYP-II)

### The R-01 redesign — the most instructive episode

The original rule raised an alert for every failed login. It satisfied a
literal reading of the requirement and was operationally useless: a user
mistyping their password three times produced three alerts indistinguishable
from a brute-force attack.

**Fix:** a threshold within a *sliding* time window — five failures for the
same user and source IP within ten minutes, anchored to the event that
completed the burst so one burst produces one alert.

**Lesson:** correctness and usefulness are different properties. For detection
systems the harder question is not what to detect but what to refrain from
reporting. The negative test cases — proving the rule does *not* fire on four
attempts, or on six spread across six hours — turned out to be the more
valuable half of the test suite.

### Separating events from alerts

An event is an observation; an alert is a judgement about one. Storing only
alerts makes the judgement permanent and the evidence disposable.

Storing them separately made rules re-runnable, which produced the project's
headline result: marking one address as `BANNED` and re-running detection
raised alerts from 13 to 31 and high-severity alerts from 3 to 21, across
evidence already on disk, with no host contacted.

### Security hardening

The prototype exempted the entire JSON API from CSRF protection for
convenience. This was a genuine vulnerability — any site an authenticated
administrator visited could have issued state-changing requests. The exemption
was removed and the front end now sends the token as a header.

Also added: server-side validation, path-traversal protection on sample
imports, open-redirect protection on login, and hardened session cookies.

---

## Phase 3 — Real Windows collection

### The "run as Administrator" bug

Symptom: the UI reported *"Cannot read the Windows Security log. Run as
Administrator"* even though `Get-WinEvent` worked manually from an elevated
PowerShell.

Debugging the actual subprocess call — rather than trusting the message —
found **three** separate defects:

1. **Real errors were discarded.** The probe caught every exception and
   returned a bare `False`, so a crash, a decode failure and an access denial
   all produced identical text.
2. **An empty result was treated as failure.** `Get-WinEvent` exits non-zero
   when its filter matches nothing. Running the exact query proved it: exit
   code 1 with completely empty stderr, producing the useless message
   `"PowerShell error: "`.
3. **One-event batches parsed differently.** `ConvertTo-Json` renders a lone
   object as `{...}` but several as `[...]`.

**Fixes:** expose the real stderr; treat "No events were found" as success;
keep stdout whenever it has content regardless of exit code; emit
newline-delimited JSON so batch size cannot change the parse; decode as UTF-8
rather than the OEM code page.

**Root cause of the original report:** the *Flask process* was not elevated,
even though the user's terminal was. The API now returns `server_is_elevated`
so this can never be ambiguous again.

**Lesson:** an error message that collapses several causes into one string
actively obstructs debugging. Each distinct failure needs a distinct message.

### Event scope

Collection grew from 4624/4625 to twelve event IDs covering lockouts,
privilege assignment, account management and audit-log clearing.

Two deliberate restrictions:

- **4688 (process creation) is opt-in.** It fires thousands of times an hour
  on a normal desktop and would bury the authentication events the project
  exists to demonstrate.
- **Command lines are never collected**, even when 4688 is enabled. They
  routinely contain passwords and tokens, and a security tool must not become
  the place those are archived.

---

## Phase 4 — Multi-host monitoring

### Remote Windows over WinRM

Added alongside the existing SSH path for Linux. A host now carries a
collection method — `LOCAL`, `WINRM` or `SSH` — inferred from the operating
system when unset, so every existing host kept working unchanged.

**Credential decision:** passwords are read from `.env` and never stored in
the database, which would put them into backups, Parquet archives and any
repository copy. Only the username is persisted.

**Command-line decision:** the password is passed to PowerShell through an
environment variable rather than interpolated into the command string. Process
command lines are readable by other accounts on Windows. A test asserts the
password never appears in the generated command.

### The schema migration bug

Adding columns to `Host` would have broken every existing installation:
`db.create_all()` creates missing *tables* but will not alter one that already
exists, so the schema fell behind the models and every host query failed with
*"no such column"*.

**Fix:** a narrow, idempotent startup step that adds missing nullable columns.
Verified against the live database — columns added, all existing hosts
resolved to their previous behaviour, no records lost.

### Host health

Hosts record `last_attempt`, `last_success`, `last_error` and latency from
real collection outcomes, and derive `ONLINE` / `DEGRADED` / `OFFLINE` /
`UNKNOWN`.

**Decision:** a host that has never been contacted reports `UNKNOWN`, not
`ONLINE`. Existing in the database proves nothing about reachability, and
claiming otherwise would make the dashboard lie. A success older than an hour
also stops counting as online — silence is not health.

Reaching a host and finding nothing new *is* recorded as a success, so a quiet
machine does not drift to `OFFLINE`.

### Test Connection

Each stage is checked and reported separately — reachable, credentials
configured, authenticated, log accessible.

**Rationale:** "connection failed" is not actionable. The PC being switched
off, a wrong password, and an account lacking permission have completely
different fixes, and a single message cannot distinguish them. The TCP probe
uses a three-second timeout so an unreachable host cannot tie up a worker.

### Rules R-05 to R-08

| Rule | Trigger | Severity | Reasoning |
|---|---|---|---|
| R-05 | Audit log cleared | HIGH | No threshold — one occurrence is the whole signal, and it destroys the evidence a SIEM depends on |
| R-06 | Account created/deleted | MEDIUM | Persistence, but also a routine administrative action |
| R-07 | Privilege widened | MEDIUM | Group membership changes and password resets |
| R-08 | Account lockout | MEDIUM | Windows independently concluding a password attack occurred |

Two deliberate exclusions:

- **R-07 ignores plain administrative logons (4672).** They occur every time
  an administrator signs in normally; alerting would train the operator to
  ignore the rule.
- **A lockout does not feed R-01.** It is the consequence of failures that
  rule has already counted, so including it would double-count one incident.

---

## Recurring problem: two copies of the project

Two checkouts existed — `Desktop\Mini-SIEM` and `C:\Users\Info-Service\Mini-SIEM`
— each with its own SQLite database and its own `admin` account with a
*different* password.

This broke login twice. The symptom looked like wrong credentials; the actual
cause was that Flask had been started from the other copy, so the password was
being checked against a different database.

**Resolution:** Desktop is authoritative. Worth remembering as a general point
— when authentication fails inexplicably, confirm which process is actually
serving the request before assuming the credential is wrong.

---

## Testing growth

| Stage | Tests |
|---|---|
| Initial prototype | 0 |
| After FYP-II detection work | 95 |
| After Windows collection fix | 145 |
| After wider event set | 157 |
| After remote collection | 182 |
| After health, testing and R-05–R-08 | 210 |

Negative cases are treated as first-class throughout: proving a rule does
*not* fire matters as much as proving it does.

---

## Decisions recorded for the viva

| Decision | Reasoning |
|---|---|
| Rule-based, not machine learning | Every alert traces to a specific rule and event. A model's score cannot be explained to an examiner, and a lab cannot establish a training baseline. |
| Events stored separately from alerts | Makes detection re-runnable, which is what allows stored evidence to be re-evaluated when threat intelligence changes. |
| Sliding window, not a fixed count | Distinguishes a burst from a user forgetting their password across an afternoon. |
| One alert per burst | Ten failures describing one incident should not produce ten alerts. |
| Idempotent detection | Rules can be re-applied live during a demonstration without duplicating the dashboard. |
| No JavaScript build step | The whole system runs directly from a checkout, which matters for work that must be inspected. |
| Front-end libraries vendored locally | Removes an internet dependency that would only have failed during the demonstration itself. |
| SQLite, not PostgreSQL | Zero configuration, adequate for lab volumes, one file to back up. |

---

## Honest limitations

- Collection is on demand, not continuous. Calling it real-time would be
  inaccurate.
- Automatic polling was deliberately not implemented: a scheduler inside
  Flask's development server risks double collection from the reloader's two
  processes, and reliability during the demonstration matters more than the
  feature.
- Remote WinRM is implemented and unit-tested, but was only exercised against
  an unreachable address during development — no second Windows machine was
  available. It should be tested against the real lab PC before the
  demonstration.
- Windows local collection requires an elevated Flask process.
- SQLite and synchronous collection suit a laboratory, not enterprise volumes.
