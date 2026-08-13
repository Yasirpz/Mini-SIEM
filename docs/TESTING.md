# Testing & Demonstration Report

Mini-SIEM — FYCP/2K26/109
IMCS, University of Sindh, Jamshoro

---

## 1. Test approach

Testing is in two layers:

1. **Automated tests** — a `pytest` suite of **95 tests** in `tests/`, run
   against a temporary in-memory database so the development data is never
   touched.
2. **Manual demonstration** — the scripted walkthrough in Section 5, used for
   the FYP viva.

Run the automated suite from the project root:

```bash
python -m pytest
```

Latest result: **95 passed**.

---

## 2. Test cases from the proposal

Each test case in Section 15 of the proposal maps to automated tests.

| ID | Test Case | Action | Expected Result | Automated in | Status |
|---|---|---|---|---|---|
| TC-01 | Login Test | Enter wrong credentials, then correct admin credentials. | Wrong credentials rejected, valid login accepted. | `test_auth.py` | Pass |
| TC-02 | Protected Page Test | Open the dashboard after logout. | Redirected to login; API returns `401`. | `test_auth.py` | Pass |
| TC-03 | Host Management Test | Add `Lab-PC` / `127.0.0.1` / Linux. | Host appears in the list and persists. | `test_hosts.py` | Pass |
| TC-04 | Threat IP Test | Add `203.0.113.50` with status `UNKNOWN`. | IP appears in the registry. | `test_threat_intel.py` | Pass |
| TC-05 | Log Analysis Test | Import sample logs with failed-login and invalid-user entries. | Events extracted, stored and archived to Parquet. | `test_sample_import.py`, `test_detection.py` | Pass |
| TC-06 | Alert Test | Run detection rules on sample events. | Alerts generated with timestamp, source IP, host and severity. | `test_detection.py` | Pass |
| TC-07 | Dashboard Test | Open the dashboard after alerts exist. | Recent alerts, counts and summaries displayed. | `test_dashboard.py` | Pass |
| TC-08 | Persistence Test | Restart the server after saving data. | Hosts, IPs, events and alerts remain. | `test_persistence.py` | Pass |

---

## 3. Detection rule verification

Each rule from Section 10.2 is tested individually, including the cases where
it must **not** fire — which is what distinguishes a real rule from a naive
one that alerts on every log line.

| Rule | Positive case | Negative case | Severity |
|---|---|---|---|
| R-01 Failed Login | 6 failures in 3 minutes → 1 alert | 4 failures (below threshold) → none; 6 failures spread over 6 hours (outside window) → none | `MEDIUM` |
| R-02 Invalid User | Invalid-user event → 1 alert naming the user and IP | Ordinary failed login → none | `LOW` |
| R-03 Threat IP Match | Event from a `BANNED` IP → 1 alert | Event from an unlisted IP → none | `HIGH` |
| R-04 Multiple Host Attempt | Same IP failing on 2 hosts → 1 alert | Same IP failing on 1 host only → none | `HIGH` |

Additional behaviours verified:

- **One alert per burst.** R-01 raises a single alert for a 10-event burst,
  not ten alerts.
- **Idempotence.** Re-running detection produces zero new alerts; existing
  ones are never duplicated.
- **Username separation.** Five failures each against two usernames are
  treated as two distinct bursts.
- **Trusted suppression.** An IP marked `TRUSTED` produces no alerts at all.
- **Cross-host correlation.** R-04 still correlates across machines even when
  analysis is scoped to one host.
- **Registry hygiene.** Unseen source IPs are auto-registered as `UNKNOWN`
  with a hit count; local console markers (`LOCAL`, `LOCAL_CONSOLE`) are not.
- **Event de-duplication.** Re-importing the same log file stores zero new
  events.

---

## 4. Security and validation testing

| Area | Test | Result |
|---|---|---|
| Password storage | Plain-text password never appears in `password_hash`. | Pass |
| Login enumeration | Wrong password and unknown user give the same message. | Pass |
| Open redirect | `?next=https://example.com` is not followed after login. | Pass |
| CSRF (forms) | Login POST without a token is rejected with `400`. | Pass |
| CSRF (JSON API) | `POST /api/hosts` without `X-CSRFToken` → `400`; with it → `201`. | Pass |
| Route protection | All 4 pages and 5 API endpoints blocked when logged out. | Pass |
| IP validation | `999.999.1.1` rejected; IPv6 accepted. | Pass |
| Hostname validation | `<script>alert(1)</script>` rejected. | Pass |
| Enum validation | `os_type=SOLARIS`, `status=SUSPICIOUS`, `severity=CRITICAL` rejected. | Pass |
| Path traversal | `POST /api/events/samples/../../config.py` refused. | Pass |
| Upload size | Files above `MAX_UPLOAD_BYTES` rejected with `413`. | Enforced by Flask |
| Output escaping | All dynamic values rendered via `textContent`, never `innerHTML`. | By design |

---

## 5. Demonstration scenario

Seeded with `python scripts/seed_sample_data.py --reset-registry`, importing
`samples/linux_auth_sample.log` against two hosts.

`--reset-registry` rather than `--reset`: a plain reset keeps the Threat
Intelligence registry, so an address left `BANNED` from an earlier run would
make R-03 fire immediately and the "before" figures could not be observed.

### Observed result before banning the IP

```
Events in database : 34
Alerts in database : 13

  R-01 Failed Login          : 2 alert(s)     (one burst per host)
  R-02 Invalid User          : 8 alert(s)     (4 invalid users x 2 hosts)
  R-03 Threat IP Match       : 0 alert(s)     (no IP banned yet)
  R-04 Multiple Host Attempt : 3 alert(s)     (3 IPs seen on both hosts)

  By severity:  HIGH 3  |  MEDIUM 2  |  LOW 8
```

### After marking `203.0.113.50` as BANNED and re-running detection

```
R-03 raised 18 new alerts
Total alerts : 31        High severity : 21        Banned IPs : 1
```

This is the key demonstration: threat intelligence changes the outcome, and
the severity of existing evidence escalates, **without re-collecting a single
log line**.

### Viva walkthrough

1. Administrator logs in to the Mini-SIEM dashboard.
2. Adds two monitored hosts on the Configuration page.
3. Adds `203.0.113.50` to the Threat Intelligence registry as `UNKNOWN`.
4. Imports `linux_auth_sample.log` against both hosts from the Events page.
5. Detection engine identifies suspicious events and creates alerts —
   R-01, R-02 and R-04 fire; R-03 does not.
6. Marks `203.0.113.50` as `BANNED`, then uses **Re-run detection**.
7. R-03 fires and severity escalates to `HIGH`.
8. Dashboard shows updated counts, severity split and per-rule breakdown.
9. Alerts page is filtered to `HIGH`; one alert is acknowledged.
10. Administrator logs out; protected pages are no longer accessible.

---

## 6. Known limitations

Consistent with Section 21 of the proposal:

- Detection covers login-related events only — no behavioural analytics.
- Alert accuracy depends on log format; unrecognised lines are skipped
  silently rather than guessed at.
- Windows collection reads the local machine's Security log and needs an
  elevated shell; it is not a remote agent.
- SQLite and synchronous collection suit a lab-scale demonstration, not an
  enterprise event volume.
- Bootstrap and Chart.js load from a CDN, so the dashboard charts need
  internet access unless those files are vendored locally.

---

## 7. Ethical statement

All testing uses synthetic events and addresses from reserved documentation
ranges (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or
private ranges (RFC 1918), so no test traffic or test data refers to a real
system. No unauthorized scanning, exploitation or credential collection was
performed at any point, in line with Section 19 of the proposal.
