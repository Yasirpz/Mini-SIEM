# Testing & Demonstration Report

Mini-SIEM — FYCP/2K26/109
IMCS, University of Sindh, Jamshoro

## Test Cases

| ID | Test Case | Action | Expected Result |
|---|---|---|---|
| TC-01 | Login Test | Enter wrong credentials, then correct admin credentials. | System rejects the wrong credentials and accepts the valid login. |
| TC-02 | Protected Page Test | Open the dashboard/config page while logged out. | System redirects to the login page. |
| TC-03 | Host Management Test | Add a sample host, e.g. `Lab-PC`, `127.0.0.1`, Linux. | Host appears in the host list and persists after refresh. |
| TC-04 | Threat IP Test | Add `203.0.113.50` with status `UNKNOWN`. | IP appears in the threat registry. |
| TC-05 | Log Analysis Test | Run `scripts/seed_sample_data.py` or trigger log collection on a test host. | Events are extracted and archived to Parquet. |
| TC-06 | Alert Test | Run the detection engine on collected/sample events. | Alerts are generated with timestamp, source IP, host, and severity. |
| TC-07 | Dashboard Test | Open the dashboard after alerts are generated. | Dashboard shows the recent alerts table with correct severity coloring. |
| TC-08 | Persistence Test | Restart the local server after saving data. | Saved hosts, IPs, and alerts remain available. |
| TC-09 | Threat Escalation Test | Mark a known IP as `BANNED`, then trigger detection again for an event from that IP. | A `CRITICAL` alert is raised. |

## Demonstration Scenario

1. The administrator logs in to the Mini-SIEM dashboard.
2. The administrator adds a monitored host, e.g. `Lab-PC` with IP
   `127.0.0.1`.
3. The administrator adds a suspicious test IP address to the threat
   registry.
4. The administrator loads sample logs (or triggers live collection)
   containing failed-login attempts.
5. The detection engine identifies suspicious events and creates alerts.
6. The dashboard shows alert severity, event counts, and recent activity.
7. The administrator logs out; protected pages are no longer accessible.

## Notes

- All testing during development uses synthetic events, reserved/example
  IP addresses (e.g. `203.0.113.50` from RFC 5737 documentation space), or
  systems the team owns/controls, in line with the project's ethical
  considerations.
