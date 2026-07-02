# User Manual

Mini-SIEM — FYCP/2K26/109
IMCS, University of Sindh, Jamshoro

## 1. Logging In

Navigate to `/login` and enter your administrator username and password.
Incorrect credentials show a generic "login failed" message (the system
never reveals whether the username or the password was wrong). Successful
login redirects to the **Configuration** panel; all dashboard and admin
pages are inaccessible until you are authenticated.

## 2. Dashboard (`/`)

The dashboard is the main monitoring view:

- **Monitoring Status** lists every registered host with its hostname, IP
  address, and OS icon.
  - **Status** — fetches live telemetry (free RAM, disk usage, CPU load,
    uptime) from the host over SSH (Linux) or locally via `psutil`
    (Windows).
  - **Logs** — triggers log collection for that host: new authentication
    events are fetched, archived to Parquet, and run through the detection
    engine.
- **Detected Threats (SIEM)** table shows the most recent alerts, with
  timestamp, host, alert type, source IP, message, and severity
  (`WARNING` or `CRITICAL`). Rows are color-coded by severity.

Use **Refresh view** to reload the page.

## 3. Configuration Panel (`/config`)

### Add / Manage Hosts
Enter a hostname, IP address, and OS type (Linux or Windows), then submit
to register a new monitored host. Existing hosts can be edited or deleted
from the list on the right.

### Threat Intelligence — IP Registry
Add an IP address with a status:
- `UNKNOWN` — not yet evaluated
- `TRUSTED` — known-good, alerts for this IP are suppressed
- `BANNED` — known-bad; any matching event is raised as a `CRITICAL` alert

Existing entries can be edited (e.g. promoted to `BANNED`) or removed.

## 4. Logging Out

Click **Logout** in the navbar. This ends the session; the dashboard and
configuration panel become inaccessible again until you log back in.

## 5. Typical Demo Flow

1. Log in as administrator.
2. Add a monitored host (e.g. `Lab-PC`, `127.0.0.1`, Linux).
3. Add a suspicious test IP (e.g. `203.0.113.50`) with status `UNKNOWN`.
4. Trigger log collection (or run `scripts/seed_sample_data.py` beforehand
   for a fully offline demo).
5. Review the generated alerts and their severity on the dashboard.
6. Mark the test IP as `BANNED` and re-run detection to see the alert
   severity escalate to `CRITICAL`.
7. Log out and confirm the dashboard is no longer reachable.
