# User Manual

Mini-SIEM — FYCP/2K26/109
IMCS, University of Sindh, Jamshoro

This manual explains each screen of the Mini-SIEM web interface and the
workflow an administrator follows. See
[`INSTALLATION.md`](INSTALLATION.md) for setup.

---

## 1. Logging in

Open `http://127.0.0.1:5000`. Because every page is protected, you are sent
to the login form.

Enter the username and password created with `scripts/create_admin.py`.

- A wrong username and a wrong password produce the same generic message,
  *"Login failed. Check your username and password."* This is deliberate: a
  specific message would confirm to an attacker that a username exists.
- Tick **Keep me signed in** to persist the session across browser restarts.
- **Logout** in the top-right ends the session immediately.

---

## 2. Dashboard

The landing page after login. It answers "what is the state of my
environment right now?"

The badge beside the **Security Dashboard** heading says whether anything is
being collected automatically: **live** means the background collector is
running and at least one host is enabled, **manual** means every collection
has to be started by hand. While it is live the page refreshes itself every
20 seconds, so alerts appear without reloading.

### Summary cards

| Card | Meaning |
|---|---|
| Monitored Hosts | Number of hosts configured for monitoring. |
| Events Collected | Normalized security events stored in the database. |
| Total Alerts | Alerts raised by the detection rules, and how many are still unreviewed. |
| High Severity | `HIGH` alerts, and how many IPs are currently banned. |

### Charts

- **Authentication Failures (last 7 days)** — daily count of failed-login,
  invalid-user and Windows logon-failure events. A spike identifies the day
  an attack occurred.
- **Alerts by Severity** — the `LOW` / `MEDIUM` / `HIGH` split.
- **Alerts by Detection Rule** — which of R-01 … R-09 is firing.
- **Top Attacking Source IPs** — the busiest sources, with their registry
  status, so you can decide what to ban.

### Recent USB Devices

The ten most recent removable storage devices connected to a monitored
Windows host, newest first:

| Column | Meaning |
|---|---|
| **Time** | When Windows recognised the device, in your local time zone. |
| **Host** | The monitored machine the device was plugged into. |
| **User** | The account that was signed in at the time. |
| **Device** | The device's own description, e.g. *SanDisk Cruzer Blade USB Device*. |

Each connection also raises a `MEDIUM` alert under rule **R-09**, so it
appears in the Alerts page alongside everything else and can be acknowledged
once you have confirmed the drive was authorised.

This panel depends on **Plug and Play auditing** being enabled on the
monitored machine, which is off by default in Windows. Run this in an
Administrator PowerShell on the machine you want to watch:

```bash
auditpol /set /subcategory:"Plug and Play Events" /success:enable
```

Until then the panel stays empty and says so — collection of every other
event type carries on as normal. Only removable devices are listed: the
internal disk, keyboard and network card that Windows also announces at boot
are filtered out during collection.

### Monitored Hosts overview

The table lists every monitored machine. The **USB audit** column reports
whether that host is capable of reporting removable media at all:

| Badge | Meaning |
|---|---|
| **on** | Plug and Play auditing is enabled — USB devices will be recorded. |
| **off** | Auditing is off. The host will never report a USB device until it is enabled. |
| **?** | Not probed yet, or the audit policy could not be read (usually because Flask is not elevated). |

This exists because an empty USB panel is otherwise ambiguous — it could mean
nothing was plugged in, or that the host would never have told you either
way. Hover the badge for the exact reason and the command to fix it.

The value is refreshed whenever you press **Status**/**Test** or **Collect**
on a host, rather than on every dashboard load, so a refresh never pays for a
policy lookup per host.

Both locally monitored machines and remote hosts collected over WinRM are
covered — the policy is read on the target itself, so the badge reports that
host's setting rather than this server's. A remote host is only asked once
its account has been accepted, and a connection problem shows as **?** with
the machine named, never as **off**.

### Monitored Hosts

Each host row offers two actions:

- **Status** — polls the host for live RAM, disk, CPU and uptime. Linux hosts
  are polled over SSH; Windows telemetry is read from the machine running
  Mini-SIEM.
- **Collect** — fetches new authentication logs from the host, archives them,
  stores them as events and runs the detection rules. Collection is
  incremental: only records newer than the previous run are fetched.

### Recent Alerts

The ten newest alerts, colour-coded by severity. **View all alerts** opens
the full Alerts page.

---

## 3. Events page

Where log data enters the system, and where the raw normalized records can be
inspected.

### Importing sample logs

First choose a **Target host** — imported events are attributed to it. Then
use one of the four tabs:

| Tab | Use |
|---|---|
| **Bundled samples** | Import one of the sample files shipped in `samples/`. The quickest route to a working demonstration. |
| **Upload a file** | Import your own Linux `auth.log`, Windows Security CSV export, or JSON. Format is detected automatically. |
| **Paste log text** | Paste a few log lines directly — handy for showing the parser live. |
| **Generate** | Produce a synthetic burst of failed logins from a chosen source IP, with no input file at all. |

After an import, a result panel reports how many events were parsed, stored
and skipped as duplicates, which Parquet file retains the raw copy, and how
many alerts each rule raised.

Re-importing the same file is safe: events are de-duplicated on host,
timestamp, type, source IP and username, so nothing is double-counted.

### Browsing events

Filter by host, event type or source IP. Each row shows the timestamp, host,
normalized event type, source IP, username, message and origin
(`COLLECTED`, `IMPORTED` or `SYNTHETIC`).

The event-type list includes a **Removable media** group holding
*USB device connected (6416)*, which shows exactly the events behind the
dashboard's USB panel. These carry `LOCAL_CONSOLE` as their source IP,
because plugging in a drive happens at the machine itself rather than over
the network.

**Clear events** deletes stored events and their alerts so a demonstration
can be repeated from a clean state. Archived Parquet files on disk are
deliberately **not** deleted — that is the forensic retention guarantee.

---

## 4. Alerts page

Full triage view of everything the detection engine has raised.

### Filters

Narrow by **severity**, **rule**, **host** and **review status**, then press
**Apply**. Results are paginated 25 at a time.

### Re-run detection

Re-applies all nine rules to events already in the database, without
re-collecting anything. Use it after changing an IP's registry status. The
engine is idempotent — existing alerts are never duplicated.

### Acknowledging

**Mark reviewed** records that an alert has been handled; the row dims. Use
the **Unreviewed** filter to see only outstanding work.

---

## 5. Configuration page

### Host Management

Add a host with a hostname, IP address, OS type and optional description.
IP addresses must be unique and valid, and are what identify a host.

Each row shows its event and alert counts. **Delete** removes the host along
with its events and alerts, and asks for confirmation first.

### Automatic collection

By default a host is only collected from when you press **Collect Logs**. The
**auto-collect** switch on each host row hands that job to the system: it will
then collect from that host by itself, every *n* seconds, for as long as
Mini-SIEM is running.

| Control | Meaning |
|---|---|
| The switch | Whether this host is collected from automatically. Off by default. |
| The number beside it | Seconds between collections. Default 300 (5 minutes), minimum 30. |
| The label | When the next automatic collection is due. |

Above the host list, an **Automatic collection** panel reports whether the
background collector is actually running, how many hosts it is watching, and
when the next collection falls due. **Run now** performs one round immediately
instead of waiting for the timer — useful when demonstrating, and useful for
telling "the schedule has not come round yet" apart from "the collection
itself is failing".

Switching the toggle on makes that host due straight away, so you see a result
within one tick (about 15 seconds) rather than after a full interval.

Notes worth knowing:

- Collection is **incremental**. Each poll asks only for log records written
  since the previous one, so polling a quiet host costs one round trip and
  stores nothing. Short intervals are cheap.
- A host that fails still waits its full interval before being retried, so an
  unreachable machine is not hammered.
- Automatic collection stops when the Flask server stops. It is a running
  process, not a Windows service.
- The whole feature can be switched off with `SCHEDULER_ENABLED=false` in
  `.env`.

### File Integrity Monitoring

Every other rule in Mini-SIEM reads a log. None of them can tell you that a
file quietly changed — and editing a startup script or replacing a program is
how an intruder stays on a machine after the sign-in that let them in has
scrolled out of the log.

Press **Files** on a host row to open the dialog.

| Control | What it does |
|---|---|
| **Watch this path** | Adds a file or folder on that host to be checked. Paths are on the *monitored* machine, not on the Mini-SIEM machine. |
| **Include subfolders** | Walks the whole tree instead of just the top level. Off by default — a recursive watch on a system folder is how you ask a host to hash tens of thousands of files. |
| **Scan now** | Hashes everything watched and reports what changed. |
| **Reset baseline** | Throws away the recorded hashes so the next scan starts fresh. |
| The switch at the top | Whether scans also run automatically, on the same schedule as log collection. |

**The first scan never reports anything.** It records what every watched file
looks like now — that is the baseline — and says so. Changes are reported from
the second scan onwards. This is deliberate: without it, watching a folder of
four hundred files would produce four hundred alerts the moment you switched
it on.

After that, three things are reported, and they appear in the **File Integrity
Changes** panel on the dashboard and as R-10 alerts:

| Finding | Meaning | Severity |
|---|---|---|
| **modified** | The file's contents changed. | `HIGH` |
| **deleted** | A file that was there has gone. | `HIGH` |
| **appeared** | A file exists that was not there before. | `MEDIUM` |

Good things to watch are files that should never change on their own: the
Windows `hosts` file, a Startup folder, a web root, a configuration directory.
Watching a folder full of logs or temporary files will report a change every
single scan and teach you to ignore the panel.

> **After a software update**, use **Reset baseline**. An update legitimately
> rewrites many files at once, and without a reset your only options would be
> to acknowledge every alert or stop watching the path. It is deliberately
> manual — a system that quietly re-baselined after reporting a change would
> erase the evidence it exists to keep.

Two limits worth knowing: each watched path checks at most 500 files per scan
(you are told when that cap is reached), and files larger than 64 MB are
tracked by size and modification date rather than hashed.

Note that a change tells you a file was altered, never *who* altered it —
hashing proves the bytes changed and nothing more. Correlate against the sign-in
events around the same time on the Events page.

### Threat Intelligence Registry

Maintains the addresses the detection engine knows about.

| Status | Effect |
|---|---|
| `UNKNOWN` | Default. Tracked, but no special treatment. |
| `BANNED` | Any event from this address raises a `HIGH` alert (rule R-03). |
| `TRUSTED` | Alerts from this address are suppressed entirely. |

Addresses seen in failure events are registered automatically as `UNKNOWN`,
with a running hit count — so the registry fills itself as you collect logs,
and you only need to decide which entries to promote.

Optional **Source** and **Notes** fields record where the intelligence came
from and why the entry exists.

> After changing a status, use **Re-run detection** on the Alerts page to
> apply it to events already stored.

---

## 6. Recommended demonstration flow

This is the sequence from Appendix B of the proposal.

1. **Log in** as the administrator.
2. **Configuration →** add a host, e.g. `Lab-PC` / `127.0.0.1` / Linux.
   Add a second host to enable rule R-04.
3. **Configuration →** add `203.0.113.50` to the registry as `UNKNOWN`.
4. **Events →** select the host, and import `linux_auth_sample.log` from
   **Bundled samples**. Repeat for the second host.
5. Point out the result panel: R-01 fired once per burst, R-02 for each
   invalid user, R-04 because one IP hit two hosts. R-03 is still zero.
6. **Configuration →** edit `203.0.113.50` and set it to `BANNED`.
7. **Alerts → Re-run detection.** R-03 now fires and severity escalates to
   `HIGH`. This shows threat intelligence changing the outcome without
   re-collecting a single log line.
8. **Dashboard →** the cards and charts reflect the new totals.
9. **Filter** the Alerts page to `HIGH` and acknowledge one alert.
10. **Logout**, then try to open `/` — you are redirected to the login page,
    demonstrating that protected pages are enforced.

---

## 7. Ethical use

Mini-SIEM is a defensive monitoring tool for authorized environments only.
Collect logs solely from machines you own or have written permission to
monitor. Every address in the bundled samples is from a reserved
documentation range (RFC 5737) or a private range (RFC 1918), so nothing in
the demonstration data points at a real system.
