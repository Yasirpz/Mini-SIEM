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

### Is this page still live?

Two different questions get two different answers, in two different places.

At the top right of the page, a pill says whether **this page** is still being
updated:

| Indicator | Meaning |
|---|---|
| ● **Live** | The page fetched fresh data successfully. Beside it is the time of that last successful read. |
| ● **Updating…** | A refresh is in flight right now. |
| ● **Connection lost — retrying…** | The last refresh failed. The figures on screen are the last good ones and are dimmed to show they are no longer current. It keeps trying, and returns to Live on its own. |
| ● **Auto-refresh off** | You turned refreshing off with the picker beside it. Press **Refresh** to update by hand. |

Next to the pill is how often the page refreshes itself: **2s, 5s, 10s, 30s**
or **Off**. Five seconds is the default. Your choice is remembered, and the
Alerts and Events pages follow it too. Turning it off is worth doing while you
work through a long alert table, so the rows stop moving under you.

Refreshing pauses while the tab is in the background — a dashboard left open
overnight should not spend the night querying a sleeping laptop — and redraws
immediately when you come back to it. Only the changed parts of the page are
re-fetched, so a filter you have set or a place you have scrolled to is never
thrown away.

Below the title, a **Collector** chip answers the other question: whether the
**server** is collecting on its own. **auto** means the background collector
is running with at least one host enabled; **manual** means every collection
has to be started by hand. A page that is Live while the collector says manual
is working exactly as it should — it means the screen is current, and that
nothing new is arriving because nothing is being collected.

### What time is that?

Every event, alert and scan is **stored in UTC**, so that a Windows PC in one
country and a Linux server in another can be placed on the same timeline at
all. What you see on screen is that stored time converted for display.

The display is **Pakistan Standard Time (PKT, UTC+05:00)**, and every
timestamp says so:

```
22 Aug 2026, 01:35:42 PKT
```

The zone is part of the value on purpose. A time without its zone is not
evidence — if you copy a row into an incident report you have to be able to
state when it happened without also having to remember how the dashboard was
configured.

It is pinned in configuration rather than taken from the browser, so a machine
whose clock is set to the wrong region cannot silently relabel every event on
screen. The **Times** chip beside the Collector chip names the zone in use.

To move the display, set an IANA zone name in `.env` and restart Flask:

```
MINISIEM_DISPLAY_TIMEZONE=Europe/London
```

Or hand it back to whatever the viewing machine is set to:

```
MINISIEM_DISPLAY_TIMEZONE=local
```

Leaving the setting blank keeps Pakistan time.

**If the times look wrong.** Check them against the clock on the machine
running Mini-SIEM first. Events are recorded on the monitored host's clock and
converted to UTC there, so a monitored PC whose own clock is hours out will
produce events that are hours out, and no amount of display configuration will
fix that — the fix is on that machine. Events collected before this version
were stored on the monitored machine's wall clock rather than in UTC;
`python scripts/fix_event_timezones.py` reports what it would change, and
`--apply` rewrites them.

### Reading severity

Severity carries three signals, not one: a colour, a shape and a word.

| Badge | Means |
|---|---|
| ▲ **HIGH** | A serious security event. Look at it now. |
| ◆ **MEDIUM** | Suspicious activity that needs investigating. |
| ● **LOW** | Informational; recorded so it can be correlated later. |

The shape and the word matter as much as the colour. On a projector the red
and the amber wash out into much the same orange, and roughly one man in
twelve does not separate them reliably in any case.

These are the three levels the project proposal specifies. There is no
"critical" level above HIGH — HIGH is the top of the scale.

### Summary cards

| Card | Meaning |
|---|---|
| Monitored Hosts | Hosts configured for monitoring, and how many are online or offline. Online means a collection actually succeeded recently — a host that has never been contacted is neither. |
| Events Collected | Normalized security events stored, and how many arrived in the last 24 hours. |
| Authentication | Successful logons against failed ones. |
| Total Alerts | Alerts raised by the detection rules, and how many are still unreviewed. |
| High Severity | `HIGH` alerts, and how many IPs are currently banned. |
| File Integrity | Watched files that stopped matching their baseline, and how many paths are being watched at all. Zero changes means something quite different when zero paths are watched. |

### System activity

A strip of four stages — **Collecting → Processing → Detecting → Alerting**
— each showing what it actually produced: hosts on automatic collection,
events stored in the last day, rules that have ever fired, and alerts raised
in the last day. A stage showing zero is not lit. Nothing here is animated for
effect; every number is read back out of the database.

### Charts

- **Authentication Failures (last 7 days)** — daily count of failed-login,
  invalid-user and Windows logon-failure events. A spike identifies the day
  an attack occurred.
- **Alerts by Severity** — the `LOW` / `MEDIUM` / `HIGH` split.
- **Alerts by Detection Rule** — which of R-01 … R-10 is firing.
- **Top Attacking Source IPs** — the busiest sources, with their registry
  status, so you can decide what to ban.

### MITRE ATT&CK coverage

This panel answers a question a list of alerts cannot: **which stages of an
intrusion can this deployment actually see?**

MITRE ATT&CK is the public catalogue of things attackers really do, organised
into *tactics* (what the attacker is trying to achieve) and *techniques* (how
they go about it). Each of the ten detection rules is tagged with the
technique it corresponds to, so an alert can be understood — and checked — by
somebody who has never seen this project's rule numbering.

The top of the panel shows the tactics in kill-chain order, each with the
number of alerts seen at that stage. A tactic showing zero stays on screen,
dimmed: **"watched, nothing seen" and "not watched at all" are different
answers**, and hiding the first would misrepresent coverage.

The table below lists every rule, what it detects, its ATT&CK technique
(which links to the public page defining it), its tactic, how many alerts it
has raised and when it last fired. Rules that have never fired are dimmed
rather than omitted, for the same reason.

| Rule | Technique | Tactic |
|---|---|---|
| R-01 Failed Login | T1110.001 Brute Force: Password Guessing | Credential Access |
| R-02 Invalid User | T1110 Brute Force | Credential Access |
| R-03 Threat IP Match | T1133 External Remote Services | Initial Access |
| R-04 Multiple Host Attempt | T1110.003 Brute Force: Password Spraying | Credential Access |
| R-05 Audit Log Cleared | T1070.001 Clear Windows Event Logs | Defense Evasion |
| R-06 Account Created or Deleted | T1136.001 Create Account: Local Account | Persistence |
| R-07 Privilege Change | T1098 Account Manipulation | Persistence |
| R-08 Account Lockout | T1110 Brute Force | Credential Access |
| R-09 External Device Connected | T1091 Replication Through Removable Media | Lateral Movement |
| R-10 File Integrity Change | T1565.001 Stored Data Manipulation | Impact |

R-02 and R-08 both map to T1110, so the panel counts nine distinct techniques
across ten rules — counting rules would overstate how much of ATT&CK the
system covers. The reasoning behind each mapping is recorded in
`app/rule_catalog.py` and shown as a tooltip on the rule.

### File integrity changes

The ten most recent findings, newest first:

| Column | Meaning |
|---|---|
| Time | When the scan noticed, in PKT. |
| Host | The machine the file lives on. |
| Change | `modified`, `appeared` or `deleted`. |
| File | Full path. |
| Previous hash | First twelve characters of the SHA-256 recorded in the baseline. Hover for the full digest. A file that has just appeared shows a dash — there was nothing to compare against. |
| New hash | The same for the digest measured in this scan. |

The pair of hashes is the point. "The file was modified" is an assertion; two
different digests are evidence you can quote.

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

The ten newest alerts, severity first. Each row carries the rule that fired,
its ATT&CK technique and tactic, the host, the source address and the message.
**View all alerts** opens the full Alerts page, where the same rows can be
filtered and acknowledged.

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
| The number beside it | Seconds between collections. Default 5, minimum 5. |
| The label | When the next automatic collection is due. |

Above the host list, an **Automatic collection** panel reports whether the
background collector is actually running, how many hosts it is watching, and
when the next collection falls due. **Run now** performs one round immediately
instead of waiting for the timer — useful when demonstrating, and useful for
telling "the schedule has not come round yet" apart from "the collection
itself is failing".

Switching the toggle on makes that host due straight away, so you see a result
within one tick (about 5 seconds) rather than after a full interval.

The Dashboard, Alerts and Events pages all redraw themselves every five
seconds while you are looking at them, so events collected in the background
appear on screen without you reloading the page. Refreshing pauses while the
tab is in the background and resumes — with an immediate redraw — when you
come back to it.

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

### Preparing a clean instance

A demonstration should not be run against the live database, which holds
whatever the lab actually collected. One command builds a separate one:

```
python scripts/run_demo.py --rebuild --password <choose one>
```

It creates `instance/demo.db` (never touching `instance/mini_siem.db`), a
`demo` account, two monitored hosts with an imported authentication log, and a
watched folder under `instance/demo_watched/` where one file is genuinely
modified after being baselined — so the File Integrity panel shows a real
finding rather than a fabricated row. It then serves on
<http://127.0.0.1:5002/> — a different port from the real instance, so the
two can run side by side. Add `--prepare-only` to build without serving.

Re-run it with `--rebuild` at any point to return to the same known state.

### The sequence

This is the sequence from Appendix B of the proposal, extended to cover the
features added since.

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
10. **Dashboard → MITRE ATT&CK coverage.** Point out that Credential Access
    and Initial Access are lit, and that Persistence and Defense Evasion are
    not — those rules are watching, and nothing has happened at those stages.
    This is coverage, not a scoreboard.
11. **Configuration → Files** on a host. Add a watched path, press **Scan**;
    it reports a baseline and deliberately no findings. Now edit one of those
    files outside Mini-SIEM and press **Scan** again: the change is reported
    with both hashes, R-10 raises an alert, and the dashboard's File Integrity
    card and panel both move.
12. **Leave the Dashboard open** on a second screen and generate an event on a
    monitored machine — a failed logon, or plugging in a USB drive on a host
    with Plug and Play auditing enabled. Within five seconds the event, the
    alert and the counts appear **without anybody touching the browser**, and
    the ● Live indicator's "last updated" time moves.
13. **Pull the network cable** (or stop Flask). The indicator turns red and
    reads *Connection lost — retrying…*, the figures on screen dim to show
    they are no longer current, and nothing is wiped. Restore it and the page
    returns to Live on its own.
14. **Logout**, then try to open `/` — you are redirected to the login page,
    demonstrating that protected pages are enforced.

---

## 7. Ethical use

Mini-SIEM is a defensive monitoring tool for authorized environments only.
Collect logs solely from machines you own or have written permission to
monitor. Every address in the bundled samples is from a reserved
documentation range (RFC 5737) or a private range (RFC 1918), so nothing in
the demonstration data points at a real system.
