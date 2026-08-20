# Real-World Lab Setup

**Mini-SIEM** — FYCP/2K26/109

Step-by-step instructions for monitoring real machines from one central
Mini-SIEM dashboard, and the exact demonstration procedure for demo day.

> **Authorisation.** Only point Mini-SIEM at machines you own or have written
> permission to monitor. Everything below is defensive: reading your own
> Windows Security log and your own Linux authentication log. Nothing here
> scans, exploits or attacks anything.

---

## 1. The architecture

```
                        CENTRAL MINI-SIEM
                     (your laptop, elevated)
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
   LOCAL (this PC)        WINRM (LAN)             SSH (LAN)
        │                      │                      │
   Windows Security      Windows Security      /var/log/auth.log
   log, read directly    log, read remotely    read over SSH
        │                      │                      │
        └──────────────────────┼──────────────────────┘
                               ▼
                    Normalised event format
                               ▼
                  Parquet archive  +  Event table
                               ▼
                    Detection engine (R-01 … R-08)
                               ▼
                            Alerts
                               ▼
                          Dashboard
```

Every source produces the same normalised event, so the detection rules never
need to know where an event came from.

---

## 2. Central Mini-SIEM (your laptop)

### 2.1 Start it

Reading the Windows Security log requires an **elevated process**. An
Administrator terminal is not enough on its own — the Flask process itself
must be elevated.

Open PowerShell with **Run as Administrator**, then:

```bash
cd C:\Users\Info-Service\Desktop\Mini-SIEM
```

```bash
venv\Scripts\activate
```

```bash
flask run
```

Leave the window open. Browse to **http://127.0.0.1:5000** and log in.

### 2.2 Confirm it is elevated

Configuration → your local host → **Test**. You should see:

```
✓ Target is this machine
✓ Flask process is elevated
✓ Security log is readable
```

If the second line fails, Flask was not started from an elevated window.

---

## 3. Local Windows monitoring

Already configured if you have a host with **Collect logs via = LOCAL**.

| Field | Value |
|---|---|
| Hostname | `Yasir` |
| IP address | `192.168.100.68` |
| Operating system | Windows |
| Collect logs via | This PC's own Security log |

Windows must be auditing logons. To check:

```bash
auditpol /get /subcategory:"Logon"
```

If it reports "No Auditing", enable it (Administrator PowerShell):

```bash
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

To detect USB storage devices (rule R-09), Windows must also audit Plug and
Play events. This is off by default on every edition. To check:

```bash
auditpol /get /subcategory:"Plug and Play Events"
```

If it reports "No Auditing", enable it (Administrator PowerShell):

```bash
auditpol /set /subcategory:"Plug and Play Events" /success:enable
```

Only `/success` is needed: Event 6416 records a device that Windows *did*
recognise, so there is no failure case to audit. Plug a USB drive in
afterwards and collect again — the device appears in the **Recent USB
Devices** panel on the dashboard. Devices already attached when auditing was
enabled are not re-reported until they are unplugged and reconnected.

---

## 4. Remote Windows monitoring (WinRM)

### 4.1 On the target PC

Run these in an **Administrator PowerShell on the machine you want to
monitor**:

```bash
Enable-PSRemoting -Force
```

That starts the WinRM service, sets it to start automatically, and adds the
firewall rule for the local subnet. It does **not** disable the firewall.

Enable logon auditing there too:

```bash
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

And Plug and Play auditing, if you want USB detection on this host:

```bash
auditpol /set /subcategory:"Plug and Play Events" /success:enable
```

The dashboard reports whether this succeeded: the **USB audit** column in the
Monitored Hosts table reads the policy from the remote machine itself, so you
can confirm the setting took effect without signing back in to it.

Find its IP address:

```bash
ipconfig
```

### 4.2 On the Mini-SIEM machine

If the target is **not** domain-joined (an ordinary home or lab PC), tell
WinRM you trust it. Replace the address with your real one:

```bash
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '192.168.100.50' -Force
```

To trust several machines, separate them with commas. To inspect the current
value:

```bash
Get-Item WSMan:\localhost\Client\TrustedHosts
```

### 4.3 Credentials

The account must be a **local Administrator on the target PC**, because the
Security log is restricted to administrators.

Create `.env` in the project root if it does not exist:

```bash
copy .env.example .env
```

Add:

```
MINISIEM_WINRM_USER=LAB-PC\Administrator
MINISIEM_WINRM_PASSWORD=the-password
```

Notes:

- For a workgroup PC the username usually needs the `COMPUTERNAME\User` form.
- `.env` is git-ignored, so the password never reaches GitHub.
- The password is **never** stored in the database — only the username is.
- Restart Flask after editing `.env`.

### 4.4 Add the host

Configuration → Add Host:

| Field | Value |
|---|---|
| Hostname | `Windows-Lab-PC` |
| IP address | the target's real IP |
| Operating system | Windows |
| Collect logs via | Remote Windows PC (WinRM) |
| Remote username | `LAB-PC\Administrator` |

Then click **Test**. A healthy result:

```
✓ Host reachable on port 5985
✓ Credentials configured
✓ Authentication successful
✓ Security log accessible
```

### 4.5 Removing the configuration afterwards

On the target PC:

```bash
Disable-PSRemoting -Force
```

On the Mini-SIEM machine:

```bash
Clear-Item WSMan:\localhost\Client\TrustedHosts -Force
```

Then delete the credentials from `.env`.

---

## 5. Linux monitoring (SSH)

### 5.1 On the Linux machine

Make sure SSH is running:

```bash
sudo systemctl status ssh
```

The account you use must be able to read the authentication log —
`/var/log/auth.log` on Debian/Ubuntu, `/var/log/secure` on RHEL/Fedora.
Usually that means membership of `adm` or `wheel`:

```bash
sudo usermod -aG adm siem-reader
```

### 5.2 On the Mini-SIEM machine

Add to `.env`:

```
SSH_DEFAULT_USER=siem-reader
SSH_DEFAULT_PORT=22
SSH_KEY_FILE=C:/Users/Info-Service/.ssh/id_ed25519
```

Key-based authentication is preferred over a password.

### 5.3 Add the host

| Field | Value |
|---|---|
| Hostname | `Linux-Lab` |
| IP address | the server's IP |
| Operating system | Linux |
| Collect logs via | Remote Linux host (SSH) |
| Remote username | `siem-reader` |

Click **Test**:

```
✓ Host reachable on port 22
✓ Authentication successful
✓ Authentication log readable — Found /var/log/auth.log
```

---

## 6. Network and firewall requirements

| Purpose | Port | Direction |
|---|---|---|
| WinRM (HTTP) | 5985/TCP | Mini-SIEM → Windows target |
| WinRM (HTTPS) | 5986/TCP | Mini-SIEM → Windows target |
| SSH | 22/TCP | Mini-SIEM → Linux target |

All machines must be on the same LAN, or routable to each other.

`Enable-PSRemoting` adds the WinRM firewall rule for private networks only.
If your network is classified **Public**, Windows blocks it. Check with:

```bash
Get-NetConnectionProfile
```

If it says Public, either change that network to Private in Windows settings,
or add a scoped rule — do **not** disable the firewall.

---

## 7. Demo day procedure

### Part A — local Windows

1. Start Flask from an **elevated** PowerShell. Log in.
2. **Configuration** → confirm your local host shows 🟢 or ⚪.
3. Lock the screen with `Win`+`L`.
4. Type the **wrong** password twice, then sign in correctly.
   Windows records 4625, 4625, 4624.
5. Back in Mini-SIEM: **Collect Logs**.
   Expect: *"Received N, stored N new, ignored 0 duplicates"*.
6. **Events** → amber `WIN_FAILED_LOGIN` rows and a green `SUCCESSFUL_LOGIN`.
7. **Dashboard** → host now 🟢 online; event counts updated.

**Say:** "The SIEM has read the machine's real Windows Security log,
normalised each record into a common event format, stored it, and applied the
detection rules."

### Part B — detection (R-01)

8. Lock the screen and fail **five times within ten minutes**.
9. **Collect Logs** again.
10. **Alerts** → one `R-01` MEDIUM alert.

**Say:** "R-01 correlates repeated failures rather than alerting on each one.
Five failures in ten minutes is a burst; the same five spread over an
afternoon is somebody forgetting their password. The rule distinguishes them,
which is the difference between a detection rule and a log viewer."

### Part C — deduplication

11. Click **Collect Logs** again immediately.
12. Result shows *"stored 0 new, ignored N duplicates"*.

**Say:** "Collections overlap in time, so the same record can arrive twice.
Each event is fingerprinted, so re-collecting cannot inflate the counts."

### Part D — remote Windows

13. **Configuration** → **Test** on the remote host → four green checks.
14. On the remote PC, fail a sign-in.
15. **Collect Logs** on that host.
16. **Events** → filter by host; the remote hostname appears with its events.
17. **Dashboard** → two hosts online.

**Say:** "This is centralised monitoring: one dashboard, multiple machines,
one detection engine."

### Part E — threat intelligence

18. **Configuration** → mark an attacking IP as `BANNED`.
19. **Alerts** → **Re-run detection**.
20. Severity escalates to HIGH via R-03.

**Say:** "Because events are stored separately from alerts, the system can
re-evaluate evidence it already holds when our knowledge changes. Nothing was
re-collected."

### Part F — Linux (if available)

21. **Test** the Linux host → three green checks.
22. **Collect Logs** → SSH events appear alongside the Windows ones.

### Part G — automatic collection

This is the part that shows the system monitoring rather than being operated.
Set it up *before* the demonstration starts.

23. **Configuration** → switch **auto-collect** on for your local host and set
    the interval to `60`. The panel above the host list should read
    **running**, and the dashboard heading should show a **live** badge.
24. Leave the **Dashboard** open on screen.
25. Now cause something: fail a sign-in at the lock screen, or plug in a USB
    drive. Do not touch Mini-SIEM.
26. Keep talking. Within about a minute the event, and any alert it triggers,
    appears on the dashboard on its own — no button, no page reload.

**Say:** "Until now every collection began with me pressing a button, which
means nothing would be noticed unless somebody was already watching. The
scheduler runs the identical pipeline on a timer, per host. What you just saw
was the system detecting something while nobody was operating it — which is
the difference between a log viewer and a monitor."

If the room's timing is tight, **Run now** forces a round immediately rather
than waiting for the interval.

> Note that automatic collection lives in the Flask process. Closing the
> server stops it; it is not installed as a Windows service.

### Part H — file integrity (R-10)

This is the rule that catches what happens *after* a break-in, and it demos
well because you can cause the change yourself in one line.

27. **Configuration** → **Files** on your local host.
28. Watch a file you can safely edit — make one first if you prefer:

    ```bash
    echo original > C:\lab\watched.txt
    ```

    Add `C:\lab` as the watched path, or the file itself.
29. **Scan now.** It reports *"Baseline recorded for N file(s)"* and finds
    nothing. Point this out — it is the correct behaviour, not a failure.
30. Now change the file:

    ```bash
    echo tampered >> C:\lab\watched.txt
    ```

31. **Scan now** again. The dialog names the file as `FILE_MODIFIED`.
32. **Dashboard** → the **File Integrity Changes** panel lists it.
33. **Alerts** → one `R-10` **HIGH** alert naming the file.

**Say:** "Every other rule in this system reads a log. Windows will happily
tell me who signed in, but nothing in any log says that a file changed — so an
intruder who edits a startup script leaves no trace the other nine rules could
find. This hashes the file with SHA-256 and compares it to a stored baseline.
The hash changed, so the bytes changed, whatever the modification date claims —
and modification dates can be forged, which is exactly why the comparison is on
the hash."

Two follow-ups worth having ready, because they are the obvious questions:

- *"What about a legitimate update?"* — **Reset baseline**. It is manual on
  purpose: a system that re-baselined by itself after reporting a change would
  destroy the evidence it exists to keep.
- *"Does it tell you who changed the file?"* — No, and it does not claim to.
  Hashing proves the contents changed and nothing else. The user is recorded
  as `UNKNOWN` rather than guessed at; correlating with the sign-in events
  around that timestamp is the analyst's job.

> If you enabled auto-collect in Part G, integrity scans run on the same
> schedule — so you can leave the dashboard open, edit the file, and let the
> alert arrive on its own.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "Flask process is elevated ✗" | Server started from a normal window | Restart Flask from an Administrator PowerShell |
| "Host reachable on port 5985 ✗" | WinRM not running, or firewall | `Enable-PSRemoting -Force` on the target; check the network is Private |
| "Authentication successful ✗" | Wrong password, or wrong username form | Use `COMPUTERNAME\User`; confirm the account is a local Administrator |
| TrustedHosts error | Target not domain-joined | `Set-Item WSMan:\localhost\Client\TrustedHosts -Value '<ip>' -Force` |
| "No new log entries" | Genuinely nothing new since last collection | Generate a failed sign-in, then collect again |
| Collection returns 0 events | Logon auditing disabled | `auditpol /set /subcategory:"Logon" /success:enable /failure:enable` |
| USB panel stays empty, other events arrive | Plug and Play auditing disabled | `auditpol /set /subcategory:"Plug and Play Events" /success:enable` |
| USB panel empty after enabling auditing | The drive was already plugged in | Unplug it and reconnect, then collect again |
| Host shows 🔴 offline | Last attempt failed | Hover the badge, or read *Last error* on the host row |
| Login rejected | Wrong copy of the project | Confirm you started Flask from `Desktop\Mini-SIEM` |
| Dashboard badge says "manual" | No host has auto-collect switched on | Turn the switch on for a host on the Configuration page |
| Scheduler panel says "not running" | `SCHEDULER_ENABLED=false`, or the server was not restarted | Set it to `true` in `.env` and restart Flask |
| Automatic collection never fires | Interval not yet elapsed | Press **Run now**, or lower the interval |
| First integrity scan reports nothing | Correct — it is recording the baseline | Change a watched file, then scan again |
| Integrity scan finds 0 files | Path does not exist on the *monitored* host | Check the path is on the target machine, not the Mini-SIEM machine |
| Integrity panel reports changes every scan | Watching logs or temp files that change by themselves | Watch files that should never change on their own |
| "Only the first files were checked" | The 500-file cap was reached | Narrow the path, or turn off "include subfolders" |

---

## 9. Security notes

- Passwords live only in `.env`, which is git-ignored. The database stores
  usernames but never credentials.
- Remote passwords are passed to PowerShell through an environment variable,
  never on the command line, because command lines are readable by other
  accounts on Windows.
- Process command lines (Event 4688) are never collected: they routinely
  contain passwords and tokens.
- Nothing here disables the Windows firewall, UAC, or any security control.
- The account used for collection needs local Administrator on the target
  purely because Windows restricts the Security log to administrators.
- All remote operations have timeouts, so one unreachable machine cannot hang
  the dashboard.

---

## 10. Limitations to state honestly

- Collection is **on demand**, triggered by the Collect Logs button. It is not
  continuous, and it would be wrong to call it real-time.
- WinRM requires both machines on the same LAN with the port open.
- Windows local collection requires an elevated Flask process.
- SQLite and synchronous collection suit a lab, not enterprise event volumes.
- Detection is rule-based, not behavioural. That is a deliberate choice: every
  alert can be traced to a specific rule and a specific event, which is what
  makes the system explainable in a viva.
