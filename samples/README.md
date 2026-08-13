# Sample Log Files

Synthetic log data for testing and demonstrating Mini-SIEM (deliverable D-05).

These files contain **no real credentials, no real hosts and no personal
data**. Every source address is drawn from a range reserved for documentation
(RFC 5737) or private use (RFC 1918), so none of them routes to a real
machine.

| File | Format | Use |
|---|---|---|
| `linux_auth_sample.log` | Linux `auth.log` / journald text | Main demo file — SSH failed logins, invalid users, one successful login and a `sudo` entry. |
| `windows_security_sample.csv` | Windows Security log CSV export | Windows logon failures (Event ID 4625) plus one success (4624). |
| `normalized_events_sample.json` | Pre-normalized JSON | Shows the internal event format the parsers produce. |

## How to import

From the web interface: **Events → Import Sample Logs**, pick a host, choose
a file, and select **Import**.

From the command line:

```bash
python scripts/seed_sample_data.py
```

## Expected detections

Importing `linux_auth_sample.log` against a single host produces:

- **R-01** — `203.0.113.50` fails six times against `root` inside five minutes.
- **R-02** — invalid users `test`, `oracle` and `postgres`.
- **R-03** — only if `203.0.113.50` has been marked `BANNED` in the Threat
  Intelligence registry first. This is the step to demonstrate in a viva:
  import once, mark the IP banned, re-run detection, and watch the severity
  escalate to `HIGH`.
- **R-04** — only after the same file is imported against a *second* host, so
  one source IP is seen attacking two machines.

The slow `192.0.2.77` attempts are deliberately spread over 90 minutes so they
stay **below** the R-01 window threshold — useful for showing that the rule
distinguishes a burst from an occasional typo.
