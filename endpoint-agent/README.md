# Endpoint agent (Sysmon)

Protects and monitors the devices *inside* the network. A small agent runs on each device,
reads that device's [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon)
log, and reports to the SOAR backend:

- **Every event** (processes, network connections, files, registry, DNS) goes to the live activity feed for that device: dashboard → **Assets** → *Connected Endpoints* → **View activity**.
- **Suspicious events** become alerts (`POST /alerts`, tagged with the device name) and go through the normal pipeline: AI severity → threat intel → MITRE → risk score → playbook.
- **Office-policy events** (too much YouTube or social media during work hours, a VPN/Tor client started, a known-malicious website visited) become alerts too, each ending with a *Recommended action*.
- A **heartbeat** every 5 s shows the device Online/Offline, who owns it, and today's usage in Assets, and brings back the ON/OFF monitoring switches.

## What it detects

| Rule key | Examples | MITRE |
|---|---|---|
| `sysmon_suspicious_process` | encoded/hidden PowerShell, Office spawning a shell, Mimikatz, certutil/bitsadmin downloads, mshta/regsvr32/rundll32 abuse | T1059, T1204.002, T1003, T1105, T1218 |
| `sysmon_credential_dumping` | unknown program opening LSASS memory, ProcDump/comsvcs against LSASS | T1003 |
| `sysmon_autorun_persistence` | Run key pointing at a user-writable program, script dropped into Startup | T1547.001 |
| `sysmon_malicious_network` | connection to an address on the VPN/Tor/proxy blocklist; script host or Office app connecting out | T1090, T1218 |
| `sysmon_ransomware` | shadow-copy deletion, 5+ `.locked`-style files in 30 s | T1486 |
| `sysmon_malicious_website` | a DNS lookup of a domain on `malicious_domains.txt` (plus the optional URLhaus feed) | T1189 |
| `sysmon_policy_violation` | over the daily limit on streaming / social media / games during work hours; a VPN or Tor client (ProtonVPN, OpenVPN, WireGuard, NordVPN, Tor ...) started | POLICY-AUP |

Each rule can be switched off from the dashboard's detection-rules page.

## The activity policy (`policy.json`)

Edit `endpoint-agent/policy.json` (read when the agent starts):

- `work_hours`: days and hours when limits apply (default Mon-Fri 09:00-18:00; set `"enabled": false` for all day).
- `categories`: each has a `limit_minutes` and a list of `domains` (default: streaming 30, social 30, games 20).
- `forbidden_programs`: program names that should not run on a work device.

Alerts fire once the limit is passed and again at double the limit. Add domains to `malicious_domains.txt`, or run `python endpoint-agent/update_malicious_domains.py` (needs internet) to download the public URLhaus list.

What this can and cannot see (be upfront about it in the viva):

- Sysmon sees the **domain** a program looked up (`youtube.com`), not the page, video title or content.
- "Minutes" are **estimated**: a minute counts when the device looked up a domain of that category during that minute. It undercounts rather than overcounts.
- A browser using encrypted DNS (DNS-over-HTTPS) hides its lookups. Turn that off in the browser for the demo if nothing shows up.
- The usage figures are today's totals kept in the agent's memory; restarting the agent resets them.

## Monitoring ON/OFF

In **Assets → Connected Endpoints**:

- **Monitoring (all devices)**: the master switch, for example at the end of the working day.
- A switch on every device card.

While a device is paused (its own switch, or the master switch, is off) the agent stops reading Sysmon and sends nothing, and the backend ignores anything that device still sends. Whatever happened during the pause is never read, even after monitoring is switched back on. The switch takes effect within about 5 seconds.

## Try it without Sysmon (any OS)

The simulator produces events in the same shape as real Sysmon, so it exercises the same rules. Start the backend, then:

```bash
python endpoint-agent/sysmon_agent.py --simulate --hostname DEMO-PC-1 --owner "Priya Sharma" --attack all
```

Run it again in another terminal with a different `--hostname` and `--owner` (and e.g. `--attack youtube,vpnclient`) to show several devices. Scenarios: `powershell office mimikatz lsass persistence ransomware tor scripthost youtube social malicioussite vpnclient`, or `all`. Without `--attack` you get normal activity only. `--dry-run` prints alerts without contacting the backend, `--once` exits when the scenarios finish. In simulate mode the activity limits apply at any hour (use `--respect-work-hours` to behave like a real device).

## Real device (Windows), for you and each team member

Each laptop needs: **Sysmon**, **Python** (with `pip install requests`) and a copy of the `endpoint-agent` folder. Nothing else.

1. Download Sysmon from Microsoft Sysinternals.
2. In an **Administrator** prompt, install it with the included config: `sysmon64 -accepteula -i endpoint-agent\sysmonconfig.xml`
3. In an **Administrator** prompt (reading the Sysmon log needs it):
   `python endpoint-agent\sysmon_agent.py --backend http://<soar-pc-ip>:8000 --owner "Their Name"`

The agent starts from the newest event (`--backfill 200` replays the last 200). `--hostname` defaults to the computer's name.

For other computers to reach the backend, run it on your PC with `python -m uvicorn backend.main:app --host 0.0.0.0` and allow port 8000 through the Windows firewall. All laptops must be on the same network (a phone hotspot works). Find your PC's address with `ipconfig`.

Optional shared secret: set `SOAR_AGENT_TOKEN` on the backend and give each agent the same value (`--token` or the same variable). Without it, anyone on the network can post to the agent endpoints: lab use only.

## Privacy and consent

This records which domains a person's computer looks up and which programs they start. Only monitor devices whose users know about it and have agreed; tell them what is recorded (domains and program names, never page content, keystrokes or screenshots) and when (the ON/OFF switches). Use it only for work devices during work hours.

## Limitations

- The agent, parser and rules were tested with simulated events and sample Sysmon XML, **not against a live Sysmon install**. `sysmonconfig.xml` targets schema 4.90; if your Sysmon rejects it, run `sysmon64 -s` and adjust.
- Detection is rule-based, with a 60 s cool-down per finding so repeats don't flood the dashboard.
- Reporting only. The platform's response actions are simulated; the agent does not kill processes or isolate the device.
