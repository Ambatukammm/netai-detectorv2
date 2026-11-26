# NetAI Detector

**Cross-platform network anomaly detection and monitoring toolkit.**  
**Made by Ruel · Version 2.8.1**

NetAI Detector is an independent cybersecurity project designed to help inspect network traffic, build a baseline of normal activity, identify statistically unusual traffic windows, and review detection events through a local web dashboard.

> **Documentation:** [Security, algorithms, APIs and tools](SECURITY_AND_TECHNOLOGY.md) · [How it works](HOW_IT_WORKS.md)

> **Important:** An anomaly is not proof of malicious activity. This project is a learning, investigation and defensive-monitoring tool. Validate alerts with packet evidence and other security telemetry before responding.

## Features

- **Fully automatic:** start it and it learns your network, trains the model and monitors live traffic. No API calls, no CLI commands.
- **One-click launcher** for Windows, Linux and macOS (Python 3.10+). It creates its own environment, installs dependencies and asks for the administrator rights packet capture needs.
- Live status dashboard: learning progress, current phase, warnings, and *why* each anomaly was flagged (the features that deviated most from normal).
- **Investigation, not just detection:** every flagged window gets a *culprit summary* (who talked to whom, which ports and protocols, how much) and a plain-English *attack-type hint* (port scan, network sweep, SYN / UDP / ICMP flood, login brute-force, data exfiltration, DNS tunnelling).
- **Incidents:** flagged windows are grouped into incidents with a start and end, the hosts involved and peak severity. Unrelated attacks running at the same time become separate incidents.
- **Offline response advisor:** each incident comes with a step-by-step plan (confirm, contain, investigate, prevent) filled in with the real addresses and ports, plus copy-paste firewall commands with undo. Runs entirely on your machine; nothing is ever blocked automatically.
- **Evidence for Wireshark:** high-severity incidents are saved as headers-only `.pcap` files (payload cut off). Download them from the dashboard.
- **Alerts:** desktop notification, browser notification, and optional email and Slack.
- **Device names everywhere:** IPs are shown with the device's name, from your own labels, nmap, the Windows computer name (NetBIOS) or reverse DNS.
- **Network & devices page:** nmap discovery of your subnets *and other VLANs* (found from your routing table, from traffic, or added by you), a searchable device inventory with vendor, OS, open ports and risky services, and a one-click port scan per device.
- **Email notifications you set up in the dashboard:** Settings page with Gmail / Microsoft 365 / Outlook presets and a test button. Choose what to be emailed about: incidents, new devices, newly found risky services, finished scans, and daily or weekly reports.
- **Reports:** network & device inventory, SPAN discovery, incident and full reports, each with a health grade, prioritised findings with recommended actions, and what changed since the last report. View, download (HTML) or email them.
- **Aya, the local AI analyst:** Aya reviews every report and every finished scan: what she found, her honest assessment, what to improve, and what changed. She runs on this computer, with built-in expert rules (no setup) or a local language model through Ollama or LM Studio. Nothing is sent to the cloud.
- **Terminal:** run nmap, ping, traceroute or any command from the dashboard with live output, one-click nmap presets, command history and an audit log. nmap scans run here go into the inventory and scan history, and Aya reviews them.
- **Scan history kept on the machine:** every scan's full results are stored, compared with the previous scan of the same networks, and downloadable as CSV or JSON.
- **SPAN discovery page:** plug into a switch's mirror port and NetAI maps every device and the services it offers *without sending a packet*, tells you whether mirroring is working, and includes setup guides for Cisco, Aruba, UniFi, Netgear and MikroTik.
- Drag-and-drop PCAP analysis in the dashboard (`.pcap` / `.pcapng`), now with incidents too.
- Versioned 32-feature representation of traffic windows; packet payloads are never stored.
- Isolation Forest anomaly model with saved preprocessing and metadata.
- SQLite event history with automatic retention, REST API, interactive API docs.
- Optional API-key protection. Unit tests and GitHub Actions CI.

## Get started (the whole thing)

1. Install **Python 3.10+** from python.org (on Windows tick *Add python.exe to PATH*).
2. **Windows:** double-click `START_DETECTOR.bat` and click **Yes** on the administrator prompt.
   **Linux:** open the `linux` folder's guide ([linux/README.md](linux/README.md)) or simply run `bash linux/run.sh`. It installs everything the machine needs (Python, nmap, capture libraries, optionally Aya's local AI model), starts NetAI and opens the dashboard. `bash linux/service.sh install` keeps it running 24/7.
   **macOS:** run `./start_detector.sh` and enter your password when asked.

That's it. The first run installs what it needs (internet required once), then opens the dashboard at **http://127.0.0.1:8000**.

### What happens automatically

| Step | What NetAI does for you |
|---|---|
| 1. Set-up | Creates `.venv`, installs/updates dependencies when `pyproject.toml` changes |
| 2. Capture | Picks your default network interface and opens it (admin rights requested) |
| 3. Learn | Collects about 60 windows of normal traffic (~100 packets each) and shows progress on the dashboard |
| 4. Train | Trains and saves the model (`models/`), with no command needed |
| 5. Monitor | Scores every window, stores events, shows anomalies with the reasons |
| Next runs | Loads the saved model and goes straight to monitoring |

Use the dashboard buttons to **Pause**, or **Relearn baseline** after a big network change (the old model keeps working until the new one is ready). **Drop a PCAP file** onto the page to analyse it. If no model exists yet, the file is used to learn normal traffic instead.

### Capture methods (automatic)

NetAI tries these in order and uses the first that works. You never choose:

1. **Scapy** (best, handles more cases), which needs Npcap on Windows or libpcap on Linux/macOS.
2. **Built-in raw-socket capture**, with no driver and no extra software. Windows and Linux, IPv4 only, administrator/root required. This means **Windows no longer needs Npcap**.
3. **Simulated demo** if neither works. The dashboard says exactly why and labels it DEMO; events are tagged `demo` and are replaced automatically once real capture works.

macOS needs Scapy (no built-in fallback). Declining the admin/sudo prompt leaves the app running in demo/PCAP-only mode.

### Optional settings

Everything works with defaults. To change something, copy `.env.example` to `.env`; it is read automatically.

## Advanced / scripted use (optional)

`netai` with no arguments is the same as the launcher. The old step-by-step commands still exist for scripting: `netai capture`, `netai train`, `netai pcap FILE`, `netai serve --no-browser`.

## API

- `GET /health` — service/model status.
- `GET /api/stats` — event totals.
- `GET /api/events?limit=50` — recent events (flagged ones include the culprit summary and hints).
- `GET /api/incidents?limit=50` — incidents, newest first.
- `GET /api/incidents/{id}` — one incident with the advisor's response plan.
- `GET /api/incidents/{id}/evidence` — download the incident's headers-only `.pcap`.
- `POST /api/alerts/test` — send a test alert on every configured channel (dashboard button).
- `GET /api/devices` · `POST /api/devices/{ip}/label` · `POST /api/devices/{ip}/scan` · `DELETE /api/devices/{ip}` — device inventory.
- `GET /api/network` · `POST /api/network/subnets` · `GET|POST /api/scan` · `POST /api/scan/cancel` — nmap subnets and scans.
- `GET /api/span` — passive discovery status and every service found.
- `GET|POST /api/settings/notifications` · `POST /api/settings/notifications/test-email` — notification and Aya settings (secrets are never returned).
- `GET /api/aya` · `POST /api/aya/test` — Aya's engine, model server status and installed models; test review.
- `GET /api/scans/{id}/results?format=json|csv` · `POST /api/scans/{id}/review` — stored scan results; ask Aya to review a scan again.
- `GET /api/data` · `POST /api/data/wipe` · `DELETE /api/reports[/{id}]` · `DELETE /api/scans[/{id}]` · `DELETE /api/incidents[/{id}]` · `DELETE /api/events` · `DELETE /api/devices[/{ip}]` · `DELETE /api/terminal/history` — stored data and removing it.
- `GET /api/terminal` · `POST /api/terminal/run` · `GET /api/terminal/runs/{id}` · `POST /api/terminal/runs/{id}/stop` — the terminal (only when enabled; see below).
- `GET|POST /api/reports` · `GET /api/reports/{id}` · `GET /api/reports/{id}/html` · `POST /api/reports/{id}/email` — reports.
- `GET /api/features` — feature names and schema version.
- `GET /api/status` — monitor phase, learning progress, warnings, model info.
- `POST /api/monitor/{pause|resume|relearn}` and `POST /api/pcap` — used by the dashboard; require header `X-Requested-With: netai` (and the API key if set).
- `POST /api/predict` — optional: score a feature vector from another tool and store the result.
- `GET /docs` — interactive OpenAPI docs.

Example request body (replace the example values with 32 actual extracted features):

```json
{
  "features": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
  "source": "analyst-workstation",
  "details": {"case": "LAB-001"}
}
```

If `NETAI_API_KEY` is set, provide it in the `X-API-Key` header for prediction and control requests, and for the event, incident and evidence endpoints, since those contain IP addresses (the dashboard asks for it once). Keep the service bound to `127.0.0.1` unless you have configured authentication, firewall rules and TLS for a trusted network.

## Configuration

All optional. Put overrides in `.env` (loaded automatically) or in the environment.

| Variable | Default | Purpose |
|---|---|---|
| `NETAI_MODE` | `auto` | `auto` live capture, falling back to demo · `live` never simulate · `demo` always simulate · `off` no background monitoring |
| `NETAI_INTERFACE` | system default | Network interface to watch |
| `NETAI_LEARN_WINDOWS` | `60` | Windows of normal traffic to learn from (min 20) |
| `NETAI_WINDOW_PACKETS` | `100` | IPv4 packets per window |
| `NETAI_WINDOW_FLUSH_SECONDS` | `20` | Close a window early on quiet networks (needs 10+ packets) |
| `NETAI_RETRAIN_HOURS` | `168` | Refresh the model from recent normal traffic this often (`0` = never) |
| `NETAI_OPEN_BROWSER` | `1` | Open the dashboard automatically |
| `NETAI_NO_ELEVATE` | empty | Set to `1` to skip the admin/sudo prompt |
| `NETAI_HOST` / `NETAI_PORT` | `127.0.0.1` / `8000` | Bind address/port (a free port is chosen automatically if busy) |
| `NETAI_DB` / `NETAI_MODEL` / `NETAI_BASELINE` | `data/netai.db` / `models/anomaly_model.joblib` / `data/baseline.npz` | File locations |
| `NETAI_MAX_EVENTS` | `50000` | Newest events kept in the database |
| `NETAI_MAX_PCAP_MB` | `500` | Largest PCAP accepted through the dashboard |
| `NETAI_API_KEY` | empty | Optional key for prediction/control requests and host data |
| `NETAI_EVIDENCE` | `high` | Save headers-only evidence for incidents at this severity and above: `off` · `high` · `medium` · `all` |
| `NETAI_EVIDENCE_DIR` / `NETAI_EVIDENCE_MAX_MB` | `data/evidence` / `200` | Where evidence goes; oldest files are deleted above the size cap |
| `NETAI_EVIDENCE_MAX_PACKETS` | `20000` | Packets saved per incident |
| `NETAI_INCIDENT_CLOSE_AFTER` | `3` | An incident ends after this many windows in a row without it |
| `NETAI_INCIDENT_GAP_SECONDS` | `120` | …or after this long with no activity |
| `NETAI_TRUSTED_HOSTS` | empty | Comma-separated addresses expected to look odd (your own scanner, backup server). The advisor points it out |
| `NETAI_ALERT_MIN_SEVERITY` | `high` | Alert for incidents at this severity and above (`medium` / `high`) |
| `NETAI_ALERT_DESKTOP` | `1` | Desktop notification |
| `NETAI_SLACK_WEBHOOK` | empty | Slack incoming-webhook URL; enables Slack alerts |
| `NETAI_SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_FROM` / `_TLS` | empty / `587` / … / `starttls` | Email server; with `NETAI_ALERT_EMAIL_TO` enables email alerts |
| `NETAI_ALERT_EMAIL_TO` | empty | Comma-separated recipients |
| `NETAI_ALERT_INCLUDE_HOSTS` | `1` | `0` replaces IP addresses with `[address]` in email/Slack alerts |
| `NETAI_DASHBOARD_URL` | empty | Link included in alerts |
| `NETAI_RESOLVE_NAMES` | `1` | Look up device names (reverse DNS, NetBIOS) |
| `NETAI_NMAP` | auto | Path to nmap if it isn't found automatically |
| `NETAI_SCAN_MAX_MINUTES` | `0` | `0` = no time limit (default). Set a number of minutes to stop long scans automatically; devices finished by then are kept |
| `NETAI_PASSIVE_DISCOVERY` | `1` | Learn devices and services from traffic (SPAN page) |
| `NETAI_PROMISCUOUS` | `1` | Capture all traffic on the interface, needed for SPAN/mirror ports |
| `NETAI_AYA_ENGINE` | `builtin` | Aya's engine: `builtin`, `ollama` or `openai` (LM Studio, llama.cpp, LocalAI). Also on the Settings page |
| `NETAI_AYA_URL` / `NETAI_AYA_MODEL` | Ollama `http://127.0.0.1:11434`, LM Studio `http://127.0.0.1:1234` / empty | Aya's local model server and model |
| `NETAI_AYA_TIMEOUT` | `300` | Seconds to wait for a local model (CPUs are slow) |
| `NETAI_TERMINAL` | `auto` | Dashboard terminal: `auto` = only when bound to 127.0.0.1 · `on` = also on the network (requires `NETAI_API_KEY`) · `off` |
| `NETAI_TERMINAL_TIMEOUT_MINUTES` | `30` | Stop any terminal command after this long |
| `NETAI_ALLOWED_HOSTS` | empty | Extra names the dashboard may be opened with when bound to 127.0.0.1 |

Email settings in this table can also be set on the **Settings** page, which overrides `.env`.

## Email notifications and reports

Open **Settings**, click your mail provider's quick-setup button (or fill in your server), enter the username, password and recipients, **Save** and press **Send test email**. Gmail and Microsoft accounts with 2-step verification need an *app password*. Then tick what you want to be emailed about. New-device and risky-service emails compare against what NetAI saw a minute earlier; the first check after switching them on only records the current state, so you won't get a flood.

Open **Reports** to create a report of any type, view it, download it as a self-contained HTML file, or email it. Scheduled reports use this computer's local time.

### How reports are graded

Each finding has a priority, judged for a business network:

- **High:** services anyone inside can abuse easily: Telnet, VNC, Redis, MongoDB, TFTP; clear attack patterns in incidents.
- **Medium:** FTP, MQTT, Remote Desktop enabled on more than three machines, newly opened ports, repeat attackers.
- **Low:** databases, SNMP, Remote Desktop on a few servers, unnamed devices, a network that has never been scanned.
- **Information (no points):** normal Windows file sharing (SMB 445, RPC 135, NetBIOS 139), printer ports, and whether a SPAN mirror is in use. They come with advice but don't lower the grade.

The score starts at 100. The first finding of a priority costs the most and further ones less, with a cap per priority, so one bad device doesn't sink the grade (high: 20 then 10 each, up to 60; medium: 8 then 4, up to 25; low: 2 each, up to 10). A 90+, B 75+, C 60+, D 40+, F below 40. Every report says what cost points and what fixing the top issues would raise the grade to. Reports saved by earlier versions keep the grade they were given: delete them and create new ones.

### Removing data

Everything can be removed from the page it's on: **Delete** on a report, a scan (with its stored results and Aya's review), an ended incident (with its evidence file) and **Forget** on a device, plus **Clear …** buttons for whole lists (reports, scan history, ended incidents, detection events, the device inventory, the terminal log). **Settings → Data & storage** shows how much is stored and can clear each kind, or everything at once (type DELETE to confirm). Ongoing incidents and running scans are never deleted, and your settings and learned baseline are kept.

### Aya, the local AI analyst

Aya reviews every report and, automatically, every finished nmap scan. Her review always has the same four parts: **what I found**, **my assessment** (her honest opinion), **what to improve** (numbered, most important first, naming the devices) and **since last time**. Scan reviews compare with the previous scan of the same networks: new devices, devices gone quiet, newly opened and closed ports.

Aya runs on this computer:

- **Built-in** (default, nothing to install): NetAI's expert rules write the review. Fast and works everywhere.
- **Local language model** for richer, more natural reviews: install [Ollama](https://ollama.com/download), run `ollama pull llama3.1:8b` (about 5 GB; 8 GB+ RAM, a graphics card makes it much faster), then in **Settings → Aya** choose *Ollama*, press *Check server*, pick the model, *Save* and *Test Aya*. LM Studio, llama.cpp server and LocalAI work too (OpenAI-compatible engine, e.g. `http://127.0.0.1:1234`).

Your network data goes only to that model server, which normally runs on the same computer; the Settings page warns you if the server you enter is outside your local network. If the model isn't running, Aya falls back to her built-in analysis and says so in the review. Her reviews are advice: check before acting.

## Network scanning and VLANs

Install **nmap** (free, https://nmap.org/download; the Windows installer also installs Npcap, which NetAI uses for better capture). Open **Network & devices**, tick the subnets to scan, confirm you're authorised, and press **Start scan**. NetAI suggests subnets from this computer's interfaces, from its **routes to other VLANs**, from private ranges seen in traffic, and from your own list. It can only scan VLANs this computer can reach through your router/firewall; for isolated VLANs, run NetAI on a machine (or VLAN-tagged interface) inside them, or allow it on the firewall. Scans are limited to /16 per range and one at a time, and can be cancelled.

**Port & OS scan of the inventory:** below the device inventory, scan the devices you already know (the ones shown by your filters, the ones you tick, devices not marked offline, or the whole inventory) for the top 1000 ports or all 65,535, with service versions and an OS guess. It skips device discovery (`nmap -Pn`), so it also works on PCs whose firewall ignores pings, and it never marks a device offline just because it showed no open ports. **Scan ports** on a single device does the same for one device. Long lists are handed to nmap in a file, so whole inventories work on Windows too.

**Long scans:** there is no time limit (a 1000-port scan of a large network can take hours). The progress line shows nmap's own estimate of the time left. If you cancel, or set `NETAI_SCAN_MAX_MINUTES`, every device nmap had already finished is kept in the inventory and scan history, and Aya reviews it.

**Sorting and filtering the inventory:** sort by most relevant (risky services and new devices first), newest or oldest devices, name A→Z or Z→A, IP address, last seen, or most open ports; filter by status (online/offline/unknown), how the device was found (nmap, traffic, added by you), when it was added (24 hours, 7 days, 30 days), named or unnamed, risky services and open ports. Your choices are remembered in your browser.

**Only scan networks you own or are authorised to scan.** Port scans can trip intrusion-prevention systems and, rarely, upset fragile devices (old printers, industrial kit): start with *Find devices (fast)* and add exclusions where needed.

## Terminal

The **Terminal** page runs commands on the NetAI computer and streams the output: nmap (with presets for device discovery, quick ports, service versions, OS detection, all ports, UDP and vulnerability scripts), ping, traceroute, nslookup, ARP table, IP configuration and connections, or anything else. Use ↑/↓ for history, **Stop** (or Ctrl+C) to end a command. Commands can't ask for keyboard input, and stop after 30 minutes. When a simple `nmap` command finishes, its results are added to the device inventory and scan history and Aya reviews it, the same as scans from the Network page. If nmap isn't on the PATH, NetAI uses the copy it found.

**Security:** commands run with NetAI's rights, which are normally administrator/root: the terminal is effectively an admin shell. So it is only available when the dashboard listens on this computer only (`NETAI_HOST=127.0.0.1`, the default); on the network it needs both `NETAI_API_KEY` and `NETAI_TERMINAL=on`, and you should also use a firewall rule and TLS. Every command (not its output) is logged with time and exit code. While bound to 127.0.0.1, NetAI also rejects requests addressed to any other host name, which stops malicious websites from reaching it through "DNS rebinding".

## SPAN (port mirroring)

Set a free switch port to mirror your uplink (or the ports/VLANs you care about), connect a second network card of the NetAI computer to it, set `NETAI_INTERFACE` to that card and restart. The **SPAN discovery** page confirms when mirrored traffic is arriving and lists every service seen. Passive discovery only finds services that are used while it listens; use an nmap scan to find quiet ones.

## When something is flagged: investigating an incident

1. Open the **Incidents** table on the dashboard and click the incident.
2. **What is happening** gives NetAI's best guess (with a confidence level). **Who was involved** lists the main conversations: from, to, protocol, packets, data, ports. Addresses marked *your network* are your own devices.
3. Follow the **Suggested response**: *Confirm* (is it real, is it yours?), *Contain* (block or isolate, with copy-paste commands and undo), *Investigate*, *Prevent*.
4. **Download evidence** and open it in Wireshark (*Statistics → Conversations* and *I/O Graph* are the quickest views). Wireshark will say the packets are shorter than their original length: that is the payload being cut off on purpose.

Hints and plans are suggestions, not verdicts. NetAI never blocks traffic by itself, because automatic blocking can cut off legitimate users.

### Privacy: what is stored

| Stored | When | Contains |
|---|---|---|
| Feature numbers | every window | aggregate counts only |
| Culprit summary | flagged windows only | IP addresses, ports, protocols, packet/byte counts |
| Evidence `.pcap` | incidents at/above `NETAI_EVIDENCE` | IP + TCP/UDP/ICMP headers (addresses, ports, flags). **No payload, no MAC addresses** |
| Alerts | when sent | summary with addresses and device names (set `NETAI_ALERT_INCLUDE_HOSTS=0` to remove them from email/Slack) |
| Settings | when saved | mail server login (and a local model server key, if you set one), stored **unencrypted** in `data/netai.db` on this computer (never shown in the dashboard). Use an app password, and protect the computer and the `data/` folder |
| Reports | when created (newest 200 kept) | the findings, tables and Aya's review shown in the report |
| Terminal log | every terminal command (newest 5,000) | the command, shell, time and exit code (not the output) |
| Scan results | after every nmap scan (newest 200 scans kept) | each device found: IP, hostname, MAC/vendor, OS guess, open ports and services |
| Device inventory | always (passive discovery, scans, name lookups) | internal IP addresses, names, MAC/vendor, OS guess, open ports. Internet servers are not listed |

IP addresses and packet headers count as personal data in many workplaces. Set `NETAI_EVIDENCE=off` if you are not allowed to keep them, and follow your organisation's retention policy. Evidence and the database stay on this machine (`data/`, ignored by git).

### Alerts

The desktop notification works out of the box (Linux needs `notify-send`, from `libnotify-bin`). Use **Send test alert** on the dashboard to check it, and **Enable browser notifications** for pop-ups while the dashboard is open. For email, set the `NETAI_SMTP_*` settings and `NETAI_ALERT_EMAIL_TO` (with Gmail, use an *app password*). For Slack, create an incoming webhook and set `NETAI_SLACK_WEBHOOK`. Simulated (demo) incidents never send desktop/email/Slack alerts.

## Model limitations and responsible use

- Learning is automatic and **robust to some contamination**: training ignores windows that are extreme outliers (up to 20%), and the dashboard warns if a lot was ignored. A *sustained* attack during learning (more than ~20% of it) can still become "normal". Use *Relearn baseline* if that happens.
- The model refreshes itself weekly from recent traffic that was **not** flagged. A very slow, deliberate drift could still shift "normal"; set `NETAI_RETRAIN_HOURS=0` to disable.
- Train on representative, known-good traffic from the environment being monitored.
- A baseline can contain attacks or unusual-but-legitimate activity; curate training data.
- Isolation Forest identifies statistical outliers, not specific malware families or attack techniques.
- The contamination setting influences the expected outlier proportion.
- Scores and severity labels are triage aids, not calibrated probabilities. *High* means the score is far above typical normal traffic, or the traffic clearly matches a known attack pattern.
- Attack-type hints are simple rules on header statistics within ~100-packet windows. Slow attacks spread over hours (a scan of one port every minute) can stay below them, and legitimate tools (backups, vulnerability scanners, VPNs) can match them. Use `NETAI_TRUSTED_HOSTS` for known ones.
- The current feature set focuses on IPv4 aggregate metadata. It does not inspect encrypted payloads, fully parse IPv6, or replace an IDS such as Zeek or Suricata.
- Do not capture networks without permission. Follow your workplace's privacy, retention and monitoring policies.

## Development

```bash
python start.py        # sets up .venv; then Ctrl+C
.venv/bin/pip install -e ".[dev]"    # Windows: .venv\Scripts\pip
.venv/bin/pytest
```

## Project structure

```text
src/netai_detector/
  monitor.py      Automatic engine: learn -> train -> monitor -> investigate
  forensics.py    Culprit summaries and attack-type hints (packet headers only)
  incidents.py    Groups flagged windows into incidents
  advisor.py      Offline response playbooks filled in with real hosts/ports
  evidence.py     Headers-only .pcap evidence files
  alerts.py       Desktop, email and Slack alerts
  devices.py      Device names (labels, NetBIOS, reverse DNS)
  scanner.py      nmap subnet/VLAN discovery and port scans
  passive.py      SPAN/mirror passive device and service discovery
  notifications.py  Dashboard-editable email/AI settings and the email sender
  notifier.py     Report service and background email notifier (new devices, schedules)
  reports.py      Report findings, grading and HTML/text rendering
  terminal.py     Dashboard terminal (commands, live output, nmap import, audit log)
  aya.py          Aya, the local AI analyst (built-in rules, Ollama, OpenAI-compatible servers)
  api.py          FastAPI API
  dashboard.py    Dashboard page
  capture.py      Live capture (Scapy or built-in raw socket) + PCAP extraction
  demo.py         Simulated traffic (fallback only, clearly labelled)
  cli.py          Entry point (`netai`)
  config.py       Configuration (.env auto-loaded)
  detection.py    Model training and inference
  features.py     Versioned feature extraction
  storage.py      SQLite event history
start.py           One-click launcher (set-up, install, elevate, run)
start_detector.sh / START_DETECTOR.bat
tests/
```

## Licence

MIT. Review the licence and organisational policy before deploying this software in a workplace environment.
