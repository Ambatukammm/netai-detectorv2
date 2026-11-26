# NetAI Detector: Security, Algorithms, APIs and Tools

**Made by Ruel** · applies to version 2.8.x

This document explains how NetAI Detector is secured, which algorithms it uses, which APIs it
exposes and calls, and which third-party tools it depends on. It's written for anyone evaluating
the project: IT managers, security reviewers and developers.

---

## Contents

1. [Security](#1-security)
   - [Security model at a glance](#11-security-model-at-a-glance)
   - [Network exposure and access control](#12-network-exposure-and-access-control)
   - [Privileges](#13-privileges)
   - [Data handling and privacy](#14-data-handling-and-privacy)
   - [Impact on the network](#15-impact-on-the-network)
   - [Outbound connections](#16-outbound-connections)
   - [Input and output safety](#17-input-and-output-safety)
   - [The dashboard terminal](#18-the-dashboard-terminal)
   - [Known limitations and hardening checklist](#19-known-limitations-and-hardening-checklist)
   - [Responsible use](#110-responsible-use)
   - [Reporting a vulnerability](#111-reporting-a-vulnerability)
2. [Algorithms](#2-algorithms)
3. [APIs](#3-apis)
4. [Tools, libraries and licences](#4-tools-libraries-and-licences)

---

## 1. Security

### 1.1 Security model at a glance

NetAI Detector is a **single-machine, self-hosted** tool. It is designed so that, by default:

- the dashboard is reachable **only from the computer it runs on** (`127.0.0.1`);
- **nothing is sent to the cloud**: detection, reports and the AI analyst (Aya) all run locally;
- **normal traffic is stored only as statistics**. IP addresses are kept only for flagged traffic
  and for the device inventory, and packet contents (payloads) are never stored;
- it **never takes action on the network by itself**: it doesn't block, quarantine or reconfigure
  anything. Response plans are suggestions for a person to carry out.

Security protects the **dashboard and API**, the **data NetAI stores**, and the **network it watches**.

### 1.2 Network exposure and access control

| Control | Default | What it does |
|---|---|---|
| Bind address (`NETAI_HOST`) | `127.0.0.1` | The web server only accepts connections from the same computer. |
| API key (`NETAI_API_KEY`) | not set | When set, every endpoint that returns network data or changes anything requires the `X-API-Key` header. The dashboard asks for it once per browser session. |
| Request-origin header | always on | Every request that changes state (all `POST`/`DELETE`) must carry `X-Requested-With: netai`. Browsers won't let other websites send this custom header cross-origin, which blocks cross-site request forgery (CSRF). |
| No CORS | always | No cross-origin resource sharing is enabled, so other websites can't read NetAI's responses. |
| Host-header check | on when bound to 127.0.0.1 | Requests addressed to any host name other than `localhost`, `127.0.0.1` or `::1` (plus names listed in `NETAI_ALLOWED_HOSTS`) are rejected. This blocks **DNS-rebinding** attacks, where a malicious website points its own domain at `127.0.0.1` to reach local services. |
| Terminal policy (`NETAI_TERMINAL`) | `auto` | The command terminal only works while the dashboard is bound to this computer. See [1.8](#18-the-dashboard-terminal). |

**Exposing the dashboard to the network** (for example `NETAI_HOST=0.0.0.0`) is supported but
should only be done with all of the following:

1. a long random `NETAI_API_KEY`;
2. a firewall rule limiting port 8000 to admin machines;
3. TLS in front of it (a reverse proxy such as Caddy or nginx), because NetAI itself serves plain
   HTTP and the API key would otherwise travel unencrypted.

The safest way to use the dashboard remotely is an SSH tunnel:
`ssh -L 8000:127.0.0.1:8000 user@netai-host`.

**Endpoints that are always public** (no key): the dashboard pages, `/health`, `/api/status`,
`/api/stats`, `/api/features`, and FastAPI's built-in `/docs` and `/openapi.json`. They reveal the
monitor's state, counts, version and the capture interface name and this machine's own addresses
(on the SPAN status), but no traffic data. If that matters on an exposed deployment, put the whole
service behind the reverse proxy's authentication.

### 1.3 Privileges

Packet capture requires administrator/root rights, so NetAI asks for them at start-up:

| Platform | How it elevates |
|---|---|
| Windows | UAC prompt via the launcher (`START_DETECTOR.bat`) |
| Linux / macOS | `sudo` via `start.py` / `linux/run.sh` |
| Linux service | systemd unit (`linux/service.sh install`) runs as root |

If elevation is declined, NetAI still runs in **demo mode** or analyses uploaded capture files, but
without live capture. Because the process is privileged:

- anything it runs (nmap, terminal commands) runs with the same rights;
- files it creates are handed back to the logged-in user where possible (`SUDO_UID`), so the
  project folder doesn't fill up with root-owned files;
- it opens the browser as the normal user, never as root.

### 1.4 Data handling and privacy

Everything is stored **on the NetAI computer**, in the project folder:

| Data | Location | When | Contents | Kept |
|---|---|---|---|---|
| Detection events | `data/netai.db` | every traffic window | 32 statistical features, score, severity. Culprit details only for flagged windows | newest 50,000 |
| Incidents | `data/netai.db` | flagged traffic | IPs, ports, protocols, packet/byte counts, attack hints | newest 5,000 |
| Evidence files | `data/evidence/*.pcap` | incidents at/above `NETAI_EVIDENCE` (default: high) | IP + TCP/UDP/ICMP **headers only**; payload cut off; no MAC addresses (raw-IP link type) | 200 MB total, 20,000 packets per incident |
| Device inventory | `data/netai.db` | scans, passive discovery, name lookups | internal IPs, names, MAC/vendor, OS guess, open ports. Internet servers are not listed | until removed |
| Scan results | `data/netai.db` | every nmap scan | each device found and its open ports | newest 200 scans |
| Reports | `data/netai.db` | when created | findings, tables, Aya's review | newest 200 |
| Terminal log | `data/netai.db` | each terminal command | command text, shell, time, exit code (**not** output) | newest 5,000 |
| Settings | `data/netai.db` | when saved | email server login, optional local-AI server key | until changed |
| Model | `models/` | after learning | scikit-learn model and feature scaler (joblib) | replaced on retrain |

**Important:**

- IP addresses, device names and packet headers count as **personal data** in many jurisdictions
  and workplaces. Set `NETAI_EVIDENCE=off` if you may not keep them, and follow your
  organisation's retention policy.
- **Secrets are stored unencrypted** in `data/netai.db`: the email password and (if used) a local
  AI server key. They're never sent back to the browser (the dashboard shows `********`), but anyone
  who can read the `data/` folder can read them. Use an **app password**, not a main account
  password, and restrict access to the NetAI computer.
- Everything can be deleted from the dashboard (per item, per category, or **Settings → Data &
  storage → Delete all data**). `data/` and `models/` are excluded from git by `.gitignore`.
- Email and Slack alerts can have addresses and names stripped (`NETAI_ALERT_INCLUDE_HOSTS=0`).

### 1.5 Impact on the network

| Component | Sends traffic? |
|---|---|
| Live capture, anomaly detection | **No**. It reads copies of packets passing the network card. |
| Promiscuous mode / SPAN discovery | **No**. Listening on a mirror port is passive. |
| Device name lookups | Minimal: one reverse-DNS query and one NetBIOS name query (UDP 137) per new internal address, cached for an hour. |
| Dashboard, reports, Aya | None on the network (local only). |
| **nmap scans** | **Yes**, and only when a user starts one. |

nmap scans are run at nmap's `-T4` timing, one scan at a time. Probes are small (about 60 bytes), so
bandwidth use is low (typically well under 5 Mbit/s). The practical risks of scanning are not
bandwidth:

- **Firewalls between VLANs** create a state entry for every probe. Large all-port scans across a
  firewall can fill a small firewall's connection table.
- **Intrusion-prevention and endpoint security** may block or alert on the scanning machine. Tell
  your security team first.
- **Fragile devices** (old printers, IoT, industrial/medical equipment, some VoIP phones) can
  misbehave when probed for versions and OS. Exclude them. nmap already skips version probes on
  printer ports 9100–9107.
- The Terminal's **"Vulnerability scripts"** preset (`nmap --script vuln`) is intrusive. Use it only
  with permission and outside business hours.
- NetAI watches the network while it scans it, so **its own scans can appear as port-scan
  incidents**. Add the NetAI computer to `NETAI_TRUSTED_HOSTS` to have them marked as expected.

### 1.6 Outbound connections

| Destination | When | Why | Avoidable? |
|---|---|---|---|
| Your DNS server | name lookups | reverse DNS of addresses | `NETAI_RESOLVE_NAMES=0` |
| Devices on UDP 137 | name lookups | Windows computer names (NetBIOS) | `NETAI_RESOLVE_NAMES=0` |
| Targets you choose | nmap scans / terminal | network discovery | only when you run them |
| Your SMTP server | email alerts/reports | notifications | leave email unset |
| `hooks.slack.com` | Slack alerts | notifications | leave `NETAI_SLACK_WEBHOOK` unset |
| Local AI server (default `127.0.0.1`) | Aya with a model | report reviews | use Aya's built-in engine. The Settings page warns if the server is outside your local network |
| PyPI (pip) | first start-up | installing Python packages | pre-install the dependencies |
| Linux package mirrors, `ollama.com` | `linux/run.sh` first run | installing system packages / optional Ollama | answer "no", or install manually |

There is **no telemetry, analytics or phone-home** of any kind.

### 1.7 Input and output safety

- **Scan targets** must be IPv4 addresses or CIDR ranges (strict pattern match), are limited to
  `/16` per range and 262,144 addresses per scan, and are passed to nmap as an argument list (no
  shell). Long lists are written to a file (`-iL`). Inventory scans accept single devices only.
- **Settings** are validated (email addresses, ports, allowed values, URL format for the AI server).
- **Uploaded capture files** are streamed to a temporary file with a size limit
  (`NETAI_MAX_PCAP_MB`, default 500), parsed, and deleted.
- **Evidence downloads and deletions** only touch files inside the evidence folder; paths are
  resolved and checked, so a tampered database entry can't point elsewhere.
- **Rendering**: device names come from the network and can't be trusted (a device can call itself
  `<script>`). All report HTML is escaped server-side; the dashboard builds pages with DOM APIs
  (`textContent`), and reports shown in the dashboard are additionally stripped of scripts, event
  handlers and `javascript:` links before display.
- **Aya's model output** is treated as untrusted text: escaped when displayed, and never executed.

### 1.8 The dashboard terminal

The Terminal page runs shell commands on the NetAI computer with NetAI's (administrator) rights.
It is effectively an **admin shell in a browser tab**. Safeguards:

- available only when the dashboard is bound to `127.0.0.1` (`NETAI_TERMINAL=auto`). To allow it on
  the network you must set **both** `NETAI_API_KEY` and `NETAI_TERMINAL=on`. `NETAI_TERMINAL=off`
  disables it completely;
- every request needs the CSRF header, the API key (if set) and passes the DNS-rebinding check;
- every command is **audit-logged** (time, command, shell, exit code);
- no keyboard input reaches commands, at most 3 run at once, output is capped at 2 MB per command,
  and commands stop after 30 minutes (`NETAI_TERMINAL_TIMEOUT_MINUTES`);
- **Stop** kills the whole process tree.

If you don't need it, set `NETAI_TERMINAL=off`.

### 1.9 Known limitations and hardening checklist

**Limitations**

- Plain HTTP: use TLS via a reverse proxy if the dashboard is exposed beyond the local computer.
- A single shared API key, with no individual user accounts or roles.
- Secrets in the local database are not encrypted.
- The model file is loaded with `joblib` (Python pickle). Anyone who can write to `models/` can run
  code as NetAI. Keep the project folder writable only by administrators.
- Capture files are parsed by Scapy/NetAI's own parser. Only analyse files from sources you trust.
- Anomaly detection produces false positives, and slow attacks spread over hours may not stand out
  within a 100-packet window. NetAI complements, but doesn't replace, a firewall, endpoint
  protection and a signature-based IDS.

**Hardening checklist for business deployments**

- [ ] Keep `NETAI_HOST=127.0.0.1` (default); use an SSH tunnel for remote access.
- [ ] If exposed: set `NETAI_API_KEY`, put TLS in front, firewall port 8000.
- [ ] `NETAI_TERMINAL=off` unless you need it.
- [ ] Use an email **app password**; restrict who can log on to the NetAI computer.
- [ ] Decide on evidence retention (`NETAI_EVIDENCE`, `NETAI_EVIDENCE_MAX_MB`).
- [ ] Add the NetAI computer and authorised scanners to `NETAI_TRUSTED_HOSTS`.
- [ ] Get written permission before scanning; schedule big scans after hours; exclude fragile devices.
- [ ] Keep Python packages, nmap and Npcap up to date.

### 1.10 Responsible use

NetAI includes active scanning tools. **Only scan networks and devices you own or have written
permission to scan.** Unauthorised scanning may breach computer-misuse laws and your network
provider's terms. NetAI asks for confirmation before every scan, but the responsibility stays with
the person running it.

### 1.11 Reporting a vulnerability

Please report security problems privately through **GitHub → Security → Report a vulnerability**
on this repository (private vulnerability reporting) rather than in a public issue. Include steps to
reproduce, the version (`/health` shows it) and the operating system.

---

## 2. Algorithms

### 2.1 Traffic windows and features

Captured packets are grouped into **windows of 100 packets** (or fewer after a few quiet seconds).
Each window becomes a vector of **32 numeric features**, computed from headers only:

| Group | Features |
|---|---|
| Volume | packet count, total bytes, packets/second, bytes/second |
| Packet sizes | mean, standard deviation, min, max, median, share of small packets |
| Diversity | unique source/destination addresses, unique source/destination ports |
| Protocols | TCP, UDP, ICMP, other ratios |
| TCP flags | SYN, ACK, RST, FIN ratios |
| Direction | inbound, outbound, internal-to-internal, external-to-external ratios |
| Headers | mean and standard deviation of TTL, mean IP header length |
| Services | share of traffic to DNS, HTTP, HTTPS ports |

### 2.2 Anomaly detection: Isolation Forest

- **Algorithm:** scikit-learn `IsolationForest`, 250 trees, `contamination = 0.02`, fixed random
  seed. It isolates unusual points with random splits: outliers need fewer splits, so they get
  higher anomaly scores. It is **unsupervised**: it needs only examples of normal traffic, no
  labelled attacks.
- **Pre-processing:** features are standardised with `StandardScaler`.
- **Learning a baseline:** NetAI collects 60 windows (configurable) of live traffic, then trains.
- **Robust training:** the model is fitted once, windows scoring above *median + 4 × MAD* (at most
  20% of the data) are dropped as likely contamination (an attack during learning), and the model
  is refitted on the rest.
- **Threshold:** the 98th percentile of the training scores. A window is flagged if its score
  exceeds it (or the forest labels it an outlier).
- **Severity:** *high* if the score is at least **4.5 robust standard deviations** (MAD × 1.4826)
  above the median training score; otherwise *medium*. Median and MAD are used because they're
  stable on small baselines.
- **Explanation:** the three features with the largest standardised deviation (z-score) from the
  baseline are reported with each flag, e.g. `syn_ratio +9.8σ`.
- **Retraining:** weekly by default (`NETAI_RETRAIN_HOURS=168`), on recent windows that were
  judged normal, so the baseline follows gradual change.

### 2.3 Attack-type hints (rule-based)

For flagged windows only, transparent rules over header statistics suggest what the anomaly
resembles. Each hint carries a confidence (low/medium/high) and the evidence that triggered it.

| Hint | Main rule (per window) |
|---|---|
| Port scan | one source→destination flow reaches ≥15 distinct ports and ≥40% of packets |
| Network sweep | one source contacts ≥15 hosts on ≤3 ports and sends ≥50% of packets |
| SYN flood | one destination gets ≥50% of packets, ≥70% TCP, ≥60% SYN-only, ≤3 ports |
| UDP flood / DDoS | one destination gets ≥50% of packets, ≥70% UDP, from ≥10 sources or at a high rate |
| ICMP flood | one destination gets ≥50% of packets, ≥60% ICMP |
| Login brute-force | repeated new connections (≥8 source ports) to a login service port (SSH, RDP, SMB, FTP, databases…) carrying ≥35% of packets |
| Data exfiltration | an internal host sends ≥60% of the bytes (≥50 KB, large packets) to one external address |
| DNS tunnelling | one host sends ≥20 DNS packets (≥40% of the window) averaging ≥160 bytes |

### 2.4 Incident grouping

Flagged windows are merged into **incidents**. A new window joins an open incident when the
attacker/target addresses of its hints overlap that incident's; windows with no recognisable pattern
join the most recent open incident. Unrelated attacks happening at the same time therefore stay
separate. An incident closes after **3 windows** that don't belong to it or **120 seconds** without
activity. Its severity is the model's peak severity, raised to *high* when a known pattern is
recognised with high confidence.

### 2.5 Discovery

- **Device names:** best of your label → nmap hostname → NetBIOS name (node-status query, UDP
  137) → reverse DNS. Lookups run on background threads with a one-hour cache.
- **Passive service discovery (SPAN):** a TCP **SYN-ACK** from a port means that port is open; a
  reply from a well-known UDP port (DNS, NTP, SNMP, mDNS…) means that service runs. Only internal
  addresses are listed.
- **Mirror detection:** if at least 20% of packets (over 2,000-packet periods) are between *other*
  devices, mirroring is working.
- **Subnets and VLANs** to scan are suggested from this computer's interfaces and routing table
  (`nmap --iflist`), private ranges seen in traffic, and the user's own list.
- **Scan comparison:** each scan is compared with the previous completed scan of overlapping
  networks: new devices, devices no longer answering, newly opened and closed ports.

### 2.6 Report grading

Each finding has a priority judged for an internal business network:

| Priority | Examples |
|---|---|
| High | Telnet, VNC, Redis, MongoDB, TFTP; clear attack patterns in incidents |
| Medium | FTP, MQTT, Remote Desktop on more than 3 machines, newly opened ports, repeat attackers |
| Low | databases, SNMP, Remote Desktop on a few servers, unnamed devices, never scanned |
| Info (no points) | standard Windows sharing (SMB/RPC/NetBIOS), printer ports, mirror status |

Score = 100 − deductions, with **diminishing, capped** deductions per priority: high 20 for the
first + 10 each after (max 60); medium 8 + 4 (max 25); low 2 each (max 10).
Grades: **A** ≥ 90, **B** ≥ 75, **C** ≥ 60, **D** ≥ 40, **F** below 40. Each report states what
cost points and what fixing the top priority would change.

### 2.7 Aya, the local AI analyst

Aya writes a four-part review of every report and scan: *what I found*, *my assessment*, *what to
improve*, *since last time*.

- **Built-in engine (default):** deterministic rules turn the prioritised findings into that
  review. No model, no network.
- **Local language model (optional):** the report's findings and statistics are sent to a model
  running on a local server (Ollama or an OpenAI-compatible server such as LM Studio) with a fixed
  system prompt, temperature 0.3 and an 8,192-token context. If the model is unreachable, Aya falls
  back to the built-in engine and says so. Her output is advice and is labelled as such.

### 2.8 Response playbooks

Offline playbooks per attack type (scan, sweep, floods, brute force, exfiltration, DNS tunnelling,
unknown) produce *confirm → contain → investigate → prevent* steps filled with the real addresses,
device names and ports. Firewall commands are generated for Windows (`New-NetFirewallRule`) and
Linux (`iptables`), each with its undo command. Nothing is executed automatically.

---

## 3. APIs

### 3.1 NetAI's REST API

Served by FastAPI on `http://127.0.0.1:8000`. Interactive documentation: `/docs`.
**Auth levels:** *Public* = none · *Key* = `X-API-Key` if `NETAI_API_KEY` is set · *Control* =
Key + `X-Requested-With: netai`.

| Area | Endpoints | Auth |
|---|---|---|
| Health and status | `GET /health`, `/api/status`, `/api/stats`, `/api/features` | Public |
| Monitoring | `POST /api/monitor/{pause\|resume\|relearn}`, `POST /api/pcap` (upload a capture) | Control |
| Integration | `POST /api/predict` (score a 32-feature vector from another tool) | Key |
| Events and incidents | `GET /api/events`, `/api/incidents`, `/api/incidents/{id}` (with response plan), `/api/incidents/{id}/evidence` (pcap) | Key |
| Devices | `GET /api/devices`; `POST /api/devices/{ip}/label`, `/api/devices/{ip}/scan` | Key / Control |
| Network scanning | `GET /api/network`, `/api/scan`, `/api/scans/{id}/results?format=json\|csv`; `POST /api/network/subnets`, `/api/scan`, `/api/scan/cancel`, `/api/scans/{id}/review` | Key / Control |
| SPAN discovery | `GET /api/span` | Key |
| Reports | `GET /api/reports`, `/api/reports/{id}`, `/api/reports/{id}/html`; `POST /api/reports`, `/api/reports/{id}/email` | Key / Control |
| Settings and Aya | `GET /api/settings/notifications`, `/api/aya`; `POST /api/settings/notifications`, `/api/settings/notifications/test-email`, `/api/aya/test`, `/api/alerts/test` | Key / Control |
| Terminal | `GET /api/terminal`; `POST /api/terminal/run`, `/api/terminal/runs/{id}/stop`; `GET /api/terminal/runs/{id}` | Key / Control (and the terminal policy) |
| Data management | `GET /api/data`; `DELETE /api/reports[/{id}]`, `/api/scans[/{id}]`, `/api/incidents[/{id}]`, `/api/events`, `/api/devices[/{ip}]`, `/api/terminal/history`; `POST /api/data/wipe` (requires `{"confirm": "DELETE"}`) | Key / Control |

### 3.2 External interfaces NetAI uses

| Interface | Used for |
|---|---|
| Raw sockets (`AF_PACKET` on Linux, `SIO_RCVALL` on Windows) or libpcap/Npcap via Scapy | packet capture |
| nmap command line (`-sn`, `-F`, `--top-ports`, `-p-`, `-sV`, `-O`, `-Pn`, `-oX`, `-iL`, `--iflist`) | discovery and port scans; XML output parsed with Python's `xml.etree` |
| DNS (reverse lookup) and NetBIOS node-status (UDP 137) | device names |
| pcap file format (link type 101, raw IPv4) | evidence files, readable by Wireshark/tcpdump |
| SMTP with STARTTLS or SSL/TLS (`smtplib`) | email alerts and reports |
| Slack incoming webhooks (HTTPS POST) | Slack alerts |
| Ollama API (`/api/chat`, `/api/tags`) | Aya with a local model |
| OpenAI-compatible API (`/v1/chat/completions`, `/v1/models`) | Aya with LM Studio, llama.cpp server, LocalAI |
| OS notifications: Windows balloon tips (PowerShell), `notify-send` (Linux), `osascript` (macOS) | desktop alerts |
| Browser Notification API | dashboard pop-ups |
| systemd | optional 24/7 service on Linux |

---

## 4. Tools, libraries and licences

NetAI Detector itself is released under the **MIT licence** (see `pyproject.toml`).

### 4.1 Python packages

| Package | Version | Purpose | Licence |
|---|---|---|---|
| Python | 3.10+ | runtime | PSF |
| FastAPI | ≥0.110, <1 | web API and dashboard server | MIT |
| Uvicorn | ≥0.27 | ASGI web server | BSD-3-Clause |
| Pydantic | ≥2.5 | request validation | MIT |
| NumPy | ≥1.24 | numeric arrays | BSD-3-Clause |
| scikit-learn | ≥1.3 | Isolation Forest, StandardScaler | BSD-3-Clause |
| joblib | ≥1.3 | saving/loading the model | BSD-3-Clause |
| Scapy *(optional)* | ≥2.5 | packet capture via libpcap/Npcap | GPL-2.0 |
| pytest, httpx, ruff *(development only)* | | tests and linting | MIT / BSD |

Everything else (SQLite, `smtplib`, `xml.etree`, `urllib`, `ipaddress`, `socket`, `struct`,
`subprocess`, `threading`) is in the Python standard library.

### 4.2 External tools (installed separately, not bundled)

| Tool | Purpose | Licence notes |
|---|---|---|
| **nmap** | network discovery and port scanning | Nmap Public Source License. Free for end users, including commercial use inside an organisation. **Bundling nmap inside a product you distribute requires an Nmap OEM licence.** NetAI does not bundle it; users install it themselves. |
| **Npcap** *(Windows, optional)* | packet capture driver for Scapy | Free edition: up to **5 systems** per organisation. The exemption for copies used *only* with Nmap/Wireshark doesn't cover other software such as NetAI, so beyond 5 Windows machines an **Npcap OEM Internal-Use licence** is needed. NetAI's built-in Windows capture works without Npcap. |
| **libpcap** *(Linux/macOS)* | packet capture library | BSD |
| **Ollama** / **LM Studio** *(optional)* | local language model server for Aya | Ollama: MIT. LM Studio: proprietary, free to use; check its terms for business use. The **models** have their own licences (e.g. the Llama Community License for Llama models). |
| **Wireshark** *(optional)* | opening evidence files | GPL-2.0 |

*Licence information is a summary for convenience, not legal advice. Check each project's current
terms before deploying in a business.*

### 4.3 Development and quality

- **Tests:** about 127 automated tests (pytest) covering detection, investigation, scanning (with a
  stand-in nmap), passive discovery, reports and grading, Aya (with stand-in Ollama/LM Studio
  servers), email (stand-in SMTP), the terminal, data deletion and the API.
- **Continuous integration:** GitHub Actions runs the suite on Python 3.10–3.12.
- **Dashboard:** plain HTML, CSS and JavaScript served by the application. No external scripts,
  fonts or CDNs, so it works offline and loads nothing from third parties.
