# How NetAI Detector works (plain-language guide)

**One sentence:** NetAI watches your network traffic, learns what "normal" looks like on its own, and then flags anything that doesn't fit, with no commands to type.

## Using it
1. Install Python.
2. Double-click `START_DETECTOR.bat` (Windows) or run `./start_detector.sh` (Linux/macOS), and approve the administrator prompt.
3. A dashboard opens in your browser. That's all.

## What happens behind the scenes

| Stage | What it does | Why |
|---|---|---|
| **Launcher** | Creates a private Python environment, installs what's needed (first run only), asks for admin rights, starts the app | So the user never installs or configures anything |
| **Capture** | Listens to the network adapter and groups traffic into "windows" of ~100 packets | Judging single packets is noisy; a window shows behaviour |
| **Features** | Turns each window into 32 numbers, such as packets per second, share of TCP/UDP, how many different destinations and ports, share of SYN flags, packet sizes. **Only metadata, never the content of messages** | Gives the AI something it can compare |
| **Learn** | Collects ~60 windows (the *baseline*) while you use the network normally. Shows a progress bar | The model needs examples of "normal" |
| **Clean-up** | Throws away baseline windows that are extreme outliers (up to 20%) | If something odd happened during learning, it should not become "normal" |
| **Train** | An *Isolation Forest* learns the shape of normal traffic. This model is a way of spotting points that are unusually easy to separate from the crowd. It is saved to disk | Next start-up skips learning |
| **Monitor** | Every new window gets an anomaly score, a severity (low/medium/high) and a record in a local database | The actual detection |
| **Explain** | For flagged windows it lists the features that deviated most, e.g. "syn_ratio +9.8 standard deviations" | Tells the analyst *why*, so they can investigate (a port scan looks different from a flood) |
| **Investigate** | For flagged windows only, it reads packet *headers* to list who talked to whom, on which ports, how much, and guesses the attack type (port scan, flood, brute-force, data exfiltration, DNS tunnelling…) | So you know *who* and *where*, not just *that* something happened |
| **Incidents** | Flagged windows that belong together become one incident with a start, end, hosts and peak severity. Unrelated attacks at the same time are kept apart | One attack is one row, not forty |
| **Advise** | Each incident gets a step-by-step plan (confirm, contain, investigate, prevent) with the real addresses filled in and copy-paste firewall commands with undo. It runs offline; nothing is blocked automatically | Turns an alert into actions |
| **Evidence** | High-severity incidents are saved as a `.pcap` file with headers only (contents cut off) to open in Wireshark | Proof, and the details for deeper investigation |
| **Alert** | Desktop notification, plus email/Slack if set up | Someone finds out without watching the screen |
| **Refresh** | Weekly, retrains on recent traffic that was *not* flagged | The network changes over time |
| **Dashboard** | Shows phase, progress, events and reasons; buttons to Pause or Relearn; drag-and-drop for `.pcap` files | Everything in one place |

## When live capture isn't possible
It tries three methods in order: **Scapy**, then a **built-in capture** (no driver needed), then a clearly labelled **simulated demo**. The dashboard always says which one is active and why.

## Why the "AI advisor" is offline
The response plans come from built-in playbooks, not a cloud AI service. Sending your internal addresses to an outside service would undo the privacy-first design, and the playbooks work with no internet. A cloud AI model could be added later as an opt-in.

## What it is *not*
- A flagged window means **unusual**, not **malicious**. A big software update can look odd too. Validate alerts.
- It is a statistical detector, not a replacement for an IDS such as Zeek or Suricata. IPv4 only, no payload inspection.
- Only monitor networks you own or are authorised to monitor.

## Evidence it works (on the built-in simulated traffic)
Seven simulated attack types (port scan, network sweep, SYN flood, UDP flood, login brute-force, data exfiltration, DNS tunnelling) are each flagged and given the right attack-type hint in the automated tests; across 20 random baselines about 80% of attack windows scored *high* on the model alone (the rest are raised to high by the pattern match), and no normal window did. Earlier tests: port scans, floods and data-exfiltration windows were flagged 100% of the time, with roughly 3-5% false alarms on normal traffic, even when 10-20% of the learning data was attack traffic. Real networks will differ; this is a test of the logic, not a guarantee.

## What has and hasn't been tested
Tested: the learn/train/monitor cycle, relearning, pause, demo-to-live switch, PCAP drops, retention, packet parsing, real loopback capture with the built-in capture on Linux, culprit summaries, attack hints, incident grouping, the advisor, evidence files (including that payloads are never written), and alerts with simulated email/Slack servers (62 automated tests, plus 5 API tests that run in CI).
**Not yet tested on real hardware:** Scapy capture, Windows raw-socket capture, the Windows administrator prompt, desktop notifications on each OS, and opening an evidence file in Wireshark itself. Run it once on the target machine and press *Send test alert*.
