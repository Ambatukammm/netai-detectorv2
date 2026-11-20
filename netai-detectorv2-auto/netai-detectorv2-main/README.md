# NetAI Detector

**Cross-platform network anomaly detection and monitoring toolkit.**  
**Made by Ruel · Version 2.1.0**

NetAI Detector is an independent cybersecurity project designed to help inspect network traffic, build a baseline of normal activity, identify statistically unusual traffic windows, and review detection events through a local web dashboard.

> **Important:** An anomaly is not proof of malicious activity. This project is a learning, investigation and defensive-monitoring tool. Validate alerts with packet evidence and other security telemetry before responding.

## Features

- **Fully automatic:** start it and it learns your network, trains the model and monitors live traffic. No API calls, no CLI commands.
- **One-click launcher** for Windows, Linux and macOS (Python 3.10+). It creates its own environment, installs dependencies and asks for the administrator rights packet capture needs.
- Live status dashboard: learning progress, current phase, warnings, and *why* each anomaly was flagged (the features that deviated most from normal).
- Drag-and-drop PCAP analysis in the dashboard (`.pcap` / `.pcapng`).
- Versioned 32-feature representation of traffic windows; packet payloads are never stored.
- Isolation Forest anomaly model with saved preprocessing and metadata.
- SQLite event history with automatic retention, REST API, interactive API docs.
- Optional API-key protection. Unit tests and GitHub Actions CI.

## Get started (the whole thing)

1. Install **Python 3.10+** from python.org (on Windows tick *Add python.exe to PATH*).
2. **Windows:** double-click `START_DETECTOR.bat` and click **Yes** on the administrator prompt.
   **Linux / macOS:** run `./start_detector.sh` and enter your password when asked.

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
- `GET /api/events?limit=50` — recent events.
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

If `NETAI_API_KEY` is set, provide it in the `X-API-Key` header for prediction and control requests (the dashboard asks for it once). Keep the service bound to `127.0.0.1` unless you have configured authentication, firewall rules and TLS for a trusted network.

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
| `NETAI_API_KEY` | empty | Optional key for prediction/control requests |

## Model limitations and responsible use

- Learning is automatic and **robust to some contamination**: training ignores windows that are extreme outliers (up to 20%), and the dashboard warns if a lot was ignored. A *sustained* attack during learning (more than ~20% of it) can still become "normal". Use *Relearn baseline* if that happens.
- The model refreshes itself weekly from recent traffic that was **not** flagged. A very slow, deliberate drift could still shift "normal"; set `NETAI_RETRAIN_HOURS=0` to disable.
- Train on representative, known-good traffic from the environment being monitored.
- A baseline can contain attacks or unusual-but-legitimate activity; curate training data.
- Isolation Forest identifies statistical outliers, not specific malware families or attack techniques.
- The contamination setting influences the expected outlier proportion.
- Scores and severity labels are triage aids, not calibrated probabilities.
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
  monitor.py      Automatic engine: learn -> train -> monitor
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
