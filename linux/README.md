# NetAI Detector on Linux

Everything you need to run NetAI Detector on a Linux machine. Keep this `linux` folder inside the
NetAI Detector project folder.

## Start it

Open a terminal in the project folder and run:

```bash
bash linux/run.sh
```

(`./linux/run.sh` works too once the files are executable: `chmod +x linux/*.sh`. Copies made on
Windows or downloaded from GitHub sometimes lose that flag, which is why `bash …` is the safe way.)

Or double-click **NetAI-Detector.desktop** in this folder (choose *Run* / *Allow Launching* if your
file manager asks).

The first run:

1. installs what's missing with your package manager: Python 3.10+, nmap, curl, libpcap, and on a
   desktop the notification and browser helpers (sudo asks for your password);
2. creates NetAI's own Python environment and downloads its components;
3. asks whether Aya, the AI analyst, should use a **local AI model** (installs Ollama and a model
   sized for your RAM: `llama3.1:8b` with 12 GB+, otherwise `llama3.2:3b`). Say no to use her
   built-in rules; you can connect a model later in **Settings → Aya**;
4. offers to add **NetAI Detector** to your applications menu and desktop;
5. starts NetAI (sudo again, because capturing traffic needs root) and opens the dashboard at
   **http://127.0.0.1:8000** in your browser.

Later runs skip straight to step 5. Stop NetAI with **Ctrl+C** in its terminal window.

Supported: Ubuntu 22.04+, Debian 12+, Linux Mint, Pop!_OS, Kali, Raspberry Pi OS (64-bit), Fedora,
RHEL/Rocky/Alma 9, Arch/Manjaro, openSUSE. Older releases with Python below 3.10 get a newer Python
installed alongside if the package manager offers one.

## Options

| Command | What it does |
|---|---|
| `bash linux/run.sh --no-browser` | Start without opening a browser (servers, SSH sessions) |
| `bash linux/run.sh --setup-only` | Install everything, don't start |
| `bash linux/install-shortcut.sh` | Add the menu/desktop shortcut (`--remove` to take it away) |
| `bash linux/service.sh install` | Run NetAI in the background from boot, 24/7 (systemd) |
| `bash linux/service.sh status` / `logs` / `remove` | Check, follow the log, or remove the service |

With the service installed, `bash linux/run.sh` just opens the dashboard.

## Using it from another computer

By default the dashboard only answers on this machine (and the Terminal page only works then).
To reach it from your laptop, the safest way is an SSH tunnel:

```bash
ssh -L 8000:127.0.0.1:8000 you@netai-machine      # then browse to http://127.0.0.1:8000
```

To open it to the network instead, set `NETAI_HOST=0.0.0.0` **and** `NETAI_API_KEY=<a long random
key>` in the project's `.env` file, and restrict port 8000 with your firewall.

## SPAN / mirror port

Plug a second network card into the switch's mirror port, find its name with `ip -brief link`
(e.g. `enp3s0`), and put `NETAI_INTERFACE=enp3s0` in the project's `.env`. NetAI switches the card
to promiscuous mode by itself. See the **SPAN discovery** page for switch setup guides.

## Troubleshooting

- **"python3-venv" or "ensurepip" errors**: run `sudo apt install python3-venv` and try again.
- **No live capture**: you declined the sudo prompt. Run `bash linux/run.sh` again and enter your password.
- **Desktop notifications don't appear**: press *Send test alert* on the Monitor page; on servers
  without a desktop use email alerts (Settings page) instead.
- **Start completely fresh**: delete the project's `.venv` folder and `linux/.state`, then run
  `bash linux/run.sh` again. Your data in `data/` is kept.
