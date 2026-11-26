#!/usr/bin/env bash
# Run NetAI Detector in the background from boot (systemd service), so it monitors 24/7 even when
# nobody is logged in.
#   ./linux/service.sh install   set it up and start it
#   ./linux/service.sh remove    stop it and remove it
#   ./linux/service.sh status    is it running? (and recent log lines)
#   ./linux/service.sh logs      follow the log live (Ctrl+C to leave)
set -u
HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
ROOT="$(dirname "$HERE")"
UNIT=/etc/systemd/system/netai-detector.service
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"

command -v systemctl >/dev/null || { echo "[NetAI] This system doesn't use systemd; run linux/run.sh instead."; exit 1; }

case "${1:-}" in
  install)
    if [ ! -x "$ROOT/.venv/bin/python" ]; then
      echo "[NetAI] First installing everything NetAI needs…"
      bash "$HERE/run.sh" --setup-only || exit 1
    fi
    echo "[NetAI] Creating the netai-detector service (sudo may ask for your password)…"
    $SUDO tee "$UNIT" >/dev/null <<EOF
[Unit]
Description=NetAI Detector (network monitoring)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$ROOT
Environment=NETAI_OPEN_BROWSER=0
Environment=NETAI_NO_ELEVATE=1
Environment=PYTHONUNBUFFERED=1
ExecStart=$ROOT/.venv/bin/python -m netai_detector
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    $SUDO systemctl daemon-reload && $SUDO systemctl enable --now netai-detector || exit 1
    echo "[NetAI] NetAI now runs in the background and starts automatically at boot."
    echo "[NetAI] Dashboard: http://127.0.0.1:${NETAI_PORT:-8000}  (or run linux/run.sh to open it)"
    ;;
  remove|uninstall)
    $SUDO systemctl disable --now netai-detector 2>/dev/null
    $SUDO rm -f "$UNIT" && $SUDO systemctl daemon-reload
    echo "[NetAI] Service removed. Your data in $ROOT/data is untouched."
    ;;
  status)
    systemctl status netai-detector --no-pager -n 15 ;;
  logs)
    $SUDO journalctl -u netai-detector -f ;;
  *)
    sed -n '2,8p' "$0"; exit 1 ;;
esac
