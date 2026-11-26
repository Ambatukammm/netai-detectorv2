#!/usr/bin/env bash
# Adds "NetAI Detector" to your applications menu and desktop (runs linux/run.sh in a terminal).
#   ./linux/install-shortcut.sh           add the shortcut
#   ./linux/install-shortcut.sh --remove  remove it
set -u
HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
DESKTOP_DIR="$(command -v xdg-user-dir >/dev/null && xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"
NAME="netai-detector.desktop"

if [ "${1:-}" = "--remove" ]; then
  rm -f "$APPS/$NAME" "$DESKTOP_DIR/$NAME"
  echo "[NetAI] Shortcut removed."
  exit 0
fi

mkdir -p "$APPS"
cat > "$APPS/$NAME" <<EOF
[Desktop Entry]
Type=Application
Name=NetAI Detector
GenericName=Network monitoring
Comment=Network monitoring, investigation and discovery with Aya, the local AI analyst
Exec=bash "$HERE/run.sh"
Icon=$HERE/netai.svg
Terminal=true
Categories=Network;Security;System;Monitor;
Keywords=network;security;nmap;monitor;ids;
EOF
chmod +x "$APPS/$NAME"
command -v update-desktop-database >/dev/null && update-desktop-database "$APPS" >/dev/null 2>&1

if [ -d "$DESKTOP_DIR" ]; then
  cp "$APPS/$NAME" "$DESKTOP_DIR/$NAME"
  chmod +x "$DESKTOP_DIR/$NAME"
  # GNOME and some others only launch desktop icons marked as trusted.
  command -v gio >/dev/null && gio set "$DESKTOP_DIR/$NAME" metadata::trusted true >/dev/null 2>&1
fi
echo "[NetAI] Added 'NetAI Detector' to your applications menu${DESKTOP_DIR:+ and desktop}."
echo "[NetAI] If the desktop icon doesn't start, right-click it and choose 'Allow Launching'."
