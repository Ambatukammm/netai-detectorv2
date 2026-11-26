#!/usr/bin/env bash
# NetAI Detector for Linux: one script that installs everything it needs and starts the dashboard.
#
#   ./linux/run.sh            install what's missing (first run), start NetAI, open the dashboard
#   ./linux/run.sh --no-browser       don't open a browser (e.g. on a server)
#   ./linux/run.sh --setup-only       install everything but don't start
#
# Works on Ubuntu, Debian, Linux Mint, Pop!_OS, Kali, Raspberry Pi OS, Fedora, RHEL/Rocky/Alma,
# Arch/Manjaro, openSUSE. Needs sudo (to install packages and to capture network traffic).
set -u

HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
ROOT="$(dirname "$HERE")"
STATE="$HERE/.state"
OPEN_BROWSER=1
SETUP_ONLY=0
DRY="${NETAI_DRY_RUN:-0}"          # 1 = print what would be done, change nothing (for testing)
for arg in "$@"; do
  case "$arg" in
    --no-browser) OPEN_BROWSER=0 ;;
    --setup-only) SETUP_ONLY=1 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg"; exit 1 ;;
  esac
done

say()  { printf '\033[1;35m[NetAI]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[NetAI]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[NetAI]\033[0m %s\n\n' "$*"; read -r -p "Press Enter to close…" _ || true; exit 1; }
run()  { if [ "$DRY" = 1 ]; then echo "  (dry run) $*"; else "$@"; fi; }
ask()  { # ask "question" default(y/n) -> returns 0 for yes
  local reply; [ -t 0 ] || { [ "$2" = y ]; return; }
  read -r -p "$1 [$([ "$2" = y ] && echo Y/n || echo y/N)] " reply || true
  reply="${reply:-$2}"; [[ "$reply" =~ ^[Yy] ]]
}

[ -f "$ROOT/start.py" ] || die "Can't find the NetAI Detector files. Keep this 'linux' folder inside the project folder."
[ "$(uname -s)" = Linux ] || die "This folder is for Linux. On Windows use START_DETECTOR.bat; on macOS ./start_detector.sh."
mkdir -p "$STATE"
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null || die "sudo is needed. Install it, or run this script as root."
  SUDO="sudo"
fi

# ------------------------------------------------------------------ 1. system packages
PM=""
for candidate in apt-get dnf yum pacman zypper; do
  command -v "$candidate" >/dev/null && { PM="$candidate"; break; }
done

python_ok() {   # a Python 3.10+ that can create virtual environments
  local py="$1"
  command -v "$py" >/dev/null || return 1
  "$py" -c 'import sys, venv, ensurepip; sys.exit(sys.version_info < (3, 10))' 2>/dev/null
}

find_python() {
  for py in python3 python3.13 python3.12 python3.11 python3.10; do
    python_ok "$py" && { command -v "$py"; return 0; }
  done
  return 1
}

need=()
PY="$(find_python || true)"
[ -n "$PY" ] || need+=(python)
command -v nmap >/dev/null || need+=(nmap)
command -v curl >/dev/null || need+=(curl)
HAS_DESKTOP=0
{ [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; } && HAS_DESKTOP=1
if [ "$HAS_DESKTOP" = 1 ]; then
  command -v notify-send >/dev/null || need+=(notify)
  command -v xdg-open >/dev/null || need+=(xdg)
fi
ldconfig -p 2>/dev/null | grep -q 'libpcap\.so' || need+=(pcap)

pkgs_for() {   # map what we need to this distribution's package names
  local want="$1"
  case "$PM:$want" in
    apt-get:python) echo "python3 python3-venv python3-pip" ;;
    dnf:python|yum:python) echo "python3 python3-pip" ;;
    pacman:python) echo "python python-pip" ;;
    zypper:python) echo "python3 python3-pip" ;;
    *:nmap) echo "nmap" ;;
    *:curl) echo "curl" ;;
    apt-get:notify) echo "libnotify-bin" ;;
    pacman:notify) echo "libnotify" ;;
    *:notify) echo "libnotify" ;;
    *:xdg) echo "xdg-utils" ;;
    apt-get:pcap) echo "libpcap0.8" ;;
    *:pcap) echo "libpcap" ;;
  esac
}

if [ ${#need[@]} -gt 0 ]; then
  [ -n "$PM" ] || die "Please install these yourself and run this again: ${need[*]} (Python 3.10+, nmap, curl)."
  packages=()
  for item in "${need[@]}"; do read -r -a p <<<"$(pkgs_for "$item")"; packages+=("${p[@]}"); done
  say "Installing what NetAI needs: ${packages[*]}"
  [ -n "$SUDO" ] && say "sudo will ask for your password (it is not stored)."
  case "$PM" in
    apt-get) run $SUDO apt-get update -qq && run $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${packages[@]}" ;;
    dnf)     run $SUDO dnf install -y -q "${packages[@]}" ;;
    yum)     run $SUDO yum install -y -q "${packages[@]}" ;;
    pacman)  run $SUDO pacman -S --needed --noconfirm "${packages[@]}" ;;
    zypper)  run $SUDO zypper --non-interactive install "${packages[@]}" ;;
  esac || warn "Some packages didn't install. Continuing; NetAI will tell you what's missing."
  PY="$(find_python || true)"
fi

if [ -z "$PY" ] && [ "$DRY" != 1 ]; then
  # Old distributions (e.g. Debian 11, Ubuntu 20.04) ship Python older than 3.10.
  if [ "$PM" = apt-get ]; then
    for v in 3.12 3.11 3.10; do
      if apt-cache show "python$v-venv" >/dev/null 2>&1; then
        say "Your system Python is too old; installing Python $v alongside it…"
        $SUDO apt-get install -y -qq "python$v" "python$v-venv" && break
      fi
    done
    PY="$(find_python || true)"
  fi
  [ -n "$PY" ] || die "NetAI needs Python 3.10 or newer, and this system doesn't have it. Upgrade the distribution
         (e.g. Ubuntu 22.04+, Debian 12+, Fedora 36+) or install Python 3.12 from your package manager."
fi
[ -n "$PY" ] || PY="python3"
say "Using $("$PY" --version 2>&1) ($PY)."

# ------------------------------------------------------------------ 2. Aya's local AI model (asked once)
ENV_FILE="$ROOT/.env"
env_has() { [ -f "$ENV_FILE" ] && grep -qE "^[[:space:]]*$1=" "$ENV_FILE"; }
if [ ! -f "$STATE/aya-asked" ] && [ -t 0 ]; then
  ram_gb=$(awk '/MemTotal/ {printf "%d", $2/1024/1024 + 0.5}' /proc/meminfo 2>/dev/null || echo 0)
  model="${NETAI_AYA_MODEL:-llama3.1:8b}"
  [ "$ram_gb" -lt 12 ] && [ -z "${NETAI_AYA_MODEL:-}" ] && model="llama3.2:3b"
  echo
  say "Aya, NetAI's AI analyst, reviews your reports and scans. She works right away with built-in"
  say "rules. Optionally she can use a local AI model on this computer for richer reviews:"
  say "this downloads Ollama and the '$model' model (about $( [ "$model" = llama3.2:3b ] && echo 2 || echo 5 ) GB). This machine has ${ram_gb} GB RAM."
  if ask "Install Aya's local AI model now?" n; then
    if ! command -v ollama >/dev/null; then
      say "Installing Ollama (from ollama.com)…"
      if [ "$DRY" = 1 ]; then echo "  (dry run) curl -fsSL https://ollama.com/install.sh | sh"
      else curl -fsSL https://ollama.com/install.sh | sh || warn "Ollama didn't install; Aya will use her built-in rules."; fi
    fi
    if command -v ollama >/dev/null || [ "$DRY" = 1 ]; then
      say "Downloading the $model model (this can take a while)…"
      run ollama pull "$model" || warn "The model download failed; you can retry later with: ollama pull $model"
      if ! env_has NETAI_AYA_ENGINE; then
        run sh -c "printf '\n# Aya uses a local model (added by linux/run.sh)\nNETAI_AYA_ENGINE=ollama\nNETAI_AYA_MODEL=%s\n' '$model' >> '$ENV_FILE'"
      fi
      say "Aya will use $model. You can change this any time on the Settings page."
    fi
  else
    say "OK, Aya will use her built-in rules. You can connect a model later in Settings → Aya."
  fi
  run touch "$STATE/aya-asked"
fi

# ------------------------------------------------------------------ 3. desktop shortcut (asked once)
if [ "$HAS_DESKTOP" = 1 ] && [ ! -f "$STATE/shortcut-asked" ] && [ -t 0 ]; then
  if ask "Add 'NetAI Detector' to your applications menu and desktop?" y; then
    run "$HERE/install-shortcut.sh"
  fi
  run touch "$STATE/shortcut-asked"
fi

if [ "$SETUP_ONLY" = 1 ]; then
  run "$PY" "$ROOT/start.py" --setup-only || die "Setting up NetAI's Python components failed (see above)."
  say "Setup finished. Start NetAI any time with: $HERE/run.sh"
  exit 0
fi


# ------------------------------------------------------------------ 4. start NetAI and open the dashboard
# NetAI runs as root (packet capture needs it). Browsers refuse to run as root, so the dashboard is
# opened from here, as you, once the server answers.
open_dashboard() {
  local port url
  for _ in $(seq 1 120); do
    for port in $(seq "${NETAI_PORT:-8000}" $(( ${NETAI_PORT:-8000} + 20 ))); do
      if curl -fs --max-time 1 "http://127.0.0.1:$port/health" 2>/dev/null | grep -q "NetAI Detector"; then
        url="http://127.0.0.1:$port"
        say "Dashboard ready: $url"
        if [ "$OPEN_BROWSER" = 1 ] && [ "$HAS_DESKTOP" = 1 ] && command -v xdg-open >/dev/null; then
          xdg-open "$url" >/dev/null 2>&1 &
        else
          say "Open $url in a browser on this computer."
        fi
        return
      fi
    done
    sleep 1
  done
  warn "The dashboard didn't answer within 2 minutes. Check the messages above."
}

# Already running in the background as a service (linux/service.sh)? Then just open the dashboard.
if command -v systemctl >/dev/null && systemctl is-active --quiet netai-detector 2>/dev/null; then
  say "NetAI is already running in the background as a service."
  open_dashboard
  exit 0
fi

say "Starting NetAI Detector. Press Ctrl+C in this window to stop it."
if [ "$DRY" = 1 ]; then echo "  (dry run) NETAI_OPEN_BROWSER=0 $PY $ROOT/start.py"; exit 0; fi
open_dashboard &
OPENER=$!
trap 'kill $OPENER 2>/dev/null' EXIT
cd "$ROOT" || die "Can't open $ROOT"
NETAI_OPEN_BROWSER=0 "$PY" "$ROOT/start.py"
status=$?
[ $status -eq 0 ] || read -r -p "NetAI stopped (exit code $status). Press Enter to close…" _ || true
exit $status
