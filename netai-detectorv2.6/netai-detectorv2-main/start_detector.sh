#!/usr/bin/env bash
# One-click launcher for Linux/macOS. Everything else happens automatically.
cd "$(dirname "$0")" || exit 1
PY="$(command -v python3 || command -v python)" || {
  echo "Python 3.10 or newer is required (https://www.python.org/downloads/)."; exit 1; }
exec "$PY" start.py
