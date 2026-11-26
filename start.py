#!/usr/bin/env python3
"""NetAI Detector one-click launcher. Uses only the standard library.

Double-click START_DETECTOR.bat (Windows) or run ./start_detector.sh (Linux/macOS). On the first
run this creates a private Python environment and installs everything; on later runs it only
checks nothing has changed. Then it asks for the administrator rights that packet capture needs
and starts NetAI Detector, which opens the dashboard and does the rest by itself.
"""
from __future__ import annotations
import hashlib
import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
STAMP = VENV / ".netai-install-stamp"
IS_WINDOWS = os.name == "nt"


def say(message: str) -> None:
    print(f"[NetAI] {message}", flush=True)


def fail(message: str) -> None:
    print(f"\n[NetAI] {message}\n", flush=True)
    if IS_WINDOWS:
        input("Press Enter to close this window…")
    sys.exit(1)


def venv_python() -> Path:
    return VENV / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")


def setting(name: str) -> str:
    """Read a setting from the environment or the project's .env file."""
    if name in os.environ:
        return os.environ[name].strip()
    try:
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key.strip() == name:
                return value.strip().strip("'\"")
    except OSError:
        pass
    return ""


def ensure_venv() -> None:
    if venv_python().exists():
        return
    say("First run: creating a private Python environment (one-time, about a minute)…")
    try:
        venv.EnvBuilder(with_pip=True, clear=VENV.exists()).create(VENV)
    except Exception as exc:
        hint = " On Ubuntu/Debian this usually means: sudo apt install python3-venv" if not IS_WINDOWS else ""
        fail(f"Could not create the Python environment ({exc}).{hint}")


def ensure_dependencies() -> None:
    py = str(venv_python())
    wanted = hashlib.sha256((ROOT / "pyproject.toml").read_bytes() + sys.version.encode()).hexdigest()
    if STAMP.exists() and STAMP.read_text().strip() == wanted:
        return
    say("Installing components (one-time, needs internet; this can take a few minutes)…")
    if sys.version_info >= (3, 15):
        say("Note: Python 3.15 is very new and some packages may not support it yet. "
            "If installation fails, install Python 3.12 or 3.13 and run this again.")
    pip = [py, "-m", "pip", "install", "--disable-pip-version-check", "-q", "--prefer-binary"]
    subprocess.run(pip + ["--upgrade", "pip"], check=False)
    if subprocess.run(pip + ["-e", f"{ROOT}[capture]"]).returncode != 0:
        say("Some components failed to install; retrying with the core only (live capture will be off).")
        if subprocess.run(pip + ["-e", str(ROOT)]).returncode != 0:
            fail("Installation failed. Check your internet connection. If the messages above mention a "
                 "missing C++ compiler, your Python version is too new for some packages: install "
                 "Python 3.12 or 3.13, delete the .venv folder, and run this launcher again.")
    STAMP.write_text(wanted)


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def run_elevated(py: Path) -> bool:
    """Ask the OS for administrator rights. Returns True if the app was started that way."""
    if setting("NETAI_NO_ELEVATE") in ("1", "true", "yes"):
        return False
    if IS_WINDOWS:
        import ctypes
        say("Packet capture needs administrator rights. Please click 'Yes' on the Windows prompt.")
        # cmd /k keeps the window open if something goes wrong, so errors can be read.
        params = f'/k ""{py}" -m netai_detector"'
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", params, str(ROOT), 1)
        return int(result) > 32
    sudo = shutil.which("sudo")
    if not sudo or not sys.stdin.isatty():
        return False
    say("Packet capture needs administrator rights. sudo will ask for your password (it is not stored).")
    if subprocess.call([sudo, "-v"]) != 0:
        return False
    os.execv(sudo, [sudo, "-E", str(py), "-m", "netai_detector"])
    return True  # not reached


def main() -> None:
    os.chdir(ROOT)
    if sys.version_info < (3, 10):
        fail("Python 3.10 or newer is required. Get it from https://www.python.org/downloads/")
    ensure_venv()
    ensure_dependencies()
    if "--setup-only" in sys.argv:
        say("Everything is installed.")
        return
    py = venv_python()
    try:
        if not is_admin() and run_elevated(py):
            return
        if not is_admin():
            say("Continuing without administrator rights: live capture may be unavailable, and the "
                "dashboard will explain what is needed.")
        sys.exit(subprocess.call([str(py), "-m", "netai_detector"]))
    except KeyboardInterrupt:
        say("Stopped.")


if __name__ == "__main__":
    main()
