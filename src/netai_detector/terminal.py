"""The dashboard terminal: run ping, nmap or any other command and watch the output live.

Commands run on this computer with NetAI's rights (usually administrator/root), one command at a
time per run, with no keyboard input (interactive programs that wait for typing will stop at the
time limit or when you press Stop). Every command is recorded in an audit log.

nmap commands are special: if nmap isn't on the PATH NetAI uses the copy it found, and when a simple
nmap command finishes its results are added to the device inventory, saved as a scan, and reviewed
by Aya, exactly like scans started from the Network page.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import os
import re
import shlex
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from . import config

SHELLS = {"nt": {"cmd": "Command Prompt", "powershell": "PowerShell"},
          "posix": {"sh": "Shell (sh/bash)"}}
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_META = re.compile(r"[|&;<>`$\n]")       # shell features that make a command not "simple"


def available_shells() -> dict:
    return SHELLS["nt" if os.name == "nt" else "posix"]


def terminal_policy() -> tuple[bool, str]:
    """(enabled, reason). auto = on only when the dashboard can't be reached from other machines."""
    mode = config.TERMINAL
    local = config.HOST in ("127.0.0.1", "localhost", "::1")
    if mode == "off":
        return False, "The terminal is turned off (NETAI_TERMINAL=off)."
    if not local and not config.API_KEY:
        return False, ("The terminal is disabled because the dashboard is reachable from other computers "
                       f"(NETAI_HOST={config.HOST}) without an API key. Set NETAI_API_KEY and NETAI_TERMINAL=on, "
                       "or use 127.0.0.1.")
    if not local and mode != "on":
        return False, ("The terminal is off because the dashboard is reachable from other computers. "
                       "Set NETAI_TERMINAL=on (with NETAI_API_KEY) to allow it.")
    return True, "Commands run on this computer with NetAI's administrator rights."


class _Run:
    def __init__(self, command: str, shell: str):
        self.id = uuid.uuid4().hex[:12]
        self.command, self.shell = command, shell
        self.started = time.time()
        self.chunks: list[str] = []
        self.size = 0
        self.truncated = False
        self.exit_code: int | None = None
        self.stopped = False
        self.timed_out = False
        self.proc: subprocess.Popen | None = None
        self.xml_path: str | None = None
        self.history_id: int | None = None
        self.note: str | None = None
        self.lock = threading.Lock()

    def text(self) -> str:
        with self.lock:
            return "".join(self.chunks)


class Terminal:
    def __init__(self, store, find_nmap=None, on_nmap_results=None, timeout: int | None = None,
                 max_output: int = 2_000_000, max_running: int = 3):
        self.store = store
        self.find_nmap = find_nmap or (lambda: None)
        self.on_nmap_results = on_nmap_results     # callback(command, xml_text) -> str | None (a note)
        self.timeout = timeout or config.TERMINAL_TIMEOUT
        self.max_output, self.max_running = max_output, max_running
        self._runs: dict[str, _Run] = {}
        self._lock = threading.Lock()

    # -------------------------------------------------------------- starting
    def prepare(self, command: str) -> tuple[str, str | None]:
        """Resolve 'nmap' to the installed copy and, for simple nmap commands, ask nmap to also write
        XML so the results can be imported. Returns (command to run, xml path or None)."""
        command = command.strip()
        m = re.match(r"^nmap(\.exe)?(?=\s|$)", command, re.I)
        if not m:
            return command, None
        nmap = self.find_nmap()
        rest = command[m.end():]
        exe = nmap if nmap and not _on_path("nmap") else "nmap"
        command = (f'"{exe}"' if " " in exe else exe) + rest
        xml = None
        if not _META.search(rest) and not re.search(r"(^|\s)-o[XAGNS]\b", rest) and \
                not re.search(r"(^|\s)(-h|--help|-V|--version|--iflist)\b", rest):
            fd, xml = tempfile.mkstemp(prefix="netai-term-", suffix=".xml")
            os.close(fd)
            command += f' -oX "{xml}"'
        return command, xml

    def run(self, command: str, shell: str | None = None) -> dict:
        command = (command or "").strip()
        if not command:
            raise ValueError("Type a command first.")
        if len(command) > 2000:
            raise ValueError("That command is too long.")
        shells = available_shells()
        shell = shell or next(iter(shells))
        if shell not in shells:
            raise ValueError(f"Unknown shell '{shell}'")
        with self._lock:
            running = [r for r in self._runs.values() if r.exit_code is None]
            if len(running) >= self.max_running:
                raise RuntimeError(f"{len(running)} commands are already running. Stop one first.")
        actual, xml = self.prepare(command)
        run = _Run(command, shell)
        run.xml_path = xml
        run.history_id = self.store.add_terminal_history(command, shell)
        try:
            run.proc = _spawn(actual, shell)
        except OSError as exc:
            run.exit_code = -1
            run.chunks.append(f"Could not start the command: {exc}\n")
            self.store.finish_terminal_history(run.history_id, -1, 0)
            self._remember(run)
            return self.read(run.id)
        self._remember(run)
        threading.Thread(target=self._pump, args=(run,), name="netai-term", daemon=True).start()
        return self.read(run.id)

    def _remember(self, run: _Run) -> None:
        with self._lock:
            self._runs[run.id] = run
            done = [r for r in self._runs.values() if r.exit_code is not None]
            for old in sorted(done, key=lambda r: r.started)[:-20]:   # keep the last 20 finished runs
                self._runs.pop(old.id, None)

    def _pump(self, run: _Run) -> None:
        proc = run.proc
        timer = threading.Timer(self.timeout, lambda: self._kill(run, timed_out=True))
        timer.daemon = True
        timer.start()
        decoder = _decoder()
        try:
            fd = proc.stdout.fileno()
            while True:
                data = os.read(fd, 8192)
                if not data:
                    break
                text = _ANSI.sub("", decoder(data))
                with run.lock:
                    if run.size + len(text) > self.max_output:
                        if not run.truncated:
                            run.chunks.append("\n[NetAI: output limit reached; the rest is not shown]\n")
                            run.truncated = True
                        continue
                    run.chunks.append(text)
                    run.size += len(text)
            code = proc.wait()
        finally:
            timer.cancel()
        if run.timed_out:
            limit = f"{self.timeout // 60}-minute" if self.timeout >= 60 else f"{self.timeout}-second"
            run.chunks.append(f"\n[NetAI: stopped after the {limit} time limit]\n")
        elif run.stopped:
            run.chunks.append("\n[NetAI: stopped]\n")
        if run.xml_path:
            try:
                text = Path(run.xml_path).read_text(encoding="utf-8", errors="replace")
                if text.strip() and self.on_nmap_results and code == 0 and not run.stopped:
                    run.note = self.on_nmap_results(run.command, text)
            except Exception as exc:   # importing is a bonus: never break the terminal over it
                run.note = f"Couldn't add these results to the inventory ({exc})."
            finally:
                try:
                    os.unlink(run.xml_path)
                except OSError:
                    pass
        if run.note:
            run.chunks.append(f"\n[NetAI: {run.note}]\n")
        run.exit_code = code
        self.store.finish_terminal_history(run.history_id, code, round(time.time() - run.started, 1))

    # -------------------------------------------------------------- reading and stopping
    def read(self, run_id: str, offset: int = 0) -> dict:
        run = self._runs.get(run_id)
        if not run:
            raise KeyError(run_id)
        text = run.text()
        return {"id": run.id, "command": run.command, "shell": run.shell, "output": text[offset:],
                "offset": len(text), "running": run.exit_code is None, "exit_code": run.exit_code,
                "elapsed": round(time.time() - run.started, 1), "note": run.note}

    def stop(self, run_id: str) -> bool:
        run = self._runs.get(run_id)
        if not run or run.exit_code is not None:
            return False
        self._kill(run)
        return True

    def _kill(self, run: _Run, timed_out: bool = False) -> None:
        proc = run.proc
        if not proc or proc.poll() is not None:
            return
        run.stopped, run.timed_out = True, timed_out
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            else:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            pass

    def running(self) -> list[dict]:
        return [self.read(r.id, len(r.text())) for r in self._runs.values() if r.exit_code is None]

    def stop_all(self) -> None:
        for run in list(self._runs.values()):
            self._kill(run)


def _on_path(name: str) -> bool:
    from shutil import which
    return which(name) is not None


def _spawn(command: str, shell: str) -> subprocess.Popen:
    common = {"stdout": subprocess.PIPE, "stderr": subprocess.STDOUT, "stdin": subprocess.DEVNULL,
              "cwd": str(Path.home())}
    if os.name == "nt":
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        if shell == "powershell":
            return subprocess.Popen(["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                                    creationflags=flags, **common)
        return subprocess.Popen(f'cmd /d /s /c "{command}"', creationflags=flags, **common)
    sh = "/bin/bash" if Path("/bin/bash").exists() else "/bin/sh"
    return subprocess.Popen([sh, "-c", command], start_new_session=True, **common)


def _decoder():
    """Incremental decoder: Windows consoles use the OEM code page, everything else UTF-8."""
    import codecs
    encoding = "utf-8"
    if os.name == "nt":
        try:
            import ctypes
            encoding = f"cp{ctypes.windll.kernel32.GetOEMCP()}"
            codecs.lookup(encoding)
        except Exception:
            encoding = "utf-8"
    dec = codecs.getincrementaldecoder(encoding)(errors="replace")
    return lambda data: dec.decode(data)


def nmap_targets(command: str) -> list[str]:
    """IPv4 addresses/ranges named in an nmap command (for the scan history)."""
    from .scanner import validate_targets
    found = []
    try:
        tokens = shlex.split(command, posix=os.name != "nt")
    except ValueError:
        tokens = command.split()
    for tok in tokens[1:]:
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?", tok):
            try:
                found += validate_targets([tok])
            except ValueError:
                pass
    return found


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
