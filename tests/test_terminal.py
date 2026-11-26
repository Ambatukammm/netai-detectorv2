"""The dashboard terminal: real commands, stopping, limits, audit log, nmap import, and when it's allowed."""
import os
import stat
import sys
import time
import pytest
from netai_detector import config
from netai_detector.scanner import ScanManager
from netai_detector.storage import EventStore
from netai_detector.terminal import Terminal, nmap_targets, terminal_policy

pytestmark = pytest.mark.skipif(os.name == "nt", reason="tests use POSIX shell commands")
PY = sys.executable


def wait_done(term, run_id, timeout=15):
    out, offset = "", 0
    end = time.time() + timeout
    while time.time() < end:
        r = term.read(run_id, offset)
        out += r["output"]
        offset = r["offset"]
        if not r["running"]:
            return out, r
        time.sleep(0.05)
    raise AssertionError("command did not finish")


@pytest.fixture
def term(tmp_path):
    t = Terminal(EventStore(tmp_path / "e.db"), timeout=60)
    yield t
    t.stop_all()


def test_runs_a_command_and_streams_output(term):
    r = term.run(f'{PY} -c "import time; print(\'hello\'); time.sleep(0.3); print(\'world\')"')
    out, final = wait_done(term, r["id"])
    assert out == "hello\nworld\n" and final["exit_code"] == 0
    history = term.store.terminal_history()
    assert history[0]["command"].startswith(PY) and history[0]["exit_code"] == 0


def test_errors_and_exit_codes_are_shown(term):
    out, final = wait_done(term, term.run("ls /definitely/not/here")["id"])
    assert final["exit_code"] != 0 and "No such file" in out


def test_stop_kills_the_whole_process_tree(term):
    r = term.run("sleep 30 & sleep 30; echo never")
    time.sleep(0.3)
    started = time.time()
    assert term.stop(r["id"])
    out, final = wait_done(term, r["id"], 5)
    assert time.time() - started < 5 and "[NetAI: stopped]" in out and "never" not in out


def test_time_limit_and_output_cap(tmp_path):
    t = Terminal(EventStore(tmp_path / "e.db"), timeout=1, max_output=1000)
    out, _ = wait_done(t, t.run("sleep 20")["id"], 10)
    assert "1-second time limit" in out
    out, final = wait_done(t, t.run(f"{PY} -c \"print('x' * 5000)\"")["id"])
    assert len(out) < 1200 and "output limit reached" in out and final["exit_code"] == 0


def test_interactive_programs_get_no_keyboard(term):
    out, final = wait_done(term, term.run("read answer; echo got:$answer")["id"])
    assert "got:" in out                       # stdin is closed, so read returns at once


def test_too_many_running_commands_and_bad_input(tmp_path):
    t = Terminal(EventStore(tmp_path / "e.db"), max_running=1)
    t.run("sleep 5")
    with pytest.raises(RuntimeError, match="already running"):
        t.run("echo hi")
    t.stop_all()
    with pytest.raises(ValueError):
        t.run("   ")
    with pytest.raises(ValueError):
        t.run("echo hi", shell="powershell")


# ------------------------------------------------------------------ nmap
def test_nmap_commands_are_prepared_for_import(term, monkeypatch):
    term.find_nmap = lambda: "/opt/nmap tools/nmap"
    monkeypatch.setattr("netai_detector.terminal._on_path", lambda name: False)
    cmd, xml = term.prepare("nmap -sn 192.168.15.0/24")
    assert cmd.startswith('"/opt/nmap tools/nmap" -sn 192.168.15.0/24 -oX "') and xml
    os.unlink(xml)
    for raw in ("nmap -sn 10.0.0.0/24 | grep up", "nmap -oX out.xml 10.0.0.1", "nmap --version", "nmap -h"):
        assert term.prepare(raw)[1] is None                    # piped, own output, or not a scan
    assert term.prepare("ping -c 1 127.0.0.1") == ("ping -c 1 127.0.0.1", None)
    assert nmap_targets("nmap -F 192.168.15.0/24 10.0.0.5 --exclude 1") == ["192.168.15.0/24", "10.0.0.5/32"]


def test_terminal_nmap_scan_lands_in_inventory_and_history(tmp_path):
    script = tmp_path / "nmap"
    script.write_text(f"""#!{PY}
import sys
args = sys.argv[1:]
print("Starting Nmap 7.95")
out = args[args.index("-oX") + 1]
open(out, "w").write('<nmaprun><host><status state="up"/><address addr="192.168.15.9" addrtype="ipv4"/>'
  '<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>')
print("Nmap done: 256 IP addresses (1 host up)")
""")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    store = EventStore(tmp_path / "e.db")
    reviewed = []
    scans = ScanManager(store, nmap=str(script))
    scans.on_finish = reviewed.append
    term = Terminal(store, find_nmap=lambda: str(script),
                    on_nmap_results=lambda cmd, xml: scans.import_results(cmd, xml, nmap_targets(cmd)))
    import netai_detector.terminal as tmod
    tmod_on_path, tmod._on_path = tmod._on_path, (lambda name: False)
    try:
        out, final = wait_done(term, term.run("nmap -F 192.168.15.0/24")["id"])
    finally:
        tmod._on_path = tmod_on_path
    assert "Nmap done" in out and "added to the inventory" in out and final["exit_code"] == 0
    assert "tcp/22" in store.device("192.168.15.9")["ports"]
    job = store.scan_jobs(1)[0]
    assert job["targets"] == ["192.168.15.0/24"] and job["profile"] == "terminal" and job["status"] == "done"
    assert store.scan_results(job["id"])[0]["ip"] == "192.168.15.9"
    deadline = time.time() + 5
    while not reviewed and time.time() < deadline:
        time.sleep(0.05)
    assert reviewed and reviewed[0]["id"] == job["id"]          # Aya's review is triggered
    assert not list(tmp_path.glob("netai-term-*.xml"))


# ------------------------------------------------------------------ when the terminal is allowed
@pytest.mark.parametrize("host,key,mode,enabled", [
    ("127.0.0.1", "", "auto", True),
    ("0.0.0.0", "", "auto", False),
    ("0.0.0.0", "", "on", False),            # never without an API key on the network
    ("0.0.0.0", "k", "auto", False),
    ("0.0.0.0", "k", "on", True),
    ("127.0.0.1", "", "off", False),
])
def test_terminal_policy(monkeypatch, host, key, mode, enabled):
    monkeypatch.setattr(config, "HOST", host)
    monkeypatch.setattr(config, "API_KEY", key)
    monkeypatch.setattr(config, "TERMINAL", mode)
    assert terminal_policy()[0] is enabled
