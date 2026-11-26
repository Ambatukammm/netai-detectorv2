"""Long scans: no time limit, partial results kept when stopped; inventory port/OS scans without discovery."""
import os
import stat
import sys
import time
import pytest
from netai_detector.scanner import PROFILES, ScanManager, build_command, parse_nmap_xml
from netai_detector.storage import EventStore

HOST = ('<host><status state="up" reason="{reason}"/><address addr="{ip}" addrtype="ipv4"/>{extra}'
        '<ports>{ports}</ports></host>')
PORT = '<port protocol="tcp" portid="{p}"><state state="open"/><service name="svc"/></port>'


def host(ip, ports=(), reason="arp-response", extra=""):
    return HOST.format(ip=ip, reason=reason, extra=extra, ports="".join(PORT.format(p=p) for p in ports))


def test_cut_off_xml_keeps_every_finished_host():
    text = ('<?xml version="1.0"?><nmaprun>' + host("10.0.0.1", [22]) + host("10.0.0.2", [80, 443])
            + '<host><status state="up"/><address addr="10.0.0.3" addrtype="ipv4"/><ports><port prot')
    hosts = parse_nmap_xml(text)                      # nmap was killed while writing host 3
    assert [h["ip"] for h in hosts] == ["10.0.0.1", "10.0.0.2"]
    assert set(hosts[1]["ports"]) == {"tcp/80", "tcp/443"}


def test_no_discovery_scans_only_count_hosts_that_answered():
    text = ("<nmaprun>" + host("10.0.0.1", [3389], reason="user-set")
            + host("10.0.0.2", [], reason="user-set")                                # silent: unknown
            + host("10.0.0.3", [], reason="user-set", extra='<os><osmatch name="Linux" accuracy="90"/></os>')
            + "</nmaprun>")
    assert [h["ip"] for h in parse_nmap_xml(text)] == ["10.0.0.1", "10.0.0.3"]


def test_inventory_profiles_skip_discovery_and_take_device_lists(tmp_path):
    assert "-Pn" in PROFILES["inventory"]["args"] and "-O" in PROFILES["inventory"]["args"]
    assert "-p-" in PROFILES["inventory_full"]["args"]
    xml = str(tmp_path / "scan.xml")
    few = build_command("nmap", ["10.0.0.1/32", "10.0.0.2/32"], "inventory", xml)
    assert few[-2:] == ["10.0.0.1/32", "10.0.0.2/32"] and "--top-ports" in few
    many = build_command("nmap", [f"10.0.{i // 250}.{i % 250 + 1}/32" for i in range(300)], "inventory", xml)
    assert many[-2] == "-iL"                                         # long lists go in a file
    listed = open(many[-1]).read().split()
    assert len(listed) == 300 and listed[0] == "10.0.0.1"              # plain addresses, no /32
    with pytest.raises(ValueError, match="individual devices"):
        build_command("nmap", ["10.0.0.0/24"], "inventory", xml)


def test_no_time_limit_by_default(tmp_path):
    scans = ScanManager(EventStore(tmp_path / "e.db"), find=lambda: None)
    assert scans.max_seconds is None and scans.status()["time_limit_minutes"] is None
    assert set(scans.status()["inventory_profiles"]) == {"inventory", "inventory_full"}
    assert "inventory" not in scans.status()["profiles"]


@pytest.fixture
def slow_nmap(tmp_path):
    """Finishes one host, then keeps 'scanning' for a long time (like a big 1000-port scan)."""
    if os.name == "nt":
        pytest.skip("stand-in nmap uses a shebang script")
    script = tmp_path / "nmap"
    script.write_text(f"""#!{sys.executable}
import sys, time
args = sys.argv[1:]
if "--version" in args: print("Nmap version 7.95"); sys.exit(0)
if "--iflist" in args: sys.exit(0)
out = open(args[args.index("-oX") + 1], "w")
out.write('<?xml version="1.0"?><nmaprun>{host("192.168.1.5", [445, 3389], reason="user-set")}')
out.flush()
print("Service scan Timing: About 12.50% done; ETC: 15:40 (1:52:10 remaining)", flush=True)
time.sleep(60)
""")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


def _wait(cond, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def test_cancelled_long_scan_keeps_finished_devices_and_gets_reviewed(tmp_path, slow_nmap):
    store = EventStore(tmp_path / "e.db")
    store.upsert_device("192.168.1.5", seen_by="passive", up=True)
    store.upsert_device("192.168.1.9", seen_by="passive", up=True)     # firewalled: shows nothing
    finished = []
    scans = ScanManager(store, nmap=slow_nmap)
    scans.on_finish = finished.append
    scans.start(["192.168.1.5/32", "192.168.1.9/32"], "inventory", authorised=True)
    assert _wait(lambda: scans.status()["current"]["remaining"] == "1:52:10")
    assert scans.cancel()
    assert _wait(lambda: scans.status()["current"]["status"] == "cancelled")
    job = store.scan_jobs(1)[0]
    assert job["hosts_up"] == 1 and "Kept the 1 device" in job["message"]
    assert set(store.device("192.168.1.5")["ports"]) == {"tcp/445", "tcp/3389"}
    assert store.scan_results(job["id"])[0]["ip"] == "192.168.1.5"
    assert store.device("192.168.1.9")["up"] is True                   # never marked offline by -Pn scans
    assert _wait(lambda: finished) and finished[0]["status"] == "cancelled"


def test_optional_time_limit_still_keeps_results(tmp_path, slow_nmap):
    store = EventStore(tmp_path / "e.db")
    scans = ScanManager(store, nmap=slow_nmap, max_minutes=1)
    scans.max_seconds = 1                                              # 1 second for the test
    scans.start(["192.168.1.5/32"], "inventory", authorised=True)
    assert _wait(lambda: scans.status()["current"]["status"] == "stopped")
    assert store.scan_jobs(1)[0]["hosts_up"] == 1 and store.device("192.168.1.5")


def test_scan_targets_are_summarised_not_listed():
    from netai_detector.scanner import describe_targets
    assert describe_targets(["192.168.1.0/24"]) == "192.168.1.0/24"
    assert describe_targets(["10.0.0.5/32", "10.0.0.6/32"]) == "10.0.0.5, 10.0.0.6"
    many = [f"10.0.0.{i}/32" for i in range(1, 54)]
    assert describe_targets(many) == "53 devices (10.0.0.1, 10.0.0.2, 10.0.0.3 and 50 more)"
    assert describe_targets(["10.0.0.0/24", "10.1.0.0/24", "10.2.0.0/24", "10.3.0.5/32"]).startswith("4 networks/devices")


def test_scan_review_title_stays_short(tmp_path):
    from netai_detector.notifications import NotificationSettings
    from netai_detector.notifier import ReportService
    store = EventStore(tmp_path / "e.db")
    targets = [f"10.0.0.{i}/32" for i in range(1, 54)]
    job = store.add_scan_job("inventory", targets)
    store.save_scan_results(job, [{"ip": "10.0.0.1", "ports": {"tcp/22": {}}}])
    store.finish_scan_job(job, "done", 1)
    review = ReportService(store, NotificationSettings(store)).review_scan(job)
    assert review["title"] == "Scan review: 53 devices (10.0.0.1, 10.0.0.2 and 51 more)"
    assert "10.0.0.40" not in review["aya"]["text"] and "53 devices" in review["aya"]["text"]
