"""Device names, nmap network scanning (with a stand-in nmap) and SPAN passive discovery."""
import os
import stat
import struct
import sys
import textwrap
import time
from types import SimpleNamespace
import pytest
from netai_detector.advisor import advise
from netai_detector.alerts import format_alert
from netai_detector.demo import _packet
from netai_detector.devices import (DeviceDirectory, display_name, netbios_request,
                                    parse_netbios_response)
from netai_detector.passive import PassiveDiscovery
from netai_detector.scanner import (ScanManager, build_command, candidate_subnets, parse_iflist,
                                    parse_nmap_xml, validate_targets)
from netai_detector.storage import EventStore

IFLIST = """Starting Nmap 7.95 ( https://nmap.org ) at 2026-11-20 12:00 AEST
************************INTERFACES************************
DEV  (SHORT)         IP/MASK                     TYPE        UP MTU   MAC
eth0 (Ethernet 2)    192.168.15.240/24           ethernet    up 1500  00:15:5D:01:02:03
eth1 (Wi-Fi)         10.20.0.7/16                ethernet    down 1500 00:15:5D:01:02:04
lo0  (Loopback)      127.0.0.1/8                 loopback    up 1500

**************************ROUTES**************************
DST/MASK             DEV  METRIC GATEWAY
192.168.15.0/24      eth0 281
192.168.30.0/24      eth0 25     192.168.15.1
10.50.0.0/16         eth0 25     192.168.15.1
0.0.0.0/0            eth0 25     192.168.15.1
8.8.8.0/24           eth0 25     192.168.15.1
"""

XML = """<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -F">
<host><status state="up"/><address addr="192.168.15.10" addrtype="ipv4"/>
<address addr="AA:BB:CC:00:11:22" addrtype="mac" vendor="Hewlett Packard"/>
<hostnames><hostname name="printer-level2.corp.local" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="9100"><state state="open"/><service name="jetdirect"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="HP HTTP Server" version="2.0"/></port>
<port protocol="tcp" portid="443"><state state="closed"/></port></ports>
<os><osmatch name="HP LaserJet printer" accuracy="96"/></os></host>
<host><status state="up"/><address addr="192.168.15.22" addrtype="ipv4"/></host>
<host><status state="down"/><address addr="192.168.15.99" addrtype="ipv4"/></host>
</nmaprun>"""


# ------------------------------------------------------------------ names
def _nbstat_answer(names):
    body = struct.pack("!HHHHHH", 0x4E41, 0x8400, 0, 1, 0, 0) + b"\x20" + b"CK" + b"A" * 30 + b"\x00"
    entries = b"".join(n.ljust(15).encode() + bytes([sfx]) + struct.pack("!H", fl) for n, sfx, fl in names)
    rdata = bytes([len(names)]) + entries + b"\x00" * 6
    return body + struct.pack("!HHIH", 0x21, 1, 0, len(rdata)) + rdata


def test_netbios_request_and_answer_parsing():
    assert netbios_request()[12:46] == b"\x20CK" + b"A" * 30 + b"\x00"
    answer = _nbstat_answer([("WORKGROUP", 0x00, 0x8000), ("RECEPTION-PC", 0x00, 0x0400),
                             ("RECEPTION-PC", 0x20, 0x0400)])
    assert parse_netbios_response(answer) == "RECEPTION-PC"
    assert parse_netbios_response(b"garbage") is None


def test_name_priority_label_beats_everything():
    assert display_name({"dns_name": "a.lan", "netbios_name": "PC1"}) == "PC1"
    assert display_name({"dns_name": "a.lan", "hostname": "nmap-name", "label": "Reception PC"}) == "Reception PC"
    assert display_name({}) is None


def test_directory_looks_names_up_in_background_and_caches(tmp_path):
    store = EventStore(tmp_path / "e.db")
    calls = []

    def dns(ip):
        calls.append(ip)
        return "fileserver.corp.local" if ip == "192.168.15.5" else None
    directory = DeviceDirectory(store, lookups={"dns_name": dns, "netbios_name": lambda ip: "FS01"})
    assert directory.names_for(["192.168.15.5", "8.8.8.8"]) == {}         # first ask: queued
    deadline = time.time() + 5
    while time.time() < deadline and not directory.names_for(["192.168.15.5"], resolve=False):
        time.sleep(0.05)
    assert directory.names_for(["192.168.15.5"]) == {"192.168.15.5": "FS01"}   # NetBIOS beats DNS
    directory.names_for(["192.168.15.5", "8.8.8.8"])
    time.sleep(0.2)
    assert calls.count("192.168.15.5") == 1                                 # cached, not re-queried
    store.set_device_label("192.168.15.5", "Main file server")
    assert directory.name("192.168.15.5") == "Main file server"


def test_names_appear_in_advice_but_never_in_commands():
    incident = {"hints": [{"type": "brute_force", "confidence": "high", "attacker": "192.168.15.66",
                           "target": "192.168.15.5", "ports": [22]}], "culprits": {}}
    names = {"192.168.15.66": "LAPTOP-JOHN", "192.168.15.5": "FS01"}
    plan = advise(incident, names)
    assert "192.168.15.66 (LAPTOP-JOHN)" in plan["summary"] and "192.168.15.5 (FS01)" in plan["summary"]
    assert plan["attacker_name"] == "LAPTOP-JOHN"
    ext = advise({"hints": [{"type": "brute_force", "confidence": "high", "attacker": "203.0.113.77",
                             "target": "192.168.15.5", "ports": [22]}], "culprits": {}},
                 {"203.0.113.77": "scanner.example.net"})
    assert all("(" not in c["run"] for c in ext["commands"])               # commands keep the bare IP


def test_alerts_include_names_only_when_hosts_are_allowed():
    inc = {"id": 1, "source": "live:x", "peak_severity": "high", "attack_type": "port_scan",
           "culprits": {"top_flows": [{"src": "192.168.15.66", "dst": "192.168.15.5", "proto": "tcp", "packets": 9}]}}
    _, body = format_alert(inc, names={"192.168.15.66": "LAPTOP-JOHN"})
    assert "192.168.15.66 = LAPTOP-JOHN" in body
    _, hidden = format_alert(inc, include_hosts=False, names={"192.168.15.66": "LAPTOP-JOHN"})
    assert "LAPTOP-JOHN" not in hidden


# ------------------------------------------------------------------ nmap parsing and targets
def test_iflist_gives_interfaces_and_vlan_routes():
    interfaces, routes = parse_iflist(IFLIST)
    assert interfaces[0] == {"dev": "eth0", "name": "Ethernet 2", "ip": "192.168.15.240", "prefix": 24,
                             "type": "ethernet", "up": True}
    assert any(r["dest"] == "192.168.30.0/24" and r["gateway"] == "192.168.15.1" for r in routes)
    subnets = {s["cidr"]: s for s in candidate_subnets(None, iflist_text=IFLIST)}
    assert subnets["192.168.15.0/24"]["source"] == "this computer"
    assert subnets["192.168.30.0/24"]["source"] == "route"           # another VLAN via the router
    assert subnets["10.50.0.0/16"]["source"] == "route"
    assert "10.20.0.0/16" not in subnets                              # interface is down
    assert "8.8.8.0/24" not in subnets and "0.0.0.0/0" not in subnets  # not internal / default route


def test_subnets_seen_in_traffic_and_added_by_hand(tmp_path):
    store = EventStore(tmp_path / "e.db")
    store.upsert_device("172.16.40.12", seen_by="passive")
    store.upsert_device("192.168.15.9", seen_by="passive")        # already covered by eth0
    store.set_setting("scan_subnets", ["10.99.0.0/24"])
    subnets = {s["cidr"]: s for s in candidate_subnets(None, store, iflist_text=IFLIST)}
    assert subnets["172.16.40.0/24"]["source"] == "seen in traffic"
    assert subnets["10.99.0.0/24"]["source"] == "added by you" and subnets["10.99.0.0/24"]["custom"]
    assert list(subnets).count("192.168.15.0/24") == 1


def test_target_validation():
    assert validate_targets(["192.168.15.0/24", " 10.0.0.5 ", "192.168.15.7/24"]) == ["192.168.15.0/24", "10.0.0.5/32"]
    for bad in (["10.0.0.0/8"], ["-oN /etc/passwd"], ["host.example.com"], ["127.0.0.1"], [""], ["224.0.0.0/24"]):
        with pytest.raises(ValueError):
            validate_targets(bad)
    cmd = build_command("nmap", ["192.168.15.0/24"], "ports", "/tmp/x.xml", exclude=["192.168.15.1"])
    assert cmd[-1] == "192.168.15.0/24" and "--exclude" in cmd and "-F" in cmd and "-oX" in cmd


def test_nmap_xml_results():
    hosts = {h["ip"]: h for h in parse_nmap_xml(XML)}
    assert set(hosts) == {"192.168.15.10", "192.168.15.22"}                # down host skipped
    printer = hosts["192.168.15.10"]
    assert printer["vendor"] == "Hewlett Packard" and printer["hostname"] == "printer-level2.corp.local"
    assert printer["os"] == "HP LaserJet printer (96%)"
    assert set(printer["ports"]) == {"tcp/9100", "tcp/80"}                 # closed port skipped
    assert printer["ports"]["tcp/80"]["product"] == "HP HTTP Server 2.0"
    assert printer["ports"]["tcp/9100"]["risk"]


# ------------------------------------------------------------------ full scan job with a stand-in nmap
@pytest.fixture
def fake_nmap(tmp_path):
    """A small program that behaves like nmap: progress lines, then an XML file."""
    if os.name == "nt":
        pytest.skip("stand-in nmap uses a shebang script")
    script = tmp_path / "nmap"
    script.write_text(textwrap.dedent(f"""\
        #!{sys.executable}
        import sys, time
        args = sys.argv[1:]
        if "--version" in args:
            print("Nmap version 7.95 ( https://nmap.org )"); sys.exit(0)
        if "--iflist" in args:
            print({IFLIST!r}); sys.exit(0)
        out = args[args.index("-oX") + 1]
        slow = "192.168.99.0/24" in args
        for pct in (25, 50, 75):
            print(f"Ping Scan Timing: About {{pct}}.00% done; ETC: 12:01 (0:00:01 remaining)", flush=True)
            time.sleep(1.0 if slow else 0.05)
        open(out, "w").write({XML!r})
        """))
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


def _wait(cond, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.05)
    return False


def test_scan_job_fills_the_inventory(tmp_path, fake_nmap):
    store = EventStore(tmp_path / "e.db")
    store.upsert_device("192.168.15.50", seen_by="passive", up=True,        # will not answer the scan
                        when="2026-01-01T00:00:00+00:00")
    store.upsert_device("192.168.15.10", seen_by="manual", label="Level 2 printer")
    scans = ScanManager(store, nmap=fake_nmap)
    assert scans.available()["version"] == "7.95"
    with pytest.raises(PermissionError):
        scans.start(["192.168.15.0/24"], "ports")
    job = scans.start(["192.168.15.0/24"], "ports", authorised=True)
    assert job["status"] == "running"
    assert _wait(lambda: scans.status()["current"]["status"] == "done")
    status = scans.status()
    assert status["current"]["hosts_up"] == 2 and status["jobs"][0]["status"] == "done"
    printer = store.device("192.168.15.10")
    assert printer["label"] == "Level 2 printer"                            # your label survives
    assert printer["vendor"] == "Hewlett Packard" and "tcp/9100" in printer["ports"]
    assert set(printer["seen_by"]) == {"manual", "nmap"}
    assert store.device("192.168.15.50")["up"] is False                     # gone quiet: marked offline


def test_scan_does_not_mark_devices_seen_in_traffic_as_offline(tmp_path, fake_nmap):
    store = EventStore(tmp_path / "e.db")
    scans = ScanManager(store, nmap=fake_nmap)
    scans.start(["192.168.15.0/24"], "discover", authorised=True)
    store.upsert_device("192.168.15.77", seen_by="passive", up=True)        # talking during the scan
    assert _wait(lambda: scans.status()["current"]["status"] == "done")
    assert store.device("192.168.15.77")["up"] is True
    assert {s["cidr"] for s in scans.subnets()} >= {"192.168.15.0/24", "192.168.30.0/24"}


def test_scan_can_be_cancelled_and_only_one_runs_at_a_time(tmp_path, fake_nmap):
    store = EventStore(tmp_path / "e.db")
    scans = ScanManager(store, nmap=fake_nmap)
    scans.start(["192.168.99.0/24"], "discover", authorised=True)
    with pytest.raises(RuntimeError, match="already running"):
        scans.start(["192.168.15.0/24"], "discover", authorised=True)
    assert _wait(lambda: scans.status()["current"]["progress"] >= 25)
    assert scans.cancel()
    assert _wait(lambda: scans.status()["current"]["status"] == "cancelled")
    assert store.scan_jobs()[0]["status"] == "cancelled"


def test_missing_nmap_explains_how_to_install(tmp_path):
    scans = ScanManager(EventStore(tmp_path / "e.db"), find=lambda: None)
    info = scans.available()
    assert not info["installed"] and "nmap.org" in info["hint"]
    with pytest.raises(RuntimeError, match="nmap.org"):
        scans.start(["192.168.15.0/24"], authorised=True)


# ------------------------------------------------------------------ SPAN passive discovery
def _syn_ack(src, sport, dst):
    return _packet(src, dst, 6, 60, 64, sport, 51000, flags=0x12)


def test_passive_discovery_finds_devices_and_open_services(tmp_path):
    store = EventStore(tmp_path / "e.db")
    passive = PassiveDiscovery(store, local_ips={"192.168.15.240"}, flush_seconds=3600)
    packets = [
        _packet("192.168.15.30", "192.168.15.5", 6, 60, 64, 51000, 3389, flags=0x02),  # client asks RDP
        _syn_ack("192.168.15.5", 3389, "192.168.15.30"),                                 # server: open
        _syn_ack("192.168.15.5", 445, "192.168.15.30"),
        _packet("192.168.15.1", "192.168.15.30", 17, 90, 64, 53, 53000),                 # DNS answer
        _packet("192.168.15.5", "192.168.15.30", 6, 60, 64, 22, 51000, flags=0x14),       # RST: closed
        _packet("192.168.15.30", "142.250.70.14", 6, 1400, 64, 51000, 443, flags=0x10),    # internet: not listed
        _packet("192.168.15.30", "224.0.0.251", 17, 90, 64, 5353, 5353),                  # multicast
    ]
    passive.observe(packets)
    passive.flush()
    server = store.device("192.168.15.5")
    assert set(server["ports"]) == {"tcp/3389", "tcp/445"}
    assert server["ports"]["tcp/3389"]["service"] == "Remote Desktop (RDP)" and server["ports"]["tcp/3389"]["risk"]
    assert "udp/53" in store.device("192.168.15.1")["ports"]
    assert "udp/5353" in store.device("192.168.15.30")["ports"]       # mDNS speaker
    ips = {d["ip"] for d in store.devices()}
    assert "142.250.70.14" not in ips and "224.0.0.251" not in ips
    assert store.device("192.168.15.30")["packets"] == 3


def test_mirror_detection():
    store = SimpleNamespace(upsert_device=lambda *a, **k: None)
    own = PassiveDiscovery(store, local_ips={"192.168.15.240"})
    own.observe([_packet("192.168.15.240", "8.8.8.8", 17, 80, 64, 50000, 53)] * 300)
    assert own.status()["mirroring_detected"] is False
    span = PassiveDiscovery(store, local_ips={"192.168.15.240"})
    span.observe([_packet("192.168.15.30", "192.168.15.5", 6, 60, 64, 50000, 445, flags=0x10)] * 300)
    assert span.status()["mirroring_detected"] is True
    assert PassiveDiscovery(store, local_ips=set()).status()["mirroring_detected"] is None   # too early
