"""Passive discovery: build a device and service inventory just by listening.

Plug NetAI into a switch's SPAN (mirror) port and it sees everyone's traffic. Without sending a
single packet it learns:
  * which devices exist (internal addresses only: internet servers are counted, not listed)
  * which services each device offers: a TCP SYN-ACK from port 22 means "SSH is open", a reply from
    UDP port 53 means "runs DNS"
  * whether mirroring is actually working (are we seeing traffic that isn't our own?)

Only headers are read. Results are merged into the device inventory every `flush_seconds`.
"""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timezone
from ipaddress import ip_address
import socket
import threading
import time
from .forensics import is_internal, packet_fields

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 69: "TFTP", 80: "HTTP",
    88: "Kerberos", 110: "POP3", 123: "NTP", 135: "MS RPC", 137: "NetBIOS name", 138: "NetBIOS datagram",
    139: "NetBIOS session", 143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB file sharing",
    465: "SMTPS", 500: "IKE (VPN)", 514: "Syslog", 515: "LPD printing", 548: "AFP (Mac sharing)",
    554: "RTSP (cameras)", 587: "SMTP submission", 631: "IPP printing", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1433: "MS SQL", 1521: "Oracle DB", 1812: "RADIUS", 1883: "MQTT (IoT)",
    1900: "SSDP / UPnP", 2049: "NFS", 3306: "MySQL", 3389: "Remote Desktop (RDP)", 3478: "STUN",
    4500: "IPsec NAT-T", 5060: "SIP (VoIP)", 5353: "mDNS / Bonjour", 5432: "PostgreSQL",
    5900: "VNC remote control", 5985: "WinRM", 5986: "WinRM (HTTPS)", 6379: "Redis",
    8000: "HTTP-alt", 8080: "HTTP-alt", 8443: "HTTPS-alt", 9100: "Printer (JetDirect)",
    27017: "MongoDB",
}
# Services worth a second look when you find them on a business network.
RISKY = {
    21: "FTP sends passwords unencrypted. Use SFTP/FTPS instead.",
    23: "Telnet sends everything, passwords included, unencrypted. Replace with SSH.",
    69: "TFTP has no authentication at all.",
    135: "Windows RPC should never be reachable from outside the LAN.",
    139: "Old NetBIOS file sharing. Disable it if SMB2/3 (port 445) is available.",
    161: "SNMP v1/v2 uses a plain-text 'community' password. Use SNMPv3 or restrict it.",
    445: "SMB file sharing is a top ransomware path. Keep it off guest/IoT VLANs and the internet.",
    1433: "A database should only be reachable from the servers that need it.",
    1883: "MQTT is often deployed without a password on IoT devices.",
    3306: "A database should only be reachable from the servers that need it.",
    3389: "Remote Desktop is heavily brute-forced. Put it behind a VPN and enable NLA/MFA.",
    5432: "A database should only be reachable from the servers that need it.",
    5900: "VNC often has weak or no passwords. Restrict it or tunnel it through a VPN.",
    6379: "Redis has no password by default.",
    9100: "Raw printing port: anyone who can reach it can print (and some printers can be reconfigured).",
    27017: "MongoDB has historically shipped without authentication.",
}
UDP_SERVICES = {53, 67, 69, 123, 137, 138, 161, 389, 500, 514, 1812, 1900, 3478, 4500, 5060, 5353}


def service_name(port: int) -> str:
    return SERVICE_NAMES.get(port, f"port {port}")


def local_ipv4s() -> set[str]:
    """This computer's own IPv4 addresses (best effort)."""
    found = {"127.0.0.1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(info[4][0])
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))   # no packet is sent for UDP connect
            found.add(sock.getsockname()[0])
    except OSError:
        pass
    return found


def _is_device_address(ip: str) -> bool:
    """Internal unicast addresses only (skip broadcast/multicast/network addresses)."""
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    if addr.version != 4 or addr.is_multicast or addr.is_unspecified or not is_internal(ip):
        return False
    last = int(str(ip).rsplit(".", 1)[-1])
    return last not in (0, 255) and not ip.startswith("127.")


class _Dev:
    __slots__ = ("packets", "bytes", "external_peers", "internal_peers", "first", "last")

    def __init__(self, ts):
        self.packets = self.bytes = 0
        self.external_peers: set = set()
        self.internal_peers: set = set()
        self.first = self.last = ts


class PassiveDiscovery:
    def __init__(self, store, local_ips: set[str] | None = None, flush_seconds: float = 30,
                 max_devices: int = 10_000, enabled: bool = True):
        self.store = store
        self.enabled = enabled
        self.local_ips = local_ips if local_ips is not None else local_ipv4s()
        self.flush_seconds = flush_seconds
        self.max_devices = max_devices
        self._lock = threading.Lock()
        self._devs: dict[str, _Dev] = {}
        self._services: dict[tuple, list] = defaultdict(lambda: [0, 0.0, 0.0])  # count, first, last
        self._last_flush = time.monotonic()
        self.packets_seen = 0
        self.devices_seen: set[str] = set()
        self.services_seen: set[tuple] = set()
        self._win_total = self._win_foreign = 0       # current measuring window
        self._ratio: float | None = None              # foreign-traffic share of the last window

    def observe(self, packets) -> None:
        if not self.enabled or not packets:
            return
        now = time.time()
        with self._lock:
            for packet in packets:
                fields = packet_fields(packet)
                if fields is None:
                    continue
                src, dst, proto, size, sport, dport, flags = fields
                self.packets_seen += 1
                self._win_total += 1
                if src not in self.local_ips and dst not in self.local_ips:
                    self._win_foreign += 1
                if self._win_total >= 2000:
                    self._ratio = self._win_foreign / self._win_total
                    self._win_total = self._win_foreign = 0
                for ip, peer in ((src, dst), (dst, src)):
                    if not _is_device_address(ip):
                        continue
                    dev = self._devs.get(ip)
                    if dev is None:
                        if len(self._devs) >= self.max_devices:
                            continue
                        dev = self._devs[ip] = _Dev(now)
                    dev.last = now
                    if ip == src:
                        dev.packets += 1
                        dev.bytes += size
                    peers = dev.internal_peers if is_internal(peer) else dev.external_peers
                    if len(peers) < 500:
                        peers.add(peer)
                if not _is_device_address(src):
                    continue
                key = None
                if proto == 6 and flags & 0x12 == 0x12:                      # SYN-ACK: port is open
                    key = (src, "tcp", sport)
                elif proto == 17 and sport in UDP_SERVICES and (dport >= 1024 or dport == sport):
                    key = (src, "udp", sport)
                if key:
                    svc = self._services[key]
                    svc[0] += 1
                    svc[1] = svc[1] or now
                    svc[2] = now
            if time.monotonic() - self._last_flush >= self.flush_seconds:
                self._flush_locked()

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        self._last_flush = time.monotonic()
        devs, services = self._devs, self._services
        self._devs, self._services = {}, defaultdict(lambda: [0, 0.0, 0.0])
        ports_by_ip: dict[str, dict] = defaultdict(dict)
        for (ip, proto, port), (_count, _first, last) in services.items():
            self.services_seen.add((ip, proto, port))
            ports_by_ip[ip][f"{proto}/{port}"] = {
                "service": service_name(port), "source": "passive", "state": "open",
                "last_seen": datetime.fromtimestamp(last, timezone.utc).isoformat(),
                "risk": RISKY.get(port)}
        for ip, dev in devs.items():
            self.devices_seen.add(ip)
            try:
                self.store.upsert_device(
                    ip, seen_by="passive", ports=ports_by_ip.pop(ip, None), packets=dev.packets,
                    nbytes=dev.bytes, up=True,
                    when=datetime.fromtimestamp(dev.last, timezone.utc).isoformat())
            except Exception:
                pass
        for ip, ports in ports_by_ip.items():
            self.store.upsert_device(ip, seen_by="passive", ports=ports, up=True)
        if len(self.devices_seen) > 100_000:
            self.devices_seen.clear()
            self.services_seen.clear()

    def status(self) -> dict:
        with self._lock:
            ratio = self._ratio
            if ratio is None and self._win_total >= 200:
                ratio = self._win_foreign / self._win_total
        mirroring = None if ratio is None else ratio >= 0.2
        return {"enabled": self.enabled, "packets_seen": self.packets_seen,
                "foreign_traffic_ratio": None if ratio is None else round(ratio, 3),
                "mirroring_detected": mirroring, "devices_seen": len(self.devices_seen),
                "services_seen": len(self.services_seen), "local_ips": sorted(self.local_ips)}
