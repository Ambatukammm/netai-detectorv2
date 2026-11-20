"""Device names for IP addresses.

A name comes from (best first): a label you typed, the hostname nmap found, the Windows (NetBIOS)
computer name, or reverse DNS. Lookups run on background threads with short timeouts and are cached,
so monitoring is never slowed down by a slow DNS server. Results are saved in the device inventory.
"""
from __future__ import annotations
import logging
import queue
import socket
import struct
import threading
import time
from ipaddress import ip_address
from .forensics import is_internal

log = logging.getLogger("netai")
RETRY_SECONDS = 3600          # don't look the same address up again within this time
NAME_ORDER = ("label", "hostname", "netbios_name", "dns_name")


def display_name(record: dict | None) -> str | None:
    if not record:
        return None
    for key in NAME_ORDER:
        if record.get(key):
            return record[key]
    return None


def valid_ipv4(value: str) -> bool:
    try:
        return ip_address(value).version == 4
    except ValueError:
        return False


# ------------------------------------------------------------------ lookups
def reverse_dns(ip: str) -> str | None:
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return None
    return None if not name or name == ip else name.rstrip(".")


NBSTAT_QUERY_NAME = b"\x20" + b"CK" + b"A" * 30 + b"\x00"   # "*" encoded, NetBIOS style


def netbios_request(tid: int = 0x4E41) -> bytes:
    return struct.pack("!HHHHHH", tid, 0, 1, 0, 0, 0) + NBSTAT_QUERY_NAME + struct.pack("!HH", 0x21, 1)


def parse_netbios_response(data: bytes) -> str | None:
    """Computer name from a NetBIOS node-status answer (the unique name with suffix 0x00)."""
    try:
        pos = 12
        while data[pos] != 0:          # skip the (uncompressed) question name in the answer
            pos += data[pos] + 1
        pos += 1 + 2 + 2 + 4 + 2       # terminator, type, class, ttl, rdlength
        count = data[pos]
        pos += 1
        names = []
        for _ in range(count):
            raw, suffix, flags = data[pos:pos + 15], data[pos + 15], struct.unpack("!H", data[pos + 16:pos + 18])[0]
            pos += 18
            names.append((raw.decode("ascii", "replace").strip(), suffix, bool(flags & 0x8000)))
    except (IndexError, struct.error):
        return None
    for name, suffix, group in names:
        if suffix == 0x00 and not group and name:
            return name
    return None


def netbios_name(ip: str, timeout: float = 1.0) -> str | None:
    """Ask a device for its Windows computer name (UDP 137). Most Windows PCs and NAS boxes answer."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(netbios_request(), (ip, 137))
            data, _ = sock.recvfrom(2048)
    except OSError:
        return None
    return parse_netbios_response(data)


class DeviceDirectory:
    """Cached name lookups backed by the device inventory table."""

    def __init__(self, store, workers: int = 4, lookups=None, enabled: bool = True):
        self.store = store
        self.enabled = enabled
        self.lookups = lookups or {"dns_name": reverse_dns, "netbios_name": netbios_name}
        self._queue: queue.Queue = queue.Queue(maxsize=5000)
        self._tried: dict[str, float] = {}
        self._lock = threading.Lock()
        self._workers = workers
        self._threads: list[threading.Thread] = []

    # -------------------------------------------------------------- reading
    def names_for(self, ips, resolve: bool = True) -> dict[str, str]:
        """{ip: best name} for the addresses we have a name for. Unknown ones are queued for lookup."""
        ips = {ip for ip in ips if ip and valid_ipv4(ip)}
        rows = self.store.device_names(ips)
        out = {ip: display_name(rows.get(ip)) for ip in ips}
        if resolve:
            self.want(ip for ip, name in out.items() if not name)
        return {ip: name for ip, name in out.items() if name}

    def name(self, ip: str) -> str | None:
        return self.names_for([ip]).get(ip)

    # -------------------------------------------------------------- resolving
    def want(self, ips) -> None:
        """Queue background lookups (skipped if the same address was tried recently)."""
        if not self.enabled:
            return
        now = time.monotonic()
        with self._lock:
            for ip in ips:
                if not ip or not valid_ipv4(ip) or now - self._tried.get(ip, -1e9) < RETRY_SECONDS:
                    continue
                self._tried[ip] = now
                try:
                    self._queue.put_nowait(ip)
                except queue.Full:
                    break
            if len(self._tried) > 50_000:
                self._tried.clear()
            self._threads = [t for t in self._threads if t.is_alive()]
            while len(self._threads) < self._workers and not self._queue.empty():
                t = threading.Thread(target=self._worker, name="netai-names", daemon=True)
                t.start()
                self._threads.append(t)

    def resolve_now(self, ip: str) -> str | None:
        """Look an address up immediately (blocking). Used by tests and alerts."""
        self._lookup(ip)
        return display_name(self.store.device_names([ip]).get(ip))

    def _worker(self) -> None:
        while True:
            try:
                ip = self._queue.get(timeout=5)
            except queue.Empty:
                return
            try:
                self._lookup(ip)
            except Exception as exc:   # never let a lookup kill the worker
                log.debug("Name lookup for %s failed: %s", ip, exc)

    def _lookup(self, ip: str) -> None:
        found = {}
        dns = self.lookups.get("dns_name")
        if dns:
            found["dns_name"] = dns(ip)
        nb = self.lookups.get("netbios_name")
        if nb and is_internal(ip) and not ip.startswith("127."):
            found["netbios_name"] = nb(ip)
        found = {k: v for k, v in found.items() if v}
        if found:
            self.store.upsert_device(ip, seen_by="name lookup", **found)
