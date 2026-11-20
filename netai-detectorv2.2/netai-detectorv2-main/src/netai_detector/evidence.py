"""Headers-only evidence files (.pcap) for incidents, openable in Wireshark.

Each packet is cut right after its TCP/UDP/ICMP header, so message contents (web pages, emails,
passwords) are never written to disk. Wireshark shows such packets as "captured length < frame
length", which is expected. Files use the raw-IPv4 link type, so no Ethernet/MAC addresses are kept.

IP addresses and ports ARE kept: that is the point of evidence, and also why it is personal data in
many workplaces. Files are capped in total size and oldest are deleted first.
"""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
import socket
import struct
import threading
import time
from .config import EVIDENCE_DIR, EVIDENCE_MAX_MB, EVIDENCE_MAX_PACKETS, hand_back_to_user
from .forensics import packet_fields

LINKTYPE_RAW = 101
PCAP_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_RAW)


def cut_headers(data: bytes) -> bytes:
    """Truncate a raw IPv4 datagram to its IP + transport headers (drops the payload)."""
    if len(data) < 20 or data[0] >> 4 != 4:
        return b""
    ihl = (data[0] & 0x0F) * 4
    proto = data[9]
    l4 = 0
    if proto == 6 and len(data) >= ihl + 13:
        l4 = max(20, (data[ihl + 12] >> 4) * 4)
    elif proto in (17, 1):
        l4 = 8
    return bytes(data[:ihl + l4])


def _checksum(header: bytes) -> int:
    if len(header) % 2:
        header += b"\0"
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def synth_headers(packet) -> bytes:
    """Rebuild IP + transport headers from parsed fields (used when raw bytes aren't available)."""
    fields = packet_fields(packet)
    if fields is None:
        return b""
    src, dst, proto, size, sport, dport, flags = fields
    try:
        ttl = int(packet["IP"].ttl)
    except Exception:
        ttl = 64
    if proto == 6:
        l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags & 0xFF, 65535, 0, 0)
    elif proto == 17:
        l4 = struct.pack("!HHHH", sport, dport, max(size - 20, 8) & 0xFFFF, 0)
    elif proto == 1:
        l4 = struct.pack("!BBHHH", 8, 0, 0, 0, 0)
    else:
        l4 = b""
    try:
        src_b, dst_b = socket.inet_aton(src), socket.inet_aton(dst)
    except OSError:
        return b""
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, max(size, 20 + len(l4)) & 0xFFFF, 0, 0x4000, ttl & 0xFF,
                     proto, 0, src_b, dst_b)
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return ip + l4


def header_bytes(packet) -> bytes:
    """Headers-only bytes for any packet type NetAI handles (Scapy, built-in capture, demo)."""
    raw = getattr(packet, "raw_headers", None)          # built-in capture keeps these
    if raw:
        return cut_headers(raw)
    try:
        if hasattr(packet, "haslayer") and packet.haslayer("IP") and hasattr(packet["IP"], "build"):
            return cut_headers(bytes(packet["IP"]))     # Scapy packet: real header bytes
    except Exception:
        pass
    return synth_headers(packet)


def write_records(handle, packets) -> int:
    written = 0
    for packet in packets:
        data = header_bytes(packet)
        if not data:
            continue
        try:
            ts = float(getattr(packet, "time", None) or time.time())
        except (TypeError, ValueError):
            ts = time.time()
        orig = max(int(len(packet)), len(data))
        sec = int(ts)
        handle.write(struct.pack("<IIII", sec, int((ts - sec) * 1e6), len(data), orig))
        handle.write(data)
        written += 1
    return written


class EvidenceStore:
    """One growing .pcap per incident, inside a size-capped folder."""

    def __init__(self, folder: Path | str = EVIDENCE_DIR, max_mb: int = EVIDENCE_MAX_MB,
                 max_packets: int = EVIDENCE_MAX_PACKETS):
        self.folder = Path(folder)
        self.max_bytes = max_mb * 1024 * 1024
        self.max_packets = max_packets
        self._lock = threading.Lock()

    def path_for(self, incident_id: int, tag: str = "") -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return self.folder / f"incident-{incident_id}{'-' + tag if tag else ''}-{stamp}.pcap"

    def append(self, path: Path | str, packets, already: int = 0) -> int:
        """Append packets (up to the per-incident cap). Returns how many were written."""
        room = self.max_packets - already
        if room <= 0 or not packets:
            return 0
        path = Path(path)
        with self._lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            new = not path.exists()
            with open(path, "ab") as handle:
                if new:
                    handle.write(PCAP_HEADER)
                count = write_records(handle, list(packets)[:room])
            if new:
                hand_back_to_user(path.parent)
                hand_back_to_user(path)
        return count

    def enforce_cap(self, keep: set[str] = frozenset()) -> list[str]:
        """Delete the oldest files until the folder fits the size cap. Returns deleted paths."""
        with self._lock:
            files = sorted(self.folder.glob("*.pcap"), key=lambda p: p.stat().st_mtime) \
                if self.folder.exists() else []
            total = sum(p.stat().st_size for p in files)
            deleted = []
            for p in files:
                if total <= self.max_bytes:
                    break
                if str(p) in keep:
                    continue
                size = p.stat().st_size
                try:
                    p.unlink()
                    total -= size
                    deleted.append(str(p))
                except OSError:
                    pass
            return deleted


def read_pcap(path: Path | str) -> list[tuple[float, bytes, int]]:
    """Minimal reader (used by tests): [(timestamp, captured bytes, original length)]."""
    data = Path(path).read_bytes()
    magic, _, _, _, _, _, linktype = struct.unpack("<IHHiIII", data[:24])
    if magic != 0xA1B2C3D4 or linktype != LINKTYPE_RAW:
        raise ValueError("not a NetAI evidence file")
    out, pos = [], 24
    while pos + 16 <= len(data):
        sec, usec, incl, orig = struct.unpack("<IIII", data[pos:pos + 16])
        pos += 16
        out.append((sec + usec / 1e6, data[pos:pos + incl], orig))
        pos += incl
    return out
