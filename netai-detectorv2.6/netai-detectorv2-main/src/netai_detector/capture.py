"""Packet capture: a live window source for automatic monitoring, plus offline PCAP extraction.

Both paths turn packets into fixed feature windows with the same code, so a model trained from
a PCAP can score live traffic and vice-versa. Payloads are never stored.
"""
from __future__ import annotations
from pathlib import Path
import os
import queue
import socket
import struct
import threading
import time
from types import SimpleNamespace
from typing import Iterator
import numpy as np
from .config import PROMISCUOUS, WINDOW_FLUSH_SECONDS, WINDOW_PACKETS
from .evidence import cut_headers
from .features import extract_window

MIN_WINDOW_PACKETS = 10


class CaptureUnavailable(RuntimeError):
    """Live capture cannot start here. The message is written for end users."""


def _scapy():
    try:
        import scapy.all as scapy
        return scapy
    except ImportError as exc:
        raise CaptureUnavailable(
            "Scapy is not installed, so live capture is off. Re-run the launcher to install it."
        ) from exc


def window_duration(packets: list) -> float | None:
    """Seconds spanned by a window, from packet timestamps (None if unavailable)."""
    try:
        span = float(packets[-1].time) - float(packets[0].time)
    except (AttributeError, IndexError, TypeError, ValueError):
        return None
    return max(span, 0.1)


def _hint(reason: str) -> str:
    low = reason.lower()
    if os.name == "nt" and any(k in low for k in ("winpcap", "npcap", "wpcap", "no such device", "layer 2")):
        return "Install Npcap (free) from https://npcap.com, tick 'WinPcap API-compatible mode', then restart."
    if "permission" in low or "not permitted" in low or "operation not permitted" in low:
        return "Packet capture needs administrator/root rights. Restart using the launcher and approve the prompt."
    return f"Live capture could not start ({reason or 'unknown reason'}). On Windows install Npcap from https://npcap.com."


class _QueueSource:
    """Shared windowing logic. Subclasses fill `self._queue` with packet-like objects.

    A window closes after `window_packets` IPv4 packets, or after `flush_seconds` once at least
    10 packets are waiting, so quiet networks still produce data.
    """
    kind = "live"

    def __init__(self, interface: str | None = None, window_packets: int = WINDOW_PACKETS,
                 flush_seconds: float = WINDOW_FLUSH_SECONDS):
        self.requested_interface = interface
        self.interface = interface or "default"
        self.window_packets = max(window_packets, MIN_WINDOW_PACKETS)
        self.flush_seconds = flush_seconds
        self.dropped = 0
        self._queue: queue.Queue = queue.Queue(maxsize=50_000)
        # The packets of the window just yielded, so flagged windows can be investigated.
        self.last_packets: list = []
        self.last_duration: float | None = None

    def _push(self, packet) -> None:
        try:
            self._queue.put_nowait(packet)
        except queue.Full:
            self.dropped += 1

    def windows(self, stop: threading.Event) -> Iterator[np.ndarray]:
        buf: list = []
        started = time.monotonic()
        while not stop.is_set():
            try:
                packet = self._queue.get(timeout=1.0)
                if not buf:
                    started = time.monotonic()
                buf.append(packet)
            except queue.Empty:
                pass
            waited = time.monotonic() - started
            if len(buf) >= self.window_packets or (len(buf) >= MIN_WINDOW_PACKETS
                                                  and waited >= self.flush_seconds):
                duration = window_duration(buf)
                try:
                    vector = extract_window(buf, duration)
                except ValueError:
                    vector = None
                if vector is not None:
                    self.last_packets, self.last_duration = buf, duration
                    yield vector
                buf = []


class LiveSource(_QueueSource):
    """Scapy-based capture (needs Scapy plus Npcap on Windows / libpcap elsewhere)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._sniffer = None

    def open(self) -> "LiveSource":
        scapy = _scapy()
        try:
            iface = self.requested_interface or scapy.conf.iface
            self.interface = str(getattr(iface, "name", iface))

            def on_packet(packet):
                try:
                    if packet.haslayer("IP"):
                        self._push(packet)
                except Exception:
                    pass

            self._sniffer = scapy.AsyncSniffer(iface=iface, prn=on_packet, store=False, promisc=PROMISCUOUS)
            self._sniffer.start()
            time.sleep(1.5)  # a sniffer that cannot open the interface dies almost immediately
            thread = getattr(self._sniffer, "thread", None)
            if thread is not None and not thread.is_alive():
                reason = str(getattr(self._sniffer, "exception", "") or "")
                raise CaptureUnavailable(_hint(reason))
        except CaptureUnavailable:
            self.close()
            raise
        except PermissionError as exc:
            self.close()
            raise CaptureUnavailable(_hint("permission denied")) from exc
        except Exception as exc:  # scapy raises many unrelated types for missing drivers/devices
            self.close()
            raise CaptureUnavailable(_hint(str(exc))) from exc
        return self

    def close(self) -> None:
        sniffer, self._sniffer = self._sniffer, None
        if sniffer is not None:
            try:
                if getattr(sniffer, "running", False):
                    sniffer.stop()
            except Exception:
                pass


# ------------------------------------------------------------------ driverless capture
class ParsedPacket:
    """Just enough of Scapy's packet interface for extract_window()."""
    __slots__ = ("_layers", "_size", "time", "raw_headers")

    def __init__(self, size: int, layers: dict, ts: float, raw_headers: bytes = b""):
        self._layers, self._size, self.time = layers, size, ts
        self.raw_headers = raw_headers  # IP + TCP/UDP/ICMP headers only; payload is never kept

    def haslayer(self, name): return name in self._layers
    def __getitem__(self, name): return self._layers[name]
    def __len__(self): return self._size


def parse_ipv4(data: bytes, ts: float | None = None) -> ParsedPacket | None:
    """Parse a raw IPv4 datagram (starting at the IP header). Returns None if it isn't IPv4."""
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    proto = data[9]
    ip = SimpleNamespace(src=socket.inet_ntoa(data[12:16]), dst=socket.inet_ntoa(data[16:20]),
                         proto=proto, ttl=data[8], ihl=ihl // 4)
    layers = {"IP": ip}
    total = struct.unpack("!H", data[2:4])[0] or len(data)
    if proto == 6 and len(data) >= ihl + 14:
        sport, dport = struct.unpack("!HH", data[ihl:ihl + 4])
        layers["TCP"] = SimpleNamespace(sport=sport, dport=dport, flags=data[ihl + 13])
    elif proto == 17 and len(data) >= ihl + 4:
        sport, dport = struct.unpack("!HH", data[ihl:ihl + 4])
        layers["UDP"] = SimpleNamespace(sport=sport, dport=dport)
    return ParsedPacket(total, layers, ts if ts is not None else time.time(), cut_headers(data))


def _default_linux_interface() -> str | None:
    try:
        with open("/proc/net/route", encoding="ascii") as handle:
            for line in list(handle)[1:]:
                fields = line.split()
                if fields[1] == "00000000":
                    return fields[0]
    except OSError:
        pass
    return None


def _local_ip() -> str:
    """The address of the interface used for internet traffic (no packet is actually sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        except OSError:
            return "127.0.0.1"


def _set_promiscuous(sock, iface: str) -> bool:
    """Linux: receive every frame on the interface (needed for SPAN/mirror ports), not only ours.
    The kernel undoes this automatically when the socket closes."""
    try:
        mreq = struct.pack("iHH8s", socket.if_nametoindex(iface), 1, 0, b"")  # PACKET_MR_PROMISC
        sock.setsockopt(263, 1, mreq)                                           # SOL_PACKET, ADD_MEMBERSHIP
        return True
    except OSError:
        return False


class RawSocketSource(_QueueSource):
    """Capture with plain operating-system sockets: no Scapy, no Npcap, no libpcap.

    Windows: an IPv4 raw socket in 'receive all' mode (administrator needed), seeing traffic of the
    main network adapter. Linux: an AF_PACKET socket (root needed) on the default interface.
    IPv4 only. macOS is not supported here (use Scapy)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = threading.Event()
        self._strip = 0

    def open(self) -> "RawSocketSource":
        try:
            if os.name == "nt":
                host = _local_ip()
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((host, 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                self.interface = f"adapter {host}"
            elif hasattr(socket, "AF_PACKET"):
                iface = self.requested_interface or _default_linux_interface()
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                if iface:
                    sock.bind((iface, 0))
                    if PROMISCUOUS:
                        _set_promiscuous(sock, iface)
                self.interface = iface or "all interfaces"
                self._strip = 14  # Ethernet header
            else:
                raise CaptureUnavailable("Built-in capture is not supported on this system; install Scapy.")
        except CaptureUnavailable:
            raise
        except PermissionError as exc:
            raise CaptureUnavailable(_hint("permission denied")) from exc
        except OSError as exc:
            raise CaptureUnavailable(_hint(str(exc))) from exc
        sock.settimeout(1.0)
        self._sock = sock
        self._running.set()
        self._thread = threading.Thread(target=self._loop, name="netai-rawcapture", daemon=True)
        self._thread.start()
        return self

    def _loop(self) -> None:
        sock = self._sock
        while self._running.is_set() and sock is not None:
            try:
                data = sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            if self._strip:
                if len(data) < self._strip or data[12:14] != b"\x08\x00":
                    continue
                data = data[self._strip:]
            packet = parse_ipv4(data)
            if packet is not None:
                self._push(packet)

    def close(self) -> None:
        self._running.clear()
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                if os.name == "nt":
                    sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
            try:
                sock.close()
            except OSError:
                pass


def open_live(interface: str | None = None):
    """Open the best available live source: Scapy first, then the built-in raw-socket capture."""
    errors: list[str] = []
    for factory in (LiveSource, RawSocketSource):
        try:
            return factory(interface).open()
        except CaptureUnavailable as exc:
            errors.append(str(exc))
    # Prefer the message about rights (actionable) over "scapy missing"/"driver missing".
    for message in errors:
        if "administrator" in message or "root" in message:
            raise CaptureUnavailable(message)
    raise CaptureUnavailable(errors[0])


def iter_pcap_windows(path: str | Path, window_packets: int = WINDOW_PACKETS):
    """Yield (feature_vector, packets, duration) for each window of an offline capture file."""
    scapy = _scapy()
    buffer: list = []
    found = False

    def flush():
        duration = window_duration(buffer)
        try:
            return extract_window(buffer, duration), list(buffer), duration
        except ValueError:
            return None

    with scapy.PcapReader(str(path)) as packets:
        for packet in packets:
            buffer.append(packet)
            if len(buffer) >= window_packets:
                item = flush()
                buffer.clear()
                if item is not None:
                    found = True
                    yield item
    if len(buffer) >= MIN_WINDOW_PACKETS:
        item = flush()
        if item is not None:
            found = True
            yield item
    if not found:
        raise RuntimeError("No usable IPv4 packet windows found in that capture file")


def extract_pcap(path: str | Path, window_packets: int = WINDOW_PACKETS) -> np.ndarray:
    """Convert an offline capture file into feature windows."""
    samples = [vector for vector, _, _ in iter_pcap_windows(path, window_packets)]
    return np.asarray(samples, dtype=np.float32)


def capture_windows(duration: int = 300, interface: str | None = None,
                    window_packets: int = 100, output: str = "data/normal_windows.npz") -> np.ndarray:
    """Manual baseline capture (advanced CLI). Normal use is fully automatic via the monitor."""
    if duration < 1 or window_packets < MIN_WINDOW_PACKETS:
        raise ValueError("duration must be positive and window_packets must be at least 10")
    source = open_live(interface)
    source.window_packets = max(window_packets, MIN_WINDOW_PACKETS)
    stop, samples = threading.Event(), []
    timer = threading.Timer(duration, stop.set)
    timer.start()
    print(f"Capturing for {duration}s on {source.interface}; Ctrl+C to stop.")
    try:
        samples.extend(source.windows(stop))
    except KeyboardInterrupt:
        pass
    finally:
        timer.cancel()
        source.close()
    if len(samples) < 20:
        raise RuntimeError(f"Only {len(samples)} usable windows captured; at least 20 are required.")
    array = np.asarray(samples, dtype=np.float32)
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(path, features=array)
    print(f"Saved {len(array)} feature windows to {path}")
    return array
