"""Simulated traffic, used ONLY when live capture is unavailable and no real model exists.

It lets a first-time user see the whole learn -> train -> monitor -> investigate loop working
immediately. Every event it produces is tagged source="demo" and the dashboard shows a banner while
it is active. Packets are synthetic objects that go through the real feature extractor and the real
culprit analysis. Addresses use reserved documentation ranges where they are "outside".
"""
from __future__ import annotations
import threading
import time
from types import SimpleNamespace
from typing import Iterator
import numpy as np
from .config import WINDOW_PACKETS
from .features import extract_window

SCENARIOS = ("portscan", "flood", "exfil", "synflood", "bruteforce", "sweep", "dnstunnel")


class _Packet:
    def __init__(self, size: int, ip, l4_name: str | None = None, l4=None, ts: float = 0.0):
        self._size = size
        self._layers = {"IP": ip}
        self.time = ts
        if l4_name:
            self._layers[l4_name] = l4

    def haslayer(self, name): return name in self._layers
    def __getitem__(self, name): return self._layers[name]
    def __len__(self): return self._size


def _packet(src, dst, proto, size, ttl, sport=0, dport=0, flags=0):
    ip = SimpleNamespace(src=src, dst=dst, proto=proto, ttl=ttl, ihl=5)
    if proto == 6:
        return _Packet(size, ip, "TCP", SimpleNamespace(sport=sport, dport=dport, flags=flags))
    if proto == 17:
        return _Packet(size, ip, "UDP", SimpleNamespace(sport=sport, dport=dport))
    return _Packet(size, ip)


def synth_packets(rng: np.random.Generator, n: int = WINDOW_PACKETS, anomaly: str | None = None,
                  start: float | None = None):
    """Return (packets, seconds, label) for one simulated window."""
    internal = [f"192.168.1.{h}" for h in rng.integers(10, 40, size=3)]
    servers = ["142.250.70.14", "151.101.1.69", "104.18.32.7", "8.8.8.8", "52.84.12.9"]
    packets, seconds = [], float(max(rng.normal(5.0, 1.0), 1.5))
    if anomaly == "portscan":
        src, dst, seconds = "192.168.1.66", "192.168.1.1", 1.5
        base = int(rng.integers(1000, 30000))
        for i in range(n):
            packets.append(_packet(src, dst, 6, 60, 64, 40000, base + i, flags=0x02))
    elif anomaly == "flood":
        seconds = 0.6
        for _ in range(n):
            src = f"198.51.{rng.integers(1, 250)}.{rng.integers(1, 250)}"
            packets.append(_packet(src, "192.168.1.27", 17, 1400, 50, int(rng.integers(1024, 65000)), 53))
    elif anomaly == "exfil":
        seconds = 2.0
        for _ in range(n):
            packets.append(_packet("192.168.1.23", "203.0.113.9", 6, 1500, 128, 51000, 4444, flags=0x10))
    elif anomaly == "synflood":
        seconds = 0.5
        for _ in range(n):
            src = f"203.0.{rng.integers(1, 250)}.{rng.integers(1, 250)}"
            packets.append(_packet(src, "192.168.1.5", 6, 60, 45, int(rng.integers(1024, 65000)), 443,
                                   flags=0x02))
    elif anomaly == "bruteforce":
        seconds = 3.0
        for i in range(n):
            flags = int(rng.choice([0x02, 0x10, 0x18, 0x11]))
            packets.append(_packet("203.0.113.77", "192.168.1.5", 6, int(rng.integers(60, 140)), 48,
                                   30000 + i // 3, 22, flags))
    elif anomaly == "sweep":
        seconds = 2.0
        for i in range(n):
            packets.append(_packet("192.168.1.66", f"192.168.1.{1 + i % 254}", 6, 60, 64,
                                   41000 + i, 445, flags=0x02))
    elif anomaly == "dnstunnel":
        seconds = 3.0
        for _ in range(n):
            packets.append(_packet("192.168.1.31", "8.8.8.8", 17, int(rng.integers(220, 300)), 64,
                                   int(rng.integers(40000, 60000)), 53))
    else:
        for _ in range(n):
            r = rng.random()
            src, dst = internal[int(rng.integers(0, 3))], servers[int(rng.integers(0, len(servers)))]
            if r < 0.70:
                size = int(rng.choice([66, 66, 66, 120, 560, 1400, 1480]))
                flags = int(rng.choice([0x10, 0x10, 0x10, 0x18, 0x02, 0x01]))
                dport = int(rng.choice([443, 443, 443, 80, 8443]))
                packets.append(_packet(src, dst, 6, size, 64, int(rng.integers(40000, 60000)), dport, flags))
            elif r < 0.95:
                packets.append(_packet(src, dst, 17, int(rng.integers(70, 300)), 64,
                                       int(rng.integers(40000, 60000)), int(rng.choice([53, 53, 443]))))
            else:
                packets.append(_packet(src, dst, 1, 84, 64))
    t0 = time.time() - seconds if start is None else start
    for i, p in enumerate(packets):
        p.time = t0 + seconds * i / max(len(packets) - 1, 1)
    return packets, seconds, (anomaly or "normal")


def synth_window(rng: np.random.Generator, n: int = WINDOW_PACKETS, anomaly: str | None = None):
    """Return (feature_vector, label). anomaly is None or one of SCENARIOS."""
    packets, seconds, label = synth_packets(rng, n, anomaly)
    return extract_window(packets, seconds), label


class DemoSource:
    kind = "demo"
    interface = "simulated traffic"

    def __init__(self, learn_pace: float = 0.03, monitor_pace: float = 2.0,
                 anomaly_rate: float = 0.05, seed: int | None = None, scenarios=SCENARIOS):
        self.learn_pace, self.monitor_pace, self.anomaly_rate = learn_pace, monitor_pace, anomaly_rate
        self.rng = np.random.default_rng(seed)
        self.scenarios = tuple(scenarios)
        self.fast = True          # the monitor flips this off after learning
        self.last_label = "normal"
        self.last_packets: list = []
        self.last_duration: float | None = None
        self._attack, self._attack_left = None, 0

    def open(self) -> "DemoSource":
        return self

    def windows(self, stop: threading.Event) -> Iterator[np.ndarray]:
        while not stop.is_set():
            kind = None
            if not self.fast:
                if self._attack_left <= 0 and self.rng.random() < self.anomaly_rate:
                    # Real attacks last a while: run this one for 2-5 consecutive windows.
                    self._attack = str(self.rng.choice(self.scenarios))
                    self._attack_left = int(self.rng.integers(2, 6))
                if self._attack_left > 0:
                    kind, self._attack_left = self._attack, self._attack_left - 1
            packets, seconds, self.last_label = synth_packets(self.rng, anomaly=kind)
            self.last_packets, self.last_duration = packets, seconds
            yield extract_window(packets, seconds)
            stop.wait(self.learn_pace if self.fast else self.monitor_pace)

    def close(self) -> None:
        pass
