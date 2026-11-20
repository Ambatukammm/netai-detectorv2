"""Simulated traffic, used ONLY when live capture is unavailable and no real model exists.

It lets a first-time user see the whole learn -> train -> monitor loop working immediately. Every
event it produces is tagged source="demo" and the dashboard shows a banner while it is active.
Packets are synthetic objects that go through the real feature extractor.
"""
from __future__ import annotations
import threading
from types import SimpleNamespace
from typing import Iterator
import numpy as np
from .config import WINDOW_PACKETS
from .features import extract_window


class _Packet:
    def __init__(self, size: int, ip, l4_name: str | None = None, l4=None):
        self._size = size
        self._layers = {"IP": ip}
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


def synth_window(rng: np.random.Generator, n: int = WINDOW_PACKETS, anomaly: str | None = None):
    """Return (feature_vector, label). anomaly in {None, 'portscan', 'flood', 'exfil'}."""
    internal = [f"192.168.1.{h}" for h in rng.integers(10, 40, size=3)]
    servers = ["142.250.70.14", "151.101.1.69", "104.18.32.7", "8.8.8.8", "52.84.12.9"]
    packets, seconds = [], float(max(rng.normal(5.0, 1.0), 1.5))
    if anomaly == "portscan":
        src, dst, seconds = internal[0], servers[0], 1.5
        base = int(rng.integers(1000, 30000))
        for i in range(n):
            packets.append(_packet(src, dst, 6, 60, 64, 40000, base + i, flags=0x02))
    elif anomaly == "flood":
        seconds = 0.6
        for _ in range(n):
            src = f"{rng.integers(20, 220)}.{rng.integers(1, 250)}.{rng.integers(1, 250)}.9"
            packets.append(_packet(src, internal[0], 17, 1400, 50, int(rng.integers(1024, 65000)), 53))
    elif anomaly == "exfil":
        seconds = 2.0
        for _ in range(n):
            packets.append(_packet(internal[1], "185.220.101.4", 6, 1500, 128, 51000, 4444, flags=0x10))
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
    return extract_window(packets, seconds), (anomaly or "normal")


class DemoSource:
    kind = "demo"
    interface = "simulated traffic"

    def __init__(self, learn_pace: float = 0.03, monitor_pace: float = 2.0,
                 anomaly_rate: float = 0.05, seed: int | None = None):
        self.learn_pace, self.monitor_pace, self.anomaly_rate = learn_pace, monitor_pace, anomaly_rate
        self.rng = np.random.default_rng(seed)
        self.fast = True          # the monitor flips this off after learning
        self.last_label = "normal"

    def open(self) -> "DemoSource":
        return self

    def windows(self, stop: threading.Event) -> Iterator[np.ndarray]:
        while not stop.is_set():
            kind = None
            if not self.fast and self.rng.random() < self.anomaly_rate:
                kind = str(self.rng.choice(["portscan", "flood", "exfil"]))
            vector, self.last_label = synth_window(self.rng, anomaly=kind)
            yield vector
            stop.wait(self.learn_pace if self.fast else self.monitor_pace)

    def close(self) -> None:
        pass
