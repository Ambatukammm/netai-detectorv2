import socket
import struct
import threading
import time
import numpy as np
import pytest
from netai_detector.capture import CaptureUnavailable, RawSocketSource, parse_ipv4
from netai_detector.features import FEATURE_NAMES, extract_window


def ipv4(proto, payload, src="192.168.1.10", dst="8.8.8.8", ttl=64):
    total = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, ttl, proto, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    return header + payload


def tcp(sport, dport, flags):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 1000, 0, 0) + b"x" * 40


def test_parse_tcp_udp_icmp_and_garbage():
    t = parse_ipv4(ipv4(6, tcp(51000, 443, 0x02)))
    assert (t["IP"].src, t["IP"].dst, t["IP"].ttl) == ("192.168.1.10", "8.8.8.8", 64)
    assert (t["TCP"].sport, t["TCP"].dport, t["TCP"].flags) == (51000, 443, 2) and len(t) == 20 + 60
    u = parse_ipv4(ipv4(17, struct.pack("!HHHH", 5353, 53, 8, 0)))
    assert u["UDP"].dport == 53
    assert not parse_ipv4(ipv4(1, b"\x08\x00" + b"\0" * 6)).haslayer("TCP")
    assert parse_ipv4(b"\x60" + b"\0" * 39) is None      # IPv6
    assert parse_ipv4(b"short") is None


def test_parsed_packets_feed_the_feature_extractor():
    pkts = [parse_ipv4(ipv4(6, tcp(50000 + i, 443, 0x10)), ts=100 + i * 0.1) for i in range(20)]
    vec = extract_window(pkts, 2.0)
    named = dict(zip(FEATURE_NAMES, vec))
    assert vec.shape == (len(FEATURE_NAMES),) and named["tcp_ratio"] == 1.0
    assert named["outbound_ratio"] == 1.0 and named["https_destination_ratio"] == 1.0


def test_real_loopback_capture_if_sandbox_allows():
    if not hasattr(socket, "AF_PACKET"):
        pytest.skip("Linux only")
    try:
        source = RawSocketSource("lo").open()
    except CaptureUnavailable:
        pytest.skip("no raw-socket permission here")
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(60):
            client.sendto(b"hello" * 10, ("127.0.0.1", port))
        time.sleep(0.5)
        stop = threading.Event()
        windows = []

        def collect():
            for w in source.windows(stop):
                windows.append(w)
                stop.set()
        thread = threading.Thread(target=collect)
        thread.start()
        thread.join(10)
        stop.set()
        assert windows, "no window captured from real packets"
        named = dict(zip(FEATURE_NAMES, windows[0]))
        assert named["udp_ratio"] > 0.9 and named["packet_count"] >= 10
    finally:
        source.close()
