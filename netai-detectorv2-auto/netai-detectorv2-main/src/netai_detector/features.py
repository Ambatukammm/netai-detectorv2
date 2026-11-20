"""Stable, versioned packet-window feature extraction.

The feature vector deliberately contains aggregate metadata only; packet payloads
are never stored. Feature order is part of the model format and must not change
without incrementing FEATURE_VERSION.
"""
from __future__ import annotations
from collections import Counter
from ipaddress import ip_address
import math
import numpy as np

# v2: fixed inbound/outbound ratios (v1 duplicated external_to_external) and per-window rates.
FEATURE_VERSION = 2
FEATURE_NAMES = [
    "packet_count", "mean_packet_bytes", "std_packet_bytes", "min_packet_bytes",
    "max_packet_bytes", "median_packet_bytes", "total_bytes", "packets_per_second",
    "bytes_per_second", "unique_sources", "unique_destinations", "unique_source_ports",
    "unique_destination_ports", "tcp_ratio", "udp_ratio", "icmp_ratio", "other_ratio",
    "syn_ratio", "ack_ratio", "rst_ratio", "fin_ratio", "inbound_ratio",
    "outbound_ratio", "internal_to_internal_ratio", "external_to_external_ratio",
    "mean_ttl", "std_ttl", "mean_ip_header_bytes", "dns_destination_ratio",
    "http_destination_ratio", "https_destination_ratio", "small_packet_ratio",
]

def _is_private(value: str) -> bool:
    try:
        return ip_address(value).is_private
    except ValueError:
        return False

def extract_window(packets: list, duration: float | None = None) -> np.ndarray:
    """Convert Scapy packets (or packet-like objects) into a numeric feature vector."""
    sizes, ttls, ip_headers = [], [], []
    srcs, dsts, sports, dports = set(), set(), set(), set()
    protocols = Counter()
    flags = Counter()
    directions = Counter()
    valid = 0

    for packet in packets:
        try:
            if packet.haslayer("IP"):
                ip = packet["IP"]
                src, dst = str(ip.src), str(ip.dst)
                proto = int(ip.proto)
                size = int(len(packet))
                valid += 1
                sizes.append(size)
                ttls.append(float(ip.ttl))
                ip_headers.append(float(ip.ihl or 5) * 4)
                srcs.add(src); dsts.add(dst)
                src_private, dst_private = _is_private(src), _is_private(dst)
                directions[(src_private, dst_private)] += 1
                if proto == 6 and packet.haslayer("TCP"):
                    tcp = packet["TCP"]
                    protocols["tcp"] += 1
                    sports.add(int(tcp.sport)); dports.add(int(tcp.dport))
                    flag_value = int(tcp.flags)
                    for bit, name in ((0x02,"syn"),(0x10,"ack"),(0x04,"rst"),(0x01,"fin")):
                        if flag_value & bit: flags[name] += 1
                elif proto == 17 and packet.haslayer("UDP"):
                    udp = packet["UDP"]
                    protocols["udp"] += 1
                    sports.add(int(udp.sport)); dports.add(int(udp.dport))
                elif proto == 1 or proto == 58:
                    protocols["icmp"] += 1
                else:
                    protocols["other"] += 1
        except (AttributeError, KeyError, TypeError, ValueError):
            continue

    if not valid:
        raise ValueError("No IPv4 packets in this feature window")

    count = float(valid)
    total_bytes = float(sum(sizes))
    seconds = max(float(duration or 1.0), 0.001)
    total_protocols = max(sum(protocols.values()), 1)
    internal_internal = directions[(True, True)]
    external_external = directions[(False, False)]
    ratios = lambda key: float(protocols[key]) / total_protocols
    vector = [
        count, float(np.mean(sizes)), float(np.std(sizes)), float(np.min(sizes)),
        float(np.max(sizes)), float(np.median(sizes)), total_bytes, count / seconds,
        total_bytes / seconds, len(srcs), len(dsts), len(sports), len(dports),
        ratios("tcp"), ratios("udp"), ratios("icmp"), ratios("other"),
        flags["syn"] / count, flags["ack"] / count, flags["rst"] / count,
        flags["fin"] / count, directions[(False, True)] / count,
        directions[(True, False)] / count, internal_internal / count,
        external_external / count, float(np.mean(ttls)), float(np.std(ttls)),
        float(np.mean(ip_headers)), len([p for p in dports if p == 53]) / max(len(dports), 1),
        len([p for p in dports if p == 80]) / max(len(dports), 1),
        len([p for p in dports if p == 443]) / max(len(dports), 1),
        sum(1 for size in sizes if size < 128) / count,
    ]
    result = np.asarray(vector, dtype=np.float32)
    return np.nan_to_num(result, nan=0.0, posinf=0.0, neginf=0.0)
