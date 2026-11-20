"""Who and where: per-window culprit summaries and plain-English attack-type hints.

Runs only on windows the model has flagged. It reads packet *headers* (addresses, ports, protocol,
TCP flags, sizes) and never message contents. The hints are simple, explainable rules on those
numbers: they suggest what an anomaly looks like, they are not a verdict.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network

AUTH_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP",
              445: "SMB", 1433: "MS SQL", 3306: "MySQL", 3389: "Remote Desktop (RDP)",
              5432: "PostgreSQL", 5900: "VNC"}
WELL_KNOWN = {**AUTH_PORTS, 53: "DNS", 80: "HTTP", 443: "HTTPS", 123: "NTP", 8080: "HTTP-alt",
              8443: "HTTPS-alt", 4444: "4444 (often used by remote-access tools)"}
PROTO_NAMES = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}

ATTACK_TITLES = {
    "port_scan": "Port scan",
    "host_sweep": "Network sweep (host discovery)",
    "syn_flood": "SYN flood",
    "udp_flood": "UDP flood / DDoS",
    "icmp_flood": "ICMP (ping) flood",
    "brute_force": "Login brute-force",
    "exfiltration": "Possible data exfiltration",
    "dns_tunnelling": "Possible DNS tunnelling",
    "unknown": "Unusual traffic (no known pattern)",
}
_CONF_RANK = {"low": 0, "medium": 1, "high": 2}


_INTERNAL_NETS = [ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "100.64.0.0/10", "fc00::/7", "fe80::/10", "::1/128")]


def is_internal(ip: str) -> bool:
    """True for addresses on a local/private network (RFC 1918, loopback, link-local, CGNAT)."""
    try:
        addr = ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _INTERNAL_NETS if net.version == addr.version)


def port_name(port: int) -> str:
    name = WELL_KNOWN.get(port)
    return f"{port} ({name})" if name and not name.startswith(str(port)) else str(port)


def packet_fields(packet):
    """(src, dst, proto, size, sport, dport, tcp_flags) for an IPv4 packet, else None."""
    try:
        if not packet.haslayer("IP"):
            return None
        ip = packet["IP"]
        proto = int(ip.proto)
        sport = dport = flags = 0
        if proto == 6 and packet.haslayer("TCP"):
            tcp = packet["TCP"]
            sport, dport, flags = int(tcp.sport), int(tcp.dport), int(tcp.flags)
        elif proto == 17 and packet.haslayer("UDP"):
            udp = packet["UDP"]
            sport, dport = int(udp.sport), int(udp.dport)
        return str(ip.src), str(ip.dst), proto, int(len(packet)), sport, dport, flags
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


@dataclass
class _Host:
    packets: int = 0
    bytes: int = 0
    peers: set = field(default_factory=set)
    dports: set = field(default_factory=set)
    sports: set = field(default_factory=set)
    syn_only: int = 0
    rst: int = 0
    tcp: int = 0
    udp: int = 0
    icmp: int = 0
    dns: int = 0
    dns_bytes: int = 0


@dataclass
class _Flow:
    packets: int = 0
    bytes: int = 0
    dports: Counter = field(default_factory=Counter)
    sports: set = field(default_factory=set)
    syn_only: int = 0


class WindowAnalysis:
    """Header statistics of one traffic window, by source, destination and flow."""

    def __init__(self, packets: list, duration: float | None = None):
        self.duration = max(float(duration or 1.0), 0.001)
        self.total_packets = 0
        self.total_bytes = 0
        self.protocols: Counter = Counter()
        self.sources: dict[str, _Host] = defaultdict(_Host)
        self.destinations: dict[str, _Host] = defaultdict(_Host)
        self.flows: dict[tuple, _Flow] = defaultdict(_Flow)      # (src, dst, proto)
        self.dst_ports: Counter = Counter()                      # (proto, port)
        self.first_ts = self.last_ts = None
        for packet in packets:
            fields = packet_fields(packet)
            if fields is None:
                continue
            src, dst, proto, size, sport, dport, flags = fields
            ts = getattr(packet, "time", None)
            try:
                ts = float(ts) if ts is not None else None
            except (TypeError, ValueError):
                ts = None
            if ts is not None:
                self.first_ts = ts if self.first_ts is None else min(self.first_ts, ts)
                self.last_ts = ts if self.last_ts is None else max(self.last_ts, ts)
            pname = PROTO_NAMES.get(proto, "other")
            self.total_packets += 1
            self.total_bytes += size
            self.protocols[pname] += 1
            syn_only = proto == 6 and (flags & 0x02) and not (flags & 0x10)
            s, d, f = self.sources[src], self.destinations[dst], self.flows[(src, dst, pname)]
            for host, peer in ((s, dst), (d, src)):
                host.packets += 1
                host.bytes += size
                host.peers.add(peer)
                if pname in ("tcp", "udp", "icmp"):
                    setattr(host, pname, getattr(host, pname) + 1)
                if syn_only:
                    host.syn_only += 1
                if proto == 6 and flags & 0x04:
                    host.rst += 1
            if dport:
                s.dports.add(dport); d.dports.add(dport)
                s.sports.add(sport)
                self.dst_ports[(pname, dport)] += 1
                f.dports[dport] += 1
                f.sports.add(sport)
            if dport == 53:
                s.dns += 1
                s.dns_bytes += size
            f.packets += 1
            f.bytes += size
            if syn_only:
                f.syn_only += 1

    # ------------------------------------------------------------------ JSON summary
    def summary(self, top: int = 5) -> dict:
        """Compact, JSON-ready culprit summary. Metadata only."""
        def host_rows(table, peers_key):
            rows = sorted(table.items(), key=lambda kv: (-kv[1].packets, -kv[1].bytes))[:top]
            return [{"ip": ip, "internal": is_internal(ip), "packets": h.packets, "bytes": h.bytes,
                     peers_key: len(h.peers), "distinct_ports": len(h.dports)} for ip, h in rows]

        flows = sorted(self.flows.items(), key=lambda kv: (-kv[1].packets, -kv[1].bytes))[:top]
        return {
            "packets": self.total_packets,
            "bytes": self.total_bytes,
            "seconds": round(self.duration, 2),
            "protocols": dict(self.protocols),
            "top_sources": host_rows(self.sources, "destinations"),
            "top_destinations": host_rows(self.destinations, "sources"),
            "top_flows": [{
                "src": src, "dst": dst, "proto": proto, "packets": f.packets, "bytes": f.bytes,
                "distinct_dst_ports": len(f.dports),
                "top_dst_ports": [p for p, _ in f.dports.most_common(5)],
                "syn_only_ratio": round(f.syn_only / f.packets, 3) if f.packets else 0.0,
            } for (src, dst, proto), f in flows],
            "top_dst_ports": [{"proto": proto, "port": port, "packets": n}
                              for (proto, port), n in self.dst_ports.most_common(top)],
        }

    # ------------------------------------------------------------------ attack-type hints
    def hints(self) -> list[dict]:
        """Rule-based guesses, strongest first. Each: type, title, confidence, evidence, hosts."""
        n = self.total_packets
        if not n:
            return []
        found: list[dict] = []

        def add(kind, confidence, evidence, attacker=None, target=None, ports=None, sources=None):
            found.append({"type": kind, "title": ATTACK_TITLES[kind], "confidence": confidence,
                          "evidence": evidence, "attacker": attacker, "target": target,
                          "ports": sorted(ports or [])[:10], "attacker_count": sources})

        top_src, s = max(self.sources.items(), key=lambda kv: kv[1].packets)
        top_dst, d = max(self.destinations.items(), key=lambda kv: kv[1].packets)
        src_share, dst_share = s.packets / n, d.packets / n

        # Port scan: one host probing many ports on one target.
        for (src, dst, proto), f in self.flows.items():
            if proto == "tcp" or proto == "udp":
                if len(f.dports) >= 15 and f.packets / n >= 0.4:
                    syn = f.syn_only / f.packets
                    conf = "high" if (proto == "tcp" and syn >= 0.6) or len(f.dports) >= 40 else "medium"
                    add("port_scan", conf,
                        f"{src} → {dst}: {len(f.dports)} different {proto.upper()} ports in "
                        f"{self.duration:.1f}s" + (f", {syn:.0%} connection attempts (SYN)" if proto == "tcp" else ""),
                        src, dst, list(f.dports))

        # Sweep: one host contacting many hosts on a handful of ports.
        if len(s.peers) >= 15 and len(s.dports) <= 3 and src_share >= 0.5:
            add("host_sweep", "high" if len(s.peers) >= 30 else "medium",
                f"{top_src} contacted {len(s.peers)} different hosts on port(s) "
                f"{', '.join(map(str, sorted(s.dports))) or 'ICMP'}", top_src, None, list(s.dports))

        # Floods: one destination receiving most of the traffic.
        if dst_share >= 0.5:
            many = len(d.peers) >= 10
            who = f"{len(d.peers)} different sources" if many else top_src
            rate = d.packets / self.duration
            if d.tcp / d.packets >= 0.7 and d.syn_only / d.packets >= 0.6 and len(d.dports) <= 3:
                add("syn_flood", "high" if rate >= 100 or many else "medium",
                    f"{d.syn_only} of {d.packets} packets to {top_dst} were connection attempts (SYN) "
                    f"with no follow-up, from {who}, {rate:.0f} packets/s",
                    None if many else top_src, top_dst, list(d.dports), len(d.peers))
            elif d.udp / d.packets >= 0.7 and (many or rate >= 200):
                add("udp_flood", "high" if many and rate >= 100 else "medium",
                    f"{d.udp} UDP packets to {top_dst} from {who}, {rate:.0f} packets/s, "
                    f"{d.bytes / self.duration / 1e6 * 8:.1f} Mbit/s",
                    None if many else top_src, top_dst, list(d.dports), len(d.peers))
            elif d.icmp / d.packets >= 0.6 and (many or rate >= 50):
                add("icmp_flood", "medium", f"{d.icmp} ICMP packets to {top_dst} from {who}, "
                    f"{rate:.0f} packets/s", None if many else top_src, top_dst, [], len(d.peers))

        # Brute force: repeated new connections to a login service.
        for (src, dst, proto), f in self.flows.items():
            if proto != "tcp":
                continue
            port, hits = (f.dports.most_common(1) or [(0, 0)])[0]
            if port in AUTH_PORTS and hits / n >= 0.35 and len(f.sports) >= 8:
                add("brute_force", "high" if len(f.sports) >= 20 else "medium",
                    f"{src} opened {len(f.sports)} separate connections to {AUTH_PORTS[port]} "
                    f"(port {port}) on {dst}", src, dst, [port])

        # Exfiltration: an internal host pushing most of the bytes to one outside address.
        for (src, dst, _proto), f in self.flows.items():
            if is_internal(src) and not is_internal(dst) and self.total_bytes and \
                    f.bytes / self.total_bytes >= 0.6 and f.bytes >= 50_000 and f.bytes / f.packets >= 700:
                odd_port = not any(p in (80, 443, 8443) for p in f.dports)
                add("exfiltration", "high" if odd_port or f.bytes >= 500_000 else "medium",
                    f"{src} (inside) sent {f.bytes / 1e6:.2f} MB to {dst} (outside) in {self.duration:.1f}s, "
                    f"port(s) {', '.join(map(str, list(f.dports)[:3])) or '?'}"
                    + (" — not a normal web port" if odd_port else ""),
                    src, dst, list(f.dports))

        # DNS tunnelling: lots of unusually large DNS traffic from one host.
        for ip, h in self.sources.items():
            if h.dns >= 20 and h.dns / n >= 0.4:
                mean = h.dns_bytes / h.dns
                if mean >= 160:
                    resolvers = sorted(self.flows_from(ip, port=53))
                    add("dns_tunnelling", "medium" if mean < 250 else "high",
                        f"{ip} sent {h.dns} DNS packets averaging {mean:.0f} bytes (normal lookups are "
                        f"usually under 100) to {', '.join(resolvers[:3])}",
                        ip, resolvers[0] if resolvers else None, [53])

        found.sort(key=lambda h: -_CONF_RANK[h["confidence"]])
        # Keep one hint per type (strongest) so the list stays readable.
        seen, unique = set(), []
        for h in found:
            if h["type"] not in seen:
                seen.add(h["type"])
                unique.append(h)
        return unique

    def flows_from(self, src: str, port: int) -> set[str]:
        return {dst for (s, dst, _), f in self.flows.items() if s == src and port in f.dports}


def analyse(packets: list, duration: float | None = None) -> dict:
    """Culprit summary plus attack hints for one window (JSON-ready)."""
    win = WindowAnalysis(packets, duration)
    hints = win.hints()
    return {"culprits": win.summary(), "hints": hints}


def unknown_hint(top_features: list[dict] | None) -> dict:
    def z(v):
        return (">+99σ" if v > 0 else "<-99σ") if abs(v) > 99 else f"{'+' if v > 0 else ''}{v}σ"
    why = ", ".join(f"{f['feature']} {z(f['z'])}" for f in (top_features or []))
    return {"type": "unknown", "title": ATTACK_TITLES["unknown"], "confidence": "low",
            "evidence": f"Traffic was statistically unusual ({why or 'several features'}) but matched "
                        "no known attack pattern. It may be legitimate (an update, a backup, a new app).",
            "attacker": None, "target": None, "ports": [], "attacker_count": None}
