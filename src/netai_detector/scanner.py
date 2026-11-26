"""Active network discovery with nmap: find every device on your subnets and VLANs.

Where VLANs come from: a computer can only scan networks it can route to. NetAI suggests subnets
from four places:
  1. this computer's own network interfaces
  2. its routing table (routes to other VLANs through your router/firewall)
  3. private address ranges seen in traffic (e.g. on a SPAN port)
  4. subnets you type in yourself
VLANs your firewall blocks between can't be scanned from here: run NetAI on a machine (or a
trunk/VLAN interface) that can reach them, or allow it on the firewall.

Only scan networks you own or are authorised to scan. nmap must be installed (https://nmap.org).
"""
from __future__ import annotations
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from .config import NMAP_PATH, SCAN_MAX_MINUTES
from .forensics import is_internal
from .passive import RISKY, service_name

log = logging.getLogger("netai")
MIN_PREFIX = 16                # largest single target: a /16 (65,536 addresses)
MAX_TOTAL_HOSTS = 4 * 65536
WINDOWS_PATHS = [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"]
PROFILES = {
    "discover": {"label": "Find devices (fast, no port scan)", "args": ["-sn"]},
    "ports": {"label": "Find devices + 100 most common ports", "args": ["-F", "--open"]},
    "services": {"label": "Find devices + 1000 ports, service versions and OS guess (slow)",
                 "args": ["--top-ports", "1000", "-sV", "--version-light", "-O", "--osscan-limit", "--open"]},
    # Inventory scans: no device discovery (-Pn), straight to the ports of devices already known.
    "inventory": {"label": "Inventory: 1000 ports, service versions and OS", "inventory": True,
                  "args": ["-Pn", "--top-ports", "1000", "-sV", "--version-light", "-O", "--open"]},
    "inventory_full": {"label": "Inventory: all 65,535 ports, service versions and OS (very slow)",
                       "inventory": True,
                       "args": ["-Pn", "-p-", "-sV", "--version-light", "-O", "--open"]},
}
LIST_FILE_OVER = 20          # pass longer target lists to nmap in a file (-iL), not on the command line
_PROGRESS = re.compile(r"About ([\d.]+)% done")
_REMAINING = re.compile(r"\((\d+:\d{2}:\d{2}) remaining\)")
_PHASE = re.compile(r"^(.+?) Timing: About")


def _no_window() -> dict:
    return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)} if os.name == "nt" else {}


def find_nmap() -> str | None:
    if NMAP_PATH:
        return NMAP_PATH if Path(NMAP_PATH).exists() else shutil.which(NMAP_PATH)
    found = shutil.which("nmap")
    if found:
        return found
    if os.name == "nt":
        return next((p for p in WINDOWS_PATHS if Path(p).exists()), None)
    return None


# ------------------------------------------------------------------ subnets
def parse_iflist(text: str) -> tuple[list[dict], list[dict]]:
    """Parse `nmap --iflist` into (interfaces, routes). IPv4 only."""
    interfaces, routes, section = [], [], None
    for line in text.splitlines():
        if "INTERFACES" in line:
            section = "if"
            continue
        if "ROUTES" in line:
            section = "rt"
            continue
        if not line.strip() or line.startswith(("DEV", "DST/MASK")):
            continue
        if section == "if":
            m = re.match(r"^(\S+)\s+\((.*?)\)\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\s+(\S+)\s+(up|down)", line)
            if m:
                interfaces.append({"dev": m.group(1), "name": m.group(2), "ip": m.group(3),
                                   "prefix": int(m.group(4)), "type": m.group(5), "up": m.group(6) == "up"})
        elif section == "rt":
            parts = line.split()
            if parts and re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", parts[0]):
                gateway = next((p for p in parts[2:] if re.match(r"^\d+\.\d+\.\d+\.\d+$", p)), None)
                routes.append({"dest": parts[0], "dev": parts[1] if len(parts) > 1 else "", "gateway": gateway})
    return interfaces, routes


def _subnet_for(ip: str, prefix: int) -> str:
    if prefix < MIN_PREFIX:
        prefix = 24      # very large networks: offer the /24 around this computer instead
    return str(ip_network(f"{ip}/{prefix}", strict=False))


def candidate_subnets(nmap: str | None, store=None, iflist_text: str | None = None) -> list[dict]:
    """Subnets worth scanning, with where each suggestion came from."""
    found: dict[str, dict] = {}

    def add(cidr: str, source: str, detail: str = ""):
        net = ip_network(cidr, strict=False)
        if net.version != 4 or net.is_loopback or net.is_multicast or net.prefixlen < MIN_PREFIX \
                or net.prefixlen > 30:
            return
        key = str(net)
        if key not in found:
            found[key] = {"cidr": key, "source": source, "detail": detail,
                          "hosts": max(net.num_addresses - 2, 1), "internal": is_internal(str(net.network_address))}

    text = iflist_text
    if text is None and nmap:
        try:
            text = subprocess.run([nmap, "--iflist"], capture_output=True, text=True, timeout=20,
                                  **_no_window()).stdout
        except (OSError, subprocess.SubprocessError):
            text = None
    if text:
        interfaces, routes = parse_iflist(text)
        for itf in interfaces:
            if itf["up"] and itf["type"] != "loopback" and not itf["ip"].startswith(("127.", "169.254.")):
                add(_subnet_for(itf["ip"], itf["prefix"]), "this computer", f"{itf['name'] or itf['dev']} ({itf['ip']})")
        for rt in routes:
            dest = rt["dest"]
            if dest.startswith("0.0.0.0") or not is_internal(dest.split("/")[0]):
                continue
            add(dest, "route", f"via {rt['gateway']}" if rt["gateway"] else f"on {rt['dev']}")
    else:
        from .passive import local_ipv4s
        for ip in local_ipv4s():
            if not ip.startswith("127."):
                add(_subnet_for(ip, 24), "this computer", f"{ip} (guessed /24: install nmap for exact subnets)")
    if store is not None:
        covered = [ip_network(c) for c in found]
        seen: dict[str, int] = {}
        for dev in store.devices():
            ip = dev["ip"]
            if is_internal(ip) and not ip.startswith("127.") and not any(ip_address(ip) in n for n in covered):
                net = str(ip_network(f"{ip}/24", strict=False))
                seen[net] = seen.get(net, 0) + 1
        for net, count in sorted(seen.items()):
            add(net, "seen in traffic", f"{count} device(s) seen; mask guessed as /24")
        for cidr in store.get_setting("scan_subnets", []) or []:
            try:
                key = str(ip_network(cidr, strict=False))
                add(cidr, "added by you")
            except ValueError:
                continue
            if key in found:
                found[key]["custom"] = True
    return list(found.values())


def validate_targets(targets: list[str]) -> list[str]:
    """Normalise IPv4 addresses / CIDR ranges. Raises ValueError with a readable message."""
    clean, total = [], 0
    for raw in targets:
        value = str(raw).strip()
        if not value:
            continue
        if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?", value):
            raise ValueError(f"'{value}' is not an IPv4 address or range like 192.168.10.0/24")
        net = ip_network(value, strict=False)
        if net.prefixlen < MIN_PREFIX:
            raise ValueError(f"{value} is too large to scan in one go (largest is /{MIN_PREFIX}, 65,536 "
                             "addresses). Split it into smaller ranges.")
        if net.is_loopback or net.is_multicast or net.is_unspecified:
            raise ValueError(f"{value} can't be scanned")
        total += net.num_addresses
        if str(net) not in clean:
            clean.append(str(net))
    if not clean:
        raise ValueError("Choose at least one subnet or address to scan")
    if total > MAX_TOTAL_HOSTS:
        raise ValueError(f"That is {total:,} addresses; the limit per scan is {MAX_TOTAL_HOSTS:,}.")
    return clean


def build_command(nmap: str, targets: list[str], profile: str, xml_path: str,
                  exclude: list[str] | None = None) -> list[str]:
    if profile not in PROFILES:
        raise ValueError(f"Unknown scan type '{profile}'")
    if PROFILES[profile].get("inventory") and any(not t.endswith("/32") for t in targets):
        raise ValueError("Inventory scans take individual devices, not whole subnets "
                         "(use 'Find devices' scans for subnets).")
    cmd = [nmap, *PROFILES[profile]["args"], "-T4", "--stats-every", "5s", "-oX", xml_path]
    if exclude:
        cmd += ["--exclude", ",".join(validate_targets(exclude))]
    if len(targets) > LIST_FILE_OVER:
        # Long lists (e.g. a whole inventory) go in a file: Windows limits command lines to 8,191 chars.
        list_path = os.path.join(os.path.dirname(xml_path) or ".", "targets.txt")
        Path(list_path).write_text("\n".join(t[:-3] if t.endswith("/32") else t for t in targets) + "\n")
        return cmd + ["-iL", list_path]
    return cmd + targets


# ------------------------------------------------------------------ results
def parse_nmap_xml(text: str) -> list[dict]:
    """Hosts that were up, with addresses, names, vendor, OS guess and open ports.
    If nmap was stopped part-way, its file is cut off: every host it had finished is still kept."""
    try:
        host_elements = ET.fromstring(text).findall("host")
    except ET.ParseError:
        host_elements = []
        for block in re.findall(r"<host[\s>].*?</host>", text, re.S):
            try:
                host_elements.append(ET.fromstring(block))
            except ET.ParseError:
                continue
    hosts = []
    for host in host_elements:
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        item = {"ip": None, "mac": None, "vendor": None, "hostname": None, "os": None, "ports": {},
                "assumed": status is not None and status.get("reason") == "user-set"}
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                item["ip"] = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                item["mac"] = addr.get("addr")
                item["vendor"] = addr.get("vendor")
        if not item["ip"]:
            continue
        name = host.find("hostnames/hostname")
        if name is not None:
            item["hostname"] = name.get("name")
        osmatch = host.find("os/osmatch")
        if osmatch is not None:
            item["os"] = f"{osmatch.get('name')} ({osmatch.get('accuracy')}%)"
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") not in ("open", "open|filtered"):
                continue
            number = int(port.get("portid"))
            svc = port.find("service")
            product = " ".join(filter(None, [svc.get("product"), svc.get("version")])) if svc is not None else ""
            item["ports"][f"{port.get('protocol')}/{number}"] = {
                "service": (svc.get("name") if svc is not None and svc.get("name") else service_name(number)),
                "product": product or None, "state": state.get("state"), "source": "nmap",
                "risk": RISKY.get(number)}
        # With -Pn nmap calls every address "up" ("user-set"). Only count a host as answering if it
        # showed something: an open port, a MAC address or an OS fingerprint.
        if item["assumed"] and not (item["ports"] or item["mac"] or item["os"]):
            continue
        hosts.append(item)
    return hosts


def describe_targets(targets: list[str], show: int = 3) -> str:
    """Short, readable description of what a scan covered: '192.168.1.0/24' or
    '53 devices (192.168.1.5, 192.168.1.9, 192.168.1.10 and 50 more)'."""
    items = [t[:-3] if t.endswith("/32") else t for t in targets]
    if len(items) <= show:
        return ", ".join(items)
    singles = all(t.endswith("/32") for t in targets)
    what = f"{len(items)} devices" if singles else f"{len(items)} networks/devices"
    return f"{what} ({', '.join(items[:show])} and {len(items) - show} more)"


def compare_scans(store, job_id: int) -> dict:
    """What changed between this scan and the previous completed scan of overlapping networks.
    Only addresses inside this scan's targets are compared."""
    job = store.scan_job(job_id)
    if not job:
        raise ValueError("No such scan")
    nets = [ip_network(t) for t in job["targets"]]
    inside = lambda ip: any(ip_address(ip) in n for n in nets)   # noqa: E731
    current = {h["ip"]: h for h in store.scan_results(job_id)}
    previous_job = None
    for other in store.scan_jobs(200):
        if other["id"] >= job_id or other["status"] != "done":
            continue
        if any(ip_network(t).overlaps(n) for t in other["targets"] for n in nets):
            previous_job = other
            break
    diff = {"job": job, "previous_job": previous_job, "hosts": list(current.values()),
            "new_hosts": [], "gone_hosts": [], "opened": [], "closed": []}
    if not previous_job:
        return diff
    before = {h["ip"]: h for h in store.scan_results(previous_job["id"]) if inside(h["ip"])}
    # Port comparisons only make sense if both scans looked at ports.
    ports_compared = job["profile"] != "discover" and previous_job["profile"] != "discover"
    for ip, h in current.items():
        if ip not in before:
            diff["new_hosts"].append(h)
        elif ports_compared:
            old = before[ip]["ports"]
            diff["opened"] += [{"ip": ip, "port": k, **v} for k, v in h["ports"].items() if k not in old]
            diff["closed"] += [{"ip": ip, "port": k, **v} for k, v in old.items() if k not in h["ports"]]
    diff["gone_hosts"] = [h for ip, h in before.items() if ip not in current]
    diff["ports_compared"] = ports_compared
    return diff


def results_csv(hosts: list[dict]) -> str:
    import csv
    import io
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["ip", "hostname", "mac", "vendor", "os", "port", "protocol", "service", "product"])
    for h in hosts:
        ports = h["ports"] or {"": {}}
        for key, info in ports.items():
            proto, _, port = key.partition("/")
            writer.writerow([h["ip"], h.get("hostname") or "", h.get("mac") or "", h.get("vendor") or "",
                             h.get("os") or "", port, proto, info.get("service") or "", info.get("product") or ""])
    return out.getvalue()


# ------------------------------------------------------------------ background jobs
class ScanManager:
    def __init__(self, store, devices=None, nmap: str | None = None, max_minutes: int = SCAN_MAX_MINUTES,
                 find=find_nmap):
        self.store, self.devices = store, devices
        self._nmap_override = nmap
        self._find = find
        self.max_seconds = max_minutes * 60 if max_minutes else None
        self._lock = threading.Lock()
        self._proc: subprocess.Popen | None = None
        self._job: dict | None = None
        self._cancelled = False
        self._cache: dict[str, tuple[float, object]] = {}
        self.on_finish = None          # optional callback(job) when a scan ends (e.g. email a report)

    def _cached(self, key: str, seconds: float, make):
        hit = self._cache.get(key)
        if hit and time.monotonic() - hit[0] < seconds:
            return hit[1]
        value = make()
        self._cache[key] = (time.monotonic(), value)
        return value

    @property
    def nmap(self) -> str | None:
        return self._nmap_override or self._find()

    def available(self) -> dict:
        return self._cached("available", 60, self._available)

    def _available(self) -> dict:
        path = self.nmap
        info = {"installed": bool(path), "path": path, "version": None}
        if not path:
            info["hint"] = ("nmap is not installed. Download it free from https://nmap.org/download "
                            "(on Windows the installer also adds Npcap, which improves live capture), "
                            "then restart NetAI.")
            return info
        try:
            out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10,
                                 **_no_window()).stdout
            m = re.search(r"Nmap version (\S+)", out)
            info["version"] = m.group(1) if m else None
        except (OSError, subprocess.SubprocessError):
            pass
        return info

    def subnets(self) -> list[dict]:
        nmap = self.nmap

        def iflist():
            if not nmap:
                return None
            try:
                return subprocess.run([nmap, "--iflist"], capture_output=True, text=True, timeout=20,
                                      **_no_window()).stdout
            except (OSError, subprocess.SubprocessError):
                return None
        text = self._cached("iflist", 60, iflist)
        return candidate_subnets(nmap if text is None else None, self.store, iflist_text=text)

    def start(self, targets: list[str], profile: str = "discover", exclude: list[str] | None = None,
              authorised: bool = False) -> dict:
        if not authorised:
            raise PermissionError("Confirm that you own these networks or are authorised to scan them.")
        nmap = self.nmap
        if not nmap:
            raise RuntimeError(self.available()["hint"])
        clean = validate_targets(targets)
        with self._lock:
            if self._job and self._job["status"] == "running":
                raise RuntimeError("A scan is already running. Wait for it or cancel it first.")
            folder = tempfile.mkdtemp(prefix="netai-scan-")
            xml_path = os.path.join(folder, "scan.xml")
            cmd = build_command(nmap, clean, profile, xml_path, exclude)
            job_id = self.store.add_scan_job(profile, clean)
            self._cancelled = False
            self._job = {"id": job_id, "profile": profile, "targets": clean, "status": "running",
                         "started_iso": datetime.now(timezone.utc).isoformat(),
                         "progress": 0.0, "phase": "Starting nmap…", "remaining": None, "started": time.time(),
                         "log": [], "hosts_up": None, "message": ""}
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                    errors="replace", **_no_window())
            self._proc = proc
        threading.Thread(target=self._watch, args=(proc, xml_path, folder), name="netai-scan",
                         daemon=True).start()
        return self.status()["current"]

    def import_results(self, command: str, xml_text: str, targets: list[str]) -> str:
        """Add an nmap run from the terminal to the inventory and scan history (Aya reviews it).
        Returns a short note for the terminal."""
        hosts = parse_nmap_xml(xml_text)
        if not targets:
            targets = sorted({h["ip"] + "/32" for h in hosts})
        if not targets:
            return "nmap found no devices, so nothing was added to the inventory."
        profile = "discover" if re.search(r"(^|\s)-sn\b", command) else "terminal"
        job_id = self.store.add_scan_job(profile, targets)
        self._save(hosts, targets, complete=False)
        if hosts:
            self.store.save_scan_results(job_id, hosts)
        msg = f"Found {len(hosts)} device(s) (from the terminal)."
        self.store.finish_scan_job(job_id, "done", len(hosts), msg)
        if self.on_finish:
            job = {"id": job_id, "status": "done", "targets": targets, "profile": profile,
                   "hosts_up": len(hosts), "message": msg}
            threading.Thread(target=self.on_finish, args=(job,), name="netai-review", daemon=True).start()
        return (f"{len(hosts)} device(s) added to the inventory and scan history; "
                "Aya is reviewing the scan (Network & devices → Scan history).")

    def cancel(self) -> bool:
        with self._lock:
            proc = self._proc
            if not proc or proc.poll() is not None:
                return False
            self._cancelled = True
        proc.terminate()
        return True

    def status(self) -> dict:
        with self._lock:
            job = dict(self._job) if self._job else None
        if job:
            job["log"] = job["log"][-8:]
            job["elapsed"] = round(time.time() - job.pop("started"), 1)
            job.pop("started_iso", None)
        return {"current": job, "jobs": self.store.scan_jobs(10),
                "profiles": {k: v["label"] for k, v in PROFILES.items() if not v.get("inventory")},
                "inventory_profiles": {k: v["label"] for k, v in PROFILES.items() if v.get("inventory")},
                "time_limit_minutes": self.max_seconds // 60 if self.max_seconds else None}

    def _update(self, **changes) -> None:
        with self._lock:
            if self._job:
                self._job.update(changes)

    def _watch(self, proc: subprocess.Popen, xml_path: str, folder: str) -> None:
        limit = self.max_seconds            # None = no time limit (the default)
        deadline = time.time() + limit if limit else None
        timer = None
        if limit:
            timer = threading.Timer(limit, lambda: proc.poll() is None and proc.terminate())
            timer.daemon = True
            timer.start()
        try:
            for line in proc.stdout:
                line = line.rstrip()
                if not line:
                    continue
                m = _PROGRESS.search(line)
                if m:
                    phase = _PHASE.match(line)
                    left = _REMAINING.search(line)
                    self._update(progress=float(m.group(1)), phase=phase.group(1) if phase else "Scanning",
                                 remaining=left.group(1) if left else None)
                with self._lock:
                    if self._job:
                        self._job["log"] = (self._job["log"] + [line[:200]])[-50:]
            code = proc.wait()
        finally:
            if timer:
                timer.cancel()
        job = self._job or {}
        hosts: list[dict] = []
        try:
            text = Path(xml_path).read_text(encoding="utf-8", errors="replace") if Path(xml_path).exists() else ""
            if text.strip():
                hosts = parse_nmap_xml(text)
        except (ET.ParseError, OSError):
            hosts = []
        finally:
            shutil.rmtree(folder, ignore_errors=True)
        # Inventory scans skip discovery, so a silent device there proves nothing: never mark it offline.
        inventory = PROFILES.get(job.get("profile"), {}).get("inventory", False)
        self._save(hosts, job.get("targets", []), complete=(code == 0 and not self._cancelled and not inventory),
                   since=job.get("started_iso"))
        if hosts and job.get("id"):
            self.store.save_scan_results(job["id"], hosts)
        if self._cancelled:
            status, msg = "cancelled", f"Cancelled. Kept the {len(hosts)} device(s) finished before stopping."
        elif deadline and time.time() >= deadline:
            status, msg = "stopped", (f"Stopped after the {limit // 60}-minute limit (NETAI_SCAN_MAX_MINUTES). "
                                      f"Kept the {len(hosts)} device(s) finished by then.")
        elif code != 0:
            tail = " ".join(job.get("log", [])[-2:])
            status, msg = "failed", f"nmap exited with code {code}. {tail}"[:300]
        else:
            status, msg = "done", f"Found {len(hosts)} device(s)."
        self.store.finish_scan_job(job.get("id", 0), status, len(hosts), msg)
        self._update(status=status, progress=100.0 if status == "done" else job.get("progress", 0),
                     phase=msg, hosts_up=len(hosts), message=msg)
        with self._lock:
            self._proc = None
        if self.on_finish:
            try:
                self.on_finish({"id": job.get("id"), "status": status, "targets": job.get("targets", []),
                                "profile": job.get("profile"), "hosts_up": len(hosts), "message": msg})
            except Exception as exc:
                log.warning("Scan finish hook failed: %s", exc)

    def _save(self, hosts: list[dict], targets: list[str], complete: bool, since: str | None = None) -> None:
        now = datetime.now(timezone.utc).isoformat()
        found = set()
        for h in hosts:
            found.add(h["ip"])
            self.store.upsert_device(h["ip"], seen_by="nmap", ports=h["ports"], up=True, when=now,
                                     hostname=h["hostname"], mac=h["mac"], vendor=h["vendor"], os=h["os"])
        if complete and targets:
            nets = [ip_network(t) for t in targets]
            for dev in self.store.devices():
                # Offline = didn't answer AND hasn't been seen in traffic since the scan started.
                # (Many PCs ignore scans: firewalls drop probes from other subnets.)
                if dev["ip"] not in found and dev.get("up") is not False and \
                        (since is None or dev["last_seen"] < since) and \
                        any(ip_address(dev["ip"]) in n for n in nets):
                    self.store.upsert_device(dev["ip"], up=False)
        if self.devices is not None and found:
            self.devices.want(found)
