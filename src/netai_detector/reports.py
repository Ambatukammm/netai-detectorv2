"""Reports: plain-English findings for the device inventory, nmap scans, SPAN discovery and incidents.

Reports are generated locally from NetAI's own data. Each one has a health grade, prioritised
findings with a recommended action, what changed since the previous report, and detail tables.
Aya, NetAI's local AI analyst, adds her review to every report (see aya.py). Rendered as HTML (dashboard, email,
download) and plain text.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from html import escape
import json
from .devices import display_name
from .forensics import ATTACK_TITLES, is_internal
from .passive import RISKY, service_name

KINDS = {"full": "Full network report", "network": "Network & device inventory report",
         "span": "SPAN discovery report", "incidents": "Incident report"}
SCAN_TITLE = "Scan review"
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
# Points lost per severity: (first finding, each additional, maximum for that severity).
SEV_COST = {"high": (20, 10, 60), "medium": (8, 4, 25), "low": (2, 2, 10), "info": (0, 0, 0)}
# How much an internal service matters, judged for a business LAN (not the internet):
#   high   = no login or plaintext logins: easy to abuse by anyone already inside
#   medium = worth fixing soon; Remote Desktop becomes medium when it's on many machines
#   low    = normal on servers but should be limited to who needs it
#   info   = standard Windows sharing/printing: noted with advice, no penalty
SERVICE_SEVERITY = {23: "high", 69: "high", 5900: "high", 6379: "high", 27017: "high",
                    21: "medium", 1883: "medium",
                    3389: "low", 1433: "low", 3306: "low", 5432: "low", 1521: "low", 161: "low",
                    135: "info", 139: "info", 445: "info", 9100: "info"}
NORMAL_LAN_ADVICE = {
    135: "Normal on Windows. Make sure guest, IoT and camera networks can't reach it.",
    139: "Old NetBIOS file sharing. Disable it where SMB2/3 (port 445) is used, and keep it off guest/IoT networks.",
    445: "Normal on Windows. Turn off SMBv1, and keep guest, IoT and camera networks from reaching it (top ransomware path).",
    9100: "Normal for printers. Keep printers on a network guests can't reach.",
}
HIGH_RISK_PORTS = {p for p, sev in SERVICE_SEVERITY.items() if sev == "high"}


def to_review(devices) -> int:
    """Services that cost points (not the normal Windows sharing/printing ones)."""
    counts = Counter(int(k.split("/")[1]) for d in devices for k, p in d["ports"].items()
                     if p.get("risk") or int(k.split("/")[1]) in RISKY)
    return sum(n for port, n in counts.items() if service_severity(port, n) != "info")


def service_severity(port: int, device_count: int) -> str:
    if port == 3389 and device_count > 3:
        return "medium"           # RDP enabled on lots of machines: easy lateral movement
    return SERVICE_SEVERITY.get(port, "medium")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _who(dev: dict) -> str:
    name = display_name(dev)
    return f"{name} ({dev['ip']})" if name else dev["ip"]


def _parse(ts: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(ts) if ts else None
    except ValueError:
        return None


def deduction(severity: str, count: int) -> int:
    """Diminishing penalty: the first issue of a severity costs most, later ones less, with a cap,
    so one bad device doesn't sink the grade and ten don't push it below zero."""
    first, extra, cap = SEV_COST[severity]
    return 0 if count <= 0 else min(cap, first + extra * (count - 1))


def grade(score: int) -> str:
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"


# ------------------------------------------------------------------ building
def build_report(kind: str, store, passive_status: dict | None = None, scan_info: dict | None = None,
                 previous: dict | None = None, period_days: int = 7, scan: dict | None = None) -> dict:
    if kind == "scan":
        return _scan_report(store, scan or {})
    if kind not in KINDS:
        raise ValueError(f"Unknown report type '{kind}'")
    now = _now()
    since = _parse((previous or {}).get("generated_at")) or now - timedelta(days=period_days)
    devices = [d for d in store.devices() if is_internal(d["ip"])]
    by_ip = {d["ip"]: d for d in devices}
    findings: list[dict] = []
    tables: list[dict] = []
    stats: list[list] = []
    services = {f"{d['ip']} {key}" for d in devices for key in d["ports"]}
    snapshot = {"devices": sorted(by_ip), "services": sorted(services)}
    changes = _changes(previous, devices, services, by_ip)

    if kind in ("full", "network", "span"):
        # With no earlier report there is nothing to compare: don't call every device "new".
        compared = changes if previous else {**changes, "new_devices": [], "new_services": []}
        _inventory_findings(findings, devices, compared, kind)
    if kind in ("full", "network"):
        _scan_findings(findings, scan_info)
        tables.append(_device_table(devices))
    if kind in ("full", "span"):
        _span_findings(findings, passive_status)
        tables.append(_service_table(devices))
    if kind in ("full", "incidents"):
        incidents = [i for i in store.incidents(500) if (_parse(i["started_at"]) or now) >= since]
        _incident_findings(findings, incidents, by_ip)
        tables.append(_incident_table(incidents, by_ip))
        stats += [["Incidents in period", len(incidents)],
                  ["High-severity incidents", sum(i["peak_severity"] == "high" for i in incidents)]]

    if kind != "incidents":
        risky = to_review(devices)
        stats = [["Devices", len(devices)],
                 ["Online", sum(d.get("up") is True for d in devices)],
                 ["Named", sum(bool(display_name(d)) for d in devices)],
                 ["Open services", len(services)],
                 ["Services to review", risky],
                 ["New since last report", len(changes["new_devices"])] if previous else ["New since last report", "first report"],
                 ] + stats
    return _finish({"kind": kind, "title": KINDS[kind], "generated_at": now.isoformat(),
                    "period": {"from": since.isoformat(), "to": now.isoformat()}, "stats": stats,
                    "findings": findings, "changes": changes if previous else None, "tables": tables,
                    "snapshot": snapshot})


def _finish(report: dict) -> dict:
    findings = report["findings"]
    findings.sort(key=lambda f: SEV_ORDER[f["severity"]])
    counts = Counter(f["severity"] for f in findings)
    score = max(0, 100 - sum(deduction(sev, n) for sev, n in counts.items()))
    headline = (f"{counts['high']} high, {counts['medium']} medium and {counts['low']} low priority finding(s)."
                if counts["high"] or counts["medium"] or counts["low"] else "No problems found in this report.")
    report.update(score=score, grade=grade(score), headline=headline, aya=None,
                  grade_reasons=grade_reasons(counts, score))
    return report


def grade_reasons(counts: Counter, score: int) -> dict:
    """Why the report got its grade, and what fixing the top issues would change."""
    lost = [{"severity": sev, "count": counts[sev], "points": deduction(sev, counts[sev])}
            for sev in ("high", "medium", "low") if counts[sev]]
    tip = None
    for sev in ("high", "medium"):
        if counts[sev]:
            better = min(100, score + deduction(sev, counts[sev]))
            if grade(better) != grade(score):
                tip = (f"Fixing the {sev}-priority finding(s) would raise the grade to "
                       f"{grade(better)} ({better}/100).")
                break
    return {"lost": lost, "tip": tip,
            "scale": "A 90+, B 75+, C 60+, D 40+, F below 40. Information items never cost points."}


def _scan_report(store, diff: dict) -> dict:
    """Review of one nmap scan: what it found, risky services on the scanned devices, and what changed
    since the previous scan of the same networks."""
    from ipaddress import ip_address, ip_network
    job = diff.get("job") or {}
    nets = [ip_network(t) for t in job.get("targets", [])]
    devices = [d for d in store.devices() if is_internal(d["ip"]) and any(ip_address(d["ip"]) in n for n in nets)]
    found = {h["ip"] for h in diff.get("hosts", [])}
    scanned = [d for d in devices if d["ip"] in found]
    by_ip = {d["ip"]: d for d in devices}
    label = lambda ip: _who(by_ip[ip]) if ip in by_ip else ip   # noqa: E731
    findings: list[dict] = []
    _inventory_findings(findings, scanned, {"new_devices": [], "new_services": [], "offline": []}, "scan")
    if diff.get("previous_job"):
        if diff["new_hosts"]:
            findings.append(_finding("medium", f"{len(diff['new_hosts'])} device(s) answered that weren't there last scan",
                                     "New devices should be expected ones: check each is yours.",
                                     "Identify and name them on the Network & devices page.",
                                     items=[label(h["ip"]) + (f" · {h['vendor']}" if h.get("vendor") else "")
                                            for h in diff["new_hosts"][:50]]))
        risky_open = [o for o in diff["opened"] if int(o["port"].split("/")[1]) in RISKY]
        if diff["opened"]:
            findings.append(_finding("high" if risky_open else "medium",
                                     f"{len(diff['opened'])} port(s) newly open since the last scan"
                                     + (f", {len(risky_open)} of them risky" if risky_open else ""),
                                     "A service that wasn't running before: a new install, a change, or something unwanted.",
                                     "Confirm who opened each one and close what isn't needed.",
                                     items=[f"{label(o['ip'])}: {o['port']} {o.get('service') or ''}".strip()
                                            for o in diff["opened"][:50]]))
        if diff["closed"]:
            findings.append(_finding("info", f"{len(diff['closed'])} port(s) closed since the last scan",
                                     "Good if intentional (hardening); check if a service stopped unexpectedly.",
                                     items=[f"{label(c['ip'])}: {c['port']}" for c in diff["closed"][:50]]))
        if diff["gone_hosts"]:
            findings.append(_finding("info", f"{len(diff['gone_hosts'])} device(s) answered last time but not now",
                                     "Switched off, moved, or now blocking scans.",
                                     items=[label(h["ip"]) for h in diff["gone_hosts"][:50]]))
    rows = [[display_name(by_ip.get(h["ip"], {})) or h.get("hostname") or "", h["ip"],
             " · ".join(filter(None, [h.get("vendor"), h.get("os")])),
             ", ".join(k.split("/")[1] + ("/udp" if k.startswith("udp") else "") for k in sorted(h["ports"]))]
            for h in diff.get("hosts", [])]
    risky = to_review(scanned)
    from .scanner import describe_targets
    stats = [["Scanned", describe_targets(job.get("targets", []))], ["Devices answering", len(found)],
             ["Open services", sum(len(h["ports"]) for h in diff.get("hosts", []))], ["Services to review", risky]]
    if diff.get("previous_job"):
        stats += [["New devices", len(diff["new_hosts"])], ["Newly open ports", len(diff["opened"])]]
    else:
        stats += [["Compared with", "first scan"]]
    report = {"kind": "scan", "title": f"{SCAN_TITLE}: {describe_targets(job.get('targets', []), show=2)}",
              "generated_at": _now().isoformat(), "stats": stats, "findings": findings, "changes": None,
              "tables": [{"title": "Scan results", "columns": ["Name", "IP", "Hardware / OS", "Open ports"], "rows": rows}],
              "snapshot": None, "job_id": job.get("id"),
              "scan": {"targets": job.get("targets", []), "profile": job.get("profile"), "hosts_up": len(found),
                       "previous_job": diff.get("previous_job"), "new_hosts": diff.get("new_hosts", []),
                       "gone_hosts": diff.get("gone_hosts", []), "opened": diff.get("opened", []),
                       "closed": diff.get("closed", [])}}
    return _finish(report)


def _finding(severity, title, detail, action=None, devices=None, items=None) -> dict:
    return {"severity": severity, "title": title, "detail": detail, "action": action,
            "devices": devices or [], "items": items or []}


def _changes(previous, devices, services, by_ip) -> dict:
    prev = (previous or {}).get("snapshot") or {"devices": [], "services": []}
    old_dev, old_svc = set(prev["devices"]), set(prev["services"])
    new_devices = sorted(ip for ip in by_ip if ip not in old_dev)
    new_services = sorted(s for s in services if s not in old_svc)
    return {"new_devices": new_devices, "new_services": new_services,
            "removed_devices": sorted(ip for ip in old_dev if ip not in by_ip),
            "offline": sorted(d["ip"] for d in devices if d.get("up") is False)}


def _inventory_findings(findings, devices, changes, kind) -> None:
    risky: dict[int, list] = defaultdict(list)
    for d in devices:
        for key, info in d["ports"].items():
            port = int(key.split("/")[1])
            if info.get("risk") or port in RISKY:
                risky[port].append(d)
    for port, devs in sorted(risky.items(), key=lambda kv: (SEV_ORDER[service_severity(kv[0], len(kv[1]))], -len(kv[1]))):
        sev = service_severity(port, len(devs))
        if sev == "info":
            findings.append(_finding(
                "info", f"{service_name(port)} (port {port}) on {len(devs)} device(s): normal for this network",
                NORMAL_LAN_ADVICE.get(port, RISKY.get(port, "")), None, [d["ip"] for d in devs], [_who(d) for d in devs]))
            continue
        findings.append(_finding(
            sev, f"{service_name(port)} (port {port}) open on {len(devs)} device(s)", RISKY.get(port, ""),
            "Close it where it isn't needed; otherwise restrict it with firewall rules or VLANs so only the "
            "devices that need it can connect.", [d["ip"] for d in devs], [_who(d) for d in devs]))
    big = [d for d in devices if len(d["ports"]) >= 8]
    if big:
        findings.append(_finding(
            "low", f"{len(big)} device(s) with 8 or more open services",
            "Every open service is a way in. Devices offering many are the biggest targets.",
            "Review what each service is for and turn off the ones nobody uses.",
            [d["ip"] for d in big], [f"{_who(d)}: {len(d['ports'])} services" for d in big]))
    if changes["new_devices"]:
        new = [d for d in devices if d["ip"] in changes["new_devices"]]
        unknown = [d for d in new if not d.get("label")]
        findings.append(_finding(
            "medium" if unknown else "low", f"{len(new)} new device(s) since the last report",
            "Unknown devices can be personal phones, new IoT gear, or something that shouldn't be there.",
            "Check each one is yours, then give it a name on the Network & devices page.",
            [d["ip"] for d in new], [_who(d) + (f" · {d['vendor']}" if d.get("vendor") else "") for d in new[:50]]))
    new_risky = [s for s in changes["new_services"] if int(s.split("/")[-1]) in RISKY]
    if new_risky:
        findings.append(_finding("medium", f"{len(new_risky)} risky service(s) appeared since the last report",
                                 "A service that wasn't there before may be a new install, a misconfiguration "
                                 "or something an attacker opened.", "Confirm who enabled each one.",
                                 items=new_risky[:50]))
    unnamed = [d for d in devices if not display_name(d)]
    if unnamed:
        findings.append(_finding(
            "low", f"{len(unnamed)} device(s) have no name",
            "Unnamed devices slow down investigations: an alert about 192.168.1.47 means less than one "
            "about 'Reception printer'.", "Name them on the Network & devices page (Rename).",
            [d["ip"] for d in unnamed], [d["ip"] + (f" · {d['vendor']}" if d.get("vendor") else "") for d in unnamed[:50]]))
    if changes["offline"] and kind != "span":
        findings.append(_finding("info", f"{len(changes['offline'])} device(s) didn't answer the last scan",
                                 "They may be switched off, moved, or blocking scans.",
                                 items=changes["offline"][:50]))


def _scan_findings(findings, scan_info) -> None:
    info = scan_info or {}
    if not info.get("installed", True):
        findings.append(_finding("info", "nmap isn't installed",
                                 "Active discovery and port scans need nmap.", "Install it free from nmap.org."))
        return
    done = [j for j in info.get("jobs", []) if j.get("status") == "done"]
    last = _parse(done[0]["finished_at"]) if done else None
    if not last:
        findings.append(_finding("low", "The network has never been scanned",
                                 "Without a scan, devices that stay quiet are invisible to NetAI.",
                                 "Run a scan on the Network & devices page."))
    elif _now() - last > timedelta(days=7):
        findings.append(_finding("low", f"No completed scan for {(_now() - last).days} days",
                                 "Devices change. A weekly scan keeps the inventory accurate.",
                                 "Run a scan, or scan regularly (e.g. every Monday morning)."))


def _span_findings(findings, status) -> None:
    status = status or {}
    if not status.get("enabled", True):
        findings.append(_finding("info", "Passive (SPAN) discovery is turned off",
                                 "Set NETAI_PASSIVE_DISCOVERY=1 to learn devices and services from traffic."))
    elif status.get("mirroring_detected") is False:
        findings.append(_finding(
            "info", "Mirroring isn't working: only this computer's traffic is visible",
            f"Only {round((status.get('foreign_traffic_ratio') or 0) * 100)}% of packets were between other "
            "devices, so passive discovery and attack detection can't see the rest of the network.",
            "Set up a SPAN/mirror port (guides on the SPAN discovery page) and point NETAI_INTERFACE at it."))
    elif status.get("mirroring_detected") is None:
        findings.append(_finding("info", "Mirroring status not measured yet",
                                 "NetAI needs a few hundred live packets to tell whether a mirror port works."))


def _incident_findings(findings, incidents, by_ip) -> None:
    def label(ip):
        return _who(by_ip[ip]) if ip in by_ip else ip
    if not incidents:
        findings.append(_finding("info", "No incidents in this period", "Nothing unusual was flagged."))
        return
    still_open = [i for i in incidents if i["status"] == "open"]
    if still_open:
        findings.append(_finding("high" if any(i["peak_severity"] == "high" for i in still_open) else "medium",
                                 f"{len(still_open)} incident(s) still ongoing",
                                 "These are happening now.", "Open them on the Monitor page and follow the response plan.",
                                 items=[f"#{i['id']} {ATTACK_TITLES.get(i['attack_type'], i['attack_type'])}" for i in still_open]))
    high = [i for i in incidents if i["peak_severity"] == "high" and i["attack_type"] != "unknown"]
    by_type: dict[str, list] = defaultdict(list)
    for i in high:
        by_type[i["attack_type"]].append(i)
    for kind, items in sorted(by_type.items(), key=lambda kv: -len(kv[1])):
        lines = []
        for i in items[:10]:
            h = (i.get("hints") or [{}])[0]
            who = " → ".join(label(x) for x in (h.get("attacker"), h.get("target")) if x)
            lines.append(f"#{i['id']} {i['started_at'][:16].replace('T', ' ')} UTC · {who}")
        findings.append(_finding("high", f"{len(items)} {ATTACK_TITLES.get(kind, kind)} incident(s)",
                                 (items[0].get("hints") or [{}])[0].get("evidence", ""),
                                 "Open each incident for its response plan and evidence.", items=lines))
    attackers = Counter(h.get("attacker") for i in incidents for h in (i.get("hints") or [])[:1] if h.get("attacker"))
    repeat = [(ip, n) for ip, n in attackers.items() if n >= 3]
    if repeat:
        findings.append(_finding("medium", f"{len(repeat)} address(es) involved in 3 or more incidents",
                                 "A repeat source is either misbehaving constantly or deliberately probing you.",
                                 "Investigate these first: identify the device (internal) or block it (external).",
                                 [ip for ip, _ in repeat], [f"{label(ip)}: {n} incidents" for ip, n in repeat]))
    medium = [i for i in incidents if i["peak_severity"] != "high" or i["attack_type"] == "unknown"]
    if medium:
        types = Counter(ATTACK_TITLES.get(i["attack_type"], i["attack_type"]) for i in medium)
        findings.append(_finding("low", f"{len(medium)} lower-severity or unclassified incident(s)",
                                 "Often legitimate (updates, backups, streaming). Recurring ones at the same time "
                                 "each day are usually scheduled jobs.",
                                 "If they're expected, use Relearn baseline so they count as normal.",
                                 items=[f"{n} × {t}" for t, n in types.most_common()]))


def _device_table(devices) -> dict:
    rows = []
    for d in sorted(devices, key=lambda d: tuple(int(x) for x in d["ip"].split("."))):
        ports = ", ".join(f"{k.split('/')[1]}{'/udp' if k.startswith('udp') else ''}" for k in sorted(d["ports"]))
        status = "online" if d.get("up") is True else "offline" if d.get("up") is False else ""
        rows.append([display_name(d) or "", d["ip"], " · ".join(filter(None, [d.get("vendor"), d.get("os")])),
                     ports, status])
    return {"title": "Device inventory", "columns": ["Name", "IP", "Hardware / OS", "Open ports", "Status"],
            "rows": rows}


def _service_table(devices) -> dict:
    rows = []
    for d in devices:
        for key, info in d["ports"].items():
            proto, port = key.split("/")
            rows.append([display_name(d) or "", d["ip"], info.get("service") or service_name(int(port)),
                         f"{port}/{proto}", info.get("source") or "", "yes" if info.get("risk") else ""])
    rows.sort(key=lambda r: (r[5] != "yes", r[1]))
    return {"title": "Services discovered", "columns": ["Device", "IP", "Service", "Port", "Found by", "Risky"],
            "rows": rows}


def _incident_table(incidents, by_ip) -> dict:
    rows = []
    for i in incidents[:200]:
        f = ((i.get("culprits") or {}).get("top_flows") or [{}])[0]
        main = " → ".join(_who(by_ip[x]) if x in by_ip else x for x in (f.get("src"), f.get("dst")) if x)
        rows.append([f"#{i['id']}", i["started_at"][:16].replace("T", " "), i["peak_severity"],
                     ATTACK_TITLES.get(i["attack_type"], i["attack_type"]), main, i["status"]])
    return {"title": "Incidents", "columns": ["#", "Started (UTC)", "Severity", "Looks like", "Main traffic", "Status"],
            "rows": rows}


# ------------------------------------------------------------------ rendering
AYA_LABELS = ("WHAT I FOUND:", "MY ASSESSMENT:", "WHAT TO IMPROVE:", "SINCE LAST TIME:")
_COLORS = {"high": "#c62828", "medium": "#b26a00", "low": "#2e7d32", "info": "#546e7a"}


def render_html(report: dict) -> str:
    """Self-contained, email-safe HTML (inline styles, light theme). Every value is escaped."""
    e = escape
    gen = report["generated_at"][:16].replace("T", " ")
    parts = [f"""<!doctype html><html><head><meta charset="utf-8"><title>{e(report['title'])}</title></head>
<body style="margin:0;background:#f4f6f9;font-family:Segoe UI,Arial,sans-serif;color:#1d2733">
<div style="max-width:860px;margin:auto;padding:24px">
<div style="background:#0b1220;color:#e8eef8;border-radius:12px;padding:22px 24px">
<div style="font-size:13px;color:#91a2ba">NetAI Detector · {e(gen)} UTC</div>
<div style="font-size:24px;font-weight:700;margin:4px 0">{e(report['title'])}</div>
<div style="font-size:15px">{e(report['headline'])}</div></div>
<table role="presentation" style="width:100%;margin:16px 0;border-collapse:separate;border-spacing:8px"><tr>
<td style="background:#fff;border-radius:10px;padding:14px;text-align:center;width:120px">
<div style="font-size:12px;color:#5b6b7f">Health grade</div><div style="font-size:36px;font-weight:700">{e(report['grade'])}</div>
<div style="font-size:12px;color:#5b6b7f">{report['score']}/100</div></td>"""]
    for label, value in report["stats"][:6]:
        parts.append(f'<td style="background:#fff;border-radius:10px;padding:14px;text-align:center">'
                     f'<div style="font-size:12px;color:#5b6b7f">{e(str(label))}</div>'
                     f'<div style="font-size:22px;font-weight:700">{e(str(value))}</div></td>')
    parts.append("</tr></table>")
    why = report.get("grade_reasons")
    if why:
        lost = " · ".join(f"−{r['points']} for {r['count']} {r['severity']}-priority finding(s)" for r in why["lost"])
        parts.append('<div style="background:#fff;border-radius:10px;padding:10px 16px;margin:-6px 0 16px;font-size:13px;color:#3b4a5c">'
                     f'<b>Why grade {e(report["grade"])}:</b> {e(lost) + "." if lost else "nothing cost points."}'
                     + (f' {e(why["tip"])}' if why.get("tip") else "")
                     + f'<div style="color:#7a8797;margin-top:3px">{e(why["scale"])}</div></div>')
    aya = report.get("aya")
    if aya and aya.get("text"):
        body = e(aya["text"])
        for label in AYA_LABELS:
            body = body.replace(label, f'<b style="color:#0b1220">{label}</b>')
        parts.append('<div style="background:#fff;border-left:4px solid #7c4dff;border-radius:10px;padding:16px 18px;margin-bottom:16px">'
                     '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">'
                     '<div style="width:34px;height:34px;border-radius:50%;background:#7c4dff;color:#fff;font-weight:700;'
                     'display:inline-flex;align-items:center;justify-content:center;font-size:16px;text-align:center;line-height:34px">A</div>'
                     '<div><div style="font-weight:700">Aya\'s review</div>'
                     f'<div style="font-size:12px;color:#5b6b7f">NetAI\'s local AI analyst · {e(aya.get("engine") or "built-in")}</div></div></div>'
                     f'<div style="white-space:pre-wrap;line-height:1.55">{body}</div>'
                     + (f'<div style="font-size:12px;color:#8a5a00;margin-top:8px">{e(aya["note"])}</div>' if aya.get("note") else "")
                     + '<div style="font-size:12px;color:#5b6b7f;margin-top:8px">Aya runs on this computer. '
                     'Her review is advice: check before acting.</div></div>')
    parts.append('<h2 style="font-size:18px">Findings</h2>')
    if not report["findings"]:
        parts.append('<p>No findings.</p>')
    for f in report["findings"]:
        color = _COLORS[f["severity"]]
        items = "".join(f"<li>{e(i)}</li>" for i in f["items"][:25])
        more = f"<li>…and {len(f['items']) - 25} more</li>" if len(f["items"]) > 25 else ""
        parts.append(f'<div style="background:#fff;border-radius:10px;padding:14px 16px;margin:10px 0;border-left:4px solid {color}">'
                     f'<div><span style="color:{color};font-weight:700;text-transform:uppercase;font-size:12px">{e(f["severity"])}</span> '
                     f'<b>{e(f["title"])}</b></div>'
                     + (f'<div style="margin-top:4px">{e(f["detail"])}</div>' if f["detail"] else "")
                     + (f'<ul style="margin:6px 0;padding-left:20px;font-size:14px">{items}{more}</ul>' if items else "")
                     + (f'<div style="margin-top:6px"><b>Recommended:</b> {e(f["action"])}</div>' if f.get("action") else "")
                     + "</div>")
    ch = report.get("changes")
    if ch:
        parts.append('<h2 style="font-size:18px">Changes since the last report</h2><ul>'
                     f"<li>{len(ch['new_devices'])} new device(s)</li><li>{len(ch['new_services'])} new service(s)</li>"
                     f"<li>{len(ch['removed_devices'])} device(s) no longer in the inventory</li></ul>")
    for t in report["tables"]:
        if not t["rows"]:
            continue
        head = "".join(f'<th style="text-align:left;padding:6px 8px;border-bottom:1px solid #d5dbe3;font-size:12px;color:#5b6b7f">{e(c)}</th>' for c in t["columns"])
        body = "".join("<tr>" + "".join(f'<td style="padding:6px 8px;border-bottom:1px solid #edf0f4;font-size:13px">{e(str(v))}</td>' for v in r) + "</tr>"
                       for r in t["rows"][:300])
        parts.append(f'<h2 style="font-size:18px">{e(t["title"])}</h2><div style="background:#fff;border-radius:10px;padding:6px;overflow:auto">'
                     f'<table style="width:100%;border-collapse:collapse"><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>')
    parts.append('<p style="font-size:12px;color:#5b6b7f;margin-top:24px">Generated by NetAI Detector on this network. '
                 'Findings are based on what NetAI could observe and are suggestions, not guarantees.</p></div></body></html>')
    return "".join(parts)


def render_text(report: dict) -> str:
    lines = [report["title"], f"Generated {report['generated_at'][:16].replace('T', ' ')} UTC",
             f"Health grade {report['grade']} ({report['score']}/100). {report['headline']}"]
    why = report.get("grade_reasons")
    if why and why["lost"]:
        lines.append("Why: " + ", ".join(f"-{r['points']} for {r['count']} {r['severity']}-priority" for r in why["lost"])
                     + (f". {why['tip']}" if why.get("tip") else ""))
    lines.append("")
    if (report.get("aya") or {}).get("text"):
        lines += [f"AYA'S REVIEW ({report['aya'].get('engine') or 'built-in'})", report["aya"]["text"], ""]
    lines += [" · ".join(f"{k}: {v}" for k, v in report["stats"]), "", "FINDINGS"]
    for f in report["findings"]:
        lines.append(f"[{f['severity'].upper()}] {f['title']}")
        if f["detail"]:
            lines.append(f"  {f['detail']}")
        for i in f["items"][:10]:
            lines.append(f"   - {i}")
        if len(f["items"]) > 10:
            lines.append(f"   - …and {len(f['items']) - 10} more")
        if f.get("action"):
            lines.append(f"  Recommended: {f['action']}")
    return "\n".join(lines)


def to_json(report: dict) -> str:
    return json.dumps(report, default=str)
