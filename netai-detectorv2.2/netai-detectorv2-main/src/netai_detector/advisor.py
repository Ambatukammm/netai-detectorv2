"""Offline response advisor: attack playbooks filled in with the real hosts and ports.

This is NetAI's "AI suggests strategies" part. It runs entirely on this machine (no cloud service
sees your internal addresses). It is advice for a person to read: nothing here is executed, and
nothing is blocked automatically, because auto-blocking can cut off legitimate users.
"""
from __future__ import annotations
from .config import TRUSTED_HOSTS
from .forensics import ATTACK_TITLES, AUTH_PORTS, is_internal, port_name

DISCLAIMER = ("Suggestions only. NetAI never blocks anything by itself. Check each step fits your "
              "network before running a command, and keep the undo command handy.")


def _block_commands(ip: str, direction: str = "in") -> list[dict]:
    """Copy-paste firewall commands (with undo) for Windows and Linux. macOS is left out on purpose:
    its firewall can't block an address without editing pf.conf, so the router is the better place."""
    name = f"NetAI block {ip}"
    if direction == "out":
        return [
            {"os": "Windows (PowerShell as admin)",
             "run": f'New-NetFirewallRule -DisplayName "{name}" -Direction Outbound -RemoteAddress {ip} -Action Block',
             "undo": f'Remove-NetFirewallRule -DisplayName "{name}"'},
            {"os": "Linux", "run": f"sudo iptables -I OUTPUT -d {ip} -j DROP",
             "undo": f"sudo iptables -D OUTPUT -d {ip} -j DROP"},
        ]
    return [
        {"os": "Windows (PowerShell as admin)",
         "run": f'New-NetFirewallRule -DisplayName "{name}" -Direction Inbound -RemoteAddress {ip} -Action Block',
         "undo": f'Remove-NetFirewallRule -DisplayName "{name}"'},
        {"os": "Linux", "run": f"sudo iptables -I INPUT -s {ip} -j DROP",
         "undo": f"sudo iptables -D INPUT -s {ip} -j DROP"},
    ]


def _find_internal_host(ip: str) -> str:
    return (f"Find the device that has {ip}: check your router's list of connected devices (DHCP "
            f"leases), or run `arp -a` on a computer in the same network and look up {ip}'s MAC "
            "address. The first half of a MAC address identifies the manufacturer.")


def _isolate(ip: str) -> str:
    return (f"If {ip} is not an authorised device, or its owner didn't start this: disconnect it "
            "(unplug the cable, turn off its Wi-Fi, or block it in the router), but do NOT wipe or "
            "switch it off yet, so its memory and logs can still be examined.")


def _ext_block(ip: str) -> str:
    return (f"Block {ip} at your router/firewall (best, protects every device), or on the targeted "
            "Windows/Linux machine with a command below. On a Mac, use the router.")


def advise(incident: dict) -> dict:
    """Return a response plan for an incident dict (as stored by IncidentStore)."""
    hints = incident.get("hints") or []
    primary = hints[0] if hints else {"type": "unknown", "confidence": "low"}
    kind = primary.get("type", "unknown")
    attacker, target = primary.get("attacker"), primary.get("target")
    ports = primary.get("ports") or []
    culprits = incident.get("culprits") or {}
    if not attacker and kind not in ("syn_flood", "udp_flood", "icmp_flood"):
        top = (culprits.get("top_sources") or [{}])[0]
        attacker = top.get("ip")
    if not target:
        top = (culprits.get("top_destinations") or [{}])[0]
        target = top.get("ip")
    a_int = bool(attacker and is_internal(attacker))
    t_int = bool(target and is_internal(target))
    port_txt = ", ".join(port_name(p) for p in ports[:5]) or "several ports"

    confirm: list[str] = []
    contain: list[str] = []
    investigate: list[str] = []
    prevent: list[str] = []
    commands: list[dict] = []
    summary = ""

    if kind in ("port_scan", "host_sweep"):
        what = "probing" if kind == "port_scan" else "looking for devices on"
        summary = (f"{attacker} is {what} {target if kind == 'port_scan' else 'your network'}"
                   f" to find open services. Scans are usually the reconnaissance step before an attack.")
        if a_int:
            confirm += [_find_internal_host(attacker),
                        "Ask whoever owns it whether they are running a network scanner or IT "
                        "inventory tool (e.g. Nmap, Advanced IP Scanner). If yes, this is expected."]
            contain += [_isolate(attacker)]
            investigate += [f"Check {attacker} for malware: run a full antivirus scan and look for "
                            "unknown programs started recently. Worms scan networks to spread."]
        else:
            confirm += [f"{attacker} is outside your network. Internet-wide scanning is common; what "
                        "matters is whether anything it found is exposed."]
            contain += [_ext_block(attacker)]
            commands += _block_commands(attacker, "in")
        investigate += [f"List which ports are actually open on {target or 'the targeted devices'} "
                        "(e.g. `netstat -an` on it, or your router's port-forwarding page). Close any "
                        "service you don't need, especially remote access (RDP 3389, SSH 22, SMB 445).",
                        "Watch for a follow-up incident from the same address (login attempts, large "
                        "transfers): that would mean the scan found something."]
        prevent += ["Don't forward ports on the router unless you need them.",
                    "Keep the targeted devices updated so a found service has no known holes."]

    elif kind in ("syn_flood", "udp_flood", "icmp_flood"):
        many = (primary.get("attacker_count") or 0) >= 10
        src_txt = (f"{primary['attacker_count']} different addresses" if many else (attacker or "one address"))
        summary = (f"{target} is being flooded with {ATTACK_TITLES[kind].split(' ')[0]} traffic from "
                   f"{src_txt}. The goal is usually to slow it down or knock it offline (denial of service).")
        confirm += [f"Check whether {target} or your internet connection is actually slow right now. "
                    "A short burst can also be a misbehaving app or a big game/streaming session."]
        if many:
            contain += ["With many sources (likely spoofed or a botnet), blocking addresses one by one "
                        "won't work. If your internet link is saturated, only your ISP can filter "
                        "upstream: call them with the times and target address from this incident.",
                        "If the target is a public server, put it behind a DDoS-protection/CDN service "
                        "(e.g. Cloudflare) or ask your host to enable their DDoS mitigation."]
            if kind == "syn_flood":
                contain += ["Turn on SYN-flood protection: Linux `sudo sysctl -w net.ipv4.tcp_syncookies=1`; "
                            "on routers/firewalls enable 'SYN flood protection' or 'DoS protection'."]
        elif attacker:
            contain += [_ext_block(attacker) if not a_int else _isolate(attacker)]
            if not a_int:
                commands += _block_commands(attacker, "in")
            else:
                contain.insert(0, _find_internal_host(attacker))
        if t_int and ports:
            contain += [f"If {target} doesn't need to receive traffic on {port_txt} from the internet, "
                        "remove that port forward on the router."]
        investigate += ["Note the start/end time and peak rate for your ISP or hosting provider.",
                        "Open the evidence file in Wireshark: Statistics → Conversations shows the "
                        "senders; Statistics → I/O Graph shows the shape of the attack over time."]
        prevent += ["Rate-limit or filter at the edge (router/firewall DoS settings).",
                    "Avoid exposing services directly to the internet where possible."]

    elif kind == "brute_force":
        svc = AUTH_PORTS.get(ports[0], port_txt) if ports else "a login service"
        summary = (f"{attacker} is repeatedly connecting to {svc} on {target}, which is what password-"
                   f"guessing tools do. If one guess succeeds the attacker gets in.")
        confirm += [f"Check the login log on {target}: Windows Event Viewer → Security, event IDs 4625 "
                    f"(failed) and 4624 (success); Linux `sudo journalctl -u ssh` or `/var/log/auth.log`. "
                    f"Many failures from {attacker} confirm it."]
        if a_int:
            confirm.insert(0, _find_internal_host(attacker))
            contain += [_isolate(attacker)]
        else:
            contain += [_ext_block(attacker)]
            commands += _block_commands(attacker, "in")
        contain += [f"Look for any SUCCESSFUL login from {attacker}. If there is one, treat {target} as "
                    "compromised: change that account's password from a different, clean device and "
                    "check for new user accounts or scheduled tasks."]
        investigate += [f"Check whether other devices were targeted by {attacker} too (other incidents, "
                        "or their login logs) and which usernames were tried: guessed names like 'admin' "
                        "or 'root' mean a generic bot, real staff names mean a targeted attack.",
                        f"In the evidence file in Wireshark, filter `ip.addr == {attacker}` and use "
                        "Statistics → Conversations to see when it started and how many attempts were made."]
        prevent += [f"Don't expose {svc} directly to the internet; use a VPN instead.",
                    "Use long unique passwords or keys, enable account lockout, and consider fail2ban "
                    "(Linux) or Windows' account lockout policy.",
                    "Turn on multi-factor authentication where the service supports it."]

    elif kind == "exfiltration":
        summary = (f"{attacker} (a device on your network) is sending an unusually large amount of data "
                   f"to {target} outside your network. That can be a backup or cloud sync, or data being stolen.")
        confirm += [_find_internal_host(attacker),
                    f"On {attacker}, find which program is talking to {target}: Windows `netstat -abno` "
                    f"(as admin) or Resource Monitor → Network; Linux `sudo ss -tunp | grep {target}`.",
                    f"Look up who owns {target} (a WHOIS lookup site). A known cloud/backup provider "
                    "with a program you recognise is probably fine."]
        contain += [f"If the program or destination is unknown: block outbound traffic to {target} "
                    f"and disconnect {attacker} from the network (keep it powered on).",
                    "Write down the time range and amount from this incident: if personal or business "
                    "data left, you may have legal reporting duties (in Australia, the Notifiable Data "
                    "Breaches scheme; elsewhere GDPR or local equivalents)."]
        commands += _block_commands(target, "out")
        investigate += [f"Run a full malware scan on {attacker} and check recently installed programs and "
                        "startup items.", "Check whether the same destination appears in other incidents."]
        prevent += ["Restrict outbound traffic on servers to what they need (egress filtering).",
                    "Keep sensitive data encrypted and access-limited so a single device can't leak it all."]

    elif kind == "dns_tunnelling":
        summary = (f"{attacker} is sending a lot of unusually large DNS requests to {target}. DNS can be "
                   "abused to sneak data out or control malware, because it's rarely blocked.")
        confirm += [_find_internal_host(attacker) if a_int else f"{attacker} is outside your network.",
                    "Some security/VPN software uses DNS heavily too. Check what is installed on the device.",
                    "In the evidence file in Wireshark, filter `dns` and look at the queried names: very "
                    "long random-looking names under one domain are the classic sign."]
        contain += [f"Force the device to use your own DNS resolver and block outbound port 53 to other "
                    f"servers at the router; if it is clearly malicious, disconnect {attacker}."]
        if target and not is_internal(target):
            commands += _block_commands(target, "out")
        investigate += [f"Run a full malware scan on {attacker}."]
        prevent += ["Use one approved DNS resolver (with filtering, e.g. Quad9 or your security product) "
                    "and block DNS to anything else."]

    else:
        summary = ("Traffic was statistically unusual but didn't match a known attack pattern. Common "
                   "harmless causes: software updates, backups, a new app, large downloads.")
        if attacker:
            confirm += [f"The busiest host was {attacker}"
                        + (f" talking to {target}" if target else "") + ". Check what it was doing at that time."]
        investigate += ["Open the evidence file (if saved) in Wireshark and look at Statistics → "
                        "Conversations to see who was talking.",
                        "If it keeps happening at the same time each day it is probably scheduled "
                        "(updates/backups). Consider Relearn baseline so it becomes 'normal'."]

    trusted = [ip for ip in (attacker, target) if ip and ip in TRUSTED_HOSTS]
    note = (f"{', '.join(trusted)} is on your trusted list (NETAI_TRUSTED_HOSTS), so this may be "
            "expected activity." if trusted else None)

    others = [h["title"] for h in hints[1:4]]
    return {
        "attack_type": kind,
        "title": ATTACK_TITLES.get(kind, kind),
        "confidence": primary.get("confidence", "low"),
        "summary": summary,
        "attacker": attacker, "attacker_internal": a_int if attacker else None,
        "target": target, "target_internal": t_int if target else None,
        "trusted_note": note,
        "also_seen": others,
        "steps": [s for s in (
            {"phase": "1. Confirm", "items": confirm},
            {"phase": "2. Contain", "items": contain},
            {"phase": "3. Investigate", "items": investigate},
            {"phase": "4. Prevent it happening again", "items": prevent},
        ) if s["items"]],
        "commands": commands,
        "disclaimer": DISCLAIMER,
    }
