"""Aya: NetAI's local AI analyst. She reviews every report: what she found, what she thinks of it,
what to improve, and what changed since last time.

Aya runs on this machine. Two ways:
  * built-in (default, nothing to install): an expert-rules analyst that writes the review from the
    findings. Fast, deterministic, works offline.
  * a local language model, through Ollama (https://ollama.com) or any OpenAI-compatible local server
    (LM Studio, llama.cpp server, LocalAI). Richer, more natural reviews. Your data goes only to that
    server, which normally runs on this same computer.
If the model can't be reached, Aya falls back to her built-in analysis and says so.
"""
from __future__ import annotations
from ipaddress import ip_address
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from . import config

ENGINES = {"builtin": "Built-in (no setup)", "ollama": "Ollama",
           "openai": "OpenAI-compatible local server (LM Studio, llama.cpp, LocalAI)"}
DEFAULT_URLS = {"ollama": "http://127.0.0.1:11434", "openai": "http://127.0.0.1:1234"}
SYSTEM = (
    "You are Aya, the network security analyst built into NetAI Detector. You review reports about a "
    "small or medium business network for its owner or IT person. Speak in the first person, plainly "
    "and honestly, like a trusted senior colleague: give your real opinion, say what worries you and "
    "what is fine. Use only the facts in the data you are given; never invent devices, numbers or "
    "attacks. Refer to devices exactly as they are written in the data. Plain text only: no markdown "
    "symbols such as #, ** or tables.")


class AyaError(RuntimeError):
    pass


def is_local_url(url: str) -> bool:
    """True if the server is on this machine or a private network (data stays in-house)."""
    host = urllib.parse.urlparse(url).hostname or ""
    if host in ("localhost",):
        return True
    try:
        addr = ip_address(host)
    except ValueError:
        try:
            addr = ip_address(socket.gethostbyname(host))
        except (OSError, ValueError):
            return False
    return addr.is_loopback or addr.is_private


# ------------------------------------------------------------------ built-in analyst
_OPEN_ON = re.compile(r"^(.*?) \(port (\d+)\) open on \d+ device\(s\)$")


def _subject(f: dict) -> str:
    """'Telnet on cam-carpark (192.168.15.40)' instead of 'Telnet (port 23) open on 1 device(s)'."""
    m = _OPEN_ON.match(f["title"])
    if m:
        where = ", ".join(f["items"][:3]) + (f" and {len(f['items']) - 3} more" if len(f["items"]) > 3 else "")
        return f"{m.group(1)} on {where}" if where else m.group(1)
    return f["title"]


def _advice(f: dict) -> str:
    """Service findings carry specific advice in their detail ('Replace with SSH.'); others in action."""
    return f["detail"] if _OPEN_ON.match(f["title"]) and f.get("detail") else (f.get("action") or f.get("detail") or "")


def builtin_review(report: dict) -> str:
    findings = report.get("findings") or []
    serious = [f for f in findings if f["severity"] == "high"]
    medium = [f for f in findings if f["severity"] == "medium"]
    stats = {str(k): v for k, v in report.get("stats") or []}
    grade_ = report.get("grade", "?")
    scan = report.get("scan") or {}

    found = []
    if scan:
        from .scanner import describe_targets
        found.append(f"I looked at the scan of {describe_targets(scan.get('targets', []))}: "
                     f"{scan.get('hosts_up', 0)} device(s) answered.")
    elif "Devices" in stats:
        found.append(f"I looked at {stats['Devices']} device(s) with {stats.get('Open services', 0)} open "
                     f"service(s); {stats.get('Services to review', 0)} of them need a closer look.")
    if "Incidents in period" in stats:
        found.append(f"There were {stats['Incidents in period']} incident(s) in this period, "
                     f"{stats.get('High-severity incidents', 0)} of them high severity.")
    counts = [f"{n} {sev}" for sev, n in (("serious", len(serious)), ("medium", len(medium))) if n]
    found.append(f"I have {' and '.join(counts)} issue(s) for you." if counts else "Nothing here needs urgent work.")

    worst = _subject(serious[0]) if serious else (_subject(medium[0]) if medium else "")
    if grade_ == "A":
        opinion = "This network is in good shape. I didn't find anything that needs urgent work."
    elif grade_ == "B":
        opinion = (f"Mostly healthy. The one thing I'd deal with soon is {worst}." if worst
                   else "Mostly healthy, with only minor housekeeping to do.")
    elif grade_ == "C":
        opinion = (f"There are real weaknesses here, the biggest being {worst}. None is a disaster on its own, "
                   "but together they make an attacker's job easier.") if worst else \
                  "There are several smaller weaknesses that add up."
    else:
        opinion = (f"I'm concerned. I count {len(serious)} serious issue(s), and the one I'd fix first is "
                   f"{worst}. I'd treat the top of my list as urgent." if worst
                   else "I'm concerned about the number of issues here. I'd work through my list this week.")
    if any("Mirroring isn't working" in f["title"] for f in findings):
        opinion += " Also, I can only see this computer's own traffic, so my view of the network is limited."

    improve, generic = [], False
    for f in findings:
        if f["severity"] == "info":
            continue
        advice = _advice(f)
        if not advice:
            continue
        if _OPEN_ON.match(f["title"]):
            generic = True
        improve.append(f"{_subject(f)}: {advice}")
        if len(improve) == 6:
            break
    if generic:
        improve.append("For every service above: if nobody needs it, turn it off; if someone does, limit who can "
                       "reach it with firewall rules or a separate VLAN.")
    if not improve:
        improve = ["Keep doing what you're doing: scan regularly and name new devices as they appear."]

    since = []
    ch = report.get("changes")
    if scan.get("previous_job"):
        bits = [f"{len(scan.get('new_hosts', []))} new device(s)", f"{len(scan.get('gone_hosts', []))} no longer answering"]
        if scan.get("profile") != "discover":
            bits += [f"{len(scan.get('opened', []))} newly opened port(s)", f"{len(scan.get('closed', []))} closed"]
        since.append(f"Compared with the scan on {scan['previous_job']['started_at'][:10]}: {', '.join(bits)}.")
        if not any((scan.get("new_hosts"), scan.get("gone_hosts"), scan.get("opened"), scan.get("closed"))):
            since.append("Nothing changed, which is what you want to see.")
    elif scan:
        since.append("This is the first scan of these networks, so I have nothing to compare it with yet. "
                     "Scan again in a week and I'll tell you what changed.")
    elif ch:
        since.append(f"Since my last report: {len(ch['new_devices'])} new device(s), {len(ch['new_services'])} "
                     f"new service(s), {len(ch['removed_devices'])} device(s) gone.")
    else:
        since.append("This is my first report, so I have nothing to compare it with yet.")

    return ("WHAT I FOUND: " + " ".join(x for x in found if x) + "\n\n"
            "MY ASSESSMENT: " + opinion + "\n\n"
            "WHAT TO IMPROVE:\n" + "\n".join(f"{i}. {line}" for i, line in enumerate(improve, 1)) + "\n\n"
            "SINCE LAST TIME: " + " ".join(since))


# ------------------------------------------------------------------ local language model
def payload(report: dict) -> dict:
    """The facts Aya's model sees (data stays on this machine / your local server)."""
    data = {"report": report["title"], "health_grade": report["grade"], "score": report["score"],
            "stats": {str(k): v for k, v in report["stats"]},
            "findings": [{"severity": f["severity"], "title": f["title"], "detail": f["detail"],
                          "recommended": f.get("action") or "", "devices": f["items"][:8],
                          "count": len(f["items"])} for f in report["findings"][:25]]}
    if report.get("changes"):
        data["changes_since_last_report"] = {k: len(v) for k, v in report["changes"].items()}
    scan = report.get("scan")
    if scan:
        from .scanner import describe_targets
        data["scan"] = {"targets": describe_targets(scan.get("targets") or [], show=10), "devices_answering": scan.get("hosts_up"),
                        "previous_scan": (scan.get("previous_job") or {}).get("started_at"),
                        "new_devices": len(scan.get("new_hosts", [])), "gone": len(scan.get("gone_hosts", [])),
                        "newly_opened_ports": len(scan.get("opened", [])), "closed_ports": len(scan.get("closed", []))}
    return data


def prompt_for(report: dict) -> str:
    return ("Here is the latest NetAI Detector report as JSON:\n\n" + json.dumps(payload(report), indent=1)
            + "\n\nWrite your review with these four labels, in this order:\n"
            "WHAT I FOUND: two or three sentences.\n"
            "MY ASSESSMENT: your honest opinion of this network's security in three or four sentences: what "
            "worries you most and what looks fine.\n"
            "WHAT TO IMPROVE: a numbered list of at most 6 concrete actions, most important first, each naming "
            "the devices involved and saying why.\n"
            "SINCE LAST TIME: one or two sentences on what changed (say so if this is the first report).")


def _post(url: str, body: dict, key: str, timeout: float, opener) -> dict:
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    return _json(req, timeout, opener)


def _json(req, timeout: float, opener) -> dict:
    try:
        with (opener or urllib.request.urlopen)(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8")[:200]
        except Exception:
            pass
        if exc.code == 404:
            raise AyaError(f"the model wasn't found on the server (HTTP 404). {detail}".strip()) from exc
        raise AyaError(f"the AI server answered HTTP {exc.code}. {detail}".strip()) from exc
    except (urllib.error.URLError, OSError) as exc:
        raise AyaError(f"couldn't reach the AI server ({getattr(exc, 'reason', exc)}). Is it running?") from exc
    except ValueError as exc:
        raise AyaError("the AI server sent an answer Aya couldn't read") from exc


def ask_model(settings: dict, system: str, user: str, opener=None) -> str:
    engine = settings.get("aya_engine", "builtin")
    base = (settings.get("aya_url") or DEFAULT_URLS.get(engine, "")).rstrip("/")
    model = settings.get("aya_model") or ""
    timeout = float(config.AYA_TIMEOUT)
    if not model:
        raise AyaError("no model chosen. Pick one in Settings → Aya.")
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    if engine == "ollama":
        answer = _post(f"{base}/api/chat", {"model": model, "messages": messages, "stream": False,
                                             "options": {"temperature": 0.3, "num_ctx": 8192}},
                       settings.get("aya_api_key", ""), timeout, opener)
        text = (answer.get("message") or {}).get("content", "")
    elif engine == "openai":
        answer = _post(f"{base}/v1/chat/completions", {"model": model, "messages": messages, "temperature": 0.3},
                       settings.get("aya_api_key", ""), timeout, opener)
        text = ((answer.get("choices") or [{}])[0].get("message") or {}).get("content", "")
    else:
        raise AyaError("the built-in engine doesn't use a model")
    text = (text or "").strip()
    if text.startswith("<think>") and "</think>" in text:     # reasoning models: drop their scratchpad
        text = text.split("</think>", 1)[1].strip()
    if not text:
        raise AyaError("the model returned an empty answer")
    return text


def list_models(settings: dict, opener=None) -> list[str]:
    engine = settings.get("aya_engine", "builtin")
    base = (settings.get("aya_url") or DEFAULT_URLS.get(engine, "")).rstrip("/")
    headers = {"Authorization": f"Bearer {settings['aya_api_key']}"} if settings.get("aya_api_key") else {}
    if engine == "ollama":
        data = _json(urllib.request.Request(f"{base}/api/tags", headers=headers), 10, opener)
        return sorted(m.get("name", "") for m in data.get("models", []) if m.get("name"))
    if engine == "openai":
        data = _json(urllib.request.Request(f"{base}/v1/models", headers=headers), 10, opener)
        return sorted(m.get("id", "") for m in data.get("data", []) if m.get("id"))
    return []


def review(report: dict, settings: dict, opener=None) -> dict:
    """Aya's review of a report: {"text", "engine", "note"}. Never raises."""
    engine = settings.get("aya_engine", "builtin")
    if engine in ("ollama", "openai"):
        try:
            text = ask_model(settings, SYSTEM, prompt_for(report), opener)
            return {"text": text, "engine": f"{ENGINES[engine].split(' (')[0]} · {settings.get('aya_model')}",
                    "note": None}
        except AyaError as exc:
            return {"text": builtin_review(report), "engine": "built-in",
                    "note": f"Aya's local model wasn't available ({exc}), so she used her built-in analysis."}
    return {"text": builtin_review(report), "engine": "built-in", "note": None}
