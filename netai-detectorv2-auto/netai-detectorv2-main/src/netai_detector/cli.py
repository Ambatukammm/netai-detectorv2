"""Command-line interface.

Running `netai` with no arguments does everything: it starts the dashboard, and the monitor
learns your network, trains the model and watches traffic automatically. The sub-commands below
are optional, for advanced or scripted use.
"""
from __future__ import annotations
import argparse
import logging
import logging.handlers
import socket
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path
import numpy as np
from . import __version__
from .config import API_KEY, HOST, LOG_PATH, MODEL_PATH, OPEN_BROWSER, PORT, hand_back_to_user
from .detection import AnomalyDetector


def _setup_logging() -> None:
    log = logging.getLogger("netai")
    if log.handlers:
        return
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    log.addHandler(console)
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        file = logging.handlers.RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=3,
                                                    encoding="utf-8")
        file.setFormatter(fmt)
        log.addHandler(file)
        hand_back_to_user(LOG_PATH.parent)
        hand_back_to_user(LOG_PATH)
    except OSError:
        pass


def _port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def _is_netai(port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as resp:
            return b"NetAI Detector" in resp.read()
    except Exception:
        return False


def _open_when_ready(url: str, port: int) -> None:
    for _ in range(40):
        if _is_netai(port):
            try:
                webbrowser.open(url)
            except Exception:
                pass
            return
        time.sleep(0.5)


def run(host: str = HOST, port: int = PORT, open_browser: bool = OPEN_BROWSER) -> None:
    """Start dashboard + automatic monitor. Picks another port if the chosen one is busy."""
    import uvicorn
    _setup_logging()
    log = logging.getLogger("netai")
    shown_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    if not _port_free(host, port):
        if _is_netai(port):
            url = f"http://{shown_host}:{port}"
            log.info("NetAI Detector is already running at %s", url)
            if open_browser:
                webbrowser.open(url)
            return
        for candidate in range(port + 1, port + 21):
            if _port_free(host, candidate):
                log.info("Port %d is busy; using %d instead.", port, candidate)
                port = candidate
                break
        else:
            raise SystemExit(f"No free port found near {port}. Set NETAI_PORT to another value.")
    if host not in ("127.0.0.1", "localhost", "::1") and not API_KEY:
        log.warning("Listening on %s without NETAI_API_KEY set: anyone on the network can control this "
                    "instance. Set NETAI_API_KEY or use 127.0.0.1.", host)
    url = f"http://{shown_host}:{port}"
    log.info("NetAI Detector %s starting. Dashboard: %s", __version__, url)
    if open_browser:
        threading.Thread(target=_open_when_ready, args=(url, port), daemon=True).start()
    uvicorn.run("netai_detector.api:app", host=host, port=port, reload=False, log_level="warning")


def main():
    parser = argparse.ArgumentParser(
        prog="netai", description="NetAI Detector — Made by Ruel. Run with no arguments to start everything automatically.")
    sub = parser.add_subparsers(dest="command", metavar="[advanced command]")
    serve = sub.add_parser("serve", help="Start the dashboard and automatic monitor (same as no command)")
    serve.add_argument("--host", default=HOST)
    serve.add_argument("--port", type=int, default=PORT)
    serve.add_argument("--no-browser", action="store_true", help="Do not open the dashboard automatically")
    cap = sub.add_parser("capture", help="Manually capture a baseline to a file")
    cap.add_argument("--duration", type=int, default=300)
    cap.add_argument("--interface", default=None)
    cap.add_argument("--window-packets", type=int, default=100)
    cap.add_argument("--output", default="data/normal_windows.npz")
    train = sub.add_parser("train", help="Manually train a model from .npz feature windows")
    train.add_argument("--input", default="data/normal_windows.npz")
    train.add_argument("--output", default=str(MODEL_PATH))
    train.add_argument("--contamination", type=float, default=0.02)
    pcap = sub.add_parser("pcap", help="Manually extract feature windows from a PCAP file")
    pcap.add_argument("file")
    pcap.add_argument("--output", default="data/pcap_windows.npz")
    args = parser.parse_args()

    if args.command in (None, "serve"):
        run(getattr(args, "host", HOST), getattr(args, "port", PORT),
            OPEN_BROWSER and not getattr(args, "no_browser", False))
    elif args.command == "capture":
        from .capture import capture_windows
        capture_windows(args.duration, args.interface, args.window_packets, args.output)
    elif args.command == "train":
        source = Path(args.input)
        if not source.exists():
            parser.error(f"Training data not found: {source}")
        with np.load(source) as data:
            samples = data["features"]
        detector = AnomalyDetector()
        print(detector.fit(samples, args.contamination))
        detector.save(args.output)
        print(f"Model saved to {args.output}")
    elif args.command == "pcap":
        from .capture import extract_pcap
        samples = extract_pcap(args.file)
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        np.savez_compressed(out, features=samples)
        print(f"Extracted {len(samples)} windows to {out}")


if __name__ == "__main__":
    main()
