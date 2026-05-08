"""
edge_node.py — Wi-Fi Edge Node (Simulated OR Live Capture)
===========================================================
Each EdgeNode:
  1. Generates synthetic traffic (simulated mode) OR captures real packets
     via Scapy from the host Wi-Fi adapter (live mode).
  2. Extracts lightweight feature vectors locally.
  3. Ships vectors to the Central Aggregator via HTTP POST.

Switch modes at runtime via the dashboard or /api/mode endpoint.
"""

import time
import json
import random
import logging
import threading
import requests
import numpy as np
from scipy.stats import entropy as scipy_entropy
from datetime import datetime, timezone

import config

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Global mode state  (shared across all EdgeNode threads)
# ──────────────────────────────────────────────────────────────────────────────
_mode_lock = threading.Lock()
_current_mode: str = config.CAPTURE_MODE        # "simulated" | "live"
_current_iface: str = config.WIFI_INTERFACE


def get_capture_mode() -> str:
    with _mode_lock:
        return _current_mode


def set_capture_mode(mode: str, iface: str | None = None):
    """Called by the aggregator when the dashboard requests a mode switch."""
    global _current_mode, _current_iface
    if mode not in ("simulated", "live"):
        raise ValueError(f"Invalid mode '{mode}'. Use 'simulated' or 'live'.")
    with _mode_lock:
        _current_mode = mode
        if iface:
            _current_iface = iface
    logger.info(f"[MODE] Capture mode → {mode}" + (f" | iface={_current_iface}" if mode == "live" else ""))


def get_capture_iface() -> str:
    with _mode_lock:
        return _current_iface


# ──────────────────────────────────────────────────────────────────────────────
# Scapy live capture  (only imported when needed, graceful fallback if missing)
# ──────────────────────────────────────────────────────────────────────────────

def _scapy_available() -> bool:
    try:
        import scapy.all  # noqa
        return True
    except ImportError:
        return False


def capture_real_traffic_window(iface: str, duration: float = config.CAPTURE_INTERVAL) -> tuple[list[dict], None]:
    """
    Sniff real packets from the specified NIC for `duration` seconds.
    Returns (packet_list, None) — no ground-truth label for real traffic.

    Requires:
      • scapy installed  (pip install scapy)
      • Npcap driver on Windows  (https://npcap.com)
      • Administrator / root privileges
    """
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP
    except ImportError:
        logger.error("[LIVE] Scapy not available — please install scapy.")
        return [], None

    try:
        # Try Layer-2 sniff first (requires Npcap with raw socket access)
        raw_pkts = sniff(iface=iface, timeout=duration, filter="ip", store=True)
    except Exception as exc:
        logger.warning(f"[LIVE] L2 sniff failed on '{iface}': {exc} — trying L3 socket mode.")
        try:
            from scapy.all import conf as scapy_conf
            raw_pkts = sniff(
                iface=iface,
                timeout=duration,
                filter="ip",
                store=True,
                L2socket=scapy_conf.L3socket,   # Layer-3 fallback
            )
        except Exception as exc2:
            logger.error(f"[LIVE] L3 sniff also failed: {exc2} — capture failed. Ensure you are running as Administrator.")
            return [], None

    if not raw_pkts:
        logger.warning(f"[LIVE] No packets captured on '{iface}' in {duration}s — check NIC name & admin rights.")
        return [], None

    from scapy.all import IP, TCP, UDP, ICMP
    packets = []
    for pkt in raw_pkts:
        try:
            if not pkt.haslayer(IP):
                continue
            if pkt.haslayer(TCP):
                dst_port = int(pkt[TCP].dport)
                proto = "HTTP" if dst_port in (80, 8080, 443) else "TCP"
            elif pkt.haslayer(UDP):
                dst_port = int(pkt[UDP].dport)
                proto = "UDP"
            elif pkt.haslayer(ICMP):
                dst_port = 0
                proto = "ICMP"
            else:
                dst_port = 0
                proto = "TCP"

            packets.append({
                "size":     len(pkt),
                "protocol": proto,
                "dst_port": dst_port,
                "ts":       float(pkt.time),
            })
        except Exception:
            continue

    logger.info(f"[LIVE] Captured {len(packets)} packets on '{iface}'")
    return packets, None   # None = no ground-truth label for real traffic


# ──────────────────────────────────────────────────────────────────────────────
# Simulated traffic generator
# ──────────────────────────────────────────────────────────────────────────────

def _simulate_normal_packet() -> dict:
    """Return a single synthetic normal packet as a dict."""
    proto = random.choices(
        list(config.NORMAL_PROTOCOLS.keys()),
        weights=list(config.NORMAL_PROTOCOLS.values()),
    )[0]
    return {
        "size":     max(40, int(np.random.normal(config.NORMAL_PKT_SIZE_MEAN, config.NORMAL_PKT_SIZE_STD))),
        "protocol": proto,
        "dst_port": random.randint(1, 65535),
        "ts":       time.time(),
    }


def _simulate_attack_packet(profile_name: str) -> dict:
    """Return a synthetic attack packet based on the given profile."""
    p = config.ATTACK_PROFILES[profile_name]
    return {
        "size":     max(40, int(np.random.normal(p["pkt_size_mean"], p["pkt_size_std"]))),
        "protocol": p["protocol"],
        "dst_port": random.choice([22, 23, 80, 443, 8080, random.randint(1024, 65535)]),
        "ts":       time.time(),
    }


def generate_traffic_window(n_packets: int = config.PACKETS_PER_BURST) -> tuple[list[dict], str | None]:
    """
    Generate a burst of synthetic packets for one collection window.
    Returns (packet_list, attack_label_or_None).
    """
    inject_attack = random.random() < config.ATTACK_PROBABILITY
    attack_label  = None
    packets       = []

    if inject_attack:
        attack_label = random.choice(list(config.ATTACK_PROFILES.keys()))
        attack_count = int(n_packets * random.uniform(0.3, 0.7))
        normal_count = n_packets - attack_count
        for _ in range(normal_count):
            packets.append(_simulate_normal_packet())
        for _ in range(attack_count):
            packets.append(_simulate_attack_packet(attack_label))
        random.shuffle(packets)
    else:
        packets = [_simulate_normal_packet() for _ in range(n_packets)]

    return packets, attack_label


# ──────────────────────────────────────────────────────────────────────────────
# Unified traffic window — respects current mode
# ──────────────────────────────────────────────────────────────────────────────

def get_traffic_window() -> tuple[list[dict], str | None]:
    """
    Returns (packets, attack_label) using whichever mode is currently active.
    Live mode: attack_label is always None (unknown ground truth).
    """
    mode = get_capture_mode()
    if mode == "live":
        return capture_real_traffic_window(iface=get_capture_iface(),
                                           duration=config.CAPTURE_INTERVAL)
    return generate_traffic_window()


# ──────────────────────────────────────────────────────────────────────────────
# Feature Extraction
# ──────────────────────────────────────────────────────────────────────────────

def extract_features(packets: list[dict], node_id: str) -> dict:
    """
    Transform a raw packet list into a structured feature vector.
    Features align exactly with config.FEATURE_COLUMNS.
    """
    if not packets:
        # Return a zero-vector if live capture produced nothing yet
        return {
            "node_id":          node_id,
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "mean_pkt_size":    0.0, "std_pkt_size":   0.0,
            "mean_freq":        0.0, "std_freq":        0.0,
            "proto_tcp_ratio":  0.0, "proto_udp_ratio": 0.0,
            "proto_icmp_ratio": 0.0, "proto_http_ratio":0.0,
            "pkt_size_entropy": 0.0, "flow_duration":   0.0,
            "unique_dst_ports": 0.0, "n_packets":       0,
        }

    sizes      = np.array([p["size"]     for p in packets], dtype=float)
    protos     = [p["protocol"] for p in packets]
    dst_ports  = [p["dst_port"] for p in packets]
    timestamps = np.array([p["ts"] for p in packets])

    total = len(packets)

    # Protocol ratios
    proto_counts = {k: 0 for k in ["TCP", "UDP", "ICMP", "HTTP"]}
    for pr in protos:
        if pr in proto_counts:
            proto_counts[pr] += 1

    # Packet-size entropy
    hist, _ = np.histogram(sizes, bins=10, range=(40, 1500))
    hist_prob   = hist / hist.sum() if hist.sum() > 0 else hist + 1e-9
    pkt_entropy = float(scipy_entropy(hist_prob, base=2))

    # Flow duration & frequency
    flow_duration = float(timestamps.max() - timestamps.min()) if len(timestamps) > 1 else 0.0
    freq          = total / max(flow_duration, 0.001)

    # Per-second frequency std
    ts_sec = (timestamps - timestamps.min()).astype(int)
    _, counts = np.unique(ts_sec, return_counts=True)
    freq_std  = float(np.std(counts)) if len(counts) > 1 else 0.0

    return {
        "node_id":           node_id,
        "timestamp":         datetime.now(timezone.utc).isoformat(),
        "mean_pkt_size":     float(np.mean(sizes)),
        "std_pkt_size":      float(np.std(sizes)),
        "mean_freq":         float(freq),
        "std_freq":          freq_std,
        "proto_tcp_ratio":   proto_counts["TCP"]  / total,
        "proto_udp_ratio":   proto_counts["UDP"]  / total,
        "proto_icmp_ratio":  proto_counts["ICMP"] / total,
        "proto_http_ratio":  proto_counts["HTTP"] / total,
        "pkt_size_entropy":  pkt_entropy,
        "flow_duration":     flow_duration,
        "unique_dst_ports":  float(len(set(dst_ports))),
        "n_packets":         total,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Edge Node Class
# ──────────────────────────────────────────────────────────────────────────────

class EdgeNode(threading.Thread):
    """
    Wi-Fi access point node — simulated or live capture.
    Runs as a daemon thread, periodically shipping feature vectors to the
    central aggregator REST endpoint.
    """

    def __init__(self, node_id: str, aggregator_url: str, interval: float = config.CAPTURE_INTERVAL):
        super().__init__(daemon=True, name=f"EdgeNode-{node_id}")
        self.node_id        = node_id
        self.aggregator_url = aggregator_url
        self.interval       = interval
        self._stop_event    = threading.Event()
        self.stats          = {"sent": 0, "errors": 0, "attacks_injected": 0}

    def stop(self):
        self._stop_event.set()

    def run(self):
        logger.info(f"[{self.node_id}] Edge node started → {self.aggregator_url}")
        while not self._stop_event.is_set():
            try:
                mode = get_capture_mode()
                packets, attack_label = get_traffic_window()

                # ── In live mode, skip windows where no packets were captured.
                #    Sending all-zero feature vectors would corrupt the ML baseline.
                if mode == "live" and not packets:
                    logger.debug(f"[{self.node_id}] Empty capture window — skipping.")
                    self._stop_event.wait(1)   # brief wait before retrying
                    continue

                features = extract_features(packets, self.node_id)

                # Ground-truth label (only meaningful in simulated mode)
                features["_ground_truth"] = attack_label if attack_label else ("real" if mode == "live" else "normal")
                features["_capture_mode"] = mode

                if attack_label:
                    self.stats["attacks_injected"] += 1

                self._send(features)
                self.stats["sent"] += 1

            except Exception as exc:
                logger.warning(f"[{self.node_id}] Error: {exc}")
                self.stats["errors"] += 1

            # In live mode the sniff already consumed ~CAPTURE_INTERVAL seconds,
            # so only sleep in simulated mode.
            if get_capture_mode() == "simulated":
                self._stop_event.wait(self.interval)

    def _send(self, payload: dict):
        resp = requests.post(
            self.aggregator_url,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code != 200:
            logger.warning(f"[{self.node_id}] Aggregator returned {resp.status_code}")


# ──────────────────────────────────────────────────────────────────────────────
# Standalone runner (for testing edge node in isolation)
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import colorama
    import argparse
    colorama.init()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")

    parser = argparse.ArgumentParser(description="Standalone Wi-Fi Edge Node")
    parser.add_argument("--url", type=str, default=f"http://127.0.0.1:{config.FLASK_PORT}/api/ingest", 
                        help="Remote Aggregator URL (e.g., https://my-app.onrender.com/api/ingest)")
    parser.add_argument("--node-id", type=str, default="AP-01", help="Identifier for this edge node")
    args = parser.parse_args()

    # When running standalone to monitor real Wi-Fi, force mode to live
    set_capture_mode("live")

    node = EdgeNode(args.node_id, args.url)
    node.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        node.stop()
        print("Edge node stopped.")
