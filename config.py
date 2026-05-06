"""
config.py — Central configuration for the Distributed Anomaly Detection System.
All tunable parameters are gathered here for easy experimentation.
"""

import os

# ─────────────────────────────────────────────
# Capture Mode
# ─────────────────────────────────────────────
CAPTURE_MODE   = "simulated"    # "simulated" | "live"  (switchable via dashboard)
WIFI_INTERFACE = "Wi-Fi"        # Windows NIC name for live capture (run: scapy ifaces)

# ─────────────────────────────────────────────
# Edge Node Simulation Parameters
# ─────────────────────────────────────────────
NUM_EDGE_NODES     = 5          # Number of simulated Wi-Fi access points (sim mode only)
CAPTURE_INTERVAL   = 2          # Seconds between each edge node report
PACKETS_PER_BURST  = 50         # Packets processed per collection window

# ─────────────────────────────────────────────
# Traffic Distribution (Normal Behaviour)
# ─────────────────────────────────────────────
NORMAL_PKT_SIZE_MEAN = 512      # Bytes — typical web / video traffic
NORMAL_PKT_SIZE_STD  = 200
NORMAL_FREQ_MEAN     = 30       # Packets per second (pps) per user
NORMAL_FREQ_STD      = 10
NORMAL_PROTOCOLS     = {"TCP": 0.60, "UDP": 0.25, "ICMP": 0.10, "HTTP": 0.05}

# ─────────────────────────────────────────────
# Attack / Anomaly Profiles
# ─────────────────────────────────────────────
ATTACK_PROFILES = {
    "DoS_Flood":       {"pkt_size_mean": 64,   "pkt_size_std": 10,  "freq_mean": 500, "freq_std": 50,  "protocol": "ICMP"},
    "Port_Scan":       {"pkt_size_mean": 60,   "pkt_size_std": 5,   "freq_mean": 200, "freq_std": 30,  "protocol": "TCP"},
    "Data_Exfil":      {"pkt_size_mean": 1400, "pkt_size_std": 50,  "freq_mean": 80,  "freq_std": 10,  "protocol": "UDP"},
    "Zero_Day_Burst":  {"pkt_size_mean": 900,  "pkt_size_std": 400, "freq_mean": 350, "freq_std": 100, "protocol": "TCP"},
}
ATTACK_PROBABILITY = 0.08       # 8 % of windows contain an injected anomaly

# ─────────────────────────────────────────────
# Feature Extraction
# ─────────────────────────────────────────────
ROLLING_WINDOW_SIZE = 60        # Buffer maxlen = 60×3 = 180 — must exceed MIN_SAMPLES_FOR_TRAIN
FEATURE_COLUMNS = [
    "mean_pkt_size", "std_pkt_size",
    "mean_freq",     "std_freq",
    "proto_tcp_ratio", "proto_udp_ratio",
    "proto_icmp_ratio", "proto_http_ratio",
    "pkt_size_entropy", "flow_duration",
    "unique_dst_ports",
]

# ─────────────────────────────────────────────
# ML Model
# ─────────────────────────────────────────────
ISOLATION_FOREST_CONFIG = {
    "n_estimators":   200,
    "contamination":  "auto",   # Let model decide — don't force a fixed anomaly %
    "max_samples":    "auto",
    "random_state":   42,
    "warm_start":     False,    # We retrain on rolling window
}

LOF_CONFIG = {
    "n_neighbors":   20,
    "contamination": 0.05,      # 5% expected anomaly rate — safe & predictable for LOF
    "algorithm":     "auto",
    "novelty":       True,
}

AUTOENCODER_CONFIG = {
    "input_dim":     len(FEATURE_COLUMNS),
    "hidden_dims":   [8, 4, 8],
    "epochs":        50,
    "batch_size":    32,
    "learning_rate": 0.001,
    "threshold_pct": 95,        # Reconstruction error percentile for threshold
}

ACTIVE_MODEL = "IsolationForest"   # "IsolationForest" | "LOF" | "Autoencoder"

# ─────────────────────────────────────────────
# Adaptive Thresholding
# ─────────────────────────────────────────────
BASE_THRESHOLD          = -0.3  # Isolation Forest score cut-off (more negative = stricter)
HIGH_VOLUME_MULTIPLIER  = 1.3   # Relax threshold at peak traffic
LOW_VOLUME_MULTIPLIER   = 0.85  # Tighten threshold at quiet hours
VOLUME_HIGH_PERCENTILE  = 80
VOLUME_LOW_PERCENTILE   = 20

# ─────────────────────────────────────────────
# Self-Learning / Online Update
# ─────────────────────────────────────────────
RETRAIN_EVERY_N_WINDOWS = 50    # Retrain model after N new windows
MIN_SAMPLES_FOR_TRAIN   = 80    # Minimum samples before first train (must be < ROLLING_WINDOW_SIZE×3=180)

# ─────────────────────────────────────────────
# Flask Dashboard
# ─────────────────────────────────────────────
FLASK_HOST  = "0.0.0.0"
FLASK_PORT  = 5000
SECRET_KEY  = os.getenv("SECRET_KEY", "wifi-anomaly-secret-2024")
MAX_ALERTS_STORED = 200         # Keep last N alerts in memory

# ─────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────
LOG_LEVEL = "INFO"
LOG_FILE  = "logs/system.log"
DATA_DIR  = "data"
MODEL_DIR = "models"
