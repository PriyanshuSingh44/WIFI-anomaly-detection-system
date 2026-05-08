# 📡 Self-Learning Distributed Wi-Fi Anomaly Detection System

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=flat&logo=flask&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-F7931E?style=flat&logo=scikit-learn&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Packet%20Capture-00897B?style=flat&logo=python&logoColor=white)
![Socket.IO](https://img.shields.io/badge/Socket.IO-Real--Time-010101?style=flat&logo=socket.io&logoColor=white)
![Unsupervised](https://img.shields.io/badge/Learning-Unsupervised-8E24AA?style=flat)

A **distributed, self-learning anomaly detection system** for public Wi-Fi networks. Edge nodes collect traffic windows (simulated or live via Scapy), extract lightweight feature vectors, and ship them to a central aggregator that runs unsupervised ML models — retraining itself continuously as it learns what normal traffic looks like.

---

## ✨ Features

- 🔄 **Dual Capture Modes** — Switch between *simulated* traffic and *live* Scapy packet capture at runtime via the dashboard
- 🤖 **Three Unsupervised ML Models** — Isolation Forest, Local Outlier Factor (LOF), and a pure-NumPy Autoencoder
- 📈 **Self-Learning / Online Retraining** — Model retrains every N windows on a rolling buffer — no labelled data required
- ⚡ **Adaptive Thresholding** — Detection threshold adjusts dynamically to traffic volume (relaxes during peak hours, tightens during quiet periods)
- 🌐 **Real-Time Dashboard** — Flask + Socket.IO web dashboard with live alert feed and per-node statistics
- 🧩 **Multi-Node Architecture** — Up to N simulated access-point edge nodes run as parallel threads
- 💾 **Persistent Models** — Trained models are saved to disk and reloaded on startup (mode-aware: prevents stale model reuse)
- 📋 **Feature Logging** — Every traffic window is appended to `data/feature_log.csv` for offline analysis

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Edge Nodes (AP-01 … AP-N)            │
│  ┌──────────────────────┐  ┌──────────────────────────┐ │
│  │   Simulated Traffic  │  │   Live Capture (Scapy)   │ │
│  │  generate_traffic()  │  │  capture_real_traffic()  │ │
│  └──────────┬───────────┘  └──────────┬───────────────┘ │
│             └─────────────────────────┘                  │
│                     extract_features()                   │
│                    HTTP POST /api/ingest                 │
└─────────────────────────┬───────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────┐
│              Central Aggregator (Flask + SocketIO)      │
│  ┌─────────────────────────────────────────────────┐    │
│  │              AnomalyEngine (ML)                 │    │
│  │  • Rolling buffer  • Adaptive threshold         │    │
│  │  • IsolationForest | LOF | Autoencoder          │    │
│  │  • Retrains every 50 windows automatically      │    │
│  └────────────────────┬────────────────────────────┘    │
│                       │ Socket.IO emit                   │
│  ┌────────────────────▼────────────────────────────┐    │
│  │           Real-Time Web Dashboard               │    │
│  │   Alerts · Stats · Mode Toggle · Node View      │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
WIFI-anomaly-detection-system/
├── main.py            # 🚀 System launcher — starts aggregator + edge nodes
├── aggregator.py      # 🌐 Central Flask/Socket.IO server & REST API
├── edge_node.py       # 📶 Edge node: traffic capture & feature extraction
├── ml_engine.py       # 🤖 Self-learning anomaly engine (3 models)
├── config.py          # ⚙️  All tunable parameters in one place
├── test_anomaly.py    # 🧪 Integration / unit tests
├── requirements.txt   # 📦 Python dependencies
├── templates/
│   └── dashboard.html # 🖥️  Real-time web dashboard (Jinja2)
├── data/              # 📊 feature_log.csv — auto-generated, gitignored
├── logs/              # 📝 system.log — auto-generated, gitignored
└── models/            # 💾 Persisted .pkl model files, gitignored
```

---

## 🧠 ML Models

| Model | Algorithm | Best For |
|---|---|---|
| **IsolationForest** *(default)* | Anomaly isolation via random trees | General-purpose, fast |
| **LOF** | Local Outlier Factor (density-based) | Dense normal clusters |
| **Autoencoder** | Pure-NumPy reconstruction error | Complex non-linear patterns |

All models share the same **11-feature vector** extracted from each traffic window:

| Feature | Description |
|---|---|
| `mean_pkt_size` / `std_pkt_size` | Packet size distribution |
| `mean_freq` / `std_freq` | Packet arrival frequency |
| `proto_tcp/udp/icmp/http_ratio` | Protocol composition |
| `pkt_size_entropy` | Shannon entropy of packet sizes |
| `flow_duration` | Window time span (seconds) |
| `unique_dst_ports` | Count of distinct destination ports |

---

## 🚨 Simulated Attack Profiles

In simulated mode, 8% of windows include a randomly injected attack:

| Attack | Signature |
|---|---|
| **DoS_Flood** | Tiny ICMP packets (64 B) at 500 pps |
| **Port_Scan** | Small TCP packets (60 B) at 200 pps |
| **Data_Exfil** | Large UDP packets (1400 B) at 80 pps |
| **Zero_Day_Burst** | Variable TCP bursts at 350 pps |

---

## 🚀 Quick Start

### 1. Prerequisites

- Python 3.10+
- **Windows only (live mode):** [Npcap](https://npcap.com) driver + run as Administrator

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run (Simulated Mode — no admin rights needed)

```bash
python main.py
```

Then open **http://127.0.0.1:5000** in your browser.

### 4. Run (Live Packet Capture)

> ⚠️ Requires **Administrator** privileges and Npcap installed.

```bash
# Check your Wi-Fi adapter name first
python -c "from scapy.all import get_if_list; print(get_if_list())"

# Then run in live mode
python main.py --mode live
```

### 5. Cloud Deployment (Split Architecture)

You can deploy the Dashboard/Aggregator to the cloud (Render, AWS EC2, Linode) while running the Edge Node locally to monitor your physical Wi-Fi network.

**Step 1: Deploy the Dashboard to the Cloud**
Host the project repository on Render or AWS EC2. 
- **Start Command:** `python main.py --mode live` (or `--mode simulated` for a portfolio demo).

**Step 2: Run the Edge Node Locally**
On your local machine (physically connected to the Wi-Fi you want to monitor), start the standalone edge node and point it to your deployed cloud URL:

```bash
# Run as Administrator for live packet capture
python edge_node.py --url https://<YOUR-CLOUD-URL>/api/ingest
```

---

## ⚙️ CLI Arguments

### `main.py` (System Launcher)

```
python main.py [--nodes N] [--port PORT] [--model MODEL] [--mode MODE]
```

| Argument | Default | Options |
|---|---|---|
| `--nodes` | 5 (sim) / 1 (live) | Any integer |
| `--port` | `5000` | Any free port |
| `--model` | `IsolationForest` | `IsolationForest`, `LOF`, `Autoencoder` |
| `--mode` | `simulated` | `simulated`, `live` |

**Examples:**

```bash
# 3 nodes, LOF model, port 8080
python main.py --nodes 3 --model LOF --port 8080

# Live capture with Autoencoder
python main.py --mode live --model Autoencoder
```

### `edge_node.py` (Standalone Edge Node)

Used when separating the Aggregator (Cloud) from the Edge Node (Local).

```bash
python edge_node.py [--url URL] [--node-id ID]
```

| Argument | Default | Description |
|---|---|---|
| `--url` | `http://127.0.0.1:5000/api/ingest` | The remote Cloud Aggregator URL |
| `--node-id` | `AP-01` | Identifier for this specific edge node |

---

## 🌐 REST API

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Real-time dashboard |
| `/api/ingest` | POST | Receive feature vector from edge node |
| `/api/alerts` | GET | List recent anomaly alerts |
| `/api/stats` | GET | System-wide statistics |
| `/api/recent` | GET | Last N data windows |
| `/api/health` | GET | Engine health & model status |
| `/api/mode` | GET | Current capture mode & interfaces |
| `/api/mode` | POST | Switch capture mode at runtime |

----

## 🔧 Configuration

All parameters are centralised in [`config.py`](config.py):

```python
CAPTURE_MODE        = "simulated"    # "simulated" | "live"
NUM_EDGE_NODES      = 5              # Parallel simulated APs
CAPTURE_INTERVAL    = 2              # Seconds per window
ACTIVE_MODEL        = "IsolationForest"
RETRAIN_EVERY_N_WINDOWS = 50         # Online retraining frequency
MIN_SAMPLES_FOR_TRAIN   = 80         # Baseline collection before first detection
ATTACK_PROBABILITY  = 0.08           # 8% of simulated windows contain an attack
```

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `flask` + `flask-socketio` | REST API & real-time dashboard |
| `scikit-learn` | IsolationForest & LOF models |
| `numpy` / `scipy` | Feature extraction & Autoencoder |
| `scapy` | Live packet capture |
| `joblib` | Model persistence |
| `pandas` | CSV feature logging |
| `eventlet` | Async Socket.IO backend |

---

## 📄 License

This project is licensed under the [MIT License](LICENSE)

----

<p align="center">Built with 🛡️ for public Wi-Fi security research</p>
