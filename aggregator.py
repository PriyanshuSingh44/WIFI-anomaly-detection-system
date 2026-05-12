"""
aggregator.py — Central Server / REST API  (updated with dashboard route)
"""

import os
import csv
import logging
import threading
from collections import deque
from datetime import datetime, timezone

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_socketio import SocketIO

import config
from ml_engine import AnomalyEngine
from edge_node import set_capture_mode, get_capture_mode, get_capture_iface

# ─────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
os.makedirs(config.DATA_DIR, exist_ok=True)

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    handlers=[
        logging.FileHandler(config.LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("aggregator")

app = Flask(__name__, template_folder="templates")
app.config["SECRET_KEY"] = config.SECRET_KEY
CORS(app, resources={r"/api/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

engine      = AnomalyEngine(config.ACTIVE_MODEL)
alerts      = deque(maxlen=config.MAX_ALERTS_STORED)
recent_data = deque(maxlen=300)
_csv_lock   = threading.Lock()
CSV_PATH    = os.path.join(config.DATA_DIR, "feature_log.csv")

engine.load_model(capture_mode=config.CAPTURE_MODE)


def _append_csv(row: dict):
    file_exists = os.path.exists(CSV_PATH)
    with _csv_lock:
        with open(CSV_PATH, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(row.keys()))
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/ingest", methods=["POST"])
def ingest():
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "empty payload"}), 400

        ground_truth = data.pop("_ground_truth", "unknown")
        result       = engine.ingest(data, ground_truth=ground_truth)

        record = {**data, "anomaly": result["anomaly"],
                  "score": result["score"], "threshold": result["threshold"],
                  "status": result["status"], "ground_truth": ground_truth}
        recent_data.append(record)
        _append_csv(record)

        if result["anomaly"]:
            alert = {
                "id":           len(alerts) + 1,
                "node_id":      data.get("node_id", "unknown"),
                "timestamp":    data.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "score":        result["score"],
                "threshold":    result["threshold"],
                "features":     {k: data[k] for k in config.FEATURE_COLUMNS if k in data},
                "ground_truth": ground_truth,
            }
            alerts.appendleft(alert)
            socketio.emit("new_alert", alert)
            logger.warning(f"ANOMALY | node={alert['node_id']} score={alert['score']:.4f} gt={ground_truth}")

        socketio.emit("stats_update", _build_stats())
        return jsonify(result), 200

    except Exception as exc:
        logger.exception("Error in /api/ingest")
        return jsonify({"error": str(exc)}), 500


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    limit = int(request.args.get("limit", 50))
    return jsonify(list(alerts)[:limit])


@app.route("/api/stats", methods=["GET"])
def get_stats():
    return jsonify(_build_stats())


@app.route("/api/recent", methods=["GET"])
def get_recent():
    n = int(request.args.get("n", 100))
    return jsonify(list(recent_data)[-n:])


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok", "model": config.ACTIVE_MODEL,
        "is_trained": engine.is_trained, "buffer_size": engine.buffer_size,
        "alerts_total": len(alerts),
        "capture_mode": get_capture_mode(),
        "capture_iface": get_capture_iface(),
    })


@app.route("/api/mode", methods=["GET"])
def get_mode():
    """Return current capture mode and available interfaces."""
    available_ifaces = []
    try:
        from scapy.all import get_if_list
        available_ifaces = get_if_list()
    except Exception:
        pass
    return jsonify({
        "mode":   get_capture_mode(),
        "iface":  get_capture_iface(),
        "ifaces": available_ifaces,
    })


@app.route("/api/mode", methods=["POST"])
def set_mode():
    """Switch between simulated and live capture modes.
    Also resets the ML engine buffer so the model relearns from the new
    traffic type instead of carrying over a stale simulated baseline.
    """
    body  = request.get_json(force=True) or {}
    mode  = body.get("mode", "").strip().lower()
    iface = body.get("iface", "").strip() or None
    try:
        if mode == "live":
            # Quick permission check before allowing the switch
            try:
                from scapy.all import sniff
                sniff(iface=iface or config.WIFI_INTERFACE, timeout=0.1)
            except Exception as e:
                return jsonify({"error": "Requires Admin Rights & Npcap"}), 403

        old_mode = get_capture_mode()
        set_capture_mode(mode, iface)

        # ── Reset ML buffer when mode changes so the model retrains on
        #    the new traffic type (avoids 100% anomaly after switching) ──
        if mode != old_mode:
            with engine._lock:
                engine._buffer.clear()
                engine._windows_seen = 0
                engine._is_trained   = False
                engine.model         = None
                
                # Reset evaluation metrics too
                engine._tp = engine._fp = engine._tn = engine._fn = 0
                
            logger.info(f"[MODE] ML buffer reset — will retrain on '{mode}' traffic.")
            recent_data.clear()
            alerts.clear()

        socketio.emit("mode_changed", {"mode": mode, "iface": get_capture_iface()})
        return jsonify({"ok": True, "mode": mode, "iface": get_capture_iface()})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


def _build_stats() -> dict:
    total     = len(recent_data)
    anomalies = sum(1 for r in recent_data if r.get("anomaly"))
    by_node: dict = {}
    for r in recent_data:
        nid = r.get("node_id", "?")
        if nid not in by_node:
            by_node[nid] = {"total": 0, "anomalies": 0}
        by_node[nid]["total"] += 1
        if r.get("anomaly"):
            by_node[nid]["anomalies"] += 1
    return {
        "total_windows":   total,
        "total_anomalies": anomalies,
        "anomaly_rate":    round(anomalies / total * 100, 2) if total else 0,
        "model":           config.ACTIVE_MODEL,
        "is_trained":      engine.is_trained,
        "buffer_size":     engine.buffer_size,
        "min_samples":     config.MIN_SAMPLES_FOR_TRAIN,
        "by_node":         by_node,
        "capture_mode":    get_capture_mode(),
        "capture_iface":   get_capture_iface(),
        "evaluation":      engine.get_metrics(),
    }


@socketio.on("connect")
def on_connect():
    logger.info("Dashboard client connected")
    socketio.emit("stats_update", _build_stats())


@socketio.on("disconnect")
def on_disconnect():
    logger.info("Dashboard client disconnected")


if __name__ == "__main__":
    logger.info(f"Starting aggregator on {config.FLASK_HOST}:{config.FLASK_PORT}")
    socketio.run(app, host=config.FLASK_HOST, port=config.FLASK_PORT, debug=False)
