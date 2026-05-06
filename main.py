"""
main.py — System Launcher
==========================
Starts the Central Aggregator server, then spawns all Edge Nodes as threads.
Run:  python main.py
"""
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

import time
import logging
import threading
import argparse

import config
from edge_node import EdgeNode

logger = logging.getLogger("main")


def launch_aggregator():
    """Import and run the Flask-SocketIO aggregator in a background thread."""
    from aggregator import socketio, app
    logger.info(f"Aggregator starting at http://127.0.0.1:{config.FLASK_PORT}")
    socketio.run(app, host=config.FLASK_HOST, port=config.FLASK_PORT, debug=False)


def launch_edge_nodes(aggregator_url: str, n_nodes: int) -> list[EdgeNode]:
    nodes = []
    for i in range(n_nodes):
        node_id = f"AP-{i+1:02d}"
        node = EdgeNode(node_id, aggregator_url, interval=config.CAPTURE_INTERVAL)
        node.start()
        nodes.append(node)
        logger.info(f"Edge node {node_id} started")
        time.sleep(0.3)          # stagger starts slightly
    return nodes


def main():
    parser = argparse.ArgumentParser(description="Distributed Wi-Fi Anomaly Detection System")
    parser.add_argument("--nodes",  type=int, default=None,               help="Number of edge nodes (default: 1 for live, 5 for simulated)")
    parser.add_argument("--port",   type=int, default=config.FLASK_PORT,  help="Aggregator port")
    parser.add_argument("--model",  type=str, default=config.ACTIVE_MODEL,
                        choices=["IsolationForest", "LOF", "Autoencoder"],  help="ML model to use")
    parser.add_argument("--mode",   type=str, default=config.CAPTURE_MODE,
                        choices=["simulated", "live"],                      help="Capture mode")
    args = parser.parse_args()

    # Override config at runtime
    config.FLASK_PORT   = args.port
    config.ACTIVE_MODEL = args.model
    config.CAPTURE_MODE = args.mode

    # ── In live mode: 1 node is enough — all nodes sniff the same NIC anyway.
    #    In simulated mode: default to NUM_EDGE_NODES (e.g. 5).
    if args.nodes is not None:
        n_nodes = args.nodes
    elif config.CAPTURE_MODE == "live":
        n_nodes = 1
    else:
        n_nodes = config.NUM_EDGE_NODES

    logging.basicConfig(
        level=getattr(logging, config.LOG_LEVEL),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )

    print("\n" + "="*60)
    print("  [*] SELF-LEARNING DISTRIBUTED ANOMALY DETECTION SYSTEM")
    print("="*60)
    print(f"  Mode     : {config.CAPTURE_MODE.upper()}")
    print(f"  Model    : {config.ACTIVE_MODEL}")
    print(f"  Nodes    : {n_nodes}")
    if config.CAPTURE_MODE == "live":
        print(f"  Interface: {config.WIFI_INTERFACE}")
        print(f"  Baseline : collecting first {config.MIN_SAMPLES_FOR_TRAIN} windows before detecting")
    print(f"  Dashboard: http://127.0.0.1:{config.FLASK_PORT}")
    print("="*60 + "\n")

    # Start aggregator in background thread
    agg_thread = threading.Thread(target=launch_aggregator, daemon=True, name="Aggregator")
    agg_thread.start()

    # Wait for Flask to be ready
    import socket as _socket, time as _time
    for _ in range(20):
        try:
            s = _socket.create_connection(("127.0.0.1", config.FLASK_PORT), timeout=1)
            s.close(); break
        except OSError:
            _time.sleep(0.5)

    AGGREGATOR_URL = f"http://127.0.0.1:{config.FLASK_PORT}/api/ingest"
    nodes = launch_edge_nodes(AGGREGATOR_URL, n_nodes)

    print(f"\n[OK] System running -- open http://127.0.0.1:{config.FLASK_PORT} in your browser")
    if config.CAPTURE_MODE == "live":
        print(f"   [!] Dashboard will show 'collecting_baseline' for the first ~{config.MIN_SAMPLES_FOR_TRAIN * config.CAPTURE_INTERVAL // 60} minutes.")
        print(f"       This is NORMAL — the model is learning what your network looks like.")
    print("   Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(5)
            alive = sum(1 for n in nodes if n.is_alive())
            sent  = sum(n.stats["sent"] for n in nodes)
            atk   = sum(n.stats["attacks_injected"] for n in nodes)
            if config.CAPTURE_MODE == "simulated":
                print(f"  ▶ Nodes alive: {alive}/{len(nodes)} | Windows sent: {sent} | Attacks injected: {atk}")
            else:
                print(f"  ▶ Nodes alive: {alive}/{len(nodes)} | Windows sent: {sent} | Iface: {config.WIFI_INTERFACE}")
    except KeyboardInterrupt:
        print("\n[STOP] Shutting down edge nodes...")
        for n in nodes:
            n.stop()
        print("   Done. Goodbye!")


if __name__ == "__main__":
    main()
