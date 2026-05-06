"""
test_anomaly.py — Safe Anomaly Traffic Generator
==================================================
Generates REAL network traffic through your Wi-Fi adapter to test
whether the anomaly detector picks it up.

ALL traffic goes to public servers (Google DNS, httpbin.org) or
your own router. Nothing destructive or illegal.

Usage:
    python test_anomaly.py          # shows menu
    python test_anomaly.py --dos    # DoS-like flood
    python test_anomaly.py --scan   # Port scan simulation
    python test_anomaly.py --exfil  # Large data transfer
    python test_anomaly.py --all    # Run all tests in sequence

⚠️  Wait until dashboard shows "active" (not "collecting_baseline")
    before running these tests. Buffer must reach 150.
"""

import socket
import time
import threading
import argparse
import sys

# ── Targets (all public/safe) ────────────────────────────────────────────────
PING_TARGET   = "8.8.8.8"          # Google DNS — safe to ping
HTTP_TARGET   = "httpbin.org"       # Public test API
HTTP_PORT     = 80
BURST_THREADS = 20                  # Concurrent threads for flooding


def separator(title: str):
    print(f"\n{'='*55}")
    print(f"  🔴 {title}")
    print(f"{'='*55}")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 1 — DoS-like UDP Flood
# Sends many small UDP packets rapidly → spikes mean_freq + ICMP ratio
# ─────────────────────────────────────────────────────────────────────────────
def test_dos_flood(duration: int = 15):
    separator("TEST 1: DoS-like UDP Flood")
    print(f"  Sending rapid UDP bursts to {PING_TARGET} for {duration}s")
    print("  This should spike: mean_freq, proto_udp_ratio")
    print("  Expected result: ANOMALY detected\n")

    stop = threading.Event()
    sent = [0]

    def _flood_worker():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b"X" * 64   # small packet like a real DoS probe
        while not stop.is_set():
            try:
                sock.sendto(payload, (PING_TARGET, 53))  # DNS port
                sent[0] += 1
            except Exception:
                pass
        sock.close()

    threads = [threading.Thread(target=_flood_worker, daemon=True)
               for _ in range(BURST_THREADS)]
    for t in threads:
        t.start()

    for i in range(duration, 0, -1):
        print(f"\r  ⏳ {i:2d}s remaining | Packets sent: {sent[0]:,}", end="", flush=True)
        time.sleep(1)

    stop.set()
    print(f"\n  ✅ Done — sent {sent[0]:,} UDP packets in {duration}s")
    print(f"  Avg rate: {sent[0]//duration:,} pps  (normal is ~30 pps)\n")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 2 — Port Scan Simulation
# Connects to many different ports on a public server
# Spikes: unique_dst_ports, proto_tcp_ratio
# ─────────────────────────────────────────────────────────────────────────────
def test_port_scan(n_ports: int = 500):
    separator("TEST 2: Port Scan Simulation")
    print(f"  Connecting to {n_ports} different ports on {PING_TARGET}")
    print("  This should spike: unique_dst_ports, proto_tcp_ratio")
    print("  Expected result: ANOMALY detected\n")

    hit = [0]
    lock = threading.Lock()

    def _scan_port(port: int):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect_ex((PING_TARGET, port))
            s.close()
            with lock:
                hit[0] += 1
        except Exception:
            pass

    ports = list(range(1, n_ports + 1))
    threads = []
    for p in ports:
        t = threading.Thread(target=_scan_port, args=(p,), daemon=True)
        threads.append(t)
        t.start()
        if len(threads) % 50 == 0:
            print(f"\r  ⏳ Scanning port {p}/{n_ports}...", end="", flush=True)

    for t in threads:
        t.join(timeout=2)

    print(f"\n  ✅ Done — probed {n_ports} ports")
    print(f"  Normal unique ports per window: ~10-30")
    print(f"  This window had: {n_ports} unique destination ports\n")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 3 — Large Data Transfer (Data Exfiltration Simulation)
# Downloads large data repeatedly → spikes mean_pkt_size + mean_freq
# ─────────────────────────────────────────────────────────────────────────────
def test_large_transfer(duration: int = 20):
    separator("TEST 3: Large Data Transfer (Exfil Simulation)")
    print(f"  Downloading data rapidly for {duration}s")
    print("  This should spike: mean_pkt_size (large packets)")
    print("  Expected result: ANOMALY if very different from baseline\n")

    stop  = threading.Event()
    bytes_rx = [0]

    def _download_worker():
        while not stop.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((HTTP_TARGET, HTTP_PORT))
                req = (
                    f"GET /bytes/65536 HTTP/1.1\r\n"
                    f"Host: {HTTP_TARGET}\r\n"
                    f"Connection: close\r\n\r\n"
                ).encode()
                s.sendall(req)
                while not stop.is_set():
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    bytes_rx[0] += len(chunk)
                s.close()
            except Exception:
                time.sleep(0.5)

    threads = [threading.Thread(target=_download_worker, daemon=True)
               for _ in range(5)]
    for t in threads:
        t.start()

    for i in range(duration, 0, -1):
        mb = bytes_rx[0] / 1_000_000
        print(f"\r  ⏳ {i:2d}s remaining | Downloaded: {mb:.1f} MB", end="", flush=True)
        time.sleep(1)

    stop.set()
    mb = bytes_rx[0] / 1_000_000
    print(f"\n  ✅ Done — downloaded {mb:.1f} MB in {duration}s")
    print(f"  Avg packet size will be much larger than baseline (~512 bytes)\n")


# ─────────────────────────────────────────────────────────────────────────────
# Menu / CLI
# ─────────────────────────────────────────────────────────────────────────────

def show_menu():
    print("""
╔══════════════════════════════════════════════════════╗
║      Wi-Fi Anomaly Test Generator                    ║
║      Safe traffic for testing detection              ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║  ⚠️  BEFORE RUNNING:                                 ║
║    1. Dashboard must show "active" (not baseline)    ║
║    2. Buffer must have reached 150+ samples          ║
║    3. Keep dashboard open to watch for alerts        ║
║                                                      ║
╠══════════════════════════════════════════════════════╣
║                                                      ║
║  [1] DoS Flood    — rapid small UDP packets          ║
║  [2] Port Scan    — probe 500 different ports        ║
║  [3] Large Xfer   — download lots of data fast       ║
║  [4] ALL tests    — run all in sequence              ║
║  [Q] Quit                                            ║
║                                                      ║
╚══════════════════════════════════════════════════════╝
""")

def main():
    parser = argparse.ArgumentParser(description="Anomaly traffic generator for testing")
    parser.add_argument("--dos",   action="store_true", help="Run DoS flood test")
    parser.add_argument("--scan",  action="store_true", help="Run port scan test")
    parser.add_argument("--exfil", action="store_true", help="Run large transfer test")
    parser.add_argument("--all",   action="store_true", help="Run all tests")
    args = parser.parse_args()

    if args.dos:
        test_dos_flood()
    elif args.scan:
        test_port_scan()
    elif args.exfil:
        test_large_transfer()
    elif args.all:
        test_dos_flood()
        time.sleep(10)
        test_port_scan()
        time.sleep(10)
        test_large_transfer()
    else:
        # Interactive menu
        show_menu()
        while True:
            choice = input("  Choose test [1/2/3/4/Q]: ").strip().upper()
            if choice == "1":
                test_dos_flood()
            elif choice == "2":
                test_port_scan()
            elif choice == "3":
                test_large_transfer()
            elif choice == "4":
                test_dos_flood()
                time.sleep(10)
                test_port_scan()
                time.sleep(10)
                test_large_transfer()
            elif choice == "Q":
                print("\n  Bye!\n")
                sys.exit(0)
            else:
                print("  Invalid choice. Enter 1, 2, 3, 4 or Q.")


if __name__ == "__main__":
    main()
