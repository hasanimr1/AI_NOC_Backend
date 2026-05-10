"""
╔══════════════════════════════════════════════════════════════════════╗
║          AI-NOC LIVE DATA SHIPPER AGENT  //  live_agent.py           ║
║          Simulates live network telemetry for FYP presentation       ║
╠══════════════════════════════════════════════════════════════════════╣
║  TASK A ─ Network Traffic Replayer  → HITS /ingest/metrics (MATH)    ║
║  TASK B ─ Live Host Monitor         → HITS /ingest/logs (TEXT NLP)   ║
╚══════════════════════════════════════════════════════════════════════╝

REQUIRED PACKAGES (run once before starting):
    pip install requests psutil pandas

USAGE:
    python live_agent.py
    (Make sure your Docker stack is up: docker-compose up --build)
"""

import threading
import time
import random
import os
import json
from datetime import datetime, timezone

import requests
import psutil
import pandas as pd

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
BACKEND_URL      = "http://localhost:8000"   
CSV_FILE         = "hikari_2021.csv"         

REPLAY_INTERVAL_MIN = 2
REPLAY_INTERVAL_MAX = 5
TELEMETRY_INTERVAL  = 3

LABEL_COLUMN_CANDIDATES =[
    "Label", "label", "Attack", "attack", "Category", "category", "Class", "class",
    "traffic_category", "traffic_cat"
]

stats_lock = threading.Lock()
stats = {
    "replays_sent"    : 0,
    "telemetry_sent"  : 0,
    "errors"          : 0,
    "start_time"      : time.time(),
}

def now_iso() -> str:
    return str(time.time())

def banner():
    print("\033[96m")   
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║   🛡️  AI-NOC LIVE DATA SHIPPER AGENT  //  SYSTEM BOOT          ║")
    print("║   Connecting to AI-NOC Backend at:  " + BACKEND_URL.ljust(29) + "║")
    print("║   CSV Source:  " + CSV_FILE.ljust(50) + "║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print("\033[0m")

def print_status():
    with stats_lock:
        uptime = int(time.time() - stats["start_time"])
        hrs, rem = divmod(uptime, 3600)
        mins, secs = divmod(rem, 60)
        print(
            f"\033[93m[STATUS] ⏱  Uptime {hrs:02d}h{mins:02d}m{secs:02d}s │ "
            f"📤 Replays: {stats['replays_sent']} │ "
            f"💻 Telemetry: {stats['telemetry_sent']} │ "
            f"⚠️  Errors: {stats['errors']}\033[0m"
        )

def safe_post(url: str, payload: dict, source_label: str) -> bool:
    try:
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()
        return True
    except Exception as e:
        pass
    with stats_lock:
        stats["errors"] += 1
    return False

# ─────────────────────────────────────────────────────────────────────────────
# TASK A  ─  NETWORK TRAFFIC REPLAYER (Fixed: Hits /ingest/metrics)
# ─────────────────────────────────────────────────────────────────────────────
DEVICE_POOL =[
    "Core-Router-01", "Firewall-Ext", "Switch-01", "Server-Web",
    "Auth-Gateway",   "Database-01", "File-Server", "API-Server",
    "Worker-Node",    "Gateway-01",
]

def load_csv() -> pd.DataFrame | None:
    if not os.path.exists(CSV_FILE):
        print(f"\033[91m❌ ERROR: '{CSV_FILE}' not found. Task A will be SKIPPED.\033[0m")
        return None
    print(f"\033[92m  📂 [Replayer] Loading dataset: {CSV_FILE} ...\033[0m", end="", flush=True)
    df = pd.read_csv(CSV_FILE, low_memory=False)
    print(f"\033[92m  Done! ({len(df):,} rows loaded)\033[0m")
    df.dropna(how="all", inplace=True)
    return df

def pick_label(row: pd.Series) -> str:
    for col in LABEL_COLUMN_CANDIDATES:
        if col in row.index and pd.notna(row[col]) and str(row[col]).strip():
            return str(row[col]).strip()
    return "Network Flow"

def row_to_payload(row: pd.Series) -> dict:
    device = random.choice(DEVICE_POOL)
    try: flow_dur = float(row.get("flow_duration", 0.0))
    except: flow_dur = 0.0
    try: fwd_pkts = float(row.get("fwd_pkts_tot", 0.0))
    except: fwd_pkts = 0.0
    try: bwd_pkts = float(row.get("bwd_pkts_tot", 0.0))
    except: bwd_pkts = 0.0

    return {
        "device_name": device,
        "flow_duration": flow_dur,
        "fwd_pkts_tot": fwd_pkts,
        "bwd_pkts_tot": bwd_pkts,
        "timestamp": now_iso(),
    }

def task_a_replayer():
    df = load_csv()
    if df is None: return

    # FIX: Pointed specifically to the metrics endpoint!
    endpoint = f"{BACKEND_URL}/ingest/metrics"
    print(f"\033[92m  🚀 [Replayer] Task A started. Targeting → {endpoint}\033[0m")

    while True:
        delay = random.uniform(REPLAY_INTERVAL_MIN, REPLAY_INTERVAL_MAX)
        time.sleep(delay)
        row   = df.sample(1).iloc[0]
        label = pick_label(row)
        payload = row_to_payload(row)

        print(f"\033[94m  🚨 [Replayer] Injecting network metrics » \033[1m{label}\033[0m")
        if safe_post(endpoint, payload, source_label="Replayer"):
            with stats_lock:
                stats["replays_sent"] += 1

# ─────────────────────────────────────────────────────────────────────────────
# TASK B  ─  LIVE HOST MONITOR (Hits /ingest/logs)
# ─────────────────────────────────────────────────────────────────────────────
def task_b_host_monitor():
    endpoint = f"{BACKEND_URL}/ingest/logs"
    print(f"\033[95m  🚀 [HostMonitor] Task B started. Targeting → {endpoint}\033[0m")

    prev_net  = psutil.net_io_counters()
    prev_time = time.time()

    while True:
        time.sleep(TELEMETRY_INTERVAL)
        cpu_pct  = psutil.cpu_percent(interval=None)
        ram      = psutil.virtual_memory()
        ram_pct  = ram.percent
        ram_used_mb = ram.used / (1024 ** 2)

        curr_net  = psutil.net_io_counters()
        curr_time = time.time()
        delta_t   = max(curr_time - prev_time, 0.001)

        bytes_sent_kbps = (curr_net.bytes_sent - prev_net.bytes_sent) / delta_t / 1024
        bytes_recv_kbps = (curr_net.bytes_recv - prev_net.bytes_recv) / delta_t / 1024
        prev_net, prev_time = curr_net, curr_time

        threat_hint = ""
        if cpu_pct > 85:
            threat_hint = "CRITICAL: CPU spike detected — possible crypto-mining or fork-bomb."
        elif bytes_sent_kbps > 5000:
            threat_hint = "WARNING: High outbound bandwidth — possible data exfiltration."
        elif bytes_recv_kbps > 10000:
            threat_hint = "WARNING: High inbound traffic — possible DDoS or flood."
        else:
            threat_hint = f"INFO: Host nominal. CPU={cpu_pct:.1f}% RAM={ram_pct:.1f}%"

        message = (
            f"HOST_TELEMETRY: {threat_hint} "
            f"[CPU={cpu_pct:.1f}% | RAM={ram_pct:.1f}% ({ram_used_mb:.0f}MB) | "
            f"TX={bytes_sent_kbps:.1f}KB/s | RX={bytes_recv_kbps:.1f}KB/s]"
        )

        payload = {"device_name": "Core-Router-Local", "message": message, "timestamp": now_iso()}

        print(f"\033[95m  📡 [HostMonitor] Streaming telemetry... CPU: {cpu_pct:.1f}% | RAM: {ram_pct:.1f}%\033[0m")
        if safe_post(endpoint, payload, source_label="HostMonitor"):
            with stats_lock:
                stats["telemetry_sent"] += 1

def task_c_status_reporter():
    while True:
        time.sleep(15)
        print_status()

if __name__ == "__main__":
    banner()
    if not os.path.exists(CSV_FILE):
        print(f"\033[93m  ⚠️ NOTE: '{CSV_FILE}' not found. Task A will skip.\033[0m\n")
    
    threading.Thread(target=task_a_replayer, name="TrafficReplayer", daemon=True).start()
    threading.Thread(target=task_b_host_monitor, name="HostMonitor", daemon=True).start()
    
    print("\033[96m  🔴 AGENT IS LIVE. Press Ctrl+C to stop.\033[0m\n")
    try:
        task_c_status_reporter()
    except KeyboardInterrupt:
        print("\n\033[91m  🛑 [Agent] Shutdown signal received. Stopping...\033[0m")
        print_status()
        print("\033[96m  👋 AI-NOC Agent offline. Goodbye.\033[0m")