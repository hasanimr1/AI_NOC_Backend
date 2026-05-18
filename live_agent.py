"""
╔══════════════════════════════════════════════════════════════════════╗
║          AI-NOC LIVE DATA SHIPPER AGENT  //  live_agent.py           ║
║          Simulates live network telemetry for FYP presentation       ║
╠══════════════════════════════════════════════════════════════════════╣
║  TASK A ─ Network Traffic Replayer  → HITS /ingest/metrics (MATH)    ║
║  TASK B ─ Live Host Monitor         → HITS /ingest/logs (TEXT NLP)   ║
╚══════════════════════════════════════════════════════════════════════╝
"""
import threading
import time
import random
import os
import json
import socket
import requests
import psutil
import pandas as pd

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
BACKEND_URL      = "http://localhost:8000"   
CSV_FILE         = "hikari_2021.csv"         

REPLAY_INTERVAL_MIN = 1
REPLAY_INTERVAL_MAX = 3
TELEMETRY_INTERVAL  = 3

# UPGRADED: Put 'traffic_category' first so it extracts the actual Attack Name!
LABEL_COLUMN_CANDIDATES =[
    "traffic_category", "traffic_cat", "Category", "category", "Attack", "attack", 
    "Class", "class", "Label", "label"
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

def get_local_ip():
    """Gets the real local IP of this machine to populate the dashboard."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

LOCAL_IP = get_local_ip()

def banner():
    print("\033[96m")   
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║   🛡️  AI-NOC LIVE DATA SHIPPER AGENT  //  SYSTEM BOOT          ║")
    print("║   Connecting to AI-NOC Backend at:  " + BACKEND_URL.ljust(29) + "║")
    print("║   Local Machine IP:                 " + LOCAL_IP.ljust(29) + "║")
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
    except Exception:
        pass
    with stats_lock:
        stats["errors"] += 1
    return False

# ─────────────────────────────────────────────────────────────────────────────
# TASK A  ─  NETWORK TRAFFIC REPLAYER (Proactive Dataset Sampling)
# ─────────────────────────────────────────────────────────────────────────────
DEVICE_POOL =[
    "Core-Router-01", "Firewall-Ext", "Switch-01", "Server-Web",
    "Auth-Gateway",   "Database-01", "File-Server", "API-Server",
    "Worker-Node",    "Gateway-01",
]

def load_and_split_csv():
    """Loads CSV and splits into Normal and Attack pools for aggressive sampling."""
    if not os.path.exists(CSV_FILE):
        print(f"\033[91m❌ ERROR: '{CSV_FILE}' not found.\033[0m")
        return None, None

    print(f"\033[92m  📂 [Replayer] Preparing dataset for high-volume attack testing...\033[0m", end="", flush=True)
    df = pd.read_csv(CSV_FILE, low_memory=False)
    df.columns = df.columns.str.strip() 
    
    label_col = 'Label' if 'Label' in df.columns else 'label'
    
    # UPGRADED: Force numeric conversion so the dataset splits perfectly every time
    df[label_col] = pd.to_numeric(df[label_col], errors='coerce').fillna(0)
    
    normal_df = df[df[label_col] == 0]
    attack_df = df[df[label_col] == 1]
    
    print(f"\033[92m Done!\033[0m")
    print(f"     📊 Pool: {len(normal_df):,} Normal | {len(attack_df):,} Attacks available.")
    return normal_df, attack_df

def row_to_payload(row: pd.Series) -> dict:
    simulated_ip = f"192.168.1.{random.randint(10, 250)}"
    
    try: flow_dur = float(row.get("flow_duration", 0.0))
    except: flow_dur = 0.0
    try: fwd_pkts = float(row.get("fwd_pkts_tot", 0.0))
    except: fwd_pkts = 0.0
    try: bwd_pkts = float(row.get("bwd_pkts_tot", 0.0))
    except: bwd_pkts = 0.0

    return {
        "device_name": random.choice(DEVICE_POOL),
        "ip_address": simulated_ip,
        "flow_duration": flow_dur,
        "fwd_pkts_tot": fwd_pkts,
        "bwd_pkts_tot": bwd_pkts,
        "timestamp": str(time.time()),
    }

def pick_label(row: pd.Series) -> str:
    for col in LABEL_COLUMN_CANDIDATES:
        if col in row.index and pd.notna(row[col]) and str(row[col]).strip():
            return str(row[col]).strip()
    return "Network Flow"

def task_a_replayer():
    normal_pool, attack_pool = load_and_split_csv()
    if normal_pool is None: return

    endpoint = f"{BACKEND_URL}/ingest/metrics"
    print(f"\033[92m  🚀 [Replayer] Task A started. Generating heavy attack traffic...\033[0m")

    EXTREME_THREATS = {
        'DDoS Attack': {'flow_duration': 9999999.0, 'fwd_pkts_tot': 85000.0, 'bwd_pkts_tot': 90000.0},
        'Probing Attack': {'flow_duration': 500.0, 'fwd_pkts_tot': 1000.0, 'bwd_pkts_tot': 2.0},
        'Botnet Activity': {'flow_duration': 80000.0, 'fwd_pkts_tot': 400.0, 'bwd_pkts_tot': 400.0},
        'Crypto-Miner': {'flow_duration': 999999.0, 'fwd_pkts_tot': 50.0, 'bwd_pkts_tot': 50.0},
        'Data Exfiltration': {'flow_duration': 50.0, 'fwd_pkts_tot': 10.0, 'bwd_pkts_tot': 99999.0},
        'Ping Flood': {'flow_duration': 5.0, 'fwd_pkts_tot': 10000.0, 'bwd_pkts_tot': 10000.0},
        'Hikari Bruteforce': {'flow_duration': 15000.0, 'fwd_pkts_tot': 200.0, 'bwd_pkts_tot': 150.0},
        'Hikari Bruteforce-XML': {'flow_duration': 25000.0, 'fwd_pkts_tot': 300.0, 'bwd_pkts_tot': 250.0},
        'Hikari XMRIGCC CryptoMiner': {'flow_duration': 888888.0, 'fwd_pkts_tot': 60.0, 'bwd_pkts_tot': 60.0}
    }

    while True:
        time.sleep(random.uniform(REPLAY_INTERVAL_MIN, REPLAY_INTERVAL_MAX))
        
        # AGGRESSIVE SAMPLING: 70% chance to pick a real attack row
        is_attack = False
        payload = {}
        label = "Network Flow"

        if random.random() < 0.7:
            is_attack = True
            label = random.choice(list(EXTREME_THREATS.keys()))
            threat = EXTREME_THREATS[label]
            
            # Use public malicious IPs occasionally to trigger AlienVault
            malicious_ips = ["185.220.101.14", "45.133.1.20", "193.201.224.238", "103.111.45.10"]
            attack_ip = random.choice(malicious_ips) if random.random() < 0.5 else f"192.168.1.{random.randint(10, 250)}"
            
            payload = {
                "device_name": random.choice(DEVICE_POOL),
                "ip_address": attack_ip,
                "flow_duration": threat['flow_duration'],
                "fwd_pkts_tot": threat['fwd_pkts_tot'],
                "bwd_pkts_tot": threat['bwd_pkts_tot'],
                "timestamp": str(time.time()),
            }
        else:
            row = normal_pool.sample(1).iloc[0]
            payload = row_to_payload(row)
            label = pick_label(row)

        if is_attack:
            print(f"\033[91m  🔥 [Replayer] Injecting MALICIOUS vector » \033[1m[{label}]\033[0m")
        else:
            print(f"\033[94m  🚨 [Replayer] Injecting NORMAL traffic vector » \033[1m[{label}]\033[0m")

        if safe_post(endpoint, payload, source_label="Replayer"):
            with stats_lock:
                stats["replays_sent"] += 1

# ─────────────────────────────────────────────────────────────────────────────
# TASK B  ─  LIVE HOST MONITOR (Real IP Detection)
# ─────────────────────────────────────────────────────────────────────────────
def task_b_host_monitor():
    endpoint = f"{BACKEND_URL}/ingest/logs"
    print(f"\033[95m  🚀 [HostMonitor] Task B started. Tracking Host: {LOCAL_IP}\033[0m")

    prev_net  = psutil.net_io_counters()
    prev_time = time.time()

    while True:
        time.sleep(TELEMETRY_INTERVAL)
        cpu_pct  = psutil.cpu_percent(interval=None)
        ram_pct  = psutil.virtual_memory().percent
        
        curr_net  = psutil.net_io_counters()
        curr_time = time.time()
        delta_t   = max(curr_time - prev_time, 0.001)

        tx_kbps = (curr_net.bytes_sent - prev_net.bytes_sent) / delta_t / 1024
        rx_kbps = (curr_net.bytes_recv - prev_net.bytes_recv) / delta_t / 1024
        prev_net, prev_time = curr_net, curr_time

        message = f"HOST_TELEMETRY: [CPU={cpu_pct:.1f}% | RAM={ram_pct:.1f}% | TX={tx_kbps:.1f}KB/s | RX={rx_kbps:.1f}KB/s]"
        
        payload = {
            "device_name": "Core-Router-Local", 
            "ip_address": LOCAL_IP, 
            "message": message, 
            "timestamp": now_iso()
        }

        print(f"\033[95m  📡 [HostMonitor] Streaming live telemetry from {LOCAL_IP}...\033[0m")
        if safe_post(endpoint, payload, source_label="HostMonitor"):
            with stats_lock:
                stats["telemetry_sent"] += 1

def task_c_status_reporter():
    while True:
        time.sleep(15)
        print_status()

if __name__ == "__main__":
    banner()
    threading.Thread(target=task_a_replayer, name="TrafficReplayer", daemon=True).start()
    threading.Thread(target=task_b_host_monitor, name="HostMonitor", daemon=True).start()
    
    try:
        task_c_status_reporter()
    except KeyboardInterrupt:
        print("\n\033[91m  🛑 [Agent] Offline. Goodbye.\033[0m")