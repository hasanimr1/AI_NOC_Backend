import os
import redis
import json
import time
import joblib
import warnings
import psycopg2
import psycopg2.extras 
import math   
from transformers import pipeline
from OTXv2 import OTXv2, IndicatorTypes


warnings.filterwarnings("ignore")
print("🛡️ Security Guard waking up with Adaptive Intelligence...")
 
# 1. LOAD THE REAL HIKARI BRAIN
print("🧠 Loading the synchronized Hikari AI Brain...")
try:
    saved_brain = joblib.load("hikari_ai_brain.pkl")
    math_ai = saved_brain['model']
    attack_profiles = saved_brain['profiles']
except FileNotFoundError:
    print("❌ ERROR: 'hikari_ai_brain.pkl' not found. Did you run train_ai.py first?")
    exit()

def identify_attack(flow, fwd, bwd):
    """
    UPGRADE: TRUE 3D EUCLIDEAN DISTANCE MAPPING
    Calculates the exact geometric distance between the incoming attack 
    and all known Hikari dataset labels.
    """
    best_match = "Unknown Hikari Anomaly"
    min_dist = float('inf')
    
    for attack_name, features in attack_profiles.items():
        # Euclidean Formula: sqrt( (x2 - x1)^2 + (y2 - y1)^2 + (z2 - z1)^2 )
        dist = math.sqrt(
            ((features['flow_duration'] - flow) ** 2) + 
            ((features['fwd_pkts_tot'] - fwd) ** 2) + 
            ((features['bwd_pkts_tot'] - bwd) ** 2)
        )
        if dist < min_dist:
            min_dist = dist
            best_match = attack_name
            
    return best_match, min_dist

# ============================================================
# SOAR ENGINE: MAPPING ATTACKS TO SOLUTIONS
# ============================================================
def get_ai_solution(threat_name):
    """
    SOAR Engine: Maps the precise AI threat classification to an expert-approved playbook.
    """
    playbook = {
        "DDoS Attack": "Rate-limit traffic on edge router. Enable DDoS protection node. Monitor bandwidth.",
        "Probing Attack": "Block the scanning IP at the perimeter firewall. Ensure unused ports are closed.",
        "Botnet Activity": "Isolate the infected device from the network. Block outbound connections to the C2 server.",
        "Crypto-Miner": "Terminate high-CPU processes. Block stratum mining ports (3333, 4444). Quarantine the server.",
        "XMRIGCC": "Kill mining process. Quarantine node for re-imaging. Review cron jobs for persistence.",
        "XMRIGCC Miner": "Kill mining process. Quarantine node for re-imaging. Review cron jobs for persistence.",
        "Data Leak": "Immediately block outbound FTP/SCP connections. Reset user credentials. Audit accessed files.",
        "Data Exfiltration": "Immediately block outbound FTP/SCP connections. Reset user credentials. Audit accessed files.",
        "Ping Flood": "Configure firewall to drop inbound ICMP echo requests from the offending subnet.",
        "Hikari Bruteforce": "Enforce account lockouts and require MFA. Temporarily ban the source IP at the firewall.",
        "Hikari Bruteforce-XML": "Deploy a WAF rule to block malformed XML payloads. Rate-limit API endpoints.",
        "Brute-Force Attack": "Force password resets for targeted accounts. Implement progressive delays on login failures.",
        "SQL Injection": "Sanitize database inputs. Deploy WAF rule to block SQL syntax strings. Audit the web form."
    }
    
    # AI Logic: Find best match in playbook
    for key, strategy in playbook.items():
        if key.lower() in threat_name.lower():
            return strategy
            
    return f"Block the source IP and isolate the affected devices to prevent {threat_name} spread."
  
print("📖 Waking up Language AI (DistilBERT)...")
text_ai = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")

print("👽 Initializing AlienVault OTX Client...")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
if OTX_API_KEY and OTX_API_KEY != "YOUR_ALIENVAULT_API_KEY":
    try:
        otx = OTXv2(OTX_API_KEY)
        print("✅ Connected to AlienVault OTX!")
    except Exception as e:
        print(f"⚠️ Failed to connect to AlienVault OTX: {e}")
        otx = None
else:
    print("⚠️ No valid OTX_API_KEY provided. AlienVault IP checks will be skipped.")
    otx = None

def get_alienvault_score(ip_address):
    if not otx or not ip_address or ip_address == '0.0.0.0':
        return 0.0
    
    # Ignore private and loopback IPs to save API rate limits and prevent worker freeze
    if ip_address.startswith(('192.168.', '10.', '127.')) or any(ip_address.startswith(f'172.{i}.') for i in range(16, 32)):
        return 0.0

    try:
        details = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip_address)
        pulse_count = details.get('general', {}).get('pulse_info', {}).get('count', 0)
        # Cap at 5 pulses for a max score of 1.0 (100%)
        return min(1.0, pulse_count / 5.0)
    except Exception as e:
        print(f"   ⚠️ AlienVault OTX check failed for {ip_address}: {e}")
        return 0.0

redis_client = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=6379, db=0, decode_responses=True)
print("✅ Connected to Redis Queue!")

DB_HOST = os.getenv("DB_HOST", "db")
DB_NAME = os.getenv("DB_NAME", "alerts_db")
DB_USER = os.getenv("DB_USER", "admin")
DB_PASS = os.getenv("DB_PASS", "adminpassword")

def get_db_connection():
    while True:
        try:
            conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
            print("✅ Successfully connected to the Vault!")
            return conn
        except psycopg2.OperationalError:
            time.sleep(3)

db_conn = get_db_connection()
cursor = db_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

# ============================================================
# ADAPTIVE LEARNING CHECK
# ============================================================
def check_for_false_positive(pattern_type, vector_or_text):
    try:
        cursor.execute(
            "SELECT 1 FROM AI_Feedback WHERE PatternType = %s AND FeatureVector = %s",
            (pattern_type, str(vector_or_text))
        )
        return cursor.fetchone() is not None
    except Exception:
        return False

# ============================================================
# DEVICE & DATA HELPERS
# ============================================================
def get_or_create_device(device_name, ip_address='0.0.0.0'):
    """Finds or creates a device and returns (DeviceID, CriticalityScore)."""
    cursor.execute("SELECT DeviceID, CriticalityScore FROM Device WHERE DeviceName = %s", (device_name,))
    result = cursor.fetchone()
    if result: return result['deviceid'], result['criticalityscore']
    
    name_lower = device_name.lower()
    if any(x in name_lower for x in ["core", "firewall", "gateway"]):
        crit_score = 100
    elif any(x in name_lower for x in ["database", "auth"]):
        crit_score = 90
    elif any(x in name_lower for x in ["server", "api", "node"]):
        crit_score = 80
    else:
        crit_score = 50
        
    cursor.execute(
        "INSERT INTO Device (DeviceName, IP_Address, CriticalityScore) VALUES (%s, %s, %s) RETURNING DeviceID", 
        (device_name, ip_address, crit_score)
    )
    return cursor.fetchone()['deviceid'], crit_score

def save_log_to_db(device_id, log_message, event_timestamp=None):
    if event_timestamp:
        cursor.execute("INSERT INTO Log (DeviceID, Timestamp, LogMessage) VALUES (%s, TO_TIMESTAMP(%s), %s) RETURNING LogID, Timestamp", (device_id, float(event_timestamp), log_message))
    else:
        cursor.execute("INSERT INTO Log (DeviceID, Timestamp, LogMessage) VALUES (%s, NOW(), %s) RETURNING LogID, Timestamp", (device_id, log_message))
    return cursor.fetchone()

def save_metrics_to_db(device_id, flow_duration, fwd_pkts, bwd_pkts, event_timestamp=None):
    # CRITICAL: We save 'flow_duration' specifically for the Dashboard Chart
    metrics =[("flow_duration", flow_duration), ("fwd_pkts_tot", fwd_pkts), ("bwd_pkts_tot", bwd_pkts)]
    for metric_type, value in metrics:
        if event_timestamp:
            cursor.execute("INSERT INTO Metric (DeviceID, Timestamp, MetricType, Value) VALUES (%s, TO_TIMESTAMP(%s), %s, %s)", (device_id, float(event_timestamp), metric_type, value))
        else:
            cursor.execute("INSERT INTO Metric (DeviceID, Timestamp, MetricType, Value) VALUES (%s, NOW(), %s, %s)", (device_id, metric_type, value))

def save_alert_from_log(log_id, log_timestamp, severity, final_score, solution, pattern_to_check, pattern_type, event_timestamp=None):
    priority = "Critical" if severity == "HIGH" else "Warning"
    status = "New"
    
    # Adaptive Suppression Logic: Check memory vault before creating alert
    if check_for_false_positive(pattern_type, pattern_to_check):
        status = "False Positive"
        print(f"   🤖 ADAPTIVE AI: Pattern recognized as known False Positive. Auto-marking.")

    if event_timestamp:
        cursor.execute("INSERT INTO Alert (LogID, LogTimestamp, Timestamp, Priority, Status, FinalScore, Solution) VALUES (%s, %s, TO_TIMESTAMP(%s), %s, %s, %s, %s)", (log_id, log_timestamp, float(event_timestamp), priority, status, final_score, solution))
    else:
        cursor.execute("INSERT INTO Alert (LogID, LogTimestamp, Timestamp, Priority, Status, FinalScore, Solution) VALUES (%s, %s, NOW(), %s, %s, %s, %s)", (log_id, log_timestamp, priority, status, final_score, solution))

print("🚀 Worker fully awake and patrolling! Waiting for data...\n")
 
while True:
    try:
        queue_name, message_data = redis_client.brpop(["log_queue", "metric_queue"])
        data = json.loads(message_data)
        device_name = data.get('device_name', 'Unknown Device')
        event_timestamp = data.get('timestamp')
        ip_addr = data.get('ip_address', '0.0.0.0')
        
        db_device_id, device_criticality = get_or_create_device(device_name, ip_addr)
        
        if queue_name == "metric_queue":
            flow, fwd, bwd = float(data['flow_duration']), float(data['fwd_pkts_tot']), float(data['bwd_pkts_tot'])
            try:
                save_metrics_to_db(db_device_id, flow, fwd, bwd, event_timestamp)
                db_conn.commit()
            except Exception: db_conn.rollback()

            prediction = math_ai.predict([[flow, fwd, bwd]])[0]
            attack_name, min_dist = identify_attack(flow, fwd, bwd)
            
            if prediction == -1 or min_dist < 1.0:
                solution = get_ai_solution(attack_name)
                
                model_score = 1.0
                av_score = get_alienvault_score(ip_addr)
                final_score = (model_score * 0.6) + (av_score * 0.4)
                
                fusion_score = float(device_criticality * final_score)
                
                # Format must perfectly match JSON dump from main.py's StatusUpdate endpoint
                metric_vector = json.dumps({"flow": flow, "fwd": fwd, "bwd": bwd})
                
                print(f"\n   🚨 THREAT DETECTED: {attack_name}")
                if av_score > 0:
                    print(f"   👽 ALIENVAULT INTEL: IP {ip_addr} is a Known Malicious Threat! (Score: {av_score*100:.1f}%)")
                print(f"   ⚙️ FUSION ENGINE SCORE: {fusion_score}")
                print(f"   🔥 CRITICALITY SCORE: {device_criticality}")
                print(f"   📏 CERTAINTY (EUCLIDEAN MATH): {round(min_dist, 4)}")
                print(f"   💡 AI SOLUTION: {solution}\n")
                
                try:
                    log_msg = f"[{attack_name}] Anomalous Traffic Detected (Flow: {flow})"
                    log_res = save_log_to_db(db_device_id, log_msg, event_timestamp)
                    save_alert_from_log(log_res['logid'], log_res['timestamp'], "HIGH", fusion_score, solution, metric_vector, "Metric", event_timestamp)
                    db_conn.commit()
                except Exception as e: 
                    print(f"Alert save error: {e}")
                    db_conn.rollback()
            else:
                # LOUD PRINT for Safe Traffic
                print(f"   ✅ HEARTBEAT: Normal metrics from {device_name} logged to baseline. (Score: 0.0)")

        elif queue_name == "log_queue":
            message_text = data['message']
            ai_result = text_ai(message_text)[0] 
            label, certainty = ai_result['label'], ai_result['score']

            if label == "NEGATIVE" and certainty > 0.85:
                threat_name = "Brute-Force Attack" if "password" in message_text.lower() else "SQL Injection" if "sql" in message_text.lower() else "Suspicious Text Log"
                solution = get_ai_solution(threat_name)
                
                model_score = certainty
                av_score = get_alienvault_score(ip_addr)
                final_score = (model_score * 0.6) + (av_score * 0.4)
                
                fusion_score = round(final_score * device_criticality, 2)
                
                print(f"\n   🚨 THREAT DETECTED: {threat_name}")
                if av_score > 0:
                    print(f"   👽 ALIENVAULT INTEL: IP {ip_addr} is a Known Malicious Threat! (Score: {av_score*100:.1f}%)")
                print(f"   ⚙️ FUSION ENGINE SCORE: {fusion_score}")
                print(f"   🔥 CRITICALITY SCORE: {device_criticality}")
                print(f"   📏 CERTAINTY (NLP SCORE): {round(certainty, 4)}")
                print(f"   💡 AI SOLUTION: {solution}\n")
                
                try:
                    final_log_msg = f"[{threat_name}] {message_text}"
                    log_res = save_log_to_db(db_device_id, final_log_msg, event_timestamp)
                    save_alert_from_log(log_res['logid'], log_res['timestamp'], "HIGH", fusion_score, solution, message_text, "Log", event_timestamp)
                    db_conn.commit()
                except Exception as e: 
                    print(f"Alert save error: {e}")
                    db_conn.rollback()
            else:
                try:
                    save_log_to_db(db_device_id, message_text, event_timestamp)
                    db_conn.commit()
                    print(f"   ✅ HEARTBEAT: Safe log from {device_name} logged to baseline.")
                except Exception: db_conn.rollback()

        time.sleep(0.1)
    except Exception as e:
        print(f"\n⚠️ Unexpected Error: {e}")
        db_conn.rollback()
        time.sleep(1)