import os
import redis
import json
import time
import joblib
import warnings
import psycopg2
import math   
from transformers import pipeline
from OTXv2 import OTXv2, IndicatorTypes

warnings.filterwarnings("ignore")
print("🛡️ Security Worker is waking up...")
 
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
            
    return best_match
  
print("📖 Waking up Language AI (DistilBERT)...")
text_ai = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")

print("💡 Waking up Solution Generator AI (DistilBERT)...")
# Note: Using distilgpt2 as the lightweight generative model corresponding to the "distil" requirement
solution_ai = pipeline("text-generation", model="distilgpt2")

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
    try:
        details = otx.get_indicator_details_full(IndicatorTypes.IPv4, ip_address)
        pulse_count = details.get('general', {}).get('pulse_info', {}).get('count', 0)
        # Cap at 5 pulses for a max score of 1.0 (100%)
        return min(1.0, pulse_count / 5.0)
    except Exception as e:
        print(f"   ⚠️ AlienVault OTX check failed for {ip_address}: {e}")
        return 0.0

def generate_solution(threat_name):
    print(f"   🧠 Generating AI solution for {threat_name}...")
    try:
        prompt = f"To mitigate the {threat_name} cyber attack, the best security solution is to"
        # We keep max_new_tokens low for fast generation
        result = solution_ai(prompt, max_new_tokens=25, num_return_sequences=1, truncation=True)
        generated_text = result[0]['generated_text']
        
        # Clean up text to avoid abrupt endings
        clean_text = generated_text.replace(prompt, "To mitigate, ").replace("\n", " ").strip()
        sentences = clean_text.split('.')
        if len(sentences) > 1:
            solution = '.'.join(sentences[:-1]) + '.'
        else:
            solution = clean_text + "..."
            
        if len(solution) > 250:
            solution = solution[:247] + "..."
        return solution
    except Exception as e:
        print(f"   ⚠️ AI Generation failed: {e}")
        return f"Block the source IP and isolate the affected devices to prevent {threat_name} spread."
 
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
cursor = db_conn.cursor()

def ensure_solution_column():
    try:
        cursor.execute("ALTER TABLE Alert ADD COLUMN IF NOT EXISTS Solution TEXT;")
        db_conn.commit()
        print("✅ Ensured 'Solution' column exists in Alert table.")
    except Exception as e:
        db_conn.rollback()
        print(f"⚠️ Could not add Solution column (might already exist): {e}")

ensure_solution_column()

# ============================================================
# UPGRADED: DEVICE CRITICALITY SCORING
# ============================================================
def get_or_create_device(device_name, ip_address='0.0.0.0'):
    cursor.execute("SELECT DeviceID FROM Device WHERE DeviceName = %s", (device_name,))
    result = cursor.fetchone()
    if result: return result[0]
    
    # NEW LOGIC: Assign a Criticality Score (0-100) based on Device Role
    name_lower = device_name.lower()
    if "core" in name_lower or "firewall" in name_lower or "gateway" in name_lower:
        crit_score = 100  # Mission Critical Infrastructure
    elif "database" in name_lower or "auth" in name_lower:
        crit_score = 90   # High Priority Servers
    elif "server" in name_lower or "api" in name_lower or "node" in name_lower:
        crit_score = 80   # Important App Servers
    else:
        crit_score = 50   # Standard Edge Switch / Unknown
        
    cursor.execute(
        "INSERT INTO Device (DeviceName, IP_Address, CriticalityScore) VALUES (%s, %s, %s) RETURNING DeviceID", 
        (device_name, ip_address, crit_score)
    )
    return cursor.fetchone()[0]

def save_log_to_db(device_id, log_message, event_timestamp=None):
    if event_timestamp:
        cursor.execute("INSERT INTO Log (DeviceID, Timestamp, LogMessage) VALUES (%s, TO_TIMESTAMP(%s), %s) RETURNING LogID, Timestamp", (device_id, float(event_timestamp), log_message))
    else:
        cursor.execute("INSERT INTO Log (DeviceID, Timestamp, LogMessage) VALUES (%s, NOW(), %s) RETURNING LogID, Timestamp", (device_id, log_message))
    return cursor.fetchone()

def save_metrics_to_db(device_id, flow_duration, fwd_pkts, bwd_pkts, event_timestamp=None):
    metrics =[("flow_duration", flow_duration), ("fwd_pkts_tot", fwd_pkts), ("bwd_pkts_tot", bwd_pkts)]
    for metric_type, value in metrics:
        if event_timestamp:
            cursor.execute("INSERT INTO Metric (DeviceID, Timestamp, MetricType, Value) VALUES (%s, TO_TIMESTAMP(%s), %s, %s)", (device_id, float(event_timestamp), metric_type, value))
        else:
            cursor.execute("INSERT INTO Metric (DeviceID, Timestamp, MetricType, Value) VALUES (%s, NOW(), %s, %s)", (device_id, metric_type, value))

def save_alert_from_log(log_id, log_timestamp, severity, score_value, event_timestamp=None, solution=""):
    priority_map = {"HIGH": "Critical", "MEDIUM": "Warning", "LOW": "Info"}
    priority = priority_map.get(severity, "Info")
    if event_timestamp:
        cursor.execute("INSERT INTO Alert (LogID, LogTimestamp, Timestamp, Priority, Status, FinalScore, Solution) VALUES (%s, %s, TO_TIMESTAMP(%s), %s, %s, %s, %s)", (log_id, log_timestamp, float(event_timestamp), priority, "New", score_value, solution))
    else:
        cursor.execute("INSERT INTO Alert (LogID, LogTimestamp, Timestamp, Priority, Status, FinalScore, Solution) VALUES (%s, %s, NOW(), %s, %s, %s, %s)", (log_id, log_timestamp, priority, "New", score_value, solution))

print("🚀 Worker fully awake and patrolling! Waiting for data...\n")
 
while True:
    try:
        queue_name, message_data = redis_client.brpop(["log_queue", "metric_queue"])
        data = json.loads(message_data)
        device_name = data.get('device_name', 'Unknown Device')
        event_timestamp = data.get('timestamp')
        
        if queue_name == "metric_queue":
            flow, fwd, bwd = float(data['flow_duration']), float(data['fwd_pkts_tot']), float(data['bwd_pkts_tot'])
            try:
                db_device_id = get_or_create_device(device_name, data.get('ip_address', '0.0.0.0'))
                save_metrics_to_db(db_device_id, flow, fwd, bwd, event_timestamp)
                db_conn.commit()
            except Exception: db_conn.rollback()

            prediction = math_ai.predict([[flow, fwd, bwd]])[0]
            if prediction == 1:
                print(f"   ✅ Traffic from {device_name} looks normal.")
            else:
                attack_name = identify_attack(flow, fwd, bwd)
                solution = generate_solution(attack_name)
                ip_addr = data.get('ip_address', '0.0.0.0')
                
                # Model score for Euclidean mapping is 1.0 (100%)
                model_score = 1.0
                av_score = get_alienvault_score(ip_addr)
                
                final_score = (model_score * 0.6) + (av_score * 0.4)
                
                print(f"   🚨 THREAT DETECTED: {attack_name}")
                print(f"   💡 SOLUTION: {solution}")
                print(f"   ⚙️ FUSION ENGINE: Euclidean Mapping ({model_score*100:.1f}%) + AlienVault ({av_score*100:.1f}%). Combined Criticality Score: {final_score * 100:.1f}%")
                try:
                    log_message = f"[{attack_name}] Anomalous Traffic Detected (Flow: {flow})"
                    log_id, log_ts = save_log_to_db(db_device_id, log_message, event_timestamp)
                    save_alert_from_log(log_id, log_ts, severity="HIGH", score_value=round(final_score, 3), event_timestamp=event_timestamp, solution=solution)
                    db_conn.commit()
                except Exception: db_conn.rollback()

        elif queue_name == "log_queue":
            message_text = data['message']
            ai_result = text_ai(message_text)[0] 
            label = ai_result['label']
            score = ai_result['score']
            
            db_device_id = get_or_create_device(device_name, data.get('ip_address', '0.0.0.0'))

            if label == "NEGATIVE" and score > 0.85:
                threat_name = "Suspicious Text Log"
                if "password" in message_text.lower() or "brute" in message_text.lower():
                    threat_name = "Brute-Force Attack"
                elif "sql" in message_text.lower() or "drop table" in message_text.lower():
                    threat_name = "SQL Injection"
                
                solution = generate_solution(threat_name)
                ip_addr = data.get('ip_address', '0.0.0.0')
                
                model_score = score
                av_score = get_alienvault_score(ip_addr)
                
                final_score = (model_score * 0.6) + (av_score * 0.4)
                
                print(f"   🚨 THREAT DETECTED: {threat_name}")
                print(f"   💡 SOLUTION: {solution}")
                print(f"   ⚙️ FUSION ENGINE: NLP Context Match ({model_score*100:.1f}%) + AlienVault ({av_score*100:.1f}%). Combined Criticality Score: {final_score * 100:.1f}%")
                
                try:
                    final_log_msg = f"[{threat_name}] {message_text}"
                    log_id, log_ts = save_log_to_db(db_device_id, final_log_msg, event_timestamp)
                    save_alert_from_log(log_id, log_ts, severity="HIGH", score_value=round(final_score, 3), event_timestamp=event_timestamp, solution=solution)
                    db_conn.commit()
                except Exception: db_conn.rollback()
            else:
                print(f"   ✅ Log from {device_name} is safe.")
                try:
                    save_log_to_db(db_device_id, message_text, event_timestamp)
                    db_conn.commit()
                except Exception: db_conn.rollback()

        time.sleep(0.1)

    except Exception as e:
        print(f"\n⚠️ Unexpected Error: {e}")
        time.sleep(1)