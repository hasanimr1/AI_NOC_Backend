import os
import redis
import json
import time
import joblib
import warnings
import psycopg2
from transformers import pipeline

warnings.filterwarnings("ignore")
print("🛡️ Security Worker is waking up...")
 
# 1. LOAD THE REAL HIKARI BRAIN (Isolation Forest + Profiles)
print("🧠 Loading the trained Hikari 2021 AI Brain...")
try:
    saved_brain = joblib.load("hikari_ai_brain.pkl")
    math_ai = saved_brain['model']
    attack_profiles = saved_brain['profiles']
except FileNotFoundError:
    print("❌ ERROR: 'hikari_ai_brain.pkl' not found. Did you run train_ai.py first?")
    exit()

# Helper Function: Name the attack using learned patterns
def identify_attack(flow, fwd, bwd):
    best_match = "Unknown Hikari Anomaly"
    min_dist = float('inf')
    for attack_name, features in attack_profiles.items():
        # Find which attack fingerprint matches these numbers closest
        dist = abs(features['flow_duration'] - flow) + abs(features['fwd_pkts_tot'] - fwd) + abs(features['bwd_pkts_tot'] - bwd)
        if dist < min_dist:
            min_dist = dist
            best_match = attack_name
    return best_match
  
# 2. WAKE UP THE TEXT AI 
print("📖 Waking up Language AI (DistilBERT)...")
text_ai = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")
 
# 3. CONNECT TO REDIS ("The Waiting Room")
redis_client = redis.Redis(host=os.getenv("REDIS_HOST", "redis"), port=6379, db=0, decode_responses=True)
print("✅ Connected to Redis Queue!")

# 4. CONNECT TO POSTGRES/TIMESCALEDB ("The Vault")
DB_HOST = os.getenv("DB_HOST", "timescaledb")
DB_NAME = os.getenv("DB_NAME", "nocsoc_db")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASS = os.getenv("DB_PASS", "yourpassword") # Change to your actual DB password

def get_db_connection():
    print("🔐 Connecting to the Database Vault...")
    while True:
        try:
            conn = psycopg2.connect(
                host=DB_HOST,
                database=DB_NAME,
                user=DB_USER,
                password=DB_PASS
            )
            print("✅ Successfully connected to the Vault (TimescaleDB)!")
            return conn
        except psycopg2.OperationalError:
            print("⏳ Database not ready yet. Retrying in 3 seconds...")
            time.sleep(3)

db_conn = get_db_connection()
cursor = db_conn.cursor()

# Helper Function: Save Alert to Database
def save_alert_to_db(device_name, threat_type, severity, raw_data):
    try:
        # Step 1: Find or create the Device
        cursor.execute("SELECT DeviceID FROM Device WHERE DeviceName = %s", (device_name,))
        result = cursor.fetchone()
        if result:
            db_device_id = result[0]
        else:
            cursor.execute(
                "INSERT INTO Device (DeviceName, IP_Address) VALUES (%s, %s) RETURNING DeviceID",
                (device_name, raw_data.get('ip_address', '0.0.0.0'))
            )
            db_device_id = cursor.fetchone()[0]

        # Step 2: Insert a Log entry (matches Log table schema)
        log_message = f"{threat_type}: {json.dumps(raw_data)}"
        cursor.execute(
            "INSERT INTO Log (DeviceID, Timestamp, LogMessage) VALUES (%s, NOW(), %s) RETURNING LogID, Timestamp",
            (db_device_id, log_message)
        )
        log_id, log_timestamp = cursor.fetchone()

        # Step 3: Map severity to Priority and FinalScore
        priority_map = {"HIGH": "Critical", "MEDIUM": "Warning", "LOW": "Info"}
        score_map = {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3}
        priority = priority_map.get(severity, "Info")
        final_score = score_map.get(severity, 0.0)

        # Step 4: Insert the Alert (matches Alert table schema)
        cursor.execute(
            """INSERT INTO Alert (LogID, LogTimestamp, Timestamp, Priority, Status, FinalScore)
               VALUES (%s, %s, NOW(), %s, %s, %s)""",
            (log_id, log_timestamp, priority, "New", final_score)
        )

        db_conn.commit() # Lock it into the hard drive
        print("   💾 Alert securely saved to the Vault!")
    except Exception as e:
        print(f"   ❌ Failed to save alert to Database: {e}")
        db_conn.rollback() # Reset transaction state so the worker doesn't crash

print("🚀 Worker fully awake and patrolling! Waiting for data...\n")
 
# 5. INFINITE LOOP (The guard never sleeps) 
while True:
    try:
        queue_name, message_data = redis_client.brpop(["log_queue", "metric_queue"])
        data = json.loads(message_data)
        
        # Determine device name for the database
        device_name = data.get('device_name', data.get('device_id', 'Unknown Device'))
        
        # --- SCENARIO A: NUMBERS (Hikari Attack Detection) ---
        if queue_name == "metric_queue":
            print(f"\n📊 Analyzing Network Traffic from {device_name}...")
            
            flow = float(data['flow_duration'])
            fwd = float(data['fwd_pkts_tot'])
            bwd = float(data['bwd_pkts_tot'])
            
            # Isolation Forest asks: Is this normal [1] or an attack [-1]?
            prediction = math_ai.predict([[flow, fwd, bwd]])[0]
            
            if prediction == 1:
                print("   ✅ Traffic looks perfectly normal.")
            else:
                attack_name = identify_attack(flow, fwd, bwd)
                print(f"   🚨 THREAT DETECTED: Network Anomaly!")
                print(f"   🔍 Hikari Signature Match -> [{attack_name}]")
                
                # NEW: Save to Database!
                save_alert_to_db(
                    device_name=device_name,
                    threat_type=f"Network Anomaly: {attack_name}",
                    severity="HIGH",
                    raw_data=data
                )

        # --- SCENARIO B: TEXT (Log Analysis) ---
        elif queue_name == "log_queue":
            print(f"\n📝 Analyzing Text Log from {device_name}...")
            
            message_text = data['message']
            ai_result = text_ai(message_text)[0] 
            
            label = ai_result['label']
            score = ai_result['score']
            
            if label == "NEGATIVE" and score > 0.90:
                print(f"   🚨 THREAT DETECTED in Text! (Certainty: {score * 100:.1f}%)")
                print(f"   -> Text flagged: '{message_text}'")
                
                # NEW: Save to Database!
                save_alert_to_db(
                    device_name=device_name,
                    threat_type="Malicious Text Log",
                    severity="MEDIUM", # Or HIGH depending on your preference
                    raw_data=data
                )
            else:
                print(f"   ✅ Log text seems safe. (Certainty: {score * 100:.1f}%)")

        time.sleep(0.1) # Tiny pause to prevent CPU pegging during massive data floods

    except Exception as e:
        print(f"\n⚠️ Unexpected Error in Main Loop: {e}")
        time.sleep(1) # Wait a second before trying to process the next queue item