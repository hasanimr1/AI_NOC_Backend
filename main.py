from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import redis
import json
import time
import os
import psycopg2
import psycopg2.extras
import random

app = FastAPI(title="AI-NOC Ingestion API")
redis_client = redis.Redis(host='redis', port=6379, db=0, decode_responses=True)
 
# ============================================================
# DATABASE CONNECTION
# ============================================================
DB_HOST = os.getenv("DB_HOST", "db")
DB_NAME = os.getenv("DB_NAME", "alerts_db")
DB_USER = os.getenv("DB_USER", "admin")
DB_PASS = os.getenv("DB_PASS", "adminpassword")

def get_db_cursor():
    """Standard connection for prototype use."""
    conn = psycopg2.connect(host=DB_HOST, database=DB_NAME, user=DB_USER, password=DB_PASS)
    return conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
 
# ============================================================
# INGESTION MODELS
# ============================================================
class LogMessage(BaseModel):
    device_name: str
    ip_address: str = "0.0.0.0"
    message: str
    timestamp: str

class MetricMessage(BaseModel):
    device_name: str
    ip_address: str = "0.0.0.0"
    flow_duration: float
    fwd_pkts_tot: float
    bwd_pkts_tot: float
    timestamp: str
 
class StatusUpdate(BaseModel):
    status: str

class AssignAlert(BaseModel):
    admin_id: int
    role: str = "Investigator"

# ============================================================
# LIVE AGENT ENDPOINTS (Task A and Task B)
# ============================================================
@app.post("/ingest/logs")
async def ingest_logs(log: LogMessage):
    """Receives TEXT logs and sends to DistilBERT"""
    redis_client.lpush("log_queue", json.dumps(log.dict()))
    return {"status": "success"}

@app.post("/ingest/metrics")
async def ingest_metrics(metric: MetricMessage):
    """Receives LIVE NUMBERS and sends to Math AI"""
    redis_client.lpush("metric_queue", json.dumps(metric.dict()))
    return {"status": "success"}

# ============================================================
# INGESTION ENDPOINTS (Simulation Buttons - Synced with UI)
# ============================================================
@app.post("/ingest/simulate/normal")
async def simulate_normal():
    data = {"device_name": "Switch-01", "ip_address": "192.168.1.10", "flow_duration": 15.0, "fwd_pkts_tot": 8.0, "bwd_pkts_tot": 8.0, "timestamp": str(time.time())}
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "Normal traffic logged successfully!"}

@app.post("/ingest/simulate/ddos")
async def simulate_ddos():
    data = {"device_name": "Core-Router-01", "ip_address": "10.0.0.1", "flow_duration": 9999999.0, "fwd_pkts_tot": 85000.0, "bwd_pkts_tot": 90000.0, "timestamp": str(time.time())}
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "DDoS attack queued!"}

@app.post("/ingest/simulate/probing")
async def simulate_probing():
    data = {"device_name": "Firewall-Ext", "ip_address": "172.16.0.5", "flow_duration": 500.0, "fwd_pkts_tot": 1000.0, "bwd_pkts_tot": 2.0, "timestamp": str(time.time())}
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "Probing attack queued!"}

@app.post("/ingest/simulate/botnet")
async def simulate_botnet():
    data = {"device_name": "Server-Web", "ip_address": "10.0.0.50", "flow_duration": 80000.0, "fwd_pkts_tot": 400.0, "bwd_pkts_tot": 400.0, "timestamp": str(time.time())}
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "Botnet activity queued!"}

@app.post("/ingest/simulate/crypto-miner")
async def simulate_crypto():
    # EXTREME NUMBERS to force Anomaly detection
    data = {"device_name": "Database-01", "ip_address": "10.0.0.100", "flow_duration": 999999.0, "fwd_pkts_tot": 50.0, "bwd_pkts_tot": 50.0, "timestamp": str(time.time())}
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "Crypto Miner queued!"}

@app.post("/ingest/simulate/data-leak")
async def simulate_data_leak():
    # EXTREME NUMBERS to force Anomaly detection
    data = {"device_name": "File-Server", "ip_address": "10.0.0.150", "flow_duration": 50.0, "fwd_pkts_tot": 10.0, "bwd_pkts_tot": 99999.0, "timestamp": str(time.time())}
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "Data Leak queued!"}

@app.post("/ingest/simulate/ping-flood")
async def simulate_ping_flood():
    data = {"device_name": "Gateway-01", "ip_address": "192.168.0.1", "flow_duration": 5.0, "fwd_pkts_tot": 10000.0, "bwd_pkts_tot": 10000.0, "timestamp": str(time.time())}
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "Ping Flood queued!"}

@app.post("/ingest/simulate/hikari-bruteforce")
async def simulate_hikari_bf():
    data = {"device_name": "Auth-Gateway", "ip_address": "10.0.0.20", "flow_duration": 15000.0, "fwd_pkts_tot": 200.0, "bwd_pkts_tot": 150.0, "timestamp": str(time.time())}
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "Hikari Net-Bruteforce queued!"}

@app.post("/ingest/simulate/hikari-bruteforce-xml")
async def simulate_hikari_bf_xml():
    data = {"device_name": "API-Server", "ip_address": "10.0.0.30", "flow_duration": 25000.0, "fwd_pkts_tot": 300.0, "bwd_pkts_tot": 250.0, "timestamp": str(time.time())}
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "Hikari Bruteforce-XML queued!"}

@app.post("/ingest/simulate/xmrigcc")
async def simulate_hikari_xmrigcc():
    # EXTREME NUMBERS to force Anomaly detection
    data = {"device_name": "Worker-Node", "ip_address": "10.0.0.40", "flow_duration": 888888.0, "fwd_pkts_tot": 60.0, "bwd_pkts_tot": 60.0, "timestamp": str(time.time())}
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "XMRIGCC Miner queued!"}

@app.post("/ingest/simulate/random-anomaly")
async def simulate_random():
    data = {
        "device_name": "Unknown-Device",
        "ip_address": "0.0.0.0",
        "flow_duration": random.uniform(1000.0, 9999999.0),
        "fwd_pkts_tot": random.uniform(50.0, 100000.0),
        "bwd_pkts_tot": random.uniform(50.0, 100000.0),
        "timestamp": str(time.time())
    }
    redis_client.lpush("metric_queue", json.dumps(data))
    return {"status": "success", "message": "Random Attack Queued!"}

@app.post("/ingest/simulate/brute-force")
async def simulate_brute_force():
    data = {"device_name": "Auth-Server", "ip_address": "10.0.0.20", "message": "CRITICAL: Multiple failed password attempts for Admin root account.", "timestamp": str(time.time())}
    redis_client.lpush("log_queue", json.dumps(data))
    return {"status": "success", "message": "Brute-Force log queued!"}

@app.post("/ingest/simulate/sql-injection")
async def simulate_sql_injection():
    data = {"device_name": "Web-App", "ip_address": "10.0.0.30", "message": "ERROR: SQL syntax error near 'DROP TABLE users' on login portal.", "timestamp": str(time.time())}
    redis_client.lpush("log_queue", json.dumps(data))
    return {"status": "success", "message": "SQL Injection log queued!"}

@app.post("/ingest/simulate/safe-log")
async def simulate_safe_log():
    data = {"device_name": "Mail-Server", "ip_address": "10.0.0.80", "message": "INFO: User Mahnoor Waseem successfully logged in from recognized IP.", "timestamp": str(time.time())}
    redis_client.lpush("log_queue", json.dumps(data))
    return {"status": "success", "message": "Safe log queued!"}

# ============================================================
# READ API ENDPOINTS (Analytics & Retrieval)
# ============================================================

@app.get("/api/stats")
async def get_dashboard_stats():
    try:
        conn, cur = get_db_cursor()
        cur.execute("SELECT COUNT(*) as count FROM Alert")
        total_alerts = cur.fetchone()['count']
        cur.execute("SELECT COUNT(*) as count FROM Alert WHERE Priority = 'Critical' AND Status = 'New'")
        critical_alerts = cur.fetchone()['count']
        cur.execute("SELECT COUNT(*) as count FROM Device")
        total_devices = cur.fetchone()['count']
        cur.execute("SELECT COUNT(*) as count FROM Log")
        total_logs = cur.fetchone()['count']
        cur.execute("SELECT COUNT(*) as count FROM Metric")
        total_metrics = cur.fetchone()['count']
        cur.execute("SELECT COUNT(*) as count FROM Alert WHERE Timestamp >= NOW() - INTERVAL '24 hours'")
        threats_24h = cur.fetchone()['count']
        cur.execute("""
            SELECT d.DeviceName, COUNT(a.AlertID) as alert_count FROM Alert a
            JOIN Log l ON a.LogID = l.LogID JOIN Device d ON l.DeviceID = d.DeviceID
            GROUP BY d.DeviceName ORDER BY alert_count DESC LIMIT 1
        """)
        top_device_row = cur.fetchone()
        top_device = top_device_row['devicename'] if top_device_row else "None"
        cur.close()
        conn.close()
        return {"total_alerts": total_alerts, "critical_alerts": critical_alerts, "total_devices": total_devices, "threats_24h": threats_24h, "top_device": top_device, "total_logs": total_logs, "total_metrics": total_metrics}
    except Exception:
        return {"total_alerts": "-", "critical_alerts": "-", "total_devices": "-", "threats_24h": "-", "top_device": "-", "total_logs": "-", "total_metrics": "-"}

@app.get("/api/alerts")
async def get_alerts(page: int = 1, limit: int = 10):
    offset = (page - 1) * limit
    try:
        conn, cur = get_db_cursor()
        # PHASE 3 UPGRADE: Added LEFT JOIN to fetch the assigned Admin's Username and Solution!
        cur.execute("""
            SELECT a.AlertID, d.DeviceName, l.LogMessage, a.Priority, a.Status, a.FinalScore, a.Timestamp AT TIME ZONE 'UTC' as timestamp, adm.Username as assignee, a.Solution
            FROM Alert a 
            JOIN Log l ON a.LogID = l.LogID AND a.LogTimestamp = l.Timestamp 
            JOIN Device d ON l.DeviceID = d.DeviceID 
            LEFT JOIN Alert_Assignment aa ON a.AlertID = aa.AlertID
            LEFT JOIN Admin adm ON aa.AdminID = adm.AdminID
            ORDER BY a.Timestamp DESC LIMIT %s OFFSET %s
        """, (limit, offset))
        alerts = cur.fetchall()
        cur.close()
        conn.close()
        return[{"id": r['alertid'], "device": r['devicename'], "message": r['logmessage'], "priority": r['priority'], "status": r['status'], "score": r['finalscore'], "timestamp": r['timestamp'].isoformat() if r['timestamp'] else None, "assignee": r['assignee'], "solution": r['solution']} for r in alerts]
    except Exception as e:
        print(e)
        return[]

@app.get("/api/metrics/chart")
async def get_chart_metrics():
    try:
        conn, cur = get_db_cursor()
        cur.execute("SELECT d.DeviceName, m.Value, m.Timestamp AT TIME ZONE 'UTC' as timestamp FROM Metric m JOIN Device d ON m.DeviceID = d.DeviceID WHERE m.MetricType = 'flow_duration' ORDER BY m.Timestamp DESC LIMIT 20")
        metrics = cur.fetchall()
        cur.close()
        conn.close()
        metrics.reverse()
        return [{"device": r['devicename'], "value": r['value'], "timestamp": r['timestamp'].strftime('%H:%M:%S') if r['timestamp'] else None} for r in metrics]
    except Exception:
        return[]

@app.get("/api/devices")
async def get_devices():
    try:
        conn, cur = get_db_cursor()
        cur.execute("SELECT DeviceID, DeviceName, IP_Address, CriticalityScore FROM Device ORDER BY DeviceID")
        devices = cur.fetchall()
        cur.close()
        conn.close()
        return[{"id": r['deviceid'], "name": r['devicename'], "ip": r['ip_address'], "criticality": r['criticalityscore']} for r in devices]
    except Exception:
        return[]

@app.get("/api/logs")
async def get_logs():
    try:
        conn, cur = get_db_cursor()
        cur.execute("SELECT l.LogID, d.DeviceName, l.LogMessage, l.Timestamp AT TIME ZONE 'UTC' as timestamp FROM Log l JOIN Device d ON l.DeviceID = d.DeviceID ORDER BY l.Timestamp DESC LIMIT 50")
        logs = cur.fetchall()
        cur.close()
        conn.close()
        return[{"id": r['logid'], "device": r['devicename'], "message": r['logmessage'], "timestamp": r['timestamp'].isoformat() if r['timestamp'] else None} for r in logs]
    except Exception:
        return[]

@app.get("/api/metrics/recent")
async def get_recent_metrics():
    try:
        conn, cur = get_db_cursor()
        cur.execute("SELECT d.DeviceName, m.MetricType, m.Value, m.Timestamp AT TIME ZONE 'UTC' as timestamp FROM Metric m JOIN Device d ON m.DeviceID = d.DeviceID ORDER BY m.Timestamp DESC LIMIT 100")
        metrics = cur.fetchall()
        cur.close()
        conn.close()
        return[{"device": r['devicename'], "type": r['metrictype'], "value": r['value'], "timestamp": r['timestamp'].isoformat() if r['timestamp'] else None} for r in metrics]
    except Exception:
        return[]

# ============================================================
# PHASE 3: INCIDENT MANAGEMENT & WORKFLOW API
# ============================================================

@app.get("/api/admins")
async def get_admins():
    """Fetches all SOC Admins. Automatically creates dummy admins if empty for testing."""
    try:
        conn, cur = get_db_cursor()
        cur.execute("SELECT AdminID, Username, Role FROM Admin")
        admins = cur.fetchall()
        
        # Auto-Setup: If no admins exist in DB, create them!
        if not admins:
            cur.execute("INSERT INTO Admin (Username, Role) VALUES ('Mahnoor_Waseem', 'L1 Analyst'), ('Hasan_Imran', 'L1 Analyst'), ('Mustafa_Furqan', 'L2 Analyst') RETURNING AdminID, Username, Role")
            conn.commit()
            admins = cur.fetchall()
            
        cur.close()
        conn.close()
        return [{"id": r['adminid'], "username": r['username'], "role": r['role']} for r in admins]
    except Exception as e:
        return[]

@app.put("/api/alerts/{alert_id}/status")
async def update_alert_status(alert_id: int, req: StatusUpdate):
    """
    PHASE 4: Adaptive Retraining (The Teacher).
    If an admin marks an alert as 'False Positive', the system saves the 
    pattern into the memory vault (AI_Feedback table).
    """
    try:
        conn, cur = get_db_cursor()
        # 1. Update the status in the main table
        cur.execute("UPDATE Alert SET Status = %s WHERE AlertID = %s", (req.status, alert_id))
        
        # 2. If status is 'False Positive', extract and save pattern memory
        if req.status == "False Positive":
            cur.execute("""
                SELECT l.LogMessage, 
                       MAX(CASE WHEN m.MetricType = 'flow_duration' THEN m.Value END) as flow,
                       MAX(CASE WHEN m.MetricType = 'fwd_pkts_tot' THEN m.Value END) as fwd,
                       MAX(CASE WHEN m.MetricType = 'bwd_pkts_tot' THEN m.Value END) as bwd
                FROM Alert a
                JOIN Log l ON a.LogID = l.LogID AND a.LogTimestamp = l.Timestamp
                LEFT JOIN Metric m ON l.DeviceID = m.DeviceID AND l.Timestamp = m.Timestamp
                WHERE a.AlertID = %s
                GROUP BY l.LogID, l.LogMessage, l.Timestamp
            """, (alert_id,))
            data = cur.fetchone()
            
            if data:
                if data['logmessage']:
                    cur.execute("INSERT INTO AI_Feedback (PatternType, FeatureVector, AdminLabel) VALUES (%s, %s, %s)", 
                                ("Log", data['logmessage'], "False Positive"))
                
                if data['flow'] is not None:
                    vector_data = json.dumps({"flow": data['flow'], "fwd": data['fwd'], "bwd": data['bwd']})
                    cur.execute("INSERT INTO AI_Feedback (PatternType, FeatureVector, AdminLabel) VALUES (%s, %s, %s)", 
                                ("Metric", vector_data, "False Positive"))
        
        conn.commit()
        cur.close()
        conn.close()
        return {"status": "success", "message": f"Alert {alert_id} marked as {req.status}"}
    except Exception as e:
        return {"status": "error", "message": "Failed to update status."}

@app.post("/api/alerts/{alert_id}/assign")
async def assign_alert(alert_id: int, req: AssignAlert):
    """Assigns an alert to a specific Admin/Operator."""
    try:
        conn, cur = get_db_cursor()
        # Check if already assigned
        cur.execute("SELECT AssignmentID FROM Alert_Assignment WHERE AlertID = %s", (alert_id,))
        exists = cur.fetchone()
        
        if exists:
            cur.execute("UPDATE Alert_Assignment SET AdminID = %s, AssignmentRole = %s WHERE AlertID = %s", (req.admin_id, req.role, alert_id))
        else:
            cur.execute("INSERT INTO Alert_Assignment (AlertID, AdminID, AssignmentRole) VALUES (%s, %s, %s)", (alert_id, req.admin_id, req.role))
            
        conn.commit()
        cur.close()
        conn.close()
        return {"status": "success", "message": "Alert assigned successfully!"}
    except Exception as e:
        return {"status": "error", "message": "Failed to assign alert."}

@app.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard():
    dashboard_path = os.path.join(os.path.dirname(__file__), "static", "dashboard.html")
    with open(dashboard_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())