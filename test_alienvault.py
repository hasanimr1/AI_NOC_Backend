import redis
import json
import time

redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# 1. Simulate a malicious metric (e.g. DDoS)
malicious_metric = {
    "device_name": "Test-Router",
    "flow_duration": 9999999.0,
    "fwd_pkts_tot": 85000.0,
    "bwd_pkts_tot": 90000.0,
    "timestamp": str(time.time()),
    "ip_address": "185.220.101.14" # Known Tor exit node / bad IP
}
redis_client.lpush("metric_queue", json.dumps(malicious_metric))
print("Sent malicious metric to metric_queue")

# 2. Simulate a malicious log
malicious_log = {
    "device_name": "Test-Server",
    "message": "CRITICAL: Multiple failed password attempts for Admin root account.",
    "timestamp": str(time.time()),
    "ip_address": "185.220.101.14" # Known bad IP
}
redis_client.lpush("log_queue", json.dumps(malicious_log))
print("Sent malicious log to log_queue")
