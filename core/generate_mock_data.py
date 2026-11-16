import random
import time
from db import init_db, upsert_alerts

random.seed(42)

ALERT_TEMPLATES = [
    {"alert_name": "Suspicious PowerShell Execution", "category": "Execution", "severity": "high",
     "action_pretty": "Detected", "description": "Encoded PowerShell command executed by user"},
    {"alert_name": "Suspicious PowerShell Execution", "category": "Execution", "severity": "high",
     "action_pretty": "Detected", "description": "Encoded PowerShell command executed by user"},
    {"alert_name": "Malware Detected", "category": "Malware", "severity": "high",
     "action_pretty": "Prevented", "description": "Known malware signature blocked on endpoint"},
    {"alert_name": "Brute Force Login Attempt", "category": "Credential Access", "severity": "medium",
     "action_pretty": "Detected", "description": "Multiple failed login attempts from same source"},
    {"alert_name": "Brute Force Login Attempt", "category": "Credential Access", "severity": "medium",
     "action_pretty": "Detected", "description": "Multiple failed login attempts from same source"},
    {"alert_name": "Port Scan Detected", "category": "Reconnaissance", "severity": "low",
     "action_pretty": "Detected", "description": "Sequential port scan identified from internal host"},
    {"alert_name": "Unusual Outbound Data Transfer", "category": "Exfiltration", "severity": "medium",
     "action_pretty": "Detected", "description": "Large volume of data sent to external IP"},
    {"alert_name": "Suspicious Scheduled Task Created", "category": "Persistence", "severity": "medium",
     "action_pretty": "Detected", "description": "New scheduled task created by non-admin user"},
    {"alert_name": "DNS Tunneling Suspected", "category": "Command and Control", "severity": "high",
     "action_pretty": "Detected", "description": "Abnormal DNS query pattern detected"},
    {"alert_name": "Local Admin Account Created", "category": "Persistence", "severity": "low",
     "action_pretty": "Detected", "description": "New local administrator account added on host"},
]

HOSTS = [f"WS-{i:03d}" for i in range(1, 26)] + [f"SRV-{i:02d}" for i in range(1, 8)]
SOURCES = ["XDR_AGENT", "FIREWALL", "EMAIL_GATEWAY", "CLOUD_APP"]


def make_alert(idx, base_ts_ms):
    tpl = random.choice(ALERT_TEMPLATES)
    jitter_ms = random.randint(0, 24 * 60 * 60 * 1000)
    creation_time = base_ts_ms - jitter_ms
    return {
        "alert_id": f"MOCK-{idx:06d}",
        "creation_time": creation_time,
        "local_insert_ts": creation_time + random.randint(500, 5000),
        "severity": tpl["severity"],
        "alert_name": tpl["alert_name"],
        "category": tpl["category"],
        "alert_source": random.choice(SOURCES),
        "host_name": random.choice(HOSTS),
        "endpoint_id": f"EP-{random.randint(1000,9999)}",
        "action_pretty": tpl["action_pretty"],
        "description": tpl["description"],
    }


def main(n=300):
    init_db()
    now_ms = int(time.time() * 1000)
    alerts = [make_alert(i, now_ms) for i in range(n)]
    inserted = upsert_alerts(alerts)
    print(f"{inserted} sintetik alert DB-yə yazıldı (cəmi yaradılan: {n}).")


if __name__ == "__main__":
    main()
