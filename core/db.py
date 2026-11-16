import sqlite3
import json
import datetime
from contextlib import contextmanager
 
from config import DB_PATH  # data/cortex_alerts.db - config.py-də təyin olunur
 
SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT UNIQUE NOT NULL,
    creation_time INTEGER,
    local_insert_ts INTEGER,
    severity TEXT,
    alert_name TEXT,
    category TEXT,
    alert_source TEXT,
    host_name TEXT,
    username TEXT,
    endpoint_id TEXT,
    action_pretty TEXT,
    description TEXT,
    mitre_attack_technique TEXT,
    mitre_attack_tactic TEXT,
    remote_ip TEXT,
    remote_host TEXT,
    local_ip TEXT,
    rule_id TEXT,
    incident_id TEXT,
    resolution_status TEXT,
    country TEXT,
    dns_query_name TEXT,
    domain TEXT,
    raw_json TEXT NOT NULL,
    cluster_label INTEGER,
    cluster_prob REAL,
    is_anomaly INTEGER DEFAULT 0,
    anomaly_reason TEXT,
    analyst_label TEXT,
    fetched_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_alerts_creation_time ON alerts(creation_time);
CREATE INDEX IF NOT EXISTS idx_alerts_local_insert_ts ON alerts(local_insert_ts);
 
CREATE TABLE IF NOT EXISTS fetch_state (
    key TEXT PRIMARY KEY,
    value TEXT
);
 
CREATE TABLE IF NOT EXISTS model_meta (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trained_at TEXT,
    n_alerts INTEGER,
    n_clusters INTEGER,
    n_noise INTEGER,
    params TEXT
);
"""
 
 
@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
 
 
def init_db():
    with get_conn() as conn:
        conn.executescript(SCHEMA)
 
 
def _flatten(value):
    """Cortex bəzi field-ləri list kimi qaytarır (məs. user_name: ['local\\\\ali']) - string-ə çeviririk."""
    if isinstance(value, list):
        cleaned = [str(v) for v in value if v not in (None, "")]
        return ", ".join(cleaned) if cleaned else None
    return value
 
 
def upsert_alerts(alerts: list) -> int:
    """Alertləri DB-yə yazır. Artıq mövcud olan alert_id-ləri sakitcə ötürür (idempotent)."""
    inserted = 0
    with get_conn() as conn:
        for a in alerts:
            alert_id = str(a.get("alert_id") or a.get("internal_id") or a.get("id") or "")
            if not alert_id:
                continue
            row = (
                alert_id,
                a.get("creation_time") or a.get("detection_timestamp") or a.get("_time"),
                a.get("server_creation_time") or a.get("local_insert_ts") or a.get("alert_arrival_timestamp"),
                (a.get("severity") or "").upper() or None,
                a.get("alert_name") or a.get("name"),
                a.get("category"),
                a.get("alert_source") or a.get("source"),
                _flatten(a.get("host_name")),
                _flatten(a.get("user_name") or a.get("os_actor_effective_username") or a.get("username")),
                a.get("endpoint_id"),
                a.get("action_pretty") or a.get("action"),
                a.get("description"),
                _flatten(a.get("mitre_attack_technique") or a.get("mitre_technique_id_and_name")),
                _flatten(a.get("mitre_attack_tactic") or a.get("mitre_tactic_id_and_name")),
                _flatten(a.get("remote_ip")),
                _flatten(a.get("remote_host") or a.get("dst_action_external_hostname")),
                _flatten(a.get("local_ip")),
                a.get("rule_id"),
                a.get("incident_id") or a.get("case_id"),
                a.get("resolution_status"),
                _flatten(a.get("country") or a.get("dst_action_country")),
                _flatten(a.get("dns_query_name")),
                _flatten(a.get("domain") or a.get("host_fqdn")),
                json.dumps(a, ensure_ascii=False, default=str),
            )
            cur = conn.execute(
                """INSERT INTO alerts
                   (alert_id, creation_time, local_insert_ts, severity, alert_name,
                    category, alert_source, host_name, username, endpoint_id, action_pretty,
                    description, mitre_attack_technique, mitre_attack_tactic, remote_ip,
                    remote_host, local_ip, rule_id, incident_id, resolution_status,
                    country, dns_query_name, domain, raw_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(alert_id) DO NOTHING""",
                row,
            )
            if cur.rowcount:
                inserted += 1
    return inserted
 
 
def get_state(key, default=None):
    with get_conn() as conn:
        r = conn.execute("SELECT value FROM fetch_state WHERE key=?", (key,)).fetchone()
        return r["value"] if r else default
 
 
def set_state(key, value):
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO fetch_state(key, value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
 
 
def load_alerts_df(limit: int = None, since_ms: int = None):
    import pandas as pd
    q = "SELECT * FROM alerts"
    params = []
    if since_ms:
        q += " WHERE creation_time >= ?"
        params.append(since_ms)
    q += " ORDER BY creation_time DESC"
    if limit:
        q += f" LIMIT {int(limit)}"
    with get_conn() as conn:
        return pd.read_sql_query(q, conn, params=params)
 
 
def load_alerts_by_alert_ids(alert_ids):
    import pandas as pd
    if not alert_ids:
        return pd.DataFrame()
    placeholders = ",".join("?" for _ in alert_ids)
    q = f"SELECT * FROM alerts WHERE alert_id IN ({placeholders})"
    with get_conn() as conn:
        return pd.read_sql_query(q, conn, params=[str(a) for a in alert_ids])
 
 
def save_cluster_labels(df) -> None:
    with get_conn() as conn:
        for _, row in df.iterrows():
            conn.execute(
                "UPDATE alerts SET cluster_label=?, cluster_prob=? WHERE id=?",
                (int(row["cluster_label"]), float(row.get("cluster_prob", 0) or 0), int(row["id"])),
            )
 
 
def save_anomaly_info(df) -> None:
    """df-də 'is_anomaly' (bool) və 'anomaly_reason' (str) sütunları olmalıdır."""
    with get_conn() as conn:
        for _, row in df.iterrows():
            conn.execute(
                "UPDATE alerts SET is_anomaly=?, anomaly_reason=? WHERE id=?",
                (int(bool(row["is_anomaly"])), row.get("anomaly_reason"), int(row["id"])),
            )
 
 
def save_analyst_labels(id_to_label: dict) -> None:
    """id_to_label: {alert-in DB id-si: label string ('True Positive'/'False Positive'/'Investigating'/'')}"""
    with get_conn() as conn:
        for alert_db_id, label in id_to_label.items():
            conn.execute(
                "UPDATE alerts SET analyst_label=? WHERE id=?",
                (label if label else None, int(alert_db_id)),
            )
 
 
def save_model_meta(n_alerts, n_clusters, n_noise, params: dict) -> None:
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO model_meta(trained_at, n_alerts, n_clusters, n_noise, params) VALUES (?,?,?,?,?)",
            (datetime.datetime.utcnow().isoformat(), n_alerts, n_clusters, n_noise, json.dumps(params)),
        )
 
 
if __name__ == "__main__":
    init_db()
    print(f"DB hazırdır: {DB_PATH}")