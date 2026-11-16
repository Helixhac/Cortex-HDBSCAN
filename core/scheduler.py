import time
import logging
from datetime import datetime, timezone
 
from config import POLL_INTERVAL_SECONDS, LOG_PATH
from db import init_db, upsert_alerts, get_state, set_state, load_alerts_by_alert_ids
from cortex_client import fetch_alerts_xql
from train import train
from notify import notify_high_risk_anomalies
 
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
        logging.StreamHandler(),  # terminalda da görünsün
    ],
)
logger = logging.getLogger("scheduler")
 
# Son uğurlu pollinq nöqtəsindən bir az geriyə qayıdırıq ki, gecikən
# (late-arriving) alertlər gözdən qaçmasın.
OVERLAP_MS = 2 * 60 * 1000
FIRST_RUN_LOOKBACK_MS = 150 * 24 * 60 * 60 * 1000  # ilk dəfə işə salınanda son ~5 ay
 
 
def run_once():
    last = get_state("last_local_insert_ts")
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    since_ms = (int(last) - OVERLAP_MS) if last else (now_ms - FIRST_RUN_LOOKBACK_MS)
 
    try:
        alerts = fetch_alerts_xql(since_ms=since_ms, limit=2000)
    except Exception:
        logger.exception("Cortex XDR-dan alert çəkilərkən xəta baş verdi, növbəti dövrə qədər gözlənilir")
        return
 
    if not alerts:
        logger.info("Yeni alert tapılmadı")
        return
 
    inserted = upsert_alerts(alerts)
    logger.info("%d alert çəkildi, %d yeni alert DB-yə yazıldı", len(alerts), inserted)
 
    max_ts = max(int(a.get("_time") or a.get("alert_arrival_timestamp") or 0) for a in alerts)
    if max_ts:
        set_state("last_local_insert_ts", max_ts)
 
    if inserted > 0:
        try:
            train()
        except Exception:
            logger.exception("Model train edilərkən xəta baş verdi")
            return
 
        try:
            new_alert_ids = [a.get("alert_id") for a in alerts]
            new_df = load_alerts_by_alert_ids(new_alert_ids)
            if not new_df.empty:
                sev_upper = new_df["severity"].astype(str).str.upper()
                high_risk = new_df[(new_df["is_anomaly"] == 1) & sev_upper.isin(["HIGH", "CRITICAL"])]
                if not high_risk.empty:
                    notify_high_risk_anomalies(high_risk)
        except Exception:
            logger.exception("Bildiriş göndərilərkən xəta baş verdi")
 
 
def main():
    init_db()
    logger.info("Scheduler başladı - hər %d saniyədə bir Cortex XDR-a müraciət olunacaq", POLL_INTERVAL_SECONDS)
    while True:
        run_once()
        time.sleep(POLL_INTERVAL_SECONDS)
 
 
if __name__ == "__main__":
    main()