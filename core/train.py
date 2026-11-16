import logging
import time
import joblib
 
from db import load_alerts_df, save_cluster_labels, save_model_meta, save_anomaly_info, init_db
from features import build_features
from config import MODEL_PATH, TRAIN_WINDOW_DAYS
 
logger = logging.getLogger(__name__)
MIN_ALERTS_TO_TRAIN = 10
RARE_ALERT_THRESHOLD = 2  # bu say və ya az təkrarlanan alert_name "nadir" sayılır
 
 
def _compute_anomaly_info(df):
    """
    Hər alert üçün is_anomaly (bool) və anomaly_reason (str, niyə anomaliya
    sayıldığını izah edir) hesablayır. Üç meyar var:
      1) HDBSCAN-ın cluster tapmadığı (-1) unikal alertlər
      2) Severity-si HIGH/CRITICAL olanlar
      3) Bu data dəstində həmin alert_name-in nadir rast gəlinməsi (<= RARE_ALERT_THRESHOLD dəfə)
    """
    sev_upper = df["severity"].astype(str).str.upper()
    is_noise = df["cluster_label"] == -1
    is_high_sev = sev_upper.isin(["HIGH", "CRITICAL"])
    name_counts = df["alert_name"].value_counts()
    is_rare_name = df["alert_name"].map(lambda n: name_counts.get(n, 0) <= RARE_ALERT_THRESHOLD)
 
    def _reason(noise, high_sev, rare, name, count):
        parts = []
        if noise:
            parts.append("Unikal davranış (heç bir oxşar qrupa uyğun gəlmir)")
        if high_sev:
            parts.append("Yüksək severity")
        if rare:
            parts.append(f"Nadir alert növü (bu dövrdə cəmi {count} dəfə görünüb)")
        return " + ".join(parts) if parts else None
 
    reasons = [
        _reason(n, h, r, nm, name_counts.get(nm, 0))
        for n, h, r, nm in zip(is_noise, is_high_sev, is_rare_name, df["alert_name"])
    ]
    is_anomaly = is_noise | is_high_sev | is_rare_name
    return is_anomaly, reasons
 
 
def train(min_cluster_size: int = 5, min_samples: int = None):
    import hdbscan
 
    init_db()
    since_ms = int(time.time() * 1000) - TRAIN_WINDOW_DAYS * 24 * 60 * 60 * 1000
    df = load_alerts_df(since_ms=since_ms)
    if len(df) < MIN_ALERTS_TO_TRAIN:
        logger.warning(
            "Train üçün kifayət qədər alert yoxdur (minimum %d lazımdır, hazırkı: %d)",
            MIN_ALERTS_TO_TRAIN, len(df),
        )
        return None
 
    X, transformers = build_features(df)
    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        metric="euclidean",
        prediction_data=True,
    )
    labels = clusterer.fit_predict(X)
    probs = clusterer.probabilities_
 
    df["cluster_label"] = labels
    df["cluster_prob"] = probs
    save_cluster_labels(df)
 
    is_anomaly, reasons = _compute_anomaly_info(df)
    df["is_anomaly"] = is_anomaly
    df["anomaly_reason"] = reasons
    save_anomaly_info(df)
 
    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    n_noise = int((labels == -1).sum())
    params = {"min_cluster_size": min_cluster_size, "min_samples": min_samples}
    save_model_meta(len(df), n_clusters, n_noise, params)
 
    joblib.dump({"clusterer": clusterer, "transformers": transformers}, MODEL_PATH)
    n_anomaly = int(is_anomaly.sum())
    logger.info(
        "Train tamamlandı: %d alert, %d cluster, %d noise, %d anomaliya (params=%s)",
        len(df), n_clusters, n_noise, n_anomaly, params,
    )
    return {"n_alerts": len(df), "n_clusters": n_clusters, "n_noise": n_noise, "n_anomaly": n_anomaly}
 
 
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    result = train()
    print(result)