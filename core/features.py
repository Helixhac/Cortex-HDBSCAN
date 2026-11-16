import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD

TEXT_COLS = ["alert_name", "description", "category", "action_pretty"]
CAT_COLS = ["severity", "alert_source", "host_name"]


def build_features(df: pd.DataFrame, n_text_components: int = 20):
    df = df.copy()
    for c in TEXT_COLS:
        if c not in df.columns:
            df[c] = ""
    for c in CAT_COLS:
        if c not in df.columns:
            df[c] = "unknown"

    df[TEXT_COLS] = df[TEXT_COLS].fillna("")
    df[CAT_COLS] = df[CAT_COLS].fillna("unknown")

    text_blob = df[TEXT_COLS].agg(" ".join, axis=1)
    tfidf = TfidfVectorizer(max_features=500, stop_words="english")
    text_matrix = tfidf.fit_transform(text_blob)

    max_possible = max(1, min(text_matrix.shape) - 1)
    n_comp = max(2, min(n_text_components, max_possible))
    svd = TruncatedSVD(n_components=n_comp, random_state=42)
    text_reduced = svd.fit_transform(text_matrix)

    cat_dummies = pd.get_dummies(df[CAT_COLS], prefix=CAT_COLS)

    creation_dt = pd.to_datetime(df["creation_time"], unit="ms", errors="coerce")
    hour_of_day = creation_dt.dt.hour.fillna(0).astype(float)
    day_of_week = creation_dt.dt.dayofweek.fillna(0).astype(float)
    numeric = pd.DataFrame({"hour_of_day": hour_of_day, "day_of_week": day_of_week})

    X = np.hstack([text_reduced, cat_dummies.values, numeric.values])
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    transformers = {
        "tfidf": tfidf,
        "svd": svd,
        "cat_columns": cat_dummies.columns.tolist(),
        "scaler": scaler,
    }
    return X_scaled, transformers
