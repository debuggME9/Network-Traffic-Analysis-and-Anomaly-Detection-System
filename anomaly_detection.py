"""
anomaly_detection.py - find unusual network flows with Isolation Forest.

Subject: Fundamentals of Data Science and Analytics (machine learning)

How Isolation Forest works, in short:
  The model builds many random decision trees. Each tree keeps splitting the
  data on a random feature at a random value until every flow is alone.
  An unusual flow (for example 1,000x more bytes than normal) is separated
  after only a few splits, so it gets a HIGH anomaly score.

Important:
  * The anomaly score is NOT the probability of an attack.
  * A flagged flow is "unusual and worth checking", not a confirmed attack.
  * The 'label' column (if present) is never given to the model. It is only
    used afterwards to check how good the model was.
"""
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score

# Features (numeric columns) the model learns from
FEATURES = ["packets", "bytes", "duration", "bytes_per_packet", "packets_per_second"]


def add_features(df):
    """Create two extra features that describe flow behaviour."""
    df = df.copy()
    # Average packet size. clip(lower=1) avoids dividing by zero
    df["bytes_per_packet"] = df["bytes"] / df["packets"].clip(lower=1)
    if "duration" in df.columns:
        # Packet rate. A minimum of 1 ms avoids dividing by a zero duration
        df["packets_per_second"] = df["packets"] / df["duration"].clip(lower=0.001)
    return df


def detect_anomalies(df, contamination=0.05, n_trees=100, random_state=42):
    """
    Train Isolation Forest and score every flow.

    contamination = the share of flows we expect to be unusual (0.05 = 5%).
    Returns (results_table, features_used).
    """
    results = add_features(df)
    features = [name for name in FEATURES if name in results.columns]

    model = IsolationForest(n_estimators=n_trees, contamination=contamination,
                            random_state=random_state)
    model.fit(results[features])

    # score_samples gives LOWER values for unusual flows; we flip the sign
    # so that a HIGHER anomaly_score means MORE unusual.
    results["anomaly_score"] = -model.score_samples(results[features])
    results["is_anomaly"] = model.predict(results[features]) == -1     # -1 means anomaly
    results["result"] = np.where(results["is_anomaly"], "Anomaly", "Normal")
    results["reason"] = explain_anomalies(results, features)
    return results, features


def explain_anomalies(results, features):
    """
    For each anomaly, name the feature that is furthest from normal traffic,
    e.g. 'bytes = 85,400,000 (1,950x the normal median 43,800)'.
    """
    normal_medians = results.loc[~results["is_anomaly"], features].median()
    reasons = []
    for _, row in results.iterrows():
        if not row["is_anomaly"]:
            reasons.append("")
            continue
        best_text, best_size = "Unusual combination of values", 1.0
        for feature in features:
            median = normal_medians[feature]
            if median <= 0:
                continue
            ratio = row[feature] / median
            size = ratio if ratio >= 1 else (1 / ratio if ratio > 0 else float("inf"))
            if size > best_size:
                best_size = size
                best_text = (f"{feature} = {format_number(row[feature])} "
                             f"({ratio:,.1f}x the normal median {format_number(median)})")
        reasons.append(best_text)
    return reasons


def format_number(value):
    """Readable numbers: 85400000 -> '85,400,000', 0.0021 -> '0.0021'."""
    return f"{value:,.0f}" if abs(value) >= 100 else f"{value:.3g}"


def evaluate(results):
    """
    Compare the model's predictions with the dataset's labels (only if labels exist).
    Returns None when there is no label column or only one class.
    """
    if "is_attack" not in results.columns or results["is_attack"].nunique() < 2:
        return None
    actual = results["is_attack"].astype(int)
    predicted = results["is_anomaly"].astype(int)
    return {
        # Of the flows we flagged, how many were really attacks?
        "precision": precision_score(actual, predicted, zero_division=0),
        # Of all real attacks, how many did we flag?
        "recall": recall_score(actual, predicted, zero_division=0),
        # One number that balances precision and recall
        "f1_score": f1_score(actual, predicted, zero_division=0),
        "true_positives": int(((actual == 1) & (predicted == 1)).sum()),
        "false_positives": int(((actual == 0) & (predicted == 1)).sum()),
        "false_negatives": int(((actual == 1) & (predicted == 0)).sum()),
        "true_negatives": int(((actual == 0) & (predicted == 0)).sum()),
    }
