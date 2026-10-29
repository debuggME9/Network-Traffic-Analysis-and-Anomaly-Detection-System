"""
database.py - save analysis results in a SQLite database.

SQLite is a small database stored in ONE file (analysis_results.db).
It is built into Python, so nothing extra needs to be installed.

Tables
  analysis_runs : one row per saved analysis (date, file, counts, settings, scores)
  anomalies     : the flagged flows of each run, linked by run_id
"""
import sqlite3
from datetime import datetime
from pathlib import Path

import pandas as pd

DB_FILE = Path(__file__).parent / "analysis_results.db"

CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS analysis_runs (
    run_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_time        TEXT,
    file_name       TEXT,
    total_flows     INTEGER,
    anomalies       INTEGER,
    anomaly_percent REAL,
    contamination   REAL,
    precision       REAL,
    recall          REAL,
    f1_score        REAL
);
CREATE TABLE IF NOT EXISTS anomalies (
    run_id        INTEGER REFERENCES analysis_runs(run_id),
    timestamp     TEXT,
    src_ip        TEXT,
    dst_ip        TEXT,
    dst_port      INTEGER,
    protocol      TEXT,
    packets       REAL,
    bytes         REAL,
    anomaly_score REAL,
    reason        TEXT
);
"""
ANOMALY_COLUMNS = ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol",
                   "packets", "bytes", "anomaly_score", "reason"]


def get_connection(db_path=None):
    """Open the database file (it is created automatically the first time)."""
    connection = sqlite3.connect(db_path or DB_FILE)
    connection.executescript(CREATE_TABLES)
    return connection


def save_analysis(file_name, results, contamination, metrics=None, db_path=None):
    """Save one analysis run and its anomalies. Returns the new run_id."""
    anomalies = results[results["is_anomaly"]]
    metrics = metrics or {}
    with get_connection(db_path) as connection:
        cursor = connection.execute(
            "INSERT INTO analysis_runs (run_time, file_name, total_flows, anomalies, anomaly_percent, "
            "contamination, precision, recall, f1_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), file_name, len(results), len(anomalies),
             round(100 * len(anomalies) / len(results), 2), contamination,
             metrics.get("precision"), metrics.get("recall"), metrics.get("f1_score")))
        run_id = cursor.lastrowid

        # Build the anomaly rows; columns missing from the CSV are saved as empty (NULL)
        rows = pd.DataFrame({name: anomalies[name] if name in anomalies.columns else None
                             for name in ANOMALY_COLUMNS})
        rows["timestamp"] = rows["timestamp"].astype(str)
        rows.insert(0, "run_id", run_id)
        rows.to_sql("anomalies", connection, if_exists="append", index=False)
    connection.close()
    return run_id


def load_runs(db_path=None) -> pd.DataFrame:
    """All saved runs, newest first."""
    connection = get_connection(db_path)
    table = pd.read_sql_query("SELECT * FROM analysis_runs ORDER BY run_id DESC", connection)
    connection.close()
    return table


def load_anomalies(run_id, db_path=None) -> pd.DataFrame:
    """The anomalies saved for one run, highest score first."""
    connection = get_connection(db_path)
    table = pd.read_sql_query("SELECT * FROM anomalies WHERE run_id = ? ORDER BY anomaly_score DESC",
                              connection, params=(int(run_id),))
    connection.close()
    return table
