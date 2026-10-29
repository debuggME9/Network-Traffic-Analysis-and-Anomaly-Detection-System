"""
test_project.py - automatic checks for the main workflow.

Run:  python -m pytest
"""
from pathlib import Path

import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

import anomaly_detection
import data_cleaning
import database
import network_analysis

PROJECT = Path(__file__).parent
SAMPLE_CSV = PROJECT / "sample_data" / "network_traffic_sample.csv"


@pytest.fixture
def sample():
    raw = data_cleaning.load_csv(SAMPLE_CSV.read_bytes())
    clean, report = data_cleaning.clean_data(raw)
    return raw, clean, report


# ---------------------------------------------------------------- data cleaning --
def test_cleaning_fixes_dirty_rows(sample):
    raw, clean, report = sample
    steps = dict(zip(report["Cleaning step"], report["Rows or values affected"]))
    assert steps["1. Removed duplicate rows"] == 5
    assert steps["2. Text in number columns turned into missing values"] == 2
    assert steps["5. Removed rows with negative values"] == 1
    assert len(clean) < len(raw)
    assert clean[["packets", "bytes", "duration"]].notna().all().all()
    assert (clean[["packets", "bytes", "duration"]] >= 0).all().all()


def test_missing_required_columns_are_explained():
    table = pd.DataFrame({"src_ip": ["10.0.0.1"] * 30, "dst_port": [80] * 30})
    with pytest.raises(ValueError, match="packets, bytes"):
        data_cleaning.clean_data(table)


def test_empty_and_invalid_files():
    with pytest.raises(ValueError):
        data_cleaning.load_csv(b"")
    with pytest.raises(ValueError):
        data_cleaning.clean_data(data_cleaning.load_csv(b"just some text\nwithout columns\n"))


def test_cic_ids2017_style_columns_are_renamed():
    rows = 30
    table = pd.DataFrame({
        " Destination Port": [443] * rows, " Protocol": [6] * rows,
        " Flow Duration": [2_000_000 + i for i in range(rows)],          # microseconds
        " Total Fwd Packets": [5] * rows, " Total Backward Packets": [3] * rows,
        "Total Length of Fwd Packets": [500] * rows, " Total Length of Bwd Packets": [700] * rows,
        " Label": ["BENIGN"] * (rows - 1) + ["DDoS"],
    })
    clean, _ = data_cleaning.clean_data(table)
    assert clean.loc[0, "packets"] == 8 and clean.loc[0, "bytes"] == 1200
    assert clean.loc[0, "duration"] == pytest.approx(2.0)
    assert clean.loc[0, "protocol"] == "TCP"
    assert clean["is_attack"].sum() == 1


# ---------------------------------------------------------------- networking -----
def test_network_helpers():
    assert network_analysis.protocol_name(6) == "TCP"
    assert network_analysis.protocol_name("udp") == "UDP"
    assert network_analysis.port_service(443) == "HTTPS"
    assert network_analysis.port_range(80).startswith("Well-known")
    assert network_analysis.port_range(50000).startswith("Dynamic")
    assert network_analysis.ip_type("192.168.1.5") == "Private"
    assert network_analysis.ip_type("142.250.183.14") == "Public"
    assert network_analysis.traffic_direction("192.168.1.5", "142.250.183.14").startswith("Outbound")


def test_traffic_statistics(sample):
    _, clean, _ = sample
    assert network_analysis.traffic_summary(clean)["Flows"] == f"{len(clean):,}"
    assert set(network_analysis.protocol_counts(clean)["protocol"]) == {"TCP", "UDP", "ICMP"}
    assert network_analysis.top_ports(clean).iloc[0]["service"] == "HTTPS"
    assert network_analysis.traffic_over_time(clean)["flows"].sum() == len(clean)
    no_ips = clean.drop(columns=["src_ip", "dst_ip"])
    assert network_analysis.top_source_ips(no_ips) is None       # missing columns are skipped


# ---------------------------------------------------------------- anomaly detection
def test_isolation_forest(sample):
    _, clean, _ = sample
    results, features = anomaly_detection.detect_anomalies(clean, contamination=0.05)
    assert "label" not in features and "is_attack" not in features   # labels are never inputs
    assert abs(results["is_anomaly"].mean() - 0.05) < 0.01
    anomalies = results[results["is_anomaly"]]
    assert (anomalies["reason"] != "").all()
    assert anomalies["anomaly_score"].min() >= results.loc[~results["is_anomaly"], "anomaly_score"].max()


def test_evaluation_uses_real_counts(sample):
    _, clean, _ = sample
    results, _ = anomaly_detection.detect_anomalies(clean, contamination=0.05)
    metrics = anomaly_detection.evaluate(results)
    assert metrics["true_positives"] + metrics["false_positives"] == results["is_anomaly"].sum()
    assert 0 <= metrics["precision"] <= 1 and 0 <= metrics["recall"] <= 1
    assert anomaly_detection.evaluate(results.drop(columns="is_attack")) is None


# ---------------------------------------------------------------- database -------
def test_database_save_and_load(sample, tmp_path):
    _, clean, _ = sample
    results, _ = anomaly_detection.detect_anomalies(clean, contamination=0.05)
    db_file = tmp_path / "test.db"
    run_id = database.save_analysis("sample.csv", results, 0.05, anomaly_detection.evaluate(results), db_file)
    runs = database.load_runs(db_file)
    assert runs.loc[0, "run_id"] == run_id and runs.loc[0, "total_flows"] == len(results)
    assert len(database.load_anomalies(run_id, db_file)) == results["is_anomaly"].sum()


# ---------------------------------------------------------------- dashboard ------
def test_dashboard_workflow(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DB_FILE", tmp_path / "app.db")
    app = AppTest.from_file(str(PROJECT / "app.py"), default_timeout=60)
    app.run()
    assert not app.exception and not app.error
    next(b for b in app.button if b.label == "Save results to database").click()
    app.run()
    assert not app.exception
    assert len(database.load_runs()) == 1
