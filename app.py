"""
app.py - Streamlit dashboard for the
Cloud-Based Network Traffic Analysis and Anomaly Detection System.

Start it with:   streamlit run app.py

The page has five tabs that follow the project workflow:
  1. Data & Cleaning     (data_cleaning.py)
  2. Traffic Analysis    (network_analysis.py)
  3. Anomaly Detection   (anomaly_detection.py)
  4. Saved Results       (database.py)
  5. Cloud Deployment    (how the app is hosted online)
"""
from pathlib import Path

import plotly.express as px
import streamlit as st

import anomaly_detection
import data_cleaning
import database
import network_analysis

SAMPLE_CSV = Path(__file__).parent / "sample_data" / "network_traffic_sample.csv"
RESULT_COLORS = {"Normal": "#16a34a", "Anomaly": "#dc2626"}

st.set_page_config(page_title="Network Traffic Anomaly Detection", layout="wide")


# Streamlit re-runs this whole script after every click. @st.cache_data remembers
# a function's result, so the same file is not cleaned or analysed twice.
@st.cache_data
def load_and_clean(file_bytes):
    raw = data_cleaning.load_csv(file_bytes)
    clean, report = data_cleaning.clean_data(raw)
    return raw, clean, report


@st.cache_data
def find_anomalies(clean, contamination, n_trees):
    return anomaly_detection.detect_anomalies(clean, contamination, n_trees)


def show_metrics(values: dict, per_row: int = 4):
    """Show a dictionary as rows of metric boxes."""
    items = list(values.items())
    for start in range(0, len(items), per_row):
        columns = st.columns(per_row)
        for column, (label, value) in zip(columns, items[start:start + per_row]):
            column.metric(label, value)


# ------------------------------------------------------------------ sidebar --------
st.sidebar.header("1. Choose data")
source = st.sidebar.radio("Data source", ["Sample CSV (synthetic)", "Upload my CSV"])
if source == "Upload my CSV":
    uploaded_file = st.sidebar.file_uploader("Network traffic CSV file", type="csv")
    if uploaded_file is None:
        st.title("Network Traffic Analysis and Anomaly Detection")
        st.info("Upload a CSV file in the sidebar, or choose the sample CSV.")
        st.markdown("**Expected columns** (only `packets` and `bytes` are required): `timestamp, src_ip, "
                    "dst_ip, src_port, dst_port, protocol, packets, bytes, duration, label`. "
                    "Common CIC-IDS2017 and UNSW-NB15 column names are renamed automatically.")
        st.stop()
    file_name, file_bytes = uploaded_file.name, uploaded_file.getvalue()
else:
    file_name, file_bytes = SAMPLE_CSV.name, SAMPLE_CSV.read_bytes()

st.sidebar.header("2. Model settings")
contamination_pct = st.sidebar.slider(
    "Expected anomalies (%)", 1, 20, 5,
    help="Isolation Forest flags this share of flows with the highest anomaly scores.")
n_trees = st.sidebar.slider("Number of trees", 50, 300, 100, 50)

# ------------------------------------------------------------------ load + analyse --
st.title("Network Traffic Analysis and Anomaly Detection")
st.caption(f"Dataset: **{file_name}**")
if source.startswith("Sample"):
    st.warning("The sample CSV is synthetic (made-up) data for demonstration. It is not real captured traffic.")

try:
    raw, clean, cleaning_report = load_and_clean(file_bytes)
except ValueError as error:
    st.error(f"This file cannot be used: {error}")
    st.stop()

results, features = find_anomalies(clean, contamination_pct / 100, n_trees)
metrics = anomaly_detection.evaluate(results)
anomalies = results[results["is_anomaly"]].sort_values("anomaly_score", ascending=False)

tab_data, tab_traffic, tab_anomaly, tab_saved, tab_cloud = st.tabs(
    ["1. Data & Cleaning", "2. Traffic Analysis", "3. Anomaly Detection", "4. Saved Results", "5. Cloud Deployment"])

# ------------------------------------------------------------------ tab 1 ----------
with tab_data:
    show_metrics({"Rows in file": f"{len(raw):,}", "Rows after cleaning": f"{len(clean):,}",
                  "Rows removed": f"{len(raw) - len(clean):,}", "Columns used": len(clean.columns)})
    st.subheader("Cleaning steps")
    st.dataframe(cleaning_report, hide_index=True)
    st.subheader("Cleaned data (first 20 rows)")
    st.dataframe(clean.head(20), hide_index=True)
    st.subheader("Statistics of the number columns")
    st.dataframe(clean.select_dtypes("number").describe().T.round(2))

# ------------------------------------------------------------------ tab 2 ----------
with tab_traffic:
    st.subheader("Traffic summary")
    show_metrics(network_analysis.traffic_summary(clean))

    left, right = st.columns(2)
    protocols = network_analysis.protocol_counts(clean)
    if protocols is not None:
        left.plotly_chart(px.pie(protocols, names="protocol", values="flows", hole=0.4,
                                 title="Flows by protocol"), width="stretch")
    directions = network_analysis.direction_counts(clean)
    if directions is not None:
        right.plotly_chart(px.bar(directions, x="flows", y="direction", orientation="h",
                                  title="Traffic direction (private vs public IPs)"), width="stretch")

    ports = network_analysis.top_ports(clean)
    if ports is not None:
        left, right = st.columns([3, 2])
        figure = px.bar(ports, x="flows", y="port_label", orientation="h", title="Top 10 destination ports")
        figure.update_yaxes(autorange="reversed", title=None)
        left.plotly_chart(figure, width="stretch")
        right.dataframe(ports[["port", "service", "range", "flows"]], hide_index=True)

    talkers = network_analysis.top_source_ips(clean)
    if talkers is not None:
        st.subheader("Top source IP addresses (by data sent)")
        st.dataframe(talkers, hide_index=True)

    timeline = network_analysis.traffic_over_time(clean)
    if timeline is not None:
        st.plotly_chart(px.line(timeline, x="timestamp", y="throughput_mbps",
                                title="Throughput per minute (Mbit/s)"), width="stretch")
    else:
        st.info("No timestamp column, so the traffic-over-time chart is not available.")

# ------------------------------------------------------------------ tab 3 ----------
with tab_anomaly:
    show_metrics({"Flows analysed": f"{len(results):,}", "Normal": f"{len(results) - len(anomalies):,}",
                  "Anomalies": f"{len(anomalies):,}",
                  "Anomaly percentage": f"{100 * len(anomalies) / len(results):.1f}%"})
    st.caption("Features used by the model: " + ", ".join(features) + ". The anomaly score shows how "
               "unusual a flow is (higher = more unusual). It is not the probability of an attack, and "
               "an anomaly is a flow worth checking, not a confirmed attack.")

    left, right = st.columns(2)
    left.plotly_chart(px.histogram(results, x="anomaly_score", color="result", nbins=50,
                                   color_discrete_map=RESULT_COLORS, title="Anomaly scores"), width="stretch")
    right.plotly_chart(px.scatter(results, x="packets", y="bytes", color="result", log_x=True, log_y=True,
                                  color_discrete_map=RESULT_COLORS, opacity=0.6,
                                  title="Packets vs bytes per flow (log scale)"), width="stretch")

    st.subheader("Anomalies (highest score first)")
    columns = [c for c in ["timestamp", "src_ip", "dst_ip", "dst_port", "protocol", "packets", "bytes",
                           "duration", "anomaly_score", "reason", "label"] if c in anomalies.columns]
    st.dataframe(anomalies[columns], hide_index=True,
                 column_config={"anomaly_score": st.column_config.NumberColumn(format="%.3f")})

    st.subheader("Model check against the dataset labels")
    if metrics:
        show_metrics({"Precision": f"{metrics['precision']:.2f}", "Recall": f"{metrics['recall']:.2f}",
                      "F1-score": f"{metrics['f1_score']:.2f}",
                      "False alarms": f"{metrics['false_positives']:,}"})
        st.markdown(f"- Flagged and really an attack (true positives): **{metrics['true_positives']}**\n"
                    f"- Flagged but actually normal (false positives): **{metrics['false_positives']}**\n"
                    f"- Attacks the model missed (false negatives): **{metrics['false_negatives']}**")
        st.caption("Labels were never given to the model; they are only used here to check its results.")
    else:
        st.info("This file has no label column (or only one class), so precision and recall cannot be calculated.")

    left, right = st.columns(2)
    left.download_button("Download anomalies as CSV", anomalies[columns].to_csv(index=False),
                         "anomalies.csv", "text/csv")
    if right.button("Save results to database", type="primary"):
        run_id = database.save_analysis(file_name, results, contamination_pct / 100, metrics)
        st.success(f"Saved as run {run_id} in {database.DB_FILE.name}. See the 'Saved Results' tab.")

# ------------------------------------------------------------------ tab 4 ----------
with tab_saved:
    runs = database.load_runs()
    if runs.empty:
        st.info("Nothing saved yet. Press 'Save results to database' on the Anomaly Detection tab.")
    else:
        st.subheader("Saved analysis runs")
        st.dataframe(runs.round(3), hide_index=True)
        run_id = st.selectbox("Show the anomalies of run", runs["run_id"])
        st.dataframe(database.load_anomalies(run_id), hide_index=True)
    st.caption(f"Database file: {database.DB_FILE}")

# ------------------------------------------------------------------ tab 5 ----------
with tab_cloud:
    st.subheader("Running locally vs in the cloud")
    st.markdown(
        "- **Locally:** `streamlit run app.py` runs the app on your own computer at `http://localhost:8501`.\n"
        "- **In the cloud:** the same code can be hosted for free on **Streamlit Community Cloud**. "
        "Streamlit's servers then run the app and anyone with the link can use it in a browser.\n"
        "- **Cloud service models:** Streamlit Community Cloud is a **PaaS** (Platform as a Service: we "
        "give it code, it provides the servers). For the people who use the app, it is **SaaS** "
        "(Software as a Service: they only need a browser).")
    st.subheader("How to deploy (summary)")
    st.markdown(
        "1. Put this project folder in a public GitHub repository.\n"
        "2. Sign in at **share.streamlit.io** with your GitHub account.\n"
        "3. Click **Create app**, choose the repository, branch `main` and file `app.py`, then **Deploy**.\n"
        "4. After a few minutes you get a public link ending in `.streamlit.app`.\n\n"
        "Full steps are in README.md.")
    st.warning("On Streamlit Community Cloud the SQLite file is temporary: saved results can be lost when "
               "the app restarts. Use the CSV download to keep results.")
