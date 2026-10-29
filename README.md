# Cloud-Based Network Traffic Analysis and Anomaly Detection System

A simple BCA project built with **Python and Streamlit**. You upload a CSV of network traffic and the app:

1. **cleans** the data (duplicates, missing values, wrong values),
2. **analyses** the traffic: IP addresses, protocols, ports, packets and data volume,
3. **finds unusual flows** with the **Isolation Forest** machine-learning model,
4. **saves** the results in a **SQLite** database,
5. can be **deployed to the cloud** for free on Streamlit Community Cloud.

Everything is free. No account or internet is needed to run it on your computer (only to install it).

---

## 1. Project files

| File | What it does | Subject |
|---|---|---|
| `app.py` | The dashboard: sidebar, five tabs, charts and buttons | All three |
| `data_cleaning.py` | Reads the CSV, renames columns, cleans the data | Data Science |
| `network_analysis.py` | Protocols, ports, IP addresses, traffic direction, throughput | Computer Networks |
| `anomaly_detection.py` | Isolation Forest, anomaly reasons, precision / recall / F1 | Data Science |
| `database.py` | Saves and loads results in `analysis_results.db` (SQLite) | Data Science (data storage) |
| `sample_data/network_traffic_sample.csv` | Ready-to-use sample (synthetic) | – |
| `create_sample_data.py` | The script that made the sample CSV | – |
| `test_project.py` | 10 automatic tests | – |
| `requirements.txt` | Libraries to install | – |
| `run_app.bat` | Double-click to set up and start on Windows | – |
| `.streamlit/config.toml` | Light theme for the dashboard | – |

---

## 2. Windows setup (step by step)

### Step 1 – Install Python (once)
1. Download **Python 3.12** (64-bit) from <https://www.python.org/downloads/windows/>. Python 3.11 and 3.13 also work.
2. In the installer, tick **"Add python.exe to PATH"**, then click **Install Now**.
3. Open **Command Prompt** (press the Windows key, type `cmd`, press Enter) and check:
   ```bat
   python --version
   ```
   You should see `Python 3.12.x` (or 3.11 / 3.13).

### Step 2 – Open the project folder
If the project is in `Downloads\network-anomaly-system`:
```bat
cd %USERPROFILE%\Downloads\network-anomaly-system
```

### Step 3 – Create a virtual environment and install the libraries (once)
A virtual environment is a private folder (`.venv`) for this project's libraries.
```bat
python -m venv .venv
.venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```
After `activate`, the prompt starts with `(.venv)`.

### Step 4 – Start the app
```bat
streamlit run app.py
```
Your browser opens **http://localhost:8501**. To stop the app, press `Ctrl + C` in the Command Prompt.

**Next time**, you only need:
```bat
cd %USERPROFILE%\Downloads\network-anomaly-system
.venv\Scripts\activate
streamlit run app.py
```

**Shortcut:** double-click **`run_app.bat`**. The first time it does Steps 3 and 4 for you; after that it just starts the app.

### Step 5 – Run the tests (optional)
```bat
.venv\Scripts\activate
python -m pytest
```
Expected: `10 passed`.

---

## 3. Using the app

| Where | What to do / see |
|---|---|
| **Sidebar → Data source** | *Sample CSV (synthetic)* or *Upload my CSV* |
| **Sidebar → Model settings** | *Expected anomalies (%)* (default 5%) and *Number of trees* (default 100) |
| **Tab 1 – Data & Cleaning** | Rows before/after cleaning, each cleaning step, preview, statistics |
| **Tab 2 – Traffic Analysis** | Traffic summary, protocol chart, traffic direction, top ports, top source IPs, throughput over time |
| **Tab 3 – Anomaly Detection** | Normal vs anomaly counts, score chart, list of anomalies with a reason, precision/recall (if labels exist), **Download CSV**, **Save results to database** |
| **Tab 4 – Saved Results** | All runs saved in SQLite; choose a run to see its anomalies |
| **Tab 5 – Cloud Deployment** | Local vs cloud, and a summary of how to deploy |

### Your own CSV format
One row = one network **flow** (one connection between two computers).

| Column | Required? | Example | Meaning |
|---|---|---|---|
| `packets` | **yes** | 14 | packets in the flow |
| `bytes` | **yes** | 9800 | bytes in the flow |
| `duration` | no | 0.52 | flow length in seconds |
| `timestamp` | no | 2026-01-15 10:00:02 | when the flow started |
| `src_ip`, `dst_ip` | no | 192.168.1.35, 142.250.183.14 | source and destination IP address |
| `src_port`, `dst_port` | no | 51544, 443 | source and destination port |
| `protocol` | no | TCP / UDP / ICMP (or 6 / 17 / 1) | transport protocol |
| `label` | no | normal / ddos | the true answer, used **only** to check the model |

Common column names from the public **CIC-IDS2017** and **UNSW-NB15** datasets are renamed automatically
(for example `Destination Port` → `dst_port`, `Total Fwd Packets` + `Total Backward Packets` → `packets`).
If an optional column is missing, the chart that needs it is simply skipped. Files over 100,000 rows are
randomly sampled down to 100,000 rows to keep the app fast.

### About the sample CSV
`sample_data/network_traffic_sample.csv` is **synthetic**: it was made by `create_sample_data.py`, not captured
from a real network, and its IP addresses are invented. It has 1,291 rows: one hour of normal traffic, three
attack patterns (`ddos`, `port_scan`, `data_exfiltration`), plus deliberate problems for the cleaning step to
fix: 5 duplicate rows, 2 missing byte counts, 2 text values in the packets column, 1 negative value and
2 missing durations. To recreate it: `python create_sample_data.py`.

---

## 4. How it works

### Data cleaning (`data_cleaning.py`)
1. Remove duplicate rows.
2. Turn text in number columns (e.g. `abc`) into missing values.
3. Turn infinite values into missing values.
4. Remove rows with no packet or byte count.
5. Remove rows with negative values (impossible for counts and times).
6. Fill missing durations with the **median** (the middle value, which very large flows can't distort).
7. Tidy text: protocol numbers → names (6 → TCP), timestamps → dates, `label` → `is_attack` (true/false).

The app shows how many rows or values each step changed.

### Network analysis (`network_analysis.py`)
* **Protocols:** IP protocol numbers 6 = TCP, 17 = UDP, 1 = ICMP.
* **Ports:** well-known services (22 SSH, 53 DNS, 80 HTTP, 443 HTTPS …) and IANA ranges: well-known 0–1023, registered 1024–49151, dynamic 49152–65535.
* **IP addresses:** private (e.g. `192.168.x.x`) or public, using Python's `ipaddress` module, which gives the **traffic direction**: outbound, inbound or internal.
* **Volume:** total packets, MB, average packet size, top source IPs, and **throughput** = bytes × 8 ÷ seconds (Mbit/s).

### Anomaly detection (`anomaly_detection.py`)
* **Features:** `packets`, `bytes`, `duration`, plus two calculated ones: `bytes_per_packet` and `packets_per_second`.
* **Isolation Forest** builds many random trees that split the data at random values. Unusual flows are isolated after only a few splits, so they get a **high anomaly score**.
* **Expected anomalies (%)** is the share of flows the model flags. You choose it; the model doesn't discover it.
* Each anomaly gets a **reason**: the feature furthest from normal, e.g. `bytes = 107,751,000 (21,383x the normal median 5,039)`.
* If the CSV has a `label` column, the app calculates **precision** (how many flagged flows were real attacks), **recall** (how many attacks were flagged) and **F1-score**. Labels are never used to train the model.
* **The anomaly score is not an attack probability, and an anomaly is not a confirmed attack.**

On the synthetic sample with 5% expected anomalies, the model flagged 64 flows: all 45 `ddos` and all 6 `data_exfiltration` flows, plus 13 normal flows. It flagged **none of the 35 `port_scan` flows** (precision 0.80, recall 0.59). Each port-scan flow is tiny (1 packet), just like many normal DNS flows, so it doesn't look unusual on its own. Catching it would need a feature such as "number of different ports contacted by one IP". This is a good example of a real limitation.

### Database (`database.py`)
SQLite stores everything in one file, `analysis_results.db`, which is created automatically. There are two tables:
* `analysis_runs`: date, file, total flows, anomalies, %, setting, precision, recall, F1.
* `anomalies`: the flagged flows of each run (IPs, port, protocol, packets, bytes, score, reason), linked by `run_id`.

---

## 5. How the three subjects are covered

| Subject | Where in the project |
|---|---|
| **Fundamentals of Data Science and Analytics** | Data cleaning steps, statistics table, calculated features, Isolation Forest (unsupervised machine learning), precision / recall / F1, charts, SQLite storage |
| **Introduction to Data Communication and Computer Networks** | Network flows, packets and bytes, TCP/UDP/ICMP protocol numbers, ports and services, IANA port ranges, private vs public IP addresses, traffic direction, throughput in Mbit/s, attack patterns (DDoS, port scan, data exfiltration) |
| **Cloud Computing and Services** | Free deployment on Streamlit Community Cloud (PaaS for us, SaaS for users), access from any browser through a public link, code hosted on GitHub; the in-app *Cloud Deployment* tab explains local vs cloud |

---

## 6. Deploy to the cloud (free) – Streamlit Community Cloud

Streamlit Community Cloud hosts Streamlit apps for free from a GitHub repository.

1. Create a free account at <https://github.com>.
2. Create a **new public repository** (e.g. `network-anomaly-system`) and upload all project files (drag and drop on the GitHub website). The `.venv` folder and `.db` file are not needed.
3. Go to <https://share.streamlit.io> and **sign in with GitHub**.
4. Click **Create app** (top right). When asked *"Do you already have an app?"*, choose **"Yup, I have an app."**
5. Fill in:
   * Repository: `your-username/network-anomaly-system`
   * Branch: `main`
   * File path: `app.py`
   * App URL (optional): a short name for your link
6. Click **Advanced settings**, choose Python version **3.12**, and click **Save**.
7. Click **Deploy**. After a few minutes you get a public link like `https://your-app-name.streamlit.app`.

Things to know:
* Streamlit reads `requirements.txt` from the repository and installs the libraries automatically.
* Apps with no visitors for 12 hours go to sleep; opening the link wakes them up.
* The cloud server's disk is **temporary**, so the SQLite database can be lost when the app restarts. Use **Download anomalies as CSV** to keep results.
* Only say the project is "deployed" after you have done these steps and opened the public link.

---

## 7. Troubleshooting

| Problem | Fix |
|---|---|
| `'python' is not recognized` | Reinstall Python with **Add python.exe to PATH** ticked, or use `py` instead of `python`. |
| `'streamlit' is not recognized` | Activate the virtual environment first: `.venv\Scripts\activate` (or run `python -m streamlit run app.py`). |
| PowerShell: *running scripts is disabled* | Use **Command Prompt** instead, or run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once. |
| `pip install` fails for numpy / pandas | Use **64-bit** Python 3.11, 3.12 or 3.13, delete the `.venv` folder and repeat Step 3. |
| `ModuleNotFoundError: No module named 'data_cleaning'` | Run the command from the project folder (the one containing `app.py`). |
| Port 8501 already in use | `streamlit run app.py --server.port 8502` |
| "Missing required column(s): packets, bytes" | Your CSV needs packet and byte counts per row. See *Your own CSV format* above. |
| No precision / recall shown | Your CSV has no `label` column; this is normal. |
| The app is slow with a big file | Files are limited to 100,000 rows. Use a smaller file or fewer trees. |

---

## 8. Limitations

* It analyses **recorded** traffic in CSV files. It doesn't capture live traffic and doesn't block anything.
* Isolation Forest finds **unusual** flows, not proven attacks. It can raise false alarms and miss attacks that look normal flow-by-flow (like the port scan in the sample).
* The sample data is synthetic. Results on it only show that the project works; they are not results on a real dataset.
* By default the app runs locally. Cloud hosting is optional and must be set up by following Section 6.
