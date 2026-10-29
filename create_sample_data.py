"""
create_sample_data.py - creates sample_data/network_traffic_sample.csv

The sample is SYNTHETIC: every row is made up by this script so the project
can be demonstrated without downloading a large real dataset. It is not real
captured traffic, and the IP addresses are invented.

It contains one hour of mostly normal traffic plus three attack patterns:
  ddos              many outside computers flood one local web server
  port_scan         one outside computer probes many ports of a local server
  data_exfiltration a local computer sends huge amounts of data outside

A few "dirty" rows (duplicates, missing values, text in number columns,
negative values) are added on purpose so the cleaning steps have work to do.

Run:  python create_sample_data.py
"""
from pathlib import Path

import numpy as np
import pandas as pd

rng = np.random.default_rng(seed=7)          # fixed seed = same file every time
START = pd.Timestamp("2026-01-15 10:00:00")
LOCAL_SERVER = "192.168.1.20"

# (destination port, protocol, share of normal flows, typical packet size in bytes)
NORMAL_SERVICES = [(443, "TCP", 0.52, 900), (80, "TCP", 0.14, 700), (53, "UDP", 0.16, 90),
                   (123, "UDP", 0.04, 76), (22, "TCP", 0.04, 120), (993, "TCP", 0.05, 400),
                   (25, "TCP", 0.02, 600), (0, "ICMP", 0.03, 64)]
PUBLIC_SERVERS = ["142.250.183.14", "104.16.132.229", "13.107.42.14", "151.101.1.69",
                  "52.84.150.39", "34.120.177.193"]


def random_times(n, start_min, end_min):
    seconds = rng.uniform(start_min * 60, end_min * 60, n)
    return [START + pd.Timedelta(seconds=float(s)) for s in seconds]


def normal_traffic(n=1200):
    shares = np.array([s[2] for s in NORMAL_SERVICES])
    picks = rng.choice(len(NORMAL_SERVICES), size=n, p=shares / shares.sum())
    rows = []
    for i, time in zip(picks, random_times(n, 0, 60)):
        port, protocol, _, packet_size = NORMAL_SERVICES[i]
        packets = int(max(1, rng.lognormal(2.3, 0.8)))                  # usually 5-30 packets
        rows.append({
            "timestamp": time,
            "src_ip": f"192.168.1.{rng.integers(30, 80)}",
            "dst_ip": "8.8.8.8" if port == 53 else str(rng.choice(PUBLIC_SERVERS)),
            "src_port": int(rng.integers(49152, 65535)) if protocol != "ICMP" else 0,
            "dst_port": port,
            "protocol": protocol,
            "packets": packets,
            "bytes": int(packets * max(40, rng.normal(packet_size, packet_size * 0.2))),
            "duration": round(float(rng.lognormal(0.0, 1.2)), 4),          # about 1 second
            "label": "normal",
        })
    return rows


def ddos(n=45):
    return [{"timestamp": t, "src_ip": f"{rng.integers(40, 220)}.{rng.integers(1, 254)}."
                                       f"{rng.integers(1, 254)}.{rng.integers(1, 254)}",
             "dst_ip": LOCAL_SERVER, "src_port": int(rng.integers(1024, 65535)), "dst_port": 80,
             "protocol": "TCP", "packets": (p := int(rng.integers(600, 1500))), "bytes": p * 60,
             "duration": round(float(rng.uniform(0.3, 1.5)), 4), "label": "ddos"}
            for t in random_times(n, 30, 33)]


def port_scan(n=35):
    return [{"timestamp": t, "src_ip": "77.88.21.11", "dst_ip": LOCAL_SERVER,
             "src_port": 45678, "dst_port": int(port), "protocol": "TCP",
             "packets": 1, "bytes": 60, "duration": round(float(rng.uniform(0.0005, 0.003)), 5),
             "label": "port_scan"}
            for t, port in zip(sorted(random_times(n, 15, 16)), rng.choice(np.arange(1, 1024), n, replace=False))]


def data_exfiltration(n=6):
    return [{"timestamp": t, "src_ip": "192.168.1.45", "dst_ip": "185.199.110.42",
             "src_port": int(rng.integers(49152, 65535)), "dst_port": 443, "protocol": "TCP",
             "packets": (p := int(rng.integers(40_000, 120_000))), "bytes": p * 1400,
             "duration": round(float(rng.uniform(300, 900)), 2), "label": "data_exfiltration"}
            for t in random_times(n, 40, 55)]


def add_dirty_rows(table):
    """Add problems that real data often has, so data cleaning can be demonstrated."""
    table = table.astype({"packets": object, "bytes": object, "duration": object})
    table.loc[3, "bytes"] = None              # missing value
    table.loc[17, "bytes"] = None
    table.loc[25, "packets"] = "abc"          # text in a number column
    table.loc[40, "packets"] = "unknown"
    table.loc[55, "bytes"] = -500             # impossible negative value
    table.loc[60, "duration"] = None          # missing duration (will be filled)
    table.loc[61, "duration"] = None
    duplicates = table.sample(5, random_state=1)
    return pd.concat([table, duplicates], ignore_index=True)


if __name__ == "__main__":
    rows = normal_traffic() + ddos() + port_scan() + data_exfiltration()
    table = pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
    table["timestamp"] = table["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    table = add_dirty_rows(table)
    output = Path(__file__).parent / "sample_data" / "network_traffic_sample.csv"
    output.parent.mkdir(exist_ok=True)
    table.to_csv(output, index=False)
    print(f"Saved {len(table)} rows to {output}")
    print(table["label"].value_counts().to_string())
