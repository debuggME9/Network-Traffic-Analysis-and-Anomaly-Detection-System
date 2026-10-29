"""
network_analysis.py - networking facts and traffic statistics.

Subject: Introduction to Data Communication and Computer Networks

Every function takes the cleaned table (one row = one network flow) and
returns a small summary table for the dashboard. If a column is missing
from the CSV, the function returns None and the dashboard skips that chart.
"""
import ipaddress

import pandas as pd

# IP header "protocol" field: number -> name
PROTOCOL_NUMBERS = {1: "ICMP", 6: "TCP", 17: "UDP"}

# Well-known ports and the service that normally uses them (IANA assignments)
PORT_SERVICES = {
    0: "No port (ICMP)",          # ICMP (e.g. ping) does not use ports; datasets store 0
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt",
}


# ----------------------------------------------------------------- single values --
def protocol_name(value) -> str:
    """6 -> 'TCP', 'udp' -> 'UDP'. Unknown numbers become 'Protocol <n>'."""
    try:
        number = int(float(value))
        return PROTOCOL_NUMBERS.get(number, f"Protocol {number}")
    except (TypeError, ValueError):
        return str(value).strip().upper()


def port_service(port) -> str:
    """443 -> 'HTTPS'. Ports that are not in our table become 'Other'."""
    if pd.isna(port):
        return "Unknown"
    return PORT_SERVICES.get(int(port), "Other")


def port_range(port) -> str:
    """IANA port ranges: well-known (0-1023), registered (1024-49151), dynamic (49152-65535)."""
    if pd.isna(port):
        return "Unknown"
    port = int(port)
    if port <= 1023:
        return "Well-known (0-1023)"
    if port <= 49151:
        return "Registered (1024-49151)"
    return "Dynamic (49152-65535)"


def ip_type(ip) -> str:
    """'Private' for local network addresses (e.g. 192.168.x.x), otherwise 'Public'."""
    try:
        return "Private" if ipaddress.ip_address(str(ip).strip()).is_private else "Public"
    except ValueError:
        return "Invalid"


def traffic_direction(src_ip, dst_ip) -> str:
    """Direction of a flow seen from our local network."""
    src, dst = ip_type(src_ip), ip_type(dst_ip)
    if "Invalid" in (src, dst):
        return "Unknown"
    if src == "Private" and dst == "Public":
        return "Outbound (local -> internet)"
    if src == "Public" and dst == "Private":
        return "Inbound (internet -> local)"
    if src == "Private" and dst == "Private":
        return "Internal (local -> local)"
    return "External (internet -> internet)"


# ----------------------------------------------------------------- summary tables --
def traffic_summary(df: pd.DataFrame) -> dict:
    """Headline numbers for the whole capture."""
    total_packets = df["packets"].sum()
    total_bytes = df["bytes"].sum()
    summary = {
        "Flows": f"{len(df):,}",
        "Total packets": f"{int(total_packets):,}",
        "Total data": f"{total_bytes / 1_000_000:,.1f} MB",
        "Avg packet size": f"{total_bytes / max(total_packets, 1):,.0f} bytes",
    }
    if "src_ip" in df.columns:
        summary["Unique source IPs"] = f"{df['src_ip'].nunique():,}"
    if "dst_ip" in df.columns:
        summary["Unique destination IPs"] = f"{df['dst_ip'].nunique():,}"
    if "dst_port" in df.columns:
        summary["Destination ports"] = f"{df['dst_port'].nunique():,}"
    if "duration" in df.columns:
        summary["Avg flow duration"] = f"{df['duration'].mean():,.2f} s"
    return summary


def protocol_counts(df: pd.DataFrame):
    """Flows and data volume per protocol (TCP, UDP, ICMP ...)."""
    if "protocol" not in df.columns:
        return None
    table = df.groupby("protocol").agg(flows=("packets", "size"), bytes=("bytes", "sum")).reset_index()
    return table.sort_values("flows", ascending=False)


def top_ports(df: pd.DataFrame, n: int = 10):
    """Most used destination ports with their usual service and IANA range."""
    if "dst_port" not in df.columns:
        return None
    table = df["dst_port"].value_counts().head(n).rename_axis("port").reset_index(name="flows")
    table["service"] = table["port"].map(port_service)
    table["range"] = table["port"].map(port_range)
    table["port_label"] = table["port"].astype(str) + " (" + table["service"] + ")"
    return table


def top_source_ips(df: pd.DataFrame, n: int = 10):
    """Source IP addresses that sent the most data ('top talkers')."""
    if "src_ip" not in df.columns:
        return None
    table = (df.groupby("src_ip").agg(flows=("packets", "size"), packets=("packets", "sum"),
                                      bytes=("bytes", "sum"))
             .sort_values("bytes", ascending=False).head(n).reset_index())
    table["ip_type"] = table["src_ip"].map(ip_type)
    table["data_MB"] = (table["bytes"] / 1_000_000).round(2)
    return table.drop(columns="bytes")


def direction_counts(df: pd.DataFrame):
    """How many flows go out to the internet, come in, or stay inside the network."""
    if "src_ip" not in df.columns or "dst_ip" not in df.columns:
        return None
    directions = [traffic_direction(s, d) for s, d in zip(df["src_ip"], df["dst_ip"])]
    return pd.Series(directions).value_counts().rename_axis("direction").reset_index(name="flows")


def traffic_over_time(df: pd.DataFrame, interval: str = "1min"):
    """Flows, data volume and throughput (Mbit/s) for each time interval."""
    if "timestamp" not in df.columns or df["timestamp"].isna().all():
        return None
    grouped = df.dropna(subset=["timestamp"]).set_index("timestamp").resample(interval)
    table = pd.DataFrame({"flows": grouped.size(), "bytes": grouped["bytes"].sum()}).reset_index()
    seconds = pd.Timedelta(interval).total_seconds()
    # Throughput = bits per second: bytes x 8 bits, divided by the interval length
    table["throughput_mbps"] = table["bytes"] * 8 / seconds / 1_000_000
    return table
