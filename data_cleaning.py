"""
data_cleaning.py - read a network traffic CSV file and clean it.

Subject: Fundamentals of Data Science and Analytics

Our project works with these column names (only packets and bytes are required):

    timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
    packets, bytes, duration (seconds), label (optional: normal / attack name)

Public datasets such as CIC-IDS2017 and UNSW-NB15 use other names for the
same information, so standardise_columns() renames them first.
"""
import io

import numpy as np
import pandas as pd

from network_analysis import protocol_name

MAX_ROWS = 100_000          # bigger files are randomly sampled down to this size
MIN_ROWS = 20               # fewer clean rows than this is not enough to analyse

REQUIRED_COLUMNS = ["packets", "bytes"]
PROJECT_COLUMNS = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
                   "packets", "bytes", "duration", "label"]
NUMBER_COLUMNS = ["src_port", "dst_port", "packets", "bytes", "duration"]
NORMAL_LABELS = {"normal", "benign", "0"}

# Other datasets' column name (lower case)  ->  our column name
COLUMN_ALIASES = {
    "source ip": "src_ip", "srcip": "src_ip",
    "destination ip": "dst_ip", "dstip": "dst_ip",
    "source port": "src_port", "sport": "src_port",
    "destination port": "dst_port", "dsport": "dst_port",
    "proto": "protocol",
    "dur": "duration",
    "stime": "timestamp",
    "attack_cat": "label",
}

# Some datasets count the two directions of a flow separately:
# forward (client -> server) and backward (server -> client). We add them up.
DIRECTION_PAIRS = {
    "packets": [("total fwd packets", "total backward packets"), ("spkts", "dpkts")],
    "bytes": [("total length of fwd packets", "total length of bwd packets"), ("sbytes", "dbytes")],
}


def load_csv(file_bytes: bytes) -> pd.DataFrame:
    """Read CSV file contents into a DataFrame (a table). Raises ValueError if it cannot."""
    if not file_bytes:
        raise ValueError("The file is empty.")
    try:
        table = pd.read_csv(io.BytesIO(file_bytes), low_memory=False)
    except UnicodeDecodeError:
        # Some files are saved in an older text encoding; try that instead
        table = pd.read_csv(io.BytesIO(file_bytes), encoding="latin-1", low_memory=False)
    except (pd.errors.ParserError, pd.errors.EmptyDataError) as error:
        raise ValueError(f"The file could not be read as a CSV table ({error}).")
    if len(table) > MAX_ROWS:
        table = table.sample(MAX_ROWS, random_state=42)   # random sample keeps the mix of traffic
    return table


def standardise_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Rename columns from other datasets to our names."""
    df = df.copy()
    df.columns = [str(name).strip().lower() for name in df.columns]

    for other_name, our_name in COLUMN_ALIASES.items():
        if other_name in df.columns and our_name not in df.columns:
            df = df.rename(columns={other_name: our_name})

    for our_name, pairs in DIRECTION_PAIRS.items():
        for forward, backward in pairs:
            if our_name not in df.columns and forward in df.columns and backward in df.columns:
                df[our_name] = (pd.to_numeric(df[forward], errors="coerce")
                                + pd.to_numeric(df[backward], errors="coerce"))

    # CIC-IDS2017 stores "Flow Duration" in microseconds; we use seconds
    if "duration" not in df.columns and "flow duration" in df.columns:
        df["duration"] = pd.to_numeric(df["flow duration"], errors="coerce") / 1_000_000
    return df


def clean_data(raw: pd.DataFrame):
    """
    Clean the raw table step by step.
    Returns (clean_table, report) where report lists each step and how many rows/values it changed.
    """
    report = []
    df = standardise_columns(raw)

    missing = [name for name in REQUIRED_COLUMNS if name not in df.columns]
    if missing:
        raise ValueError(f"Missing required column(s): {', '.join(missing)}. "
                         "Each row must have the number of packets and bytes in the flow.")

    # Step 1: exact duplicate rows add no information, so remove them
    before = len(df)
    df = df.drop_duplicates()
    report.append(("1. Removed duplicate rows", before - len(df)))

    # Keep only the columns this project uses
    df = df[[name for name in PROJECT_COLUMNS if name in df.columns]].copy()

    # Step 2 and 3: text such as "abc" in a number column becomes missing (NaN);
    # infinite values (from dividing by a zero duration) also become missing
    invalid_text, infinite = 0, 0
    for name in NUMBER_COLUMNS:
        if name in df.columns:
            numbers = pd.to_numeric(df[name], errors="coerce")
            invalid_text += int((numbers.isna() & df[name].notna()).sum())
            infinite += int(np.isinf(numbers).sum())
            df[name] = numbers.replace([np.inf, -np.inf], np.nan)
    report.append(("2. Text in number columns turned into missing values", invalid_text))
    report.append(("3. Infinite values turned into missing values", infinite))

    # Step 4: a flow without packet or byte counts cannot be analysed
    before = len(df)
    df = df.dropna(subset=REQUIRED_COLUMNS)
    report.append(("4. Removed rows with missing packets or bytes", before - len(df)))

    # Step 5: counts and durations can never be negative, so those rows are errors
    checked = [name for name in ["packets", "bytes", "duration"] if name in df.columns]
    negative = (df[checked] < 0).any(axis=1)
    df = df[~negative]
    report.append(("5. Removed rows with negative values", int(negative.sum())))

    # Step 6: fill a missing duration with the median (middle value) of all durations
    if "duration" in df.columns:
        filled = int(df["duration"].isna().sum())
        median = df["duration"].median()
        df["duration"] = df["duration"].fillna(0.0 if pd.isna(median) else median)
        report.append(("6. Filled missing durations with the median", filled))

    # Step 7: tidy the text columns
    for port in ["src_port", "dst_port"]:
        if port in df.columns:
            df[port] = df[port].round().astype("Int64")      # whole numbers; missing allowed
    if "protocol" in df.columns:
        df["protocol"] = df["protocol"].map(protocol_name)    # 6 -> TCP, 'udp' -> UDP
    if "timestamp" in df.columns:
        df["timestamp"] = parse_timestamps(df["timestamp"])
    if "label" in df.columns:
        df["label"] = df["label"].astype(str).str.strip()
        df["is_attack"] = ~df["label"].str.lower().isin(NORMAL_LABELS)

    if len(df) < MIN_ROWS:
        raise ValueError(f"Only {len(df)} usable rows remain after cleaning; at least {MIN_ROWS} are needed.")

    report_table = pd.DataFrame(report, columns=["Cleaning step", "Rows or values affected"])
    return df.reset_index(drop=True), report_table


def parse_timestamps(column: pd.Series) -> pd.Series:
    """Turn timestamps into date-time values. Numbers are treated as Unix seconds."""
    if pd.api.types.is_numeric_dtype(column):
        return pd.to_datetime(column, unit="s", errors="coerce")
    return pd.to_datetime(column, errors="coerce", format="mixed")
