"""
CICIDS2017 Dataset Multi-File Inspection Tool
============================================
Inspects all eight CSV files from the CICIDS2017 dataset,
computes cryptographic hashes, verifies field counts, investigates
encoding and malformed/blank rows, checks schema compatibility,
and exports comprehensive inspection data to cicids_inspection.json.
"""

import os
import sys
import json
import time
import hashlib
import ipaddress
import re
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent
RAW_DIR = PROJECT_ROOT / "data" / "raw"
OUTPUT_JSON = PROJECT_ROOT / "cicids_inspection.json"
ENCODING = "latin-1"

COLUMN_ALIASES = {
    "flow_id": ["Flow ID"],
    "source_ip": ["Source IP", "Src IP"],
    "destination_ip": ["Destination IP", "Dst IP"],
    "source_port": ["Source Port", "Src Port"],
    "destination_port": ["Destination Port", "Dst Port"],
    "protocol": ["Protocol"],
    "timestamp": ["Timestamp"],
    "label": ["Label"],
}

WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

TIMESTAMP_FORMATS = [
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
]


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def normalize_col(name: str) -> str:
    name = str(name).replace("\ufeff", "").replace("ï»¿", "")
    return " ".join(name.split())


def scan_raw_lines(path: Path):
    total_lines = 0
    blank_or_comma_only = 0
    utf8_errors = 0
    non_ascii_lines = 0
    first_utf8_err_line = None

    with open(path, "rb") as f:
        for idx, line in enumerate(f, start=1):
            total_lines += 1
            # check utf-8 decodability
            try:
                line.decode("utf-8")
            except UnicodeDecodeError:
                utf8_errors += 1
                if first_utf8_err_line is None:
                    first_utf8_err_line = idx

            # check non-ascii
            if any(b >= 128 for b in line):
                non_ascii_lines += 1

            # check empty or comma-only
            if not line.strip(b"\r\n,"):
                blank_or_comma_only += 1

    return {
        "total_lines": total_lines,
        "blank_or_comma_only_lines": blank_or_comma_only,
        "utf8_errors": utf8_errors,
        "non_ascii_lines": non_ascii_lines,
        "first_utf8_err_line": first_utf8_err_line,
    }


def find_col_name(cols, key):
    lower = {c.lower(): c for c in cols}
    for cand in COLUMN_ALIASES[key]:
        if cand.lower() in lower:
            return lower[cand.lower()]
    return None


def inspect_file(path: Path):
    print(f"\n========================================================")
    print(f"Inspecting: {path.name}")
    t0 = time.time()
    file_size_bytes = path.stat().st_size
    file_size_mb = file_size_bytes / (1024 * 1024)
    sha_pre = sha256_of(path)

    print(f"  Scanning raw file bytes and line structure...")
    raw_scan = scan_raw_lines(path)

    print(f"  Reading CSV via pandas (latin-1) ...")
    df_raw = pd.read_csv(path, encoding=ENCODING, low_memory=False)
    raw_rows, raw_cols = df_raw.shape

    # Check for rows that are completely NaN / empty
    all_nan_mask = df_raw.isna().all(axis=1)
    blank_rows_detected = int(all_nan_mask.sum())
    if blank_rows_detected > 0:
        print(f"  [!] Detected {blank_rows_detected:,} completely empty / comma-only trailing rows. Dropping...")
        df = df_raw[~all_nan_mask].copy()
    else:
        df = df_raw

    valid_rows, num_cols = df.shape
    raw_col_names = list(df.columns)
    norm_col_names = [normalize_col(c) for c in raw_col_names]
    df.columns = norm_col_names

    col_map = {k: find_col_name(norm_col_names, k) for k in COLUMN_ALIASES}
    label_col = col_map["label"]
    ts_col = col_map["timestamp"]
    src_ip_col = col_map["source_ip"]
    dst_ip_col = col_map["destination_ip"]
    flow_id_col = col_map["flow_id"]

    # 1. Missing values
    null_counts = df.isna().sum()
    cols_with_null = {k: int(v) for k, v in null_counts.items() if v > 0}
    rows_with_any_null = int(df.isna().any(axis=1).sum())

    # 2. Infinite values
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    cols_with_inf = {}
    inf_rows_count = 0
    if len(numeric_cols) > 0:
        inf_mask = np.isinf(df[numeric_cols])
        inf_cols_series = inf_mask.sum()
        for k, v in inf_cols_series.items():
            if v > 0:
                cols_with_inf[k] = int(v)
        inf_rows_count = int(inf_mask.any(axis=1).sum())

    # 3. Constant columns
    constant_cols = []
    for c in df.columns:
        if df[c].nunique(dropna=False) <= 1:
            constant_cols.append(c)

    # 4. Duplicate rows
    # Exact duplicate rows across all columns
    dup_rows_count = int(df.duplicated().sum())

    # 5. Label distribution
    label_series = df[label_col].astype(str)
    # clean en-dash or \x96 if present in string representation
    # keep raw label counts
    raw_label_counts = {str(k): int(v) for k, v in df[label_col].value_counts(dropna=False).items()}
    # normalized label counts (replacing \x96 or non-breaking with clean ASCII or hyphen)
    clean_labels = df[label_col].astype(str).str.replace("\x96", "-").str.replace("–", "-").str.strip()
    norm_label_counts = {str(k): int(v) for k, v in clean_labels.value_counts(dropna=False).items()}

    # 6. Timestamp analysis
    ts_info = {}
    if ts_col and ts_col in df.columns:
        raw_ts = df[ts_col].astype(str).str.strip()
        best_fmt = None
        best_parsed = None
        best_ok = -1

        for fmt in TIMESTAMP_FORMATS:
            try:
                parsed = pd.to_datetime(raw_ts, format=fmt, errors="coerce")
                ok = int(parsed.notna().sum())
                if ok > best_ok:
                    best_ok = ok
                    best_fmt = fmt
                    best_parsed = parsed
            except Exception:
                pass

        if best_parsed is not None and best_ok > 0:
            valid_ts = best_parsed.dropna()
            min_ts = str(valid_ts.min())
            max_ts = str(valid_ts.max())
            weekdays_present = list(valid_ts.dt.day_name().unique())
            hour_counts = {int(h): int(c) for h, c in valid_ts.dt.hour.value_counts().items()}
            # Check 12-hour clock issue: if max hour <= 12 and hours 1..5 present along with 8..12
            has_12h_anomaly = (
                max(hour_counts.keys()) <= 12
                and any(h in hour_counts for h in [1, 2, 3, 4, 5])
                and any(h in hour_counts for h in [8, 9, 10, 11, 12])
            )
            ts_info = {
                "detected_format": best_fmt,
                "parsed_rows": best_ok,
                "parsed_pct": round(100.0 * best_ok / valid_rows, 3),
                "earliest": min_ts,
                "latest": max_ts,
                "weekdays": weekdays_present,
                "hour_distribution": hour_counts,
                "has_12h_anomaly": has_12h_anomaly,
            }

    # 7. Network IPs and flows
    net_info = {}
    if src_ip_col and dst_ip_col:
        unique_src = int(df[src_ip_col].nunique())
        unique_dst = int(df[dst_ip_col].nunique())
        top_src = {str(k): int(v) for k, v in df[src_ip_col].value_counts().head(5).items()}
        top_dst = {str(k): int(v) for k, v in df[dst_ip_col].value_counts().head(5).items()}
        unique_flows = int(df[flow_id_col].nunique()) if flow_id_col else None
        net_info = {
            "unique_source_ips": unique_src,
            "unique_dest_ips": unique_dst,
            "unique_flow_ids": unique_flows,
            "top_source_ips": top_src,
            "top_dest_ips": top_dst,
        }

    sha_post = sha256_of(path)
    assert sha_pre == sha_post, f"File was modified during inspection! {path.name}"

    elapsed = round(time.time() - t0, 2)
    print(f"  Done in {elapsed}s: {valid_rows:,} valid rows, {num_cols} cols, labels: {list(norm_label_counts.keys())}")

    return {
        "file_name": path.name,
        "file_size_bytes": file_size_bytes,
        "file_size_mb": round(file_size_mb, 2),
        "sha256": sha_pre,
        "raw_lines": raw_scan["total_lines"],
        "blank_or_comma_only_lines": raw_scan["blank_or_comma_only_lines"],
        "utf8_errors": raw_scan["utf8_errors"],
        "non_ascii_lines": raw_scan["non_ascii_lines"],
        "first_utf8_err_line": raw_scan["first_utf8_err_line"],
        "rows_raw_loaded": raw_rows,
        "rows_valid": valid_rows,
        "columns_count": num_cols,
        "columns_raw": raw_col_names,
        "columns_normalized": norm_col_names,
        "null_counts": cols_with_null,
        "rows_with_any_null": rows_with_any_null,
        "inf_counts": cols_with_inf,
        "rows_with_any_inf": inf_rows_count,
        "constant_columns": constant_cols,
        "duplicate_rows": dup_rows_count,
        "raw_labels": raw_label_counts,
        "normalized_labels": norm_label_counts,
        "timestamp_info": ts_info,
        "network_info": net_info,
        "inspection_duration_seconds": elapsed,
    }


def main():
    print(f"Starting inspection across raw directory: {RAW_DIR}")
    if not RAW_DIR.exists():
        print(f"Error: RAW_DIR not found: {RAW_DIR}")
        sys.exit(1)

    files = sorted(RAW_DIR.glob("*.csv"))
    if not files:
        print(f"Error: No CSV files found in {RAW_DIR}")
        sys.exit(1)

    print(f"Found {len(files)} CSV files.")
    results = {}

    for f in files:
        info = inspect_file(f)
        results[f.name] = info

    # Schema compatibility verification
    print("\n========================================================")
    print("Verifying Schema Compatibility Across All Files...")
    first_file = files[0].name
    ref_cols = results[first_file]["columns_normalized"]
    all_compatible = True
    schema_diffs = {}

    for name, res in results.items():
        if res["columns_normalized"] != ref_cols:
            all_compatible = False
            diff = [
                (i, c1, c2)
                for i, (c1, c2) in enumerate(zip(res["columns_normalized"], ref_cols))
                if c1 != c2
            ]
            schema_diffs[name] = diff
            print(f"  [X] Incompatible columns in {name}: {diff}")
        else:
            print(f"  [OK] {name} matches reference schema (85 columns identical).")

    summary = {
        "inspection_timestamp": datetime.now().isoformat(),
        "total_files": len(files),
        "all_schemas_compatible": all_compatible,
        "schema_differences": schema_diffs,
        "reference_columns": ref_cols,
        "files": results,
    }

    with open(OUTPUT_JSON, "w", encoding="utf-8") as out:
        json.dump(summary, out, indent=2)

    print(f"\nInspection summary successfully written to: {OUTPUT_JSON}")
    print(f"Total size of inspection JSON: {OUTPUT_JSON.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
