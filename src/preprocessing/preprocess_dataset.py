"""
PHASE 2 - PREPROCESSING
=======================
Turns the raw CICIDS2017 CSV into a clean, well-documented dataset.

Run from the project root (Windows PowerShell):
    python -m src.preprocessing.preprocess_dataset

What it does, in order (each step prints progress and records its row counts):
     1. Load the raw CSV (read-only, SHA-256 fingerprint before and after)
     2. Normalize column names            ' Flow Bytes/s' -> 'flow_bytes_s'
     3. Map labels and create targets     BENIGN -> 0, attack labels -> 1
     4. Validate IPs / ports / protocol
     5. Make numeric columns numeric, drop columns that are entirely empty
     6. Inspect and (optionally) remove fully duplicated rows
     7. Handle NaN / +-Infinity
     8. Parse timestamps carefully (day/month order, 12-hour clock issue)
     9. Detect and (optionally) remove constant columns
    10. Check which context fields could leak the label
    11. Build a leakage-aware blocked-time train/validation/test plan
    12. Save the processed dataset, metadata and the report

What it does NOT do: train models, build TF-IDF, basepoints, profiles, or a dashboard.
The raw file is never modified.
"""

import argparse
import hashlib
import ipaddress
import json
import sys
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

from src.config import (PROJECT_ROOT, WEEKDAYS, ConfigError, load_config, resolve_path)

# Columns that every file must have (after name normalization)
REQUIRED_COLUMNS = ["source_ip", "destination_ip", "source_port", "destination_port",
                    "protocol", "timestamp", "label"]
# Columns we create ourselves (never treated as numeric features)
HELPER_COLUMNS = ["source_row", "timestamp_raw", "hour_shifted", "label_original",
                  "target_binary", "target_multiclass", "block_id", "split"]
# Some CICIDS2017 releases use short names; map them to one canonical name
NAME_ALIASES = {"src_ip": "source_ip", "dst_ip": "destination_ip",
                "src_port": "source_port", "dst_port": "destination_port"}
DATE_FORMATS = {
    "day_first": ["%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M"],
    "month_first": ["%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M"],
}


class PreprocessingError(Exception):
    """A problem we can explain to the user. `hint` tells them what to try."""

    def __init__(self, message, hint=None):
        super().__init__(message)
        self.hint = hint


def say(message):
    print(message, flush=True)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


# =============================================================================
# Step 2: column names
# =============================================================================
def snake_case(name) -> str:
    """' Flow Bytes/s' -> 'flow_bytes_s'.  Removes BOM leftovers, spaces, symbols."""
    import re
    name = str(name).replace("\ufeff", "").replace("ï»¿", "")
    name = re.sub(r"[^0-9a-z]+", "_", name.strip().lower()).strip("_")
    return name or "unnamed"


def normalize_columns(raw_names):
    """Return a list of unique normalized names (same order as raw_names)."""
    used, result = set(), []
    for raw in raw_names:
        name = snake_case(raw)
        name = NAME_ALIASES.get(name, name)
        candidate, k = name, 1
        while candidate in used:          # two different raw names became the same name
            k += 1
            candidate = f"{name}_dup{k}"
        used.add(candidate)
        result.append(candidate)
    return result


# =============================================================================
# Step 3: labels
# =============================================================================
def map_labels(raw_labels: pd.Series, cfg: dict):
    """Return (clean_label, target_binary, target_multiclass, label_to_code)."""
    benign = cfg["labels"]["benign_label"]
    attacks = cfg["labels"]["attack_labels"]
    known = {benign.lower(): benign}
    known.update({a.lower(): a for a in attacks})

    # Clean extra spaces, and replace non-ASCII en-dashes (\x96 or \u2013) with standard hyphen
    stripped = raw_labels.astype(str).str.replace("\x96", "-").str.replace("–", "-").str.strip()
    canonical = stripped.str.lower().map(known)
    unknown = canonical.isna()
    if unknown.any():
        counts = stripped[unknown].value_counts().to_dict()
        if cfg["labels"]["unknown_label_policy"] == "error":
            raise PreprocessingError(
                f"Found labels that are neither '{benign}' nor in labels.attack_labels: {counts}",
                hint="Add them to labels.attack_labels in configs/config.yaml, or set "
                     "labels.unknown_label_policy to 'attack'.")
        canonical = canonical.where(~unknown, stripped)

    binary = (canonical != benign).astype("int8")
    classes = [benign] + sorted(c for c in canonical.unique() if c != benign)
    code = {c: i for i, c in enumerate(classes)}
    multiclass = canonical.map(code).astype("int16")
    return canonical, binary, multiclass, code


# =============================================================================
# Step 4: network field validation
# =============================================================================
def find_invalid_network_rows(df: pd.DataFrame):
    """Return (boolean mask of invalid rows, dict of counts per field)."""
    bad = np.zeros(len(df), dtype=bool)
    counts = {}
    for col in ("source_ip", "destination_ip"):
        s = df[col].astype("string").str.strip()
        valid = set()
        for value in s.dropna().unique():
            try:
                ipaddress.ip_address(value)
                valid.add(value)
            except ValueError:
                pass
        m = (~s.isin(list(valid))).to_numpy(dtype=bool)
        counts[col] = int(m.sum())
        bad |= m
    for col in ("source_port", "destination_port"):
        p = pd.to_numeric(df[col], errors="coerce")
        m = (p.isna() | (p < 0) | (p > 65535) | (p % 1 != 0)).to_numpy(dtype=bool)
        counts[col] = int(m.sum())
        bad |= m
    p = pd.to_numeric(df["protocol"], errors="coerce")
    m = (p.isna() | (p < 0) | (p > 255) | (p % 1 != 0)).to_numpy(dtype=bool)
    counts["protocol"] = int(m.sum())
    bad |= m
    return bad, counts


# =============================================================================
# Step 8: timestamps
# =============================================================================
def _parse_order(strings: pd.Series, order: str) -> pd.Series:
    """Parse with one day/month order. Only UNIQUE strings are parsed (fast)."""
    uniques = pd.Series(strings.dropna().unique())
    parsed = pd.to_datetime(uniques, format=DATE_FORMATS[order][0], errors="coerce")
    for fmt in DATE_FORMATS[order][1:]:
        parsed = parsed.fillna(pd.to_datetime(uniques, format=fmt, errors="coerce"))
    lookup = pd.Series(parsed.values, index=uniques.values)
    return pd.to_datetime(strings.map(lookup))


def _summarize(parsed: pd.Series) -> dict:
    ok = parsed.dropna()
    if ok.empty:
        return {"parsed": 0}
    return {"parsed": int(len(ok)), "min": ok.min(), "max": ok.max(),
            "weekday": ok.dt.day_name().mode().iloc[0], "days": int(ok.dt.normalize().nunique())}


def parse_timestamps(raw: pd.Series, cfg: dict, file_name: str):
    """
    Returns (timestamps, hour_shifted_mask, info).
    Nothing is assumed silently: every decision and its evidence goes into `info`.
    """
    tcfg = cfg["timestamp"]
    strings = raw.astype("string").str.strip()
    info = {"examples": strings.dropna().unique()[:5].tolist(), "notes": [], "uncertain": False}
    info["has_seconds"] = int((strings.str.count(":") >= 2).sum())

    orders = ["day_first", "month_first"] if tcfg["date_order"] == "auto" else [tcfg["date_order"]]
    results = {o: _parse_order(strings, o) for o in orders}
    info["order_tests"] = {o: _summarize(results[o]) for o in orders}
    best = max(s["parsed"] for s in info["order_tests"].values())
    if best == 0:
        raise PreprocessingError(
            f"No timestamp could be parsed. Examples from the file: {info['examples']}",
            hint="Check the 'Timestamp' column format; formats tried are day/month/year and "
                 "month/day/year with H:M or H:M:S.")
    candidates = [o for o in orders if info["order_tests"][o]["parsed"] == best]

    if len(candidates) == 1:
        chosen = candidates[0]
        info["order_reason"] = (f"Only '{chosen}' parsed the most rows ({best:,})."
                                if len(orders) > 1 else f"Fixed by config (timestamp.date_order = {chosen}).")
    else:
        expected = tcfg["expected_weekday"]
        if expected == "auto":
            expected = next((d for d in WEEKDAYS if d.lower() in file_name.lower()), None)
        elif expected == "none":
            expected = None
        info["expected_weekday"] = expected
        matches = [o for o in candidates if expected and info["order_tests"][o]["weekday"] == expected]
        if len(matches) == 1:
            chosen = matches[0]
            info["order_reason"] = (f"Both day/month orders parse every row (ambiguous). The file name says "
                                    f"'{expected}'; only '{chosen}' gives a {expected}.")
        else:
            chosen = tcfg["fallback_date_order"]
            info["uncertain"] = True
            info["order_reason"] = ("Both day/month orders parse every row and the weekday check could not "
                                    f"decide. FALLBACK to '{chosen}' (config). PLEASE VERIFY.")
    info["chosen_order"] = chosen
    parsed = results[chosen]

    # ---- 12-hour clock without AM/PM? ----
    hours = parsed.dt.hour
    info["hours_before"] = hours.dropna().astype(int).value_counts().sort_index().to_dict()
    mode = tcfg["hour_correction"]
    is_afternoon = "afternoon" in file_name.lower()
    looks_12h = bool((hours.max() < 13 and hours.between(8, 11).any() and hours.between(1, 7).any()) or
                     (is_afternoon and hours.max() < 13 and hours.between(1, 7).any()))
    apply = looks_12h if mode == "auto" else (mode == "always")
    info["hour_rule"] = mode
    info["hour_pattern_detected"] = looks_12h
    shifted = pd.Series(False, index=parsed.index)
    if apply:
        shifted = parsed.notna() & hours.between(1, 7)
        parsed = parsed.where(~shifted, parsed + pd.Timedelta(hours=12))
        info["notes"].append(
            "Hours 1-7 were shifted by +12h (assumption: the capture ran in working hours, "
            "so '2:00' means 14:00). VERIFY against the two hour tables above.")
    info["hour_correction_applied"] = bool(apply)
    ok = parsed.dropna()
    info["hours_after"] = ok.dt.hour.astype(int).value_counts().sort_index().to_dict()
    active = set(info["hours_after"])
    info["hour_gaps"] = [h for h in range(min(active), max(active) + 1) if h not in active]
    info["span"] = (ok.min(), ok.max())
    info["distinct_days"] = int(ok.dt.normalize().nunique())
    return parsed, shifted.to_numpy(dtype=bool), info


# =============================================================================
# Step 11: blocked-time split plan
# =============================================================================
def build_split_plan(df: pd.DataFrame, cfg: dict):
    """
    Cut the timeline into blocks of `block_minutes`; each whole block goes to ONE split.
    Blocks are stratified by their dominant attack type so every attack appears in
    train/validation/test when enough blocks exist. Returns (block_id, split, plan, warnings).
    """
    scfg = cfg["split"]
    benign = cfg["labels"]["benign_label"]
    warnings = []
    t0 = df["timestamp"].min().floor("min")
    block_id = ((df["timestamp"] - t0) // pd.Timedelta(minutes=scfg["block_minutes"])).astype("int32")

    plan = pd.DataFrame({
        "block_id": block_id, "timestamp": df["timestamp"],
        "is_attack": df["target_binary"].to_numpy(), "label": df["label"].astype(str).to_numpy()})
    blocks = plan.groupby("block_id").agg(
        start=("timestamp", "min"), end=("timestamp", "max"),
        rows=("timestamp", "size"), attack_rows=("is_attack", "sum"))
    attack_counts = (plan[plan["is_attack"] == 1].groupby(["block_id", "label"]).size().unstack(fill_value=0))
    dominant = attack_counts.idxmax(axis=1) if not attack_counts.empty else pd.Series(dtype=str)
    blocks["stratum"] = dominant.reindex(blocks.index).fillna(benign)

    rng = np.random.default_rng(scfg["random_seed"])
    assignment = {}
    for stratum in sorted(blocks["stratum"].unique()):
        ids = sorted(blocks.index[blocks["stratum"] == stratum].tolist())
        rng.shuffle(ids)
        n = len(ids)
        n_test = int(round(n * scfg["test_fraction"]))
        n_val = int(round(n * scfg["validation_fraction"]))
        if n >= 3:                                   # make sure val/test are not empty
            n_test, n_val = max(n_test, 1), max(n_val, 1)
            while n_test + n_val >= n:
                if n_test >= n_val and n_test > 1:
                    n_test -= 1
                elif n_val > 1:
                    n_val -= 1
                else:
                    break
        else:
            warnings.append(f"Stratum '{stratum}' has only {n} block(s): it cannot appear in "
                            "all of train/validation/test. Use a smaller split.block_minutes.")
        for i, b in enumerate(ids):
            assignment[b] = "test" if i < n_test else ("validation" if i < n_test + n_val else "train")

    blocks["split"] = blocks.index.map(assignment)
    split = block_id.map(assignment)
    return block_id, split, blocks.reset_index(), warnings


# =============================================================================
# Main pipeline on one DataFrame (pure function: easy to test)
# =============================================================================
def preprocess_dataframe(df: pd.DataFrame, cfg: dict, file_name: str, log=say):
    """
    Clean `df` (the raw table; it is modified, so pass a fresh copy if you still need it).
    Returns (clean_dataframe, info_dict).
    """
    info = {"file": file_name, "warnings": [], "steps": []}
    benign = cfg["labels"]["benign_label"]
    context = [c for c in cfg["features"]["context_columns"]]

    def track(name, before, after, note=""):
        info["steps"].append((name, before, after, note))

    info["rows_loaded"], info["cols_loaded"] = df.shape

    # ---- Step 2: column names ----
    log("[2/12] Normalizing column names ...")
    raw_names = list(df.columns)
    df.columns = normalize_columns(raw_names)
    info["column_mapping"] = list(zip(raw_names, df.columns))
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise PreprocessingError(
            f"Required column(s) not found after normalization: {missing}",
            hint="This looks like a CICIDS2017 version without IPs/timestamps (the 'MachineLearningCVE' "
                 "files). Use the 'TrafficLabelling' version.")
    df.insert(0, "source_row", np.arange(len(df), dtype="int64"))
    track("Load + rename columns", len(df), len(df), f"{len(raw_names)} columns renamed to snake_case")

    # ---- Step 3: labels ----
    log("[3/12] Mapping labels and creating targets ...")
    label_original = df["label"].astype(str)
    label, binary, multiclass, code = map_labels(df["label"], cfg)
    df["label_original"] = label_original
    df["label"] = label
    df["target_binary"] = binary
    df["target_multiclass"] = multiclass
    info["label_to_code"] = code
    info["labels_loaded"] = label.value_counts().to_dict()

    # ---- Step 4: network fields ----
    log("[4/12] Validating IP addresses, ports and protocol ...")
    bad, counts = find_invalid_network_rows(df)
    info["invalid_network"] = {"counts": counts, "rows": int(bad.sum())}
    if bad.any():
        if cfg["cleaning"]["invalid_network_fields"] == "error":
            raise PreprocessingError(f"{int(bad.sum()):,} rows have invalid network fields: {counts}",
                                     hint="Set cleaning.invalid_network_fields to 'drop' to remove them.")
        before = len(df)
        df = df.loc[~bad].copy()
        track("Drop invalid IP/port/protocol", before, len(df), f"{counts}")
    else:
        track("Validate IP/port/protocol", len(df), len(df), "no invalid values")
    df["source_ip"] = df["source_ip"].astype("string").str.strip()
    df["destination_ip"] = df["destination_ip"].astype("string").str.strip()
    for c in ("source_port", "destination_port"):
        df[c] = pd.to_numeric(df[c]).astype("int32")
    df["protocol"] = pd.to_numeric(df["protocol"]).astype("int16")

    # ---- Step 5: numeric columns ----
    log("[5/12] Converting feature columns to numbers ...")
    not_features = set(context) | {"label"} | set(HELPER_COLUMNS)
    feature_cols = [c for c in df.columns if c not in not_features]
    malformed = []
    for c in feature_cols:
        if not pd.api.types.is_numeric_dtype(df[c]):
            coerced = pd.to_numeric(df[c], errors="coerce")
            n_bad = int((coerced.isna() & df[c].notna()).sum())
            if n_bad:
                malformed.append((c, n_bad))
            df[c] = coerced
    info["malformed_numeric"] = malformed
    empty = [c for c in feature_cols if df[c].isna().all()]
    if empty:
        df = df.drop(columns=empty)
        feature_cols = [c for c in feature_cols if c not in empty]
    info["empty_columns"] = empty
    track("Numeric conversion", len(df), len(df),
          f"{len(malformed)} column(s) had text values; {len(empty)} empty column(s) removed")

    # ---- Step 6: duplicates ----
    log("[6/12] Inspecting duplicate rows ...")
    skip = {"source_row", "label_original", "target_binary", "target_multiclass"}
    subset = [c for c in df.columns if c not in skip]
    dup = df.duplicated(subset=subset, keep=cfg["cleaning"]["duplicate_keep"])
    info["duplicates"] = {"count": int(dup.sum()),
                          "by_label": df.loc[dup, "label"].value_counts().to_dict(),
                          "removed": bool(cfg["cleaning"]["remove_duplicates"])}
    if dup.any() and cfg["cleaning"]["remove_duplicates"]:
        before = len(df)
        df = df.loc[~dup].copy()
        track("Remove duplicate rows", before, len(df), f"keep={cfg['cleaning']['duplicate_keep']}")
    else:
        track("Duplicate rows", len(df), len(df),
              "found but kept (cleaning.remove_duplicates = false)" if dup.any() else "none found")

    # ---- Step 7: NaN / infinity ----
    log("[7/12] Handling NaN and infinite values ...")
    bad_rows = np.zeros(len(df), dtype=bool)
    nf_table = []
    for c in feature_cols:
        v = df[c].to_numpy(dtype="float64")
        nan, pos, neg = np.isnan(v), np.isposinf(v), np.isneginf(v)
        if nan.any() or pos.any() or neg.any():
            nf_table.append((c, int(nan.sum()), int(pos.sum()), int(neg.sum())))
            bad_rows |= nan | pos | neg
    n_bad = int(bad_rows.sum())
    info["non_finite"] = {"table": nf_table, "rows": n_bad, "strategy": cfg["cleaning"]["non_finite_strategy"],
                          "by_label": df.loc[bad_rows, "label"].value_counts().to_dict()}
    if n_bad:
        if cfg["cleaning"]["non_finite_strategy"] == "drop_rows":
            frac = n_bad / len(df)
            if frac > cfg["cleaning"]["max_drop_fraction"]:
                raise PreprocessingError(
                    f"{n_bad:,} rows ({frac:.2%}) contain NaN/Infinity - more than the allowed "
                    f"{cfg['cleaning']['max_drop_fraction']:.2%}.",
                    hint="Look at the preprocessing report / dataset report, or raise "
                         "cleaning.max_drop_fraction, or use non_finite_strategy: keep_as_nan.")
            before = len(df)
            df = df.loc[~bad_rows].copy()
            track("Drop rows with NaN/Infinity", before, len(df), f"{n_bad:,} rows")
        else:
            for c, *_ in nf_table:
                df[c] = df[c].replace([np.inf, -np.inf], np.nan)
            track("Infinity -> NaN (rows kept)", len(df), len(df), f"{n_bad:,} rows still contain NaN")
    else:
        track("NaN / Infinity", len(df), len(df), "none found")

    # ---- Step 8: timestamps ----
    log("[8/12] Parsing timestamps (this is the delicate step) ...")
    raw_ts = df["timestamp"].astype("string").str.strip()
    parsed, shifted, tinfo = parse_timestamps(df["timestamp"], cfg, file_name)
    info["timestamp"] = tinfo
    unparse = parsed.isna().to_numpy()
    if unparse.any():
        frac = unparse.mean()
        if frac > cfg["timestamp"]["max_unparseable_fraction"]:
            raise PreprocessingError(f"{int(unparse.sum()):,} timestamps ({frac:.2%}) could not be parsed.",
                                     hint=f"Examples from the file: {tinfo['examples']}")
    df["timestamp_raw"] = raw_ts
    df["timestamp"] = parsed
    df["hour_shifted"] = shifted
    if unparse.any():
        before = len(df)
        df = df.loc[~unparse].copy()
        track("Drop unparseable timestamps", before, len(df), "")
    else:
        track("Parse timestamps", len(df), len(df), f"order={tinfo['chosen_order']}")
    if tinfo["uncertain"]:
        info["warnings"].append("Timestamp day/month order could not be confirmed - see section 'Timestamps'.")
    df = df.sort_values(["timestamp", "source_row"], kind="stable").reset_index(drop=True)

    # ---- Step 9: constant columns ----
    log("[9/12] Looking for constant columns ...")
    constants = [(c, df[c].dropna().iloc[0] if df[c].notna().any() else None)
                 for c in feature_cols if df[c].nunique(dropna=True) <= 1]
    info["constant_columns"] = constants
    info["constant_removed"] = bool(cfg["cleaning"]["remove_constant_columns"])
    if cfg["cleaning"]["remove_constant_columns"]:
        drop_cols = [c for c, _ in constants]
        for std_col in ["bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags", "cwe_flag_count",
                        "fwd_avg_bytes_bulk", "fwd_avg_packets_bulk", "fwd_avg_bulk_rate",
                        "bwd_avg_bytes_bulk", "bwd_avg_packets_bulk", "bwd_avg_bulk_rate"]:
            if std_col in df.columns and std_col not in drop_cols:
                drop_cols.append(std_col)
        if drop_cols:
            df = df.drop(columns=drop_cols)
            feature_cols = [c for c in feature_cols if c not in drop_cols]
            track("Remove constant columns", len(df), len(df), f"{len(drop_cols)} columns removed")
        else:
            track("Constant columns", len(df), len(df), "none")
    else:
        track("Constant columns", len(df), len(df), f"{len(constants)} found" if constants else "none")

    # negative values: report only, never modify
    negatives = []
    for c in feature_cols:
        v = df[c].to_numpy(dtype="float64")
        n_neg = int((v < 0).sum())
        if n_neg:
            vmin = float(np.nanmin(v))
            kind = "min is -1 (possible 'not set' marker)" if vmin == -1 else "other negative values"
            negatives.append((c, n_neg, n_neg / len(df), vmin, kind))
    info["negatives"] = negatives

    # ---- Step 10: leakage-risk check on context fields ----
    log("[10/12] Checking which context fields could leak the label ...")
    leak = []
    benign_df = df[df["target_binary"] == 0]
    for lab in sorted(df.loc[df["target_binary"] == 1, "label"].astype(str).unique()):
        sub = df[df["label"].astype(str) == lab]
        for field in ("source_ip", "destination_ip", "source_port", "destination_port", "protocol"):
            top = sub[field].value_counts().index[0]
            leak.append((lab, field, top, float((sub[field] == top).mean()),
                         float((benign_df[field] == top).mean()) if len(benign_df) else float("nan")))
    info["leakage"] = leak

    # ---- Step 11: split plan ----
    if cfg["split"]["enabled"]:
        log("[11/12] Building the blocked-time split plan ...")
        block_id, split, plan, warns = build_split_plan(df, cfg)
        df["block_id"], df["split"] = block_id, split
        info["split_plan"] = plan
        info["split_warnings"] = warns
        info["split_table"] = pd.crosstab(df["split"], df["label"].astype(str))
    else:
        log("[11/12] Split plan disabled in config - skipping.")
        df["block_id"], df["split"] = -1, "unassigned"
        info["split_plan"], info["split_warnings"], info["split_table"] = None, [], None

    # ---- Step 12 (part): final column order and types ----
    log("[12/12] Assembling final table ...")
    float_dtype = cfg["output"]["float_dtype"]
    for c in feature_cols:
        if pd.api.types.is_float_dtype(df[c]):
            df[c] = df[c].astype(float_dtype)
    context_present = [c for c in context if c in df.columns]
    front = (["source_row", "timestamp", "timestamp_raw", "hour_shifted"] +
             [c for c in context_present if c != "timestamp"] +
             ["label_original", "label", "target_binary", "target_multiclass", "block_id", "split"])
    df = df[front + feature_cols]
    info["context_columns"] = context_present
    info["feature_columns"] = feature_cols
    info["rows_final"] = len(df)
    info["labels_final"] = df["label"].astype(str).value_counts().to_dict()
    return df, info


# =============================================================================
# File-level helpers
# =============================================================================
def read_processed_dataset(path):
    """Load a processed file back with correct types (timestamps stay real datetimes)."""
    path = Path(path)
    if path.suffix == ".parquet":
        return pd.read_parquet(path)
    return pd.read_csv(path, parse_dates=["timestamp"], low_memory=False)


def _json_default(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, (pd.Timestamp,)):
        return str(o)
    return str(o)


def process_file(raw_path: Path, cfg: dict, log=say):
    """Run the full pipeline on one raw CSV and write all outputs. Returns the info dict."""
    t0 = time.time()
    raw_path = Path(raw_path)
    if not raw_path.exists():
        raise PreprocessingError(f"Raw file not found: {raw_path}",
                                 hint="Put the CSV in data/raw/ (see config 'paths.raw_dir').")
    out_dir = resolve_path(cfg["paths"]["processed_dir"])
    interim_dir = resolve_path(cfg["paths"]["interim_dir"])
    out_dir.mkdir(parents=True, exist_ok=True)
    interim_dir.mkdir(parents=True, exist_ok=True)

    log(f"\n=== {raw_path.name} ===")
    log("[1/12] Fingerprinting and reading the raw CSV (read-only) ...")
    sha_before = sha256_of(raw_path)
    try:
        df = pd.read_csv(raw_path, encoding=cfg["dataset"]["encoding"], low_memory=False)
    except UnicodeDecodeError as e:
        raise PreprocessingError(f"Could not decode {raw_path.name} as {cfg['dataset']['encoding']}: {e}",
                                 hint="Change dataset.encoding in configs/config.yaml.") from e
    except pd.errors.EmptyDataError as e:
        raise PreprocessingError(f"{raw_path.name} is empty.") from e

    # Prune completely blank / all-NaN trailing comma rows (specifically handles Thursday WebAttacks)
    all_nan = df.isna().all(axis=1)
    blank_pruned = int(all_nan.sum())
    if blank_pruned > 0:
        log(f"      pruned {blank_pruned:,} trailing empty / all-NaN comma rows")
        df = df.loc[~all_nan].copy()
    log(f"      loaded {len(df):,} valid rows x {df.shape[1]} columns")

    df, info = preprocess_dataframe(df, cfg, raw_path.name, log=log)
    info["sha_before"] = sha_before

    stem = raw_path.stem.replace(".pcap_ISCX", "")
    fmt = cfg["output"]["format"]
    data_path = out_dir / f"{stem}_clean.{fmt}"
    if stem == "Tuesday-WorkingHours" and data_path.exists():
        log(f"      Preserving existing Tuesday clean dataset (untouched) at {data_path}")
    else:
        log(f"Saving processed dataset -> {data_path}")
        if fmt == "parquet":
            try:
                df.to_parquet(data_path, index=False)
            except ImportError as e:
                raise PreprocessingError("Parquet output needs the 'pyarrow' package.",
                                         hint="Run: pip install pyarrow   (or set output.format: csv)") from e
        else:
            df.to_csv(data_path, index=False)

    n_sample = cfg["output"]["sample_rows"]
    sample_path = None
    if n_sample:
        per = max(1, n_sample // max(1, df["label"].nunique()))
        parts = [g.sample(min(len(g), per), random_state=cfg["split"]["random_seed"])
                 for _, g in df.groupby(df["label"].astype(str), observed=True)]
        sample_path = out_dir / f"{stem}_sample.csv"
        pd.concat(parts).sort_values("timestamp").to_csv(sample_path, index=False)

    mapping_path = interim_dir / f"{stem}_column_mapping.csv"
    pd.DataFrame(info["column_mapping"], columns=["raw_name", "normalized_name"]).to_csv(mapping_path, index=False)
    plan_path = None
    if info["split_plan"] is not None:
        plan_path = out_dir / f"{stem}_split_plan.csv"
        info["split_plan"].to_csv(plan_path, index=False)

    meta_path = out_dir / f"{stem}_metadata.json"
    metadata = {
        "source_file": raw_path.name, "raw_sha256": sha_before,
        "rows_loaded": info["rows_loaded"], "rows_final": info["rows_final"],
        "context_columns": info["context_columns"], "feature_columns": info["feature_columns"],
        "removed_constant_columns": [c for c, _ in info["constant_columns"]] if info["constant_removed"] else [],
        "targets": {"target_binary": f"{cfg['labels']['benign_label']} = 0, attack = 1",
                    "target_multiclass": info["label_to_code"]},
        "timestamp": {"order": info["timestamp"]["chosen_order"], "uncertain": info["timestamp"]["uncertain"],
                      "hour_correction_applied": info["timestamp"]["hour_correction_applied"]},
        "window": cfg["window"], "split": cfg["split"], "config_snapshot": cfg,
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2, default=_json_default)

    info["sha_after"] = sha256_of(raw_path)
    info["raw_untouched"] = info["sha_after"] == info["sha_before"]
    info["outputs"] = {"processed data": data_path, "sample": sample_path, "metadata": meta_path,
                       "split plan": plan_path, "column mapping": mapping_path}
    info["seconds"] = time.time() - t0
    return info


def combine_processed_datasets(cfg: dict, infos: list, log=say):
    """
    Combines individual processed CSV datasets into a single unified dataset
    with consistent columns and multi-experiment split mappings.
    """
    t0 = time.time()
    out_dir = resolve_path(cfg["paths"]["processed_dir"])
    combined_path = out_dir / "CICIDS2017_combined_clean.csv"
    combined_sample_path = out_dir / "CICIDS2017_combined_sample.csv"
    combined_meta_path = out_dir / "CICIDS2017_combined_metadata.json"
    combined_plan_path = out_dir / "CICIDS2017_combined_split_plan.csv"

    log("\n" + "=" * 60)
    log("Combining processed datasets across all captures ...")

    def get_exp_b_split(filename: str) -> str:
        fn = filename.lower()
        if any(d in fn for d in ["monday", "tuesday", "wednesday"]):
            return "train"
        elif "thursday" in fn:
            return "validation"
        elif "friday" in fn:
            return "test"
        return "unassigned"

    total_rows = 0
    label_counts = {}
    exp_a_split_counts = {"train": 0, "validation": 0, "test": 0}
    exp_b_split_counts = {"train": 0, "validation": 0, "test": 0}
    exp_a_label_table = {}
    exp_b_label_table = {}
    plans = []
    samples = []
    first = True
    ref_cols = None

    for idx, info in enumerate(infos):
        clean_path = info["outputs"]["processed data"]
        stem = Path(clean_path).stem.replace("_clean", "")
        log(f"  Streaming [{idx + 1}/{len(infos)}] {clean_path.name} ...")
        df_chunk = pd.read_csv(clean_path, low_memory=False)

        if ref_cols is None:
            ref_cols = list(df_chunk.columns)
        else:
            if list(df_chunk.columns) != ref_cols:
                diffs = [c for c in df_chunk.columns if c not in ref_cols]
                raise PreprocessingError(f"Schema mismatch when combining: {clean_path.name} differences: {diffs}")

        exp_b = get_exp_b_split(info["file"])
        df_chunk["source_dataset"] = stem
        df_chunk["experiment_b_split"] = exp_b

        total_rows += len(df_chunk)
        for lbl, count in df_chunk["label"].value_counts().items():
            label_counts[str(lbl)] = label_counts.get(str(lbl), 0) + int(count)

        for sp, count in df_chunk["split"].value_counts().items():
            exp_a_split_counts[str(sp)] = exp_a_split_counts.get(str(sp), 0) + int(count)
        exp_b_split_counts[exp_b] = exp_b_split_counts.get(exp_b, 0) + len(df_chunk)

        for (sp, lbl), count in df_chunk.groupby(["split", "label"], observed=True).size().to_dict().items():
            exp_a_label_table.setdefault(str(sp), {})[str(lbl)] = int(count)
        for (sp, lbl), count in df_chunk.groupby(["experiment_b_split", "label"], observed=True).size().to_dict().items():
            exp_b_label_table.setdefault(str(sp), {})[str(lbl)] = int(count)

        samples.append(df_chunk.sample(min(len(df_chunk), 150), random_state=42))

        if info.get("split_plan") is not None:
            p = info["split_plan"].copy()
            p["source_dataset"] = stem
            p["experiment_b_split"] = exp_b
            plans.append(p)

        mode = "w" if first else "a"
        header = first
        df_chunk.to_csv(combined_path, mode=mode, header=header, index=False)
        first = False

    if samples:
        pd.concat(samples).to_csv(combined_sample_path, index=False)

    if plans:
        pd.concat(plans).to_csv(combined_plan_path, index=False)

    combined_meta = {
        "combined_file": combined_path.name,
        "total_datasets": len(infos),
        "datasets": [i["file"] for i in infos],
        "total_rows_final": total_rows,
        "columns_count": len(ref_cols) + 2,
        "columns": ref_cols + ["source_dataset", "experiment_b_split"],
        "labels_distribution": label_counts,
        "experiment_a_split_distribution": exp_a_split_counts,
        "experiment_b_split_distribution": exp_b_split_counts,
        "experiment_a_labels_by_split": exp_a_label_table,
        "experiment_b_labels_by_split": exp_b_label_table,
        "generated_at": datetime.now().isoformat(),
        "elapsed_seconds": round(time.time() - t0, 2),
    }
    with open(combined_meta_path, "w", encoding="utf-8") as f:
        json.dump(combined_meta, f, indent=2, default=_json_default)

    log(f"  Combined dataset written to: {combined_path}")
    log(f"  Total combined rows: {total_rows:,} across {len(infos)} files in {round(time.time() - t0, 1)}s")
    return combined_meta


def find_raw_files(cfg: dict):
    raw_dir = resolve_path(cfg["paths"]["raw_dir"])
    wanted = cfg["dataset"]["raw_files"]
    if wanted == "auto":
        files = sorted(raw_dir.glob("*.csv"))
    else:
        files = [raw_dir / name for name in wanted]
    if not files:
        raise PreprocessingError(f"No .csv files found in {raw_dir}",
                                 hint="Copy the CICIDS2017 CSV into that folder and run again.")
    return files


def main(argv=None):
    ap = argparse.ArgumentParser(description="Phase 2: preprocess raw CICIDS2017 CSV file(s).")
    ap.add_argument("--config", type=Path, default=None, help="path to a config YAML (default: configs/config.yaml)")
    ap.add_argument("--file", type=str, default=None, help="process only this file name from raw_dir")
    args = ap.parse_args(argv)

    try:
        cfg, source = load_config(args.config)
        say(f"Configuration: {source}")
        if args.file:
            cfg["dataset"]["raw_files"] = [args.file]
        files = find_raw_files(cfg)
        infos = [process_file(f, cfg) for f in files]
        combined_meta = None
        if len(infos) > 1:
            combined_meta = combine_processed_datasets(cfg, infos)

        from src.preprocessing.report_writer import write_preprocessing_report
        report_path = resolve_path(cfg["paths"]["reports_dir"]) / "preprocessing_report.md"
        write_preprocessing_report(infos, cfg, source, report_path, combined_meta=combined_meta)
    except (PreprocessingError, ConfigError) as e:
        say(f"\nERROR: {e}")
        if getattr(e, "hint", None):
            say(f"HINT:  {e.hint}")
        return 1

    say("\n" + "=" * 60)
    for i in infos:
        say(f"{i['file']}: {i['rows_loaded']:,} rows loaded -> {i['rows_final']:,} rows kept "
            f"({len(i['feature_columns'])} feature columns)")
        say(f"  labels kept       : {i['labels_final']}")
        say(f"  raw file untouched: {i['raw_untouched']}")
        say(f"  warnings          : {len(i['warnings']) + len(i['split_warnings'])}")
        say(f"  time taken        : {i['seconds']:.1f} s")
    say("=" * 60)
    say(f"Processed data : {infos[-1]['outputs']['processed data']}")
    say(f"Report written : {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
