"""
Multi-Day Event Profile Generation for CICIDS2017
=================================================
Generates leakage-safe event profiles across all eight CICIDS2017 capture files,
supporting both:
  - EXPERIMENT A: Multi-Class Classification (Time-Blocked per Day)
  - EXPERIMENT B: Unseen Attack Detection (Mon/Tue/Wed Train, Thu Val, Fri Held-Out Test)

Methodological Principles:
  - Source-Destination Communication Grouping within 10-minute sliding windows (60s step).
  - Capture-Day Window Isolation: Windows NEVER cross capture days or split boundaries.
  - Strict Leakage Prevention: Flow thresholds, Set thresholds, TF-IDF IDF weights,
    and Basepoint selection are fitted EXCLUSIVELY on the TRAINING partition.
  - Separate Ground Truth: Labels, IP addresses, ports, and timestamps are NEVER
    used as model input features.
"""

import os
import sys
import json
import time
import shutil
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List, Tuple

import numpy as np
import pandas as pd

from src.config import load_config, resolve_path, PROJECT_ROOT
from src.event_profiles.settings import load_settings
from src.event_profiles.errors import EventProfileError
from src.event_profiles.events import (
    EVENT_INPUT_COLUMNS, EVENT_NAMES, FLOW_EVENT_SPECS,
    fit_flow_thresholds, apply_flow_events, fit_set_threshold, compare,
    assert_no_forbidden_columns
)
from src.event_profiles.windows import compute_bins, bin_split_names, valid_windows, aggregate_to_windows
from src.event_profiles.tfidf import fit_idf, transform
from src.event_profiles.basepoints import select_basepoints, compute_profiles
from src.event_profiles.targets import assign_targets, mixed_statistics
from src.event_profiles.validation import validate_model_files, PROFILE_ID_COLUMNS

LABEL_COLUMNS = ["source_row", "label", "target_binary", "target_multiclass"]

GLOBAL_LABEL_TO_CODE = {
    "BENIGN": 0,
    "Bot": 1,
    "DDoS": 2,
    "DoS GoldenEye": 3,
    "DoS Hulk": 4,
    "DoS Slowhttptest": 5,
    "DoS slowloris": 6,
    "FTP-Patator": 7,
    "Heartbleed": 8,
    "Infiltration": 9,
    "PortScan": 10,
    "SSH-Patator": 11,
    "Web Attack - Brute Force": 12,
    "Web Attack - Sql Injection": 13,
    "Web Attack - XSS": 14,
}
GLOBAL_CODE_TO_LABEL = {v: k for k, v in GLOBAL_LABEL_TO_CODE.items()}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def say(msg):
    print(msg, flush=True)


def get_capture_files(proc_dir: Path):
    return sorted([f for f in proc_dir.glob("*_clean.csv") if "combined" not in f.name])


TUESDAY_CONTROL_BLOCKS = (4, 27)


def assign_experiment_b_split(filename: str, block_id: Optional[int] = None) -> str:
    """
    Assigns partition split for Experiment B.
    - Monday & Wednesday: 100% train
    - Tuesday: Non-control blocks -> train, Held-out blocks (4, 27) -> control_test
    - Thursday: 100% validation
    - Friday: 100% test (held-out unseen attacks)
    """
    fn = filename.lower()
    if "tuesday" in fn and block_id is not None:
        try:
            if int(block_id) in TUESDAY_CONTROL_BLOCKS:
                return "control_test"
        except (ValueError, TypeError):
            pass
        return "train"
    elif any(d in fn for d in ["monday", "tuesday", "wednesday"]):
        return "train"
    elif "thursday" in fn:
        return "validation"
    elif "friday" in fn:
        return "test"
    return "unassigned"


def run_multi_day_pipeline(experiment_mode: str = "exp_a", log=say):
    t_start = time.time()
    cfg, _ = load_config()
    settings = load_settings(cfg)
    proc_dir = resolve_path(cfg["paths"]["processed_dir"])
    clean_files = get_capture_files(proc_dir)

    if not clean_files:
        raise EventProfileError(f"No clean files found in {proc_dir}")

    experiment_mode = str(experiment_mode).lower().strip()
    if experiment_mode not in ("exp_a", "exp_b"):
        raise EventProfileError(
            f"Invalid experiment_mode '{experiment_mode}'. Expected 'exp_a' or 'exp_b'.",
            "Pass 'exp_a' for Experiment A (Multi-Class) or 'exp_b' for Experiment B (Unseen Attack)."
        )

    # STRICT ISOLATION GUARD: Tuesday baseline must remain completely separate and untouched
    baseline_dir = (proc_dir / "event_profiles").resolve()
    baseline_profile_file = baseline_dir / "event_profiles.csv"
    baseline_before_hash = sha256_of(baseline_profile_file) if baseline_profile_file.exists() else None

    out_dirname = "event_profiles_exp_a" if experiment_mode == "exp_a" else "event_profiles_exp_b"
    out_dir = proc_dir / out_dirname

    if out_dir.resolve() == baseline_dir:
        raise EventProfileError(
            f"CRITICAL SAFETY VIOLATION: Output directory '{out_dir}' resolves to baseline directory '{baseline_dir}'. "
            f"Multi-day profiles must never write to or overwrite data/processed/event_profiles/."
        )

    # BACKUP GUARD: If output directory contains existing output files, back them up before overwriting
    out_dir.mkdir(parents=True, exist_ok=True)
    existing_files = [f for f in out_dir.iterdir() if f.is_file() and f.suffix in (".csv", ".json")]
    if existing_files:
        backup_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = PROJECT_ROOT / "backups" / f"{out_dirname}_backup_{backup_ts}"
        backup_path.mkdir(parents=True, exist_ok=True)
        for f_exist in existing_files:
            shutil.copy2(f_exist, backup_path / f_exist.name)
        log(f"[SAFETY BACKUP] Existing {experiment_mode.upper()} output detected ({len(existing_files)} files).")
        log(f"                Backed up safely to: {backup_path}")

    log("\n" + "=" * 70)
    log(f"STARTING MULTI-DAY EVENT PROFILE GENERATION: [{experiment_mode.upper()}]")
    log(f"Output directory: {out_dir}")
    log(f"Baseline directory protected: {baseline_dir}")
    log("=" * 70)

    # 1. Determine training split for flow threshold fitting
    log("[1/8] Collecting TRAINING flows across assigned partitions to fit flow thresholds ...")
    train_flow_samples = []
    for f in clean_files:
        if experiment_mode == "exp_a":
            df_cols = pd.read_csv(f, usecols=["split", "flow_packets_s", "flow_bytes_s", "syn_flag_count", "flow_duration"])
            mask = df_cols["split"] == "train"
        else:
            df_cols = pd.read_csv(f, usecols=["block_id", "flow_packets_s", "flow_bytes_s", "syn_flag_count", "flow_duration"])
            fn_l = f.name.lower()
            if "tuesday" in fn_l:
                # Exclude Tuesday control holdout blocks from training flow threshold fitting
                mask = ~df_cols["block_id"].isin(TUESDAY_CONTROL_BLOCKS)
            elif any(d in fn_l for d in ["monday", "wednesday"]):
                mask = np.ones(len(df_cols), dtype=bool)
            else:
                mask = np.zeros(len(df_cols), dtype=bool)
        if mask.any():
            train_flow_samples.append(df_cols.loc[mask, ["flow_packets_s", "flow_bytes_s", "syn_flag_count", "flow_duration"]])

    train_flows_combined = pd.concat(train_flow_samples, ignore_index=True)
    log(f"      Total training flows pooled for threshold calibration: {len(train_flows_combined):,}")

    thresholds = fit_flow_thresholds(train_flows_combined, settings)
    for k, v in thresholds.items():
        log(f"      Threshold [{k}]: {v['threshold']:.4f} (Rule: {v['comparison']}, {v['percentile']}th percentile)")
    del train_flows_combined

    # 2. Per-Capture Sliding Window Aggregation
    log("\n[2/8] Generating sliding-window event sets within each isolated capture day ...")
    size_sec = cfg["window"]["size_seconds"]
    step_sec = cfg["window"]["step_seconds"]
    W = size_sec // step_sec
    block_min = cfg["split"]["block_minutes"]

    all_capture_sets = []
    all_capture_keys = []
    all_capture_counts = []
    all_capture_targets = []
    global_set_counter = 0

    for idx, f in enumerate(clean_files, 1):
        cap_stem = f.stem.replace("_clean", "")
        log(f"  [{idx}/{len(clean_files)}] Processing capture: {f.name} ...")
        df_flow = pd.read_csv(f, usecols=EVENT_INPUT_COLUMNS, parse_dates=["timestamp"])
        assert_no_forbidden_columns(df_flow)

        # Set effective split for this capture
        if experiment_mode == "exp_b":
            fn_l = f.name.lower()
            if "tuesday" in fn_l:
                # Chronologically assign held-out Tuesday blocks (4, 27) to control_test
                df_flow["split"] = np.where(
                    df_flow["block_id"].isin(TUESDAY_CONTROL_BLOCKS),
                    "control_test",
                    "train"
                )
            else:
                df_flow["split"] = assign_experiment_b_split(f.name)

        # Time bins and sliding windows within this capture
        df_flow = df_flow.sort_values(["timestamp", "source_row"], kind="stable").reset_index(drop=True)
        bins, t0 = compute_bins(df_flow["timestamp"], step_sec)
        n_bins = int(bins.max()) + 1
        names = bin_split_names(bins, df_flow["block_id"].to_numpy(), df_flow["split"].to_numpy(),
                                n_bins, step_sec, block_min)
        valid, window_split = valid_windows(names, W)

        # Pair grouping (source_ip, destination_ip)
        pair = df_flow.groupby(["source_ip", "destination_ip"], sort=False).ngroup().to_numpy()
        cap_keys = (df_flow.assign(pair=pair).drop_duplicates("pair")[["pair", "source_ip", "destination_ip"]].copy())
        cap_keys["source_dataset"] = cap_stem

        # Apply flow thresholds
        flags = apply_flow_events(df_flow, thresholds)
        values = np.column_stack([np.ones(len(df_flow), dtype="int64"), flags.astype("int64")])

        # Aggregate flows into windows
        agg = aggregate_to_windows(pair, bins, values, W, valid, len(valid))
        agg = agg.sort_values(["k", "pair"], kind="stable").reset_index(drop=True)

        if agg.empty:
            log(f"      Warning: No valid event sets for {f.name}")
            continue

        cap_sets = pd.DataFrame({"pair": agg["pair"], "k": agg["k"], "n_flows": agg["v0"]})
        for j, (name, _, _) in enumerate(FLOW_EVENT_SPECS, start=1):
            cap_sets[name] = agg[f"v{j}"]
        cap_sets["split"] = window_split[cap_sets["k"].to_numpy()]
        cap_sets["source_dataset"] = cap_stem

        # Assign unique global IDs
        n_sets_cap = len(cap_sets)
        cap_sets["event_set_id"] = ["ES" + str(global_set_counter + i + 1).zfill(7) for i in range(n_sets_cap)]
        cap_sets["window_id"] = [f"{cap_stem[:4].upper()}_W" + str(k).zfill(5) for k in cap_sets["k"]]
        cap_sets["window_start"] = t0 + pd.to_timedelta(cap_sets["k"].to_numpy() * step_sec, unit="s")
        cap_sets["window_end"] = cap_sets["window_start"] + pd.Timedelta(seconds=size_sec)
        global_set_counter += n_sets_cap

        # Flow index for target join
        flow_idx = pd.DataFrame({"source_row": df_flow["source_row"].to_numpy(), "pair": pair, "bin": bins})

        # Load labels separately for targets
        df_labels = pd.read_csv(f, usecols=LABEL_COLUMNS)
        merged_lbl = flow_idx.merge(df_labels, on="source_row", how="left", validate="one_to_one")

        # Map labels to global 15 classes
        global_multiclass = merged_lbl["label"].map(GLOBAL_LABEL_TO_CODE).fillna(0).astype("int64")
        n_classes = len(GLOBAL_LABEL_TO_CODE)
        onehot = np.eye(n_classes, dtype="int64")[global_multiclass.to_numpy()]

        agg_lbl = aggregate_to_windows(pair, bins, onehot, W, valid, len(valid))
        agg_lbl = agg_lbl.sort_values(["k", "pair"], kind="stable").reset_index(drop=True)

        if len(agg) != len(agg_lbl):
            raise EventProfileError(
                f"Mismatch between aggregated event sets ({len(agg)}) and target counts ({len(agg_lbl)}) for {cap_stem}."
            )
        if not ((agg["k"].to_numpy() == agg_lbl["k"].to_numpy()).all() and (agg["pair"].to_numpy() == agg_lbl["pair"].to_numpy()).all()):
            raise EventProfileError(
                f"Ordering mismatch between event sets and target counts for {cap_stem}."
            )

        class_counts = agg_lbl[[f"v{i}" for i in range(n_classes)]].to_numpy()
        benign_code = GLOBAL_LABEL_TO_CODE["BENIGN"]
        t = assign_targets(class_counts, benign_code, settings["min_attack_flows"], settings["min_attack_fraction"])
        t.insert(0, "event_set_id", cap_sets["event_set_id"].to_numpy())
        t.insert(1, "window_id", cap_sets["window_id"].to_numpy())
        t.insert(2, "split", cap_sets["split"].to_numpy())
        t.insert(3, "source_dataset", cap_stem)
        t["target_label"] = t["target_multiclass"].map(GLOBAL_CODE_TO_LABEL)
        t = t.drop(columns=["n_flows"]).assign(n_flows=class_counts.sum(axis=1))

        cols_tgt = ["event_set_id", "window_id", "split", "source_dataset", "n_flows", "n_attack_flows",
                    "attack_fraction", "label_purity", "is_mixed", "is_multi_attack",
                    "target_binary", "target_multiclass", "target_label"]
        t = t[cols_tgt]

        cap_keys_merged = cap_sets[["event_set_id", "window_id", "pair"]].merge(cap_keys, on="pair", how="left").drop(columns="pair")

        all_capture_sets.append(cap_sets)
        all_capture_keys.append(cap_keys_merged)
        all_capture_targets.append(t)
        log(f"      -> {n_sets_cap:,} event sets generated for {cap_stem}")

    # Combine all event sets
    df_all_sets = pd.concat(all_capture_sets, ignore_index=True)
    df_all_targets = pd.concat(all_capture_targets, ignore_index=True)
    df_all_keys = pd.concat(all_capture_keys, ignore_index=True)
    total_event_sets = len(df_all_sets)
    log(f"\n[3/8] Total multi-day event sets assembled: {total_event_sets:,}")

    # 3. Fit HIGH_FLOW_RATE threshold on training event sets only
    train_mask = (df_all_sets["split"] == "train").to_numpy()
    log(f"[4/8] Fitting HIGH_FLOW_RATE threshold on {train_mask.sum():,} TRAINING event sets ...")
    thresholds["HIGH_FLOW_RATE"] = fit_set_threshold(df_all_sets.loc[train_mask, "n_flows"], settings)
    log(f"      Threshold [HIGH_FLOW_RATE]: {thresholds['HIGH_FLOW_RATE']['threshold']:.1f} flows/set "
        f"({thresholds['HIGH_FLOW_RATE']['percentile']}th percentile)")

    hfr = compare(df_all_sets["n_flows"].to_numpy(dtype="float64"),
                  thresholds["HIGH_FLOW_RATE"]["threshold"],
                  thresholds["HIGH_FLOW_RATE"]["comparison"]).astype("int64")
    df_all_sets["HIGH_FLOW_RATE"] = hfr

    counts_matrix = df_all_sets[EVENT_NAMES].to_numpy(dtype="int64")
    df_all_sets["is_empty"] = counts_matrix.sum(axis=1) == 0

    # 4. Fit TF-IDF model on TRAINING event sets only
    log(f"[5/8] Fitting TF-IDF model on {train_mask.sum():,} TRAINING event sets ...")
    idf_model = fit_idf(counts_matrix[train_mask], settings["sublinear_tf"])
    for name, df_val in zip(EVENT_NAMES, idf_model["document_frequency"]):
        log(f"      Term '{name}': Document Frequency = {df_val:,} sets in training split")

    log("      Transforming all event sets with fitted sublinear TF-IDF and L2 normalization ...")
    tfidf_vectors = transform(counts_matrix, idf_model)

    # 5. Basepoint Selection strictly on TRAINING TF-IDF vectors
    log("[6/8] Selecting 8 basepoints using training vectors and rare-event criteria ...")
    bp_result = select_basepoints(tfidf_vectors[train_mask], idf_model["document_frequency"], settings)
    for i, tr in enumerate(bp_result["trace"], 1):
        cos_prev = tr.get("max_cosine_to_previous")
        cos_str = f"{cos_prev:.4f}" if cos_prev is not None else "N/A (first pick)"
        rare_w = tr.get("rare_event_weight", 0.0)
        log(f"      Basepoint bp_{i:02d}: selected from candidate (cosine to previous: {cos_str}, rare weight: {rare_w:.4f})")

    # 6. Compute 8-dimensional Cosine Similarity Profiles
    log("[7/8] Computing 8-dimensional cosine similarity profiles across all event sets ...")
    profiles = compute_profiles(tfidf_vectors, bp_result["basepoints"])
    bp_cols = [f"bp_{i:02d}" for i in range(1, profiles.shape[1] + 1)]

    # 7. Write Output Files
    log("[8/8] Writing multi-day event profile datasets and verifying joins ...")
    ff = "%.8f"
    ids = df_all_sets[PROFILE_ID_COLUMNS]
    df_profiles = pd.concat([ids, pd.DataFrame(profiles, columns=bp_cols)], axis=1)

    profiles_csv = out_dir / "event_profiles.csv"
    targets_csv = out_dir / "event_set_targets.csv"
    sets_csv = out_dir / "event_sets.csv"
    keys_csv = out_dir / "event_set_keys.csv"
    tfidf_csv = out_dir / "tfidf_event_vectors.csv"

    df_profiles.to_csv(profiles_csv, index=False, float_format=ff)
    df_all_targets.to_csv(targets_csv, index=False, float_format=ff)
    df_all_sets.to_csv(sets_csv, index=False)
    df_all_keys.to_csv(keys_csv, index=False)

    tv = pd.concat([ids, pd.DataFrame(tfidf_vectors, columns=[f"tfidf_{n}" for n in EVENT_NAMES])], axis=1)
    tv.to_csv(tfidf_csv, index=False, float_format=ff)

    # Metadata & model JSON files
    (out_dir / "tfidf_model.json").write_text(json.dumps(idf_model, indent=2), encoding="utf-8")
    (out_dir / "event_thresholds.json").write_text(json.dumps(thresholds, indent=2), encoding="utf-8")
    b_df = pd.DataFrame(bp_result["basepoints"], columns=EVENT_NAMES)
    b_df.insert(0, "basepoint", bp_cols)
    b_df["max_cosine_to_previous"] = [t["max_cosine_to_previous"] for t in bp_result["trace"]]
    b_df["rare_event_weight"] = [t["rare_event_weight"] for t in bp_result["trace"]]
    b_df.to_csv(out_dir / "basepoints.csv", index=False, float_format=ff)
    (out_dir / "basepoints.json").write_text(
        json.dumps({k: v for k, v in bp_result.items() if k != "basepoints"}, indent=2), encoding="utf-8"
    )

    # Join validation
    p_disk = pd.read_csv(profiles_csv, dtype={"event_set_id": str, "window_id": str})
    t_disk = pd.read_csv(targets_csv, dtype={"event_set_id": str, "window_id": str})
    checks = validate_model_files(p_disk, t_disk)
    log(f"      All {len(checks)} integrity join checks passed successfully!")

    meta = {
        "experiment_mode": experiment_mode,
        "output_directory": str(out_dir),
        "model_input_file": "event_profiles.csv",
        "ground_truth_file": "event_set_targets.csv",
        "model_input_columns": bp_cols,
        "identifier_columns": PROFILE_ID_COLUMNS,
        "join_key": "event_set_id",
        "total_event_sets": total_event_sets,
        "split_distribution": {str(k): int(v) for k, v in df_profiles["split"].value_counts().items()},
        "target_binary_distribution": {
            s: {str(b): int(cnt) for b, cnt in sub.items()}
            for s, sub in df_all_targets.groupby(["split", "target_binary"]).size().unstack(fill_value=0).to_dict("index").items()
        },
        "target_multiclass_distribution": {str(k): int(v) for k, v in df_all_targets["target_label"].value_counts().items()},
        "basepoints_count": len(bp_cols),
        "thresholds": thresholds,
        "control_blocks": {"Tuesday": list(TUESDAY_CONTROL_BLOCKS)} if experiment_mode == "exp_b" else {},
        "elapsed_seconds": round(time.time() - t_start, 2),
        "generated_at": datetime.now().isoformat()
    }
    (out_dir / "event_profiles_metadata.json").write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")

    # Verify baseline preservation
    if baseline_before_hash is not None:
        baseline_after_hash = sha256_of(baseline_profile_file)
        if baseline_before_hash != baseline_after_hash:
            raise EventProfileError(
                "CRITICAL ERROR: Baseline file 'data/processed/event_profiles/event_profiles.csv' was modified!"
            )
        log(f"      [BASELINE PRESERVED] Baseline Tuesday profiles confirmed untouched ({baseline_profile_file.name}).")
    log(f"      [ISOLATION CONFIRMED] Output written exclusively to: {out_dir}")

    elapsed = round(time.time() - t_start, 1)
    log(f"SUCCESS: Completed {experiment_mode.upper()} event profiles in {elapsed}s.")
    return meta


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "exp_a"
    run_multi_day_pipeline(mode)
