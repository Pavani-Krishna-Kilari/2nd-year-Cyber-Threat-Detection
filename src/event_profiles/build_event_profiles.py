"""
PHASE 3 - EVENT PROFILE GENERATION
==================================
Run from the project root (Windows PowerShell):
    python -m src.event_profiles.build_event_profiles

Pipeline (every fitted value uses TRAINING data only):
    cleaned flows -> 60 s bins -> valid sliding windows (10 min, never crossing a split)
    -> source->destination event sets -> derived event counts -> TF-IDF -> basepoints
    -> cosine similarities (= event profile)            [model input file]
    -> ground-truth targets, read separately afterwards [target file]
    -> join validation of the two files, reports

No neural network is trained here. The cleaned dataset is read-only.
"""

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

from src.config import ConfigError, load_config, resolve_path

from .basepoints import compute_profiles, select_basepoints
from .errors import EventProfileError
from .events import (EVENT_INPUT_COLUMNS, EVENT_NAMES, FLOW_EVENT_SPECS, apply_flow_events,
                     assert_no_forbidden_columns, compare, fit_flow_thresholds, fit_set_threshold)
from .settings import load_settings
from .targets import compute_event_set_targets, mixed_statistics
from .tfidf import fit_idf, transform
from .validation import PROFILE_ID_COLUMNS, validate_model_files
from .windows import aggregate_to_windows, bin_split_names, compute_bins, valid_windows

LABEL_COLUMNS = ["source_row", "label", "target_binary", "target_multiclass"]


def say(msg):
    print(msg, flush=True)


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


# ----------------------------------------------------------------------------- loading
def _read(path, columns, parse_dates):
    path = Path(path)
    if path.suffix == ".parquet":
        return pd.read_parquet(path, columns=columns)
    header = list(pd.read_csv(path, nrows=0).columns)
    missing = [c for c in columns if c not in header]
    if missing:
        raise EventProfileError(f"{path.name} is missing required column(s): {missing}",
                                "Run Phase 2 (python -m src.preprocessing.preprocess_dataset) first.")
    return pd.read_csv(path, usecols=columns, parse_dates=parse_dates)


def load_event_inputs(path):
    """Read ONLY the columns the event stage is allowed to see (no labels, no ports)."""
    df = _read(path, EVENT_INPUT_COLUMNS, ["timestamp"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def load_labels(path):
    """Read ONLY the ground-truth columns, separately and later."""
    return _read(path, LABEL_COLUMNS, None)


# ----------------------------------------------------------------------------- event stage
def compute_event_sets(flows, size_seconds, step_seconds, block_minutes, settings, log=say):
    """Cleaned flows (no label columns) -> source->destination event sets with derived event counts."""
    assert_no_forbidden_columns(flows)
    missing = [c for c in EVENT_INPUT_COLUMNS if c not in flows.columns]
    if missing:
        raise EventProfileError(f"Missing columns for event generation: {missing}")
    if size_seconds % step_seconds:
        raise EventProfileError(f"window.size_seconds ({size_seconds}) must be a multiple of step_seconds ({step_seconds}).")
    W = size_seconds // step_seconds

    flows = flows.sort_values(["timestamp", "source_row"], kind="stable").reset_index(drop=True)
    bins, t0 = compute_bins(flows["timestamp"], step_seconds)
    n_bins = int(bins.max()) + 1
    names = bin_split_names(bins, flows["block_id"].to_numpy(), flows["split"].to_numpy(), n_bins,
                            step_seconds, block_minutes)
    valid, window_split = valid_windows(names, W)
    n_windows = len(valid)
    log(f"      {len(flows):,} flows, {n_bins:,} one-minute bins, {n_windows:,} possible windows "
        f"({int(valid.sum()):,} valid, {int((~valid).sum()):,} dropped because they cross splits)")

    pair = flows.groupby(["source_ip", "destination_ip"], sort=False).ngroup().to_numpy()
    split_arr = flows["split"].to_numpy().astype(str)
    is_train = split_arr == "train"
    if not is_train.any():
        raise EventProfileError("The cleaned file has no 'train' flows.")

    log("[3/9] Fitting flow-level thresholds on TRAINING flows ...")
    thresholds = fit_flow_thresholds(flows[is_train], settings)
    flags = apply_flow_events(flows, thresholds)

    log("[4/9] Building source->destination event sets inside valid windows ...")
    values = np.column_stack([np.ones(len(flows), dtype="int64"), flags.astype("int64")])
    agg = aggregate_to_windows(pair, bins, values, W, valid, n_windows)
    agg = agg.sort_values(["k", "pair"], kind="stable").reset_index(drop=True)
    if agg.empty:
        raise EventProfileError("No event sets were produced - no valid window contains flows.")
    sets = pd.DataFrame({"pair": agg["pair"], "k": agg["k"], "n_flows": agg["v0"]})
    for j, (name, _, _) in enumerate(FLOW_EVENT_SPECS, start=1):
        sets[name] = agg[f"v{j}"]
    sets["split"] = window_split[sets["k"].to_numpy()]

    train_sets = (sets["split"] == "train").to_numpy()
    thresholds["HIGH_FLOW_RATE"] = fit_set_threshold(sets.loc[train_sets, "n_flows"], settings)
    hfr = compare(sets["n_flows"].to_numpy(dtype="float64"), thresholds["HIGH_FLOW_RATE"]["threshold"],
                  thresholds["HIGH_FLOW_RATE"]["comparison"]).astype("int64")
    sets["HIGH_FLOW_RATE"] = hfr
    counts = sets[EVENT_NAMES].to_numpy(dtype="int64")
    sets["is_empty"] = counts.sum(axis=1) == 0

    sets["event_set_id"] = "ES" + pd.Series(np.arange(1, len(sets) + 1)).astype(str).str.zfill(7)
    sets["window_id"] = "W" + sets["k"].astype(str).str.zfill(5)
    sets["window_start"] = t0 + pd.to_timedelta(sets["k"].to_numpy() * step_seconds, unit="s")
    sets["window_end"] = sets["window_start"] + pd.Timedelta(seconds=size_seconds)

    keys = (flows.assign(pair=pair).drop_duplicates("pair")[["pair", "source_ip", "destination_ip"]])
    return {"sets": sets, "counts": counts, "thresholds": thresholds, "keys": keys,
            "flow_index": pd.DataFrame({"source_row": flows["source_row"].to_numpy(), "pair": pair, "bin": bins}),
            "flow_flags": flags, "flow_split": split_arr, "t0": t0, "W": W, "n_bins": n_bins,
            "n_windows": n_windows, "valid": valid, "window_split": window_split,
            "size_seconds": size_seconds, "step_seconds": step_seconds, "n_flows": len(flows)}


def fit_transform_profiles(res, settings):
    """TF-IDF, basepoints and profiles - all fitted on TRAINING event sets only."""
    train = (res["sets"]["split"] == "train").to_numpy()
    model = fit_idf(res["counts"][train], settings["sublinear_tf"])
    vectors = transform(res["counts"], model)
    bp = select_basepoints(vectors[train], model["document_frequency"], settings)
    profiles = compute_profiles(vectors, bp["basepoints"])
    return model, vectors, bp, profiles


def event_text(counts):
    out = []
    for row in counts:
        parts = [f"{n}={int(c)}" for n, c in zip(EVENT_NAMES, row) if c > 0]
        out.append("; ".join(parts) if parts else "(no events)")
    return out


# ----------------------------------------------------------------------------- statistics for the report
def collect_statistics(res, model, bp, settings):
    sets, counts = res["sets"], res["counts"]
    stats = {"per_split": {}, "flow_trigger": {}, "set_event_rates": {}, "warnings": []}
    window_split = res["window_split"]
    for s in ["train", "validation", "test"]:
        m = (sets["split"] == s).to_numpy()
        n_valid = int(((window_split == s) & res["valid"]).sum())
        stats["per_split"][s] = {
            "valid_windows": n_valid,
            "windows_with_event_sets": int(sets.loc[m, "k"].nunique()),
            "event_sets": int(m.sum()),
            "empty_sets": int(sets.loc[m, "is_empty"].sum()),
            "empty_pct": 100.0 * float(sets.loc[m, "is_empty"].mean()) if m.any() else 0.0,
            "flows_in_sets_median": float(sets.loc[m, "n_flows"].median()) if m.any() else 0.0,
            "flows_in_sets_max": int(sets.loc[m, "n_flows"].max()) if m.any() else 0}
        stats["set_event_rates"][s] = {n: (100.0 * float((counts[m, j] > 0).mean()) if m.any() else 0.0)
                                       for j, n in enumerate(EVENT_NAMES)}
        if not m.any():
            stats["warnings"].append(f"No event sets in the '{s}' split.")
    for j, (name, _, _) in enumerate(FLOW_EVENT_SPECS):
        stats["flow_trigger"][name] = {s: 100.0 * float(res["flow_flags"][res["flow_split"] == s, j].mean())
                                       if (res["flow_split"] == s).any() else float("nan")
                                       for s in ["train", "validation", "test"]}
    stats["flows_per_split"] = {s: int((res["flow_split"] == s).sum()) for s in ["train", "validation", "test"]}
    stats["n_pairs"] = int(len(res["keys"]))
    stats["n_empty_total"] = int(sets["is_empty"].sum())
    stats["n_sets_total"] = int(len(sets))
    stats["dropped_windows"] = int((~res["valid"]).sum())
    stats["valid_windows"] = int(res["valid"].sum())

    limit = 100.0 * settings["trigger_share_warning"]
    for name, share in stats["flow_trigger"].items():
        t = share["train"]
        if t == 0:
            stats["warnings"].append(f"{name} fires on 0% of training flows (threshold "
                                     f"{res['thresholds'][name]['threshold']:.6g}, rule '{res['thresholds'][name]['comparison']}'): "
                                     "the rule is degenerate for this feature (ties/discrete values). The term carries no information.")
        elif t > limit:
            stats["warnings"].append(f"{name} fires on {t:.1f}% of training flows (> {limit:.0f}% warning limit).")
    tr = (sets["split"] == "train").to_numpy()
    hfr_share = 100.0 * float((counts[tr, 0] > 0).mean())
    if hfr_share == 0:
        stats["warnings"].append("HIGH_FLOW_RATE fires on 0% of training event sets.")
    for name, dfv in zip(EVENT_NAMES, model["document_frequency"]):
        if dfv == 0:
            stats["warnings"].append(f"{name} never occurs in any training event set (document frequency 0).")
    if len(bp["basepoints"]) < settings["basepoints"]:
        stats["warnings"].append(f"Only {len(bp['basepoints'])} basepoints were found (requested {settings['basepoints']}): {bp['stop_reason']}.")
    return stats


# ----------------------------------------------------------------------------- output files
def write_outputs(out_dir, res, model, vectors, bp, profiles, settings):
    out_dir.mkdir(parents=True, exist_ok=True)
    sets = res["sets"]
    ids = sets[["event_set_id", "window_id"]]
    bp_cols = [f"bp_{i:02d}" for i in range(1, profiles.shape[1] + 1)]
    ff = "%.8f"
    files = {}

    prof = pd.concat([ids, sets[["split", "window_start"]]], axis=1)
    prof = pd.concat([prof, pd.DataFrame(profiles, columns=bp_cols)], axis=1)
    files["event_profiles"] = out_dir / "event_profiles.csv"
    prof.to_csv(files["event_profiles"], index=False, float_format=ff)

    es = pd.concat([ids, sets[["split", "window_start", "window_end", "n_flows"] + EVENT_NAMES]], axis=1)
    es["event_set_text"] = event_text(res["counts"])
    es["is_empty"] = sets["is_empty"].to_numpy()
    files["event_sets"] = out_dir / "event_sets.csv"
    es.to_csv(files["event_sets"], index=False)

    keys = sets[["event_set_id", "window_id", "pair"]].merge(res["keys"], on="pair", how="left").drop(columns="pair")
    files["event_set_keys"] = out_dir / "event_set_keys.csv"
    keys.to_csv(files["event_set_keys"], index=False)

    tv = pd.concat([ids, pd.DataFrame(vectors, columns=[f"tfidf_{n}" for n in EVENT_NAMES])], axis=1)
    files["tfidf_event_vectors"] = out_dir / "tfidf_event_vectors.csv"
    tv.to_csv(files["tfidf_event_vectors"], index=False, float_format=ff)

    files["tfidf_model"] = out_dir / "tfidf_model.json"
    files["tfidf_model"].write_text(json.dumps(model, indent=2), encoding="utf-8")

    thr = {k: v for k, v in res["thresholds"].items()}
    files["event_thresholds"] = out_dir / "event_thresholds.json"
    files["event_thresholds"].write_text(json.dumps(thr, indent=2), encoding="utf-8")

    b = pd.DataFrame(bp["basepoints"], columns=EVENT_NAMES)
    b.insert(0, "basepoint", bp_cols)
    b["max_cosine_to_previous"] = [t["max_cosine_to_previous"] for t in bp["trace"]]
    b["rare_event_weight"] = [t["rare_event_weight"] for t in bp["trace"]]
    files["basepoints_csv"] = out_dir / "basepoints.csv"
    b.to_csv(files["basepoints_csv"], index=False, float_format=ff)
    files["basepoints_json"] = out_dir / "basepoints.json"
    files["basepoints_json"].write_text(json.dumps({k: v for k, v in bp.items() if k != "basepoints"}, indent=2), encoding="utf-8")
    return files, bp_cols


# ----------------------------------------------------------------------------- pipeline
def run_pipeline(input_path, out_dir, reports_dir, cfg, settings, log=say, write_reports=True):
    t_start = time.time()
    input_path, out_dir, reports_dir = Path(input_path), Path(out_dir), Path(reports_dir)
    if not input_path.exists():
        raise EventProfileError(f"Cleaned dataset not found: {input_path}",
                                "Run Phase 2 first: python -m src.preprocessing.preprocess_dataset")
    info = {"input_file": input_path.name, "settings": settings}
    log(f"\n=== {input_path.name} ===")
    log("[1/9] Fingerprinting and reading the cleaned flows (read-only; label columns are NOT loaded) ...")
    info["sha_before"] = sha256_of(input_path)
    flows = load_event_inputs(input_path)
    info["rows"] = len(flows)
    log(f"      loaded {len(flows):,} flows with {len(EVENT_INPUT_COLUMNS)} permitted columns")

    block_minutes, source = cfg["split"]["block_minutes"], "config split.block_minutes"
    suffix = input_path.suffix
    stem = input_path.name[: -len("_clean" + suffix)] if input_path.name.endswith("_clean" + suffix) else input_path.stem
    meta_path = input_path.with_name(f"{stem}_metadata.json")
    if meta_path.exists():
        try:
            block_minutes = json.loads(meta_path.read_text(encoding="utf-8"))["split"]["block_minutes"]
            source = f"Phase 2 metadata ({meta_path.name})"
        except (KeyError, ValueError):
            pass
    info["block_minutes"], info["block_minutes_source"] = block_minutes, source

    log("[2/9] Building windows (size/step from config) ...")
    res = compute_event_sets(flows, cfg["window"]["size_seconds"], cfg["window"]["step_seconds"],
                             block_minutes, settings, log)
    info["window"] = {"size_seconds": res["size_seconds"], "step_seconds": res["step_seconds"], "bins_per_window": res["W"],
                      "t0": str(res["t0"]), "n_bins": res["n_bins"]}
    del flows

    log("[5/9] Fitting TF-IDF and selecting basepoints on TRAINING event sets; computing profiles ...")
    model, vectors, bp, profiles = fit_transform_profiles(res, settings)
    stats = collect_statistics(res, model, bp, settings)

    log("[6/9] Writing model-input and intermediate files ...")
    files, bp_cols = write_outputs(out_dir, res, model, vectors, bp, profiles, settings)

    log("[7/9] Reading ground-truth labels SEPARATELY and building targets ...")
    labels = load_labels(input_path)
    targets, code_to_label = compute_event_set_targets(
        res["sets"], res["flow_index"], labels, res["W"], res["valid"], res["n_windows"], settings,
        cfg["labels"]["benign_label"])
    files["event_set_targets"] = out_dir / "event_set_targets.csv"
    targets.to_csv(files["event_set_targets"], index=False, float_format="%.8f")
    mixed = mixed_statistics(targets)
    for s in ["train", "validation", "test"]:
        if s in mixed and mixed[s]["positive_sets"] == 0:
            stats["warnings"].append(f"The '{s}' split has no attack event sets.")

    log("[8/9] Validating that profiles and targets join correctly (re-reading both files from disk) ...")
    p_disk = pd.read_csv(files["event_profiles"], dtype={"event_set_id": str, "window_id": str})
    t_disk = pd.read_csv(files["event_set_targets"], dtype={"event_set_id": str, "window_id": str})
    checks = validate_model_files(p_disk, t_disk)
    log(f"      all {len(checks)} join checks passed")

    info.update({"stats": stats, "mixed": mixed, "code_to_label": code_to_label, "checks": checks,
                 "thresholds": res["thresholds"], "model": model, "bp": bp, "files": files, "bp_cols": bp_cols,
                 "targets_summary": targets.groupby("split")["target_binary"].agg(["size", "sum"]).to_dict("index"),
                 "targets_by_class": targets.groupby(["split", "target_label"]).size().unstack(fill_value=0)})
    meta = {"input_file": input_path.name, "input_sha256": info["sha_before"],
            "model_input_file": "event_profiles.csv", "model_input_columns": bp_cols,
            "identifier_columns": PROFILE_ID_COLUMNS, "ground_truth_file": "event_set_targets.csv",
            "target_columns": ["target_binary", "target_multiclass"], "join_key": "event_set_id",
            "multiclass_codes": {str(k): v for k, v in code_to_label.items()}, "settings": settings,
            "window": info["window"], "n_event_sets": stats["n_sets_total"]}
    files["metadata"] = out_dir / "event_profiles_metadata.json"
    files["metadata"].write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")

    info["sha_after"] = sha256_of(input_path)
    info["input_untouched"] = info["sha_after"] == info["sha_before"]
    if not info["input_untouched"]:
        raise EventProfileError("The cleaned dataset changed while Phase 3 ran - this must never happen.")
    info["seconds"] = time.time() - t_start

    if write_reports:
        log("[9/9] Writing reports ...")
        from .report_writer import write_reports as _write
        info["reports"] = _write(info, cfg, reports_dir)
    return info


def find_input(cfg, settings, override=None):
    processed = resolve_path(cfg["paths"]["processed_dir"])
    name = override or settings["input_file"]
    if name != "auto":
        p = Path(name)
        return p if p.is_absolute() or p.exists() else processed / name
    found = sorted(list(processed.glob("*_clean.csv")) + list(processed.glob("*_clean.parquet")))
    if len(found) != 1:
        raise EventProfileError(f"Expected exactly one *_clean file in {processed}, found {len(found)}.",
                                "Pass --file <name> or set event_profiles.input_file.")
    return found[0]


def main(argv=None):
    ap = argparse.ArgumentParser(description="Phase 3: build event profiles from the cleaned CICIDS2017 flows.")
    ap.add_argument("--config", type=Path, default=None)
    ap.add_argument("--file", type=str, default=None, help="cleaned dataset file name or path")
    args = ap.parse_args(argv)
    try:
        cfg, source = load_config(args.config)
        settings = load_settings(cfg)
        say(f"Configuration: {source}")
        info = run_pipeline(find_input(cfg, settings, args.file), resolve_path(settings["output_dir"]),
                            resolve_path(cfg["paths"]["reports_dir"]), cfg, settings)
    except (EventProfileError, ConfigError) as e:
        say(f"\nERROR: {e}")
        if getattr(e, "hint", None):
            say(f"HINT:  {e.hint}")
        return 1

    st, mx = info["stats"], info["mixed"]["overall"]
    say("\n" + "=" * 64)
    say(f"flows read            : {info['rows']:,}")
    say(f"windows valid/dropped : {st['valid_windows']:,} / {st['dropped_windows']:,}")
    say(f"event sets            : {st['n_sets_total']:,}  (empty: {st['n_empty_total']:,} = {100*st['n_empty_total']/st['n_sets_total']:.1f}%)")
    for s in ["train", "validation", "test"]:
        p = st["per_split"][s]
        say(f"  {s:<11}: {p['event_sets']:>9,} sets, {p['empty_sets']:>9,} empty ({p['empty_pct']:.1f}%), "
            f"attack sets {info['mixed'].get(s, {}).get('positive_sets', 0):,}")
    say(f"mixed sets            : {mx['mixed_sets']:,} ({mx['mixed_pct_of_all']:.3f}% of all, "
        f"{mx['mixed_pct_of_positive']:.2f}% of attack sets)")
    say(f"basepoints selected   : {len(info['bp']['basepoints'])} (requested {info['settings']['basepoints']})")
    say(f"join checks           : {len(info['checks'])} passed")
    say(f"cleaned file untouched: {info['input_untouched']}")
    say(f"warnings              : {len(st['warnings'])}")
    for w in st["warnings"]:
        say(f"  - {w}")
    say(f"time taken            : {info['seconds']:.1f} s")
    say("=" * 64)
    say(f"Outputs: {resolve_path(settings['output_dir'])}")
    say(f"Reports: {resolve_path(cfg['paths']['reports_dir'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
