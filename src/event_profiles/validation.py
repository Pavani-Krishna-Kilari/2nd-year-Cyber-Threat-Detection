"""
Checks that event_profiles.csv (model input) and event_set_targets.csv (ground truth) can be joined safely.

Run on the files WRITTEN TO DISK:
    python -m src.event_profiles.validation [--dir data/processed/event_profiles]
"""

import argparse
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from .errors import EventProfileError, ValidationError

PROFILE_ID_COLUMNS = ["event_set_id", "window_id", "split", "window_start"]
TARGET_REQUIRED = ["event_set_id", "window_id", "split", "target_binary", "target_multiclass"]
ID_PATTERN = re.compile(r"^ES\d{7,}$")
BP_PATTERN = re.compile(r"^bp_\d+$")


def validate_model_files(profiles: pd.DataFrame, targets: pd.DataFrame):
    """Return a list of (check, passed, detail). Raises ValidationError listing every failed check."""
    checks = []

    def check(name, ok, detail=""):
        checks.append((name, bool(ok), detail))

    bp_cols = [c for c in profiles.columns if BP_PATTERN.match(c)]
    extra = [c for c in profiles.columns if c not in PROFILE_ID_COLUMNS and c not in bp_cols]
    check("profiles: only identifiers + bp_* feature columns (no IPs, labels, targets, counts)",
          not extra and len(bp_cols) > 0, f"unexpected columns: {extra}" if extra else f"{len(bp_cols)} bp_* columns")
    check("profiles: all identifier columns present", all(c in profiles.columns for c in PROFILE_ID_COLUMNS))
    check("targets: required columns present", all(c in targets.columns for c in TARGET_REQUIRED),
          f"missing: {[c for c in TARGET_REQUIRED if c not in targets.columns]}")
    check("targets: contains no bp_* feature columns", not any(BP_PATTERN.match(c) for c in targets.columns))
    if any(not ok for _, ok, _ in checks[:4]):
        _raise(checks)

    for name, df in (("profiles", profiles), ("targets", targets)):
        ids = df["event_set_id"]
        check(f"{name}: event_set_id has no missing values", ids.notna().all() and (ids.astype(str).str.len() > 0).all())
        check(f"{name}: event_set_id has no duplicates", not ids.duplicated().any(),
              f"{int(ids.duplicated().sum())} duplicated" if ids.duplicated().any() else f"{len(ids):,} unique")
        check(f"{name}: event_set_id format ES#######", ids.astype(str).map(lambda s: bool(ID_PATTERN.match(s))).all())
        check(f"{name}: window_id has no missing values", df["window_id"].notna().all())
    if any(not ok for _, ok, _ in checks):
        _raise(checks)

    p_ids, t_ids = set(profiles["event_set_id"]), set(targets["event_set_id"])
    only_p, only_t = p_ids - t_ids, t_ids - p_ids
    check("ID sets identical in both files", not only_p and not only_t,
          f"only in profiles: {len(only_p)}, only in targets: {len(only_t)}")
    check("same number of rows", len(profiles) == len(targets), f"{len(profiles):,} vs {len(targets):,}")
    if only_p or only_t or len(profiles) != len(targets):
        _raise(checks)
    check("rows are in the same order", bool((profiles["event_set_id"].to_numpy() == targets["event_set_id"].to_numpy()).all()))

    joined = profiles.merge(targets[["event_set_id", "window_id", "split"]], on="event_set_id",
                            how="inner", validate="one_to_one", suffixes=("", "_t"))
    check("one-to-one join gives every row", len(joined) == len(profiles), f"{len(joined):,} joined rows")
    check("window_id agrees between files", bool((joined["window_id"] == joined["window_id_t"]).all()))
    check("split agrees between files", bool((joined["split"] == joined["split_t"]).all()))

    vals = profiles[bp_cols].to_numpy(dtype="float64")
    check("profile features are finite (no NaN/inf)", bool(np.isfinite(vals).all()))
    check("profile features lie in [0, 1]", bool(((vals >= 0) & (vals <= 1 + 1e-9)).all()))
    check("target_binary only contains 0/1", set(targets["target_binary"].unique()) <= {0, 1})
    check("target_multiclass has no missing values", targets["target_multiclass"].notna().all())
    if any(not ok for _, ok, _ in checks):
        _raise(checks)
    return checks


def _raise(checks):
    failed = [f"{n} ({d})" if d else n for n, ok, d in checks if not ok]
    raise ValidationError("Join validation FAILED: " + "; ".join(failed),
                          "Do not use these files for model training until this is fixed.")


def validate_directory(directory):
    d = Path(directory)
    for name in ("event_profiles.csv", "event_set_targets.csv"):
        if not (d / name).exists():
            raise EventProfileError(f"{d / name} not found.", "Run python -m src.event_profiles.build_event_profiles first.")
    profiles = pd.read_csv(d / "event_profiles.csv", dtype={"event_set_id": str, "window_id": str})
    targets = pd.read_csv(d / "event_set_targets.csv", dtype={"event_set_id": str, "window_id": str})
    return validate_model_files(profiles, targets)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Validate that profiles and targets join correctly.")
    ap.add_argument("--dir", default="data/processed/event_profiles")
    args = ap.parse_args(argv)
    try:
        checks = validate_directory(args.dir)
    except EventProfileError as e:
        print(f"\nERROR: {e}")
        if e.hint:
            print(f"HINT:  {e.hint}")
        return 1
    for name, ok, detail in checks:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  - {detail}" if detail else ""))
    print("\nAll join checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
