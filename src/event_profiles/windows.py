"""
Sliding windows over 60-second time bins (paper: window interval 60 s, window size 10 min).

* Every flow falls into exactly ONE bin.
* A window is `W = size/step` consecutive bins: window k covers bins k .. k+W-1, i.e. [start, start+size).
  So a flow is counted ONCE per window, and in up to W different (overlapping) windows.
* A window is valid only if all its bins belong to the SAME split (train / validation / test).
"""

import numpy as np
import pandas as pd
from numpy.lib.stride_tricks import sliding_window_view

from .errors import EventProfileError


def compute_bins(timestamps: pd.Series, step_seconds: int):
    """Return (bin index per flow, t0). t0 = first minute of the data (same origin as Phase 2 blocks)."""
    t0 = timestamps.min().floor("min")
    bins = ((timestamps - t0) // pd.Timedelta(seconds=step_seconds)).to_numpy(dtype="int64")
    return bins, t0


def bin_split_names(bin_idx, block_id, split, n_bins, step_seconds, block_minutes):
    """Split name of every bin (None = unknown). Also checks our block arithmetic equals Phase 2's block_id."""
    block_seconds = int(block_minutes * 60)
    if block_seconds % step_seconds:
        raise EventProfileError(f"split.block_minutes ({block_minutes} min) is not a multiple of the window step "
                                f"({step_seconds} s).", "Choose a window step that divides the block length.")
    bins_per_block = block_seconds // step_seconds
    mismatches = int((bin_idx // bins_per_block != np.asarray(block_id)).sum())
    if mismatches:
        raise EventProfileError(
            f"{mismatches:,} flows have a block_id that disagrees with their timestamp "
            f"(block length {block_minutes} min).",
            "The cleaned file and split.block_minutes must come from the same Phase 2 run.")
    pairs = pd.DataFrame({"b": np.asarray(block_id), "s": np.asarray(split).astype(str)}).drop_duplicates()
    if pairs["b"].duplicated().any():
        raise EventProfileError("A block contains more than one split value - the Phase 2 output is inconsistent.")
    mapping = dict(zip(pairs["b"].tolist(), pairs["s"].tolist()))
    bin_block = np.arange(n_bins) // bins_per_block
    return np.array([mapping.get(int(b)) for b in bin_block], dtype=object)


def valid_windows(names, window_bins):
    """Return (valid mask per window start k, split name per window start k)."""
    n = len(names)
    if n < window_bins:
        raise EventProfileError(f"The data spans only {n} time bin(s), fewer than one window ({window_bins} bins).")
    uniq = sorted({x for x in names if x is not None})
    code = {u: i for i, u in enumerate(uniq)}
    codes = np.array([code.get(x, -1) for x in names], dtype="int64")
    view = sliding_window_view(codes, window_bins)
    mn, mx = view.min(axis=1), view.max(axis=1)
    valid = (mn == mx) & (mn >= 0)
    split_of = np.array([uniq[c] if c >= 0 else None for c in mn], dtype=object)
    return valid, split_of


def aggregate_to_windows(pair_idx, bin_idx, values, window_bins, valid, n_windows):
    """
    Sum `values` (n_flows x m) per (pair, window) for VALID windows only.

    Step 1: sum per (pair, bin). Step 2: add each (pair, bin) row to the `window_bins` windows that contain it.
    Because step 1 collapses flows into bins first, a flow is added to each window exactly once.
    Returns a DataFrame with columns: pair, k, v0 .. v{m-1}  (only (pair, window) combinations with >= 1 flow).
    """
    values = np.asarray(values)
    m = values.shape[1]
    cols = [f"v{i}" for i in range(m)]
    frame = pd.DataFrame(values, columns=cols)
    frame["pair"] = np.asarray(pair_idx)
    frame["bin"] = np.asarray(bin_idx)
    pb = frame.groupby(["pair", "bin"], sort=True).sum().reset_index()

    n_rows = len(pb)
    row_of = np.repeat(np.arange(n_rows), window_bins)
    offset = np.tile(np.arange(window_bins), n_rows)
    k = pb["bin"].to_numpy()[row_of] - offset
    keep = (k >= 0) & (k < n_windows)
    keep[keep] = valid[k[keep]]
    row_of, k = row_of[keep], k[keep]

    out = pd.DataFrame(pb[cols].to_numpy()[row_of], columns=cols)
    out["pair"] = pb["pair"].to_numpy()[row_of]
    out["k"] = k
    out = out.groupby(["pair", "k"], sort=True).sum().reset_index()
    return out[["pair", "k"] + cols]
