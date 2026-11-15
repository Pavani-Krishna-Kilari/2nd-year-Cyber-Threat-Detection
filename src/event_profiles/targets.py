"""
Ground-truth targets for event sets. Runs AFTER profiles exist and never feeds back into them.

Policy (initial):
    n_attack_flows = flows in the set whose flow label is not BENIGN
    target_binary  = 1 if n_attack_flows >= min_attack_flows AND attack_fraction >= min_attack_fraction else 0
    target_multiclass = the attack class with the most flows in the set (ties -> lower code), BENIGN code if target_binary = 0
    mixed set      = contains BOTH benign and attack flows (0 < n_attack_flows < n_flows)
    multi-attack   = contains flows of 2 or more different attack classes
"""

import numpy as np
import pandas as pd

from .errors import EventProfileError
from .windows import aggregate_to_windows


def assign_targets(class_counts, benign_code, min_attack_flows, min_attack_fraction):
    """class_counts: (n_sets x n_classes) flows per label class. Returns a DataFrame of target columns."""
    cc = np.asarray(class_counts, dtype="int64")
    n_flows = cc.sum(axis=1)
    n_benign = cc[:, benign_code]
    n_attack = n_flows - n_benign
    attack_fraction = np.divide(n_attack, n_flows, out=np.zeros(len(cc)), where=n_flows > 0)
    binary = ((n_attack >= min_attack_flows) & (attack_fraction >= min_attack_fraction)).astype("int8")

    attack_counts = cc.copy()
    attack_counts[:, benign_code] = -1          # benign never wins the attack vote
    majority_attack = attack_counts.argmax(axis=1)
    multiclass = np.where(binary == 1, majority_attack, benign_code).astype("int16")

    purity = np.divide(cc.max(axis=1), n_flows, out=np.zeros(len(cc)), where=n_flows > 0)
    n_attack_classes = ((cc > 0).sum(axis=1) - (n_benign > 0).astype(int))
    return pd.DataFrame({
        "n_flows": n_flows, "n_attack_flows": n_attack, "attack_fraction": attack_fraction,
        "label_purity": purity, "is_mixed": ((n_attack > 0) & (n_benign > 0)),
        "is_multi_attack": n_attack_classes >= 2,
        "target_binary": binary, "target_multiclass": multiclass})


def compute_event_set_targets(sets, flow_index, labels, window_bins, valid, n_windows, settings, benign_label):
    """
    sets       : event-set table (needs pair, k, n_flows, event_set_id, window_id, split) from the event stage
    flow_index : DataFrame(source_row, pair, bin) from the event stage (no labels)
    labels     : DataFrame(source_row, label, target_binary, target_multiclass) read separately from the cleaned file
    """
    if labels["source_row"].duplicated().any() or flow_index["source_row"].duplicated().any():
        raise EventProfileError("Duplicate source_row values - cannot align flows with labels.")
    merged = flow_index.merge(labels, on="source_row", how="left", validate="one_to_one")
    if merged["label"].isna().any():
        raise EventProfileError(f"{int(merged['label'].isna().sum()):,} flows have no label row.",
                                "The label columns must come from the same cleaned file.")
    pairs = merged[["target_multiclass", "label"]].drop_duplicates()
    if pairs["target_multiclass"].duplicated().any() or pairs["label"].duplicated().any():
        raise EventProfileError("label and target_multiclass are not one-to-one in the cleaned file.")
    code_to_label = dict(zip(pairs["target_multiclass"].astype(int), pairs["label"].astype(str)))
    n_classes = max(code_to_label) + 1
    label_to_code = {v: k for k, v in code_to_label.items()}
    if benign_label not in label_to_code:
        raise EventProfileError(f"Benign label {benign_label!r} not found among labels {sorted(label_to_code)}.")
    benign_code = label_to_code[benign_label]
    if not (merged["target_binary"].to_numpy() == (merged["target_multiclass"].to_numpy() != benign_code)).all():
        raise EventProfileError("target_binary and target_multiclass disagree in the cleaned file.")

    onehot = np.eye(n_classes, dtype="int64")[merged["target_multiclass"].to_numpy(dtype="int64")]
    agg = aggregate_to_windows(merged["pair"].to_numpy(), merged["bin"].to_numpy(), onehot,
                               window_bins, valid, n_windows)
    agg = agg.sort_values(["k", "pair"], kind="stable").reset_index(drop=True)
    base = sets.sort_values(["k", "pair"], kind="stable").reset_index(drop=True)
    if len(agg) != len(base) or not (np.array_equal(agg["k"].to_numpy(), base["k"].to_numpy())
                                     and np.array_equal(agg["pair"].to_numpy(), base["pair"].to_numpy())):
        raise EventProfileError("Target aggregation does not produce the same event sets as the event stage.")
    class_counts = agg[[f"v{i}" for i in range(n_classes)]].to_numpy()
    if not np.array_equal(class_counts.sum(axis=1), base["n_flows"].to_numpy()):
        raise EventProfileError("Flow counts differ between the event stage and the target stage.")

    t = assign_targets(class_counts, benign_code, settings["min_attack_flows"], settings["min_attack_fraction"])
    t.insert(0, "event_set_id", base["event_set_id"].to_numpy())
    t.insert(1, "window_id", base["window_id"].to_numpy())
    t.insert(2, "split", base["split"].to_numpy())
    t["target_label"] = t["target_multiclass"].map(code_to_label)
    t = t.drop(columns=["n_flows"]).assign(n_flows=class_counts.sum(axis=1))
    cols = ["event_set_id", "window_id", "split", "n_flows", "n_attack_flows", "attack_fraction", "label_purity",
            "is_mixed", "is_multi_attack", "target_binary", "target_multiclass", "target_label"]
    return t[cols], code_to_label


def mixed_statistics(targets):
    """Counts and percentages of mixed event sets, overall and per split."""
    def block(df):
        n, pos = len(df), int((df["target_binary"] == 1).sum())
        mixed = int(df["is_mixed"].sum())
        mixed_pos = int((df["is_mixed"] & (df["target_binary"] == 1)).sum())
        low = int(((df["target_binary"] == 1) & (df["attack_fraction"] < 0.5)).sum())
        return {"event_sets": n, "positive_sets": pos, "mixed_sets": mixed,
                "mixed_pct_of_all": 100.0 * mixed / n if n else 0.0,
                "mixed_pct_of_positive": 100.0 * mixed_pos / pos if pos else 0.0,
                "positive_with_attack_fraction_below_half": low,
                "positive_below_half_pct": 100.0 * low / pos if pos else 0.0,
                "multi_attack_sets": int(df["is_multi_attack"].sum())}
    out = {"overall": block(targets)}
    for s, g in targets.groupby("split"):
        out[str(s)] = block(g)
    return out
