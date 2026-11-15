"""
Derived security events (NOT real IDS alerts) and their training-only thresholds.

Flow-level events (one flag per flow, counted inside each event set):
    HIGH_PACKET_RATE            flow_packets_s  >  Q(train flows, high_percentile)
    HIGH_BYTE_RATE              flow_bytes_s    >  Q(train flows, high_percentile)
    SYN_ACTIVITY                syn_flag_count  >  Q(train flows, high_percentile)
    SHORT_REPEATED_CONNECTIONS  flow_duration   <  Q(train flows, short_percentile)    (microseconds)
Event-set-level event (one yes/no value per source->destination event set):
    HIGH_FLOW_RATE              flows_in_this_set > Q(flows per TRAINING event set, high_percentile)

Q is numpy.quantile with linear interpolation: h = q*(n-1); Q = x[floor(h)] + (h-floor(h))*(x[floor(h)+1]-x[floor(h)]).
"""

import numpy as np

from .errors import EventProfileError

EVENT_NAMES = ["HIGH_FLOW_RATE", "HIGH_PACKET_RATE", "HIGH_BYTE_RATE", "SYN_ACTIVITY", "SHORT_REPEATED_CONNECTIONS"]
FLOW_EVENT_SPECS = [("HIGH_PACKET_RATE", "flow_packets_s", "high"),
                    ("HIGH_BYTE_RATE", "flow_bytes_s", "high"),
                    ("SYN_ACTIVITY", "syn_flag_count", "high"),
                    ("SHORT_REPEATED_CONNECTIONS", "flow_duration", "short")]

# The ONLY columns the event stage may read. Anything else is refused.
# source_ip / destination_ip are used only to form the source->destination groups.
EVENT_INPUT_COLUMNS = ["source_row", "timestamp", "split", "block_id", "source_ip", "destination_ip",
                       "flow_duration", "flow_packets_s", "flow_bytes_s", "syn_flag_count"]
FORBIDDEN_EVENT_COLUMNS = {"label", "label_original", "target_binary", "target_multiclass",
                           "source_port", "destination_port", "flow_id", "protocol"}


def assert_no_forbidden_columns(df):
    bad = sorted(FORBIDDEN_EVENT_COLUMNS & set(df.columns))
    if bad:
        raise EventProfileError(f"Event generation received forbidden column(s): {bad}",
                                "Ground-truth, port and ID columns must never be inputs to event generation.")


def compare(x, threshold, how):
    return {"gt": x > threshold, "ge": x >= threshold, "lt": x < threshold, "le": x <= threshold}[how]


def fit_flow_thresholds(train, settings):
    """Thresholds from TRAINING flows only. Returns {event: details}."""
    out = {}
    for name, col, kind in FLOW_EVENT_SPECS:
        x = train[col].to_numpy(dtype="float64")
        finite = x[np.isfinite(x)]
        if finite.size == 0:
            raise EventProfileError(f"No finite training values in '{col}'.", "Check the cleaned dataset.")
        pct = settings["high_percentile"] if kind == "high" else settings["short_percentile"]
        out[name] = {"level": "flow", "feature": col, "percentile": pct,
                     "comparison": settings["comparisons"][name],
                     "threshold": float(np.quantile(finite, pct / 100.0, method="linear")),
                     "n_training_values": int(finite.size), "n_nonfinite_ignored": int(x.size - finite.size)}
    return out


def apply_flow_events(flows, thresholds):
    """int8 matrix (n_flows x 4) in FLOW_EVENT_SPECS order."""
    cols = []
    for name, col, _ in FLOW_EVENT_SPECS:
        t = thresholds[name]
        x = flows[col].to_numpy(dtype="float64")
        cols.append(compare(x, t["threshold"], t["comparison"]).astype("int8"))
    return np.column_stack(cols)


def fit_set_threshold(n_flows_training_sets, settings):
    """HIGH_FLOW_RATE threshold: percentile of flows-per-event-set over TRAINING event sets."""
    x = np.asarray(n_flows_training_sets, dtype="float64")
    if x.size == 0:
        raise EventProfileError("There are no valid training event sets.",
                                "Check that the cleaned file has a 'train' split and that windows fit inside it.")
    return {"level": "event_set", "feature": "flows in the source->destination event set",
            "percentile": settings["high_percentile"], "comparison": settings["comparisons"]["HIGH_FLOW_RATE"],
            "threshold": float(np.quantile(x, settings["high_percentile"] / 100.0, method="linear")),
            "n_training_values": int(x.size), "n_nonfinite_ignored": 0}
