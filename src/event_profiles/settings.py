"""Phase 3 settings: defaults + the `event_profiles:` section of configs/config.yaml."""

import copy

from .errors import EventProfileError

DEFAULTS = {
    "grouping": "source_destination",
    "input_file": "auto",
    "output_dir": "data/processed/event_profiles",
    "high_percentile": 95,
    "short_percentile": 5,
    "rare_event_types": 2,
    "basepoints": 8,
    "redundancy_threshold": 0.95,
    "sublinear_tf": True,
    "min_attack_flows": 1,
    "min_attack_fraction": 0.0,
    "trigger_share_warning": 0.10,
    "comparisons": {"HIGH_FLOW_RATE": "gt", "HIGH_PACKET_RATE": "gt", "HIGH_BYTE_RATE": "gt",
                    "SYN_ACTIVITY": "gt", "SHORT_REPEATED_CONNECTIONS": "lt"},
}


def _merge(base, over):
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def validate_settings(s):
    def bad(msg, hint=None):
        raise EventProfileError(f"event_profiles config: {msg}", hint)

    if s["grouping"] != "source_destination":
        bad(f"grouping = {s['grouping']!r} is not supported.", "Only 'source_destination' is implemented (the paper's grouping).")
    if not 0 < s["high_percentile"] < 100 or not 0 < s["short_percentile"] < 100:
        bad("percentiles must be between 0 and 100 (exclusive).")
    if not 1 <= s["rare_event_types"] <= 5:
        bad("rare_event_types must be between 1 and 5 (there are 5 event types).")
    if s["basepoints"] < 1:
        bad("basepoints must be at least 1.")
    if not 0 < s["redundancy_threshold"] <= 1:
        bad("redundancy_threshold must be in (0, 1].")
    if s["min_attack_flows"] < 1:
        bad("min_attack_flows must be at least 1.")
    if not 0 <= s["min_attack_fraction"] <= 1:
        bad("min_attack_fraction must be in [0, 1].")
    allowed = {"HIGH_FLOW_RATE": ("gt", "ge"), "HIGH_PACKET_RATE": ("gt", "ge"), "HIGH_BYTE_RATE": ("gt", "ge"),
               "SYN_ACTIVITY": ("gt", "ge"), "SHORT_REPEATED_CONNECTIONS": ("lt", "le")}
    for name, ok in allowed.items():
        if s["comparisons"].get(name) not in ok:
            bad(f"comparisons.{name} must be one of {ok}.")


def load_settings(cfg: dict) -> dict:
    s = _merge(DEFAULTS, cfg.get("event_profiles", {}))
    validate_settings(s)
    return s
