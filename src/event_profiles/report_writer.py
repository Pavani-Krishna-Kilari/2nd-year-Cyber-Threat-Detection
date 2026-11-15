"""Writes reports/event_profile_report.md, reports/event_mapping.md, reports/paper_vs_implementation.md."""

from datetime import datetime
from pathlib import Path

from .events import EVENT_NAMES, FLOW_EVENT_SPECS


def _esc(x):
    return str(x).replace("|", "\\|").replace("\n", " ")


def table(headers, rows):
    out = ["| " + " | ".join(_esc(h) for h in headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    out += ["| " + " | ".join(_esc(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def _f(x, nd=4):
    return f"{x:.{nd}f}" if isinstance(x, float) else str(x)


SPLITS = ["train", "validation", "test"]


def profile_report(info, cfg):
    s, st, mx = info["settings"], info["stats"], info["mixed"]
    L = ["# Event Profile Report (Phase 3)\n",
         f"*Generated automatically on {datetime.now():%Y-%m-%d %H:%M:%S}. Every number was computed by the run; none were typed by hand.*\n",
         "**Scope:** event generation, TF-IDF, basepoints, cosine-similarity event profiles and ground-truth targets. "
         "No neural network was trained, and no Phase 4 or dashboard work was done. The events are **derived from "
         "network-flow features; they are not real IDS/IPS alerts.**\n"]

    L.append("## 1. Input and integrity\n")
    L.append(table(["Item", "Value"], [
        ["Cleaned dataset (read-only)", info["input_file"]],
        ["SHA-256 before / after", f"`{info['sha_before']}` / `{info['sha_after']}`  ->  **{'UNCHANGED' if info['input_untouched'] else 'CHANGED (!)'}**"],
        ["Flows read", f"{info['rows']:,}"],
        ["Flows per split", ", ".join(f"{k}: {v:,}" for k, v in st["flows_per_split"].items())],
        ["Block length (for split check)", f"{info['block_minutes']} min (from {info['block_minutes_source']})"],
        ["Columns the event stage was allowed to read", "source_row, timestamp, split, block_id, source_ip, destination_ip, flow_duration, flow_packets_s, flow_bytes_s, syn_flag_count"],
        ["Columns it never read", "label, label_original, target_binary, target_multiclass, source_port, destination_port, flow_id, protocol"],
    ]))
    L.append("\nThe label columns are loaded by a different function, only after all profiles are written, and only to build targets.\n")

    w = info["window"]
    L.append("## 2. Windows\n")
    L.append(f"Window size {w['size_seconds']} s, step {w['step_seconds']} s ({w['bins_per_window']} one-minute bins per window, "
             f"overlap {w['size_seconds'] - w['step_seconds']} s). Time origin {w['t0']}. A flow lies in exactly one bin and is counted "
             "once per window (but in up to 10 overlapping windows).\n")
    L.append(table(["Item", "Count"], [
        ["Possible windows in the timeline", f"{st['valid_windows'] + st['dropped_windows']:,}"],
        ["Valid windows (all bins in ONE split)", f"{st['valid_windows']:,}"],
        ["Dropped (cross a split boundary or an unknown block)", f"{st['dropped_windows']:,}"]]))
    L.append("")

    L.append("## 3. Event sets and empty event sets\n")
    L.append("An event set is one source->destination pair inside one window (the paper's grouping). "
             "**Empty** = none of the 5 events occurred in the set.\n")
    L.append(table(["Split", "Valid windows", "Windows with >= 1 set", "Event sets", "Empty sets", "Empty %", "Median flows/set", "Max flows/set"],
                   [[sp, f"{st['per_split'][sp]['valid_windows']:,}", f"{st['per_split'][sp]['windows_with_event_sets']:,}",
                     f"{st['per_split'][sp]['event_sets']:,}", f"{st['per_split'][sp]['empty_sets']:,}",
                     f"{st['per_split'][sp]['empty_pct']:.2f}%", _f(st['per_split'][sp]['flows_in_sets_median'], 1),
                     f"{st['per_split'][sp]['flows_in_sets_max']:,}"] for sp in SPLITS]
                   + [["**all**", "", "", f"{st['n_sets_total']:,}", f"{st['n_empty_total']:,}",
                       f"{100*st['n_empty_total']/st['n_sets_total']:.2f}%", "", ""]]))
    L.append(f"\nDistinct source->destination pairs in the data: {st['n_pairs']:,}. "
             "Empty sets get an all-zero TF-IDF vector and an all-zero profile (cosine similarity 0 to every basepoint); "
             "they are never dropped, and `event_sets.csv` has an `is_empty` flag.\n")

    L.append("## 4. Thresholds (fitted on TRAINING data only)\n")
    rows = []
    for name in EVENT_NAMES:
        t = info["thresholds"][name]
        share = st["flow_trigger"].get(name)
        rows.append([name, t["level"], t["feature"], f"{t['percentile']}th", t["comparison"], f"{t['threshold']:.6g}",
                     f"{t['n_training_values']:,}",
                     (" / ".join(f"{share[x]:.2f}%" for x in SPLITS) if share else
                      " / ".join(f"{st['set_event_rates'][x]['HIGH_FLOW_RATE']:.2f}%" for x in SPLITS))])
    L.append(table(["Event", "Level", "Feature", "Percentile", "Rule", "Threshold", "Training values", "Trigger share train / val / test"], rows))
    L.append("\nPercentile = `numpy.quantile` with linear interpolation. `flow_duration` is in **microseconds** (CICFlowMeter). "
             "Trigger share is the % of flows (flow-level events) or event sets (HIGH_FLOW_RATE) for which the event fired. "
             "HIGH_FLOW_RATE's threshold is the percentile of flows-per-event-set over training event sets; it measures the "
             "source->destination event set, not the whole window.\n")
    L.append("**Share of event sets in which each event occurred at least once:**\n")
    L.append(table(["Event"] + SPLITS, [[n] + [f"{st['set_event_rates'][x][n]:.2f}%" for x in SPLITS] for n in EVENT_NAMES]))
    L.append("")

    m = info["model"]
    L.append("## 5. TF-IDF (training event sets only)\n")
    L.append(f"Training documents: {m['n_training_documents']:,}. `{m['formula']}`.\n")
    L.append(table(["Term (event)", "Document frequency", "IDF"],
                   [[n, f"{d:,}", _f(i, 4)] for n, d, i in zip(EVENT_NAMES, m["document_frequency"], m["idf"])]))
    L.append("\n")

    bp = info["bp"]
    L.append("## 6. Basepoints (training vectors only, no labels)\n")
    L.append(f"Rare-event list ({s['rare_event_types']} lowest training document frequency): **{', '.join(bp['rare_events'])}**. "
             f"Non-empty training event sets: {bp['n_training_nonempty_sets']:,}; distinct candidate vectors containing a rare event: "
             f"{bp['n_distinct_candidates']:,}. Selected **{len(bp['basepoints'])}** of {s['basepoints']} requested "
             f"(redundancy threshold {s['redundancy_threshold']}). Stop reason: {bp['stop_reason']}.\n")
    L.append(table(["Order", "Max cosine to earlier basepoints", "Weight on rare events"] + EVENT_NAMES,
                   [[t["order"], "-" if t["max_cosine_to_previous"] is None else _f(t["max_cosine_to_previous"]),
                     _f(t["rare_event_weight"])] + [_f(float(v)) for v in row]
                    for t, row in zip(bp["trace"], bp["basepoints"])]))
    L.append(f"\n> **Representation, not dimensionality reduction.** There are only {len(EVENT_NAMES)} event dimensions and "
             f"{len(bp['basepoints'])} basepoints, so the event profile has {len(bp['basepoints'])} numbers per event set - "
             "not fewer than the event vector. In the paper the profile *reduces* thousands of event types to a few "
             "basepoint similarities; here it is a similarity-based re-encoding of the TF-IDF vector.\n")

    L.append("## 7. Targets and mixed event sets (ground truth, kept in a separate file)\n")
    L.append(f"Policy: `target_binary = 1` if the set holds at least **{s['min_attack_flows']}** attack flow(s) and an attack "
             f"fraction of at least **{s['min_attack_fraction']}**; `target_multiclass` = attack class with the most flows in the set "
             "(ties -> lower code), BENIGN otherwise. **Mixed set** = contains both benign and attack flows.\n")
    L.append("Class codes: " + ", ".join(f"{c} = {n}" for c, n in sorted(info["code_to_label"].items())) + "\n")
    L.append(table(["Split", "Event sets", "Attack sets (target 1)", "Attack %", "Mixed sets", "Mixed % of all", "Mixed % of attack sets",
                    "Attack sets with attack fraction < 0.5", "Multi-attack sets"],
                   [[k if k != "overall" else "**all**", f"{v['event_sets']:,}", f"{v['positive_sets']:,}",
                     f"{100*v['positive_sets']/v['event_sets']:.3f}%" if v["event_sets"] else "n/a",
                     f"{v['mixed_sets']:,}", f"{v['mixed_pct_of_all']:.3f}%", f"{v['mixed_pct_of_positive']:.2f}%",
                     f"{v['positive_with_attack_fraction_below_half']:,} ({v['positive_below_half_pct']:.2f}%)",
                     f"{v['multi_attack_sets']:,}"] for k, v in mx.items()]))
    L.append("\n**Event sets per target class and split:**\n")
    tc = info["targets_by_class"]
    L.append(table(["Split"] + list(tc.columns), [[i] + [f"{int(x):,}" for x in r] for i, r in tc.iterrows()]))
    L.append("\nUnder this policy every mixed set is labelled attack, so label noise is concentrated in mixed sets where the "
             "attack fraction is small (counted above).\n")

    L.append("## 8. Output files\n")
    L.append(table(["File", "Role", "Contains"], [
        ["event_profiles.csv", "**MODEL INPUT**", f"event_set_id, window_id, split, window_start, {', '.join(info['bp_cols'])}  (no IPs, labels, targets)"],
        ["event_set_targets.csv", "**GROUND TRUTH**", "event_set_id, window_id, split, n_flows, n_attack_flows, attack_fraction, label_purity, is_mixed, is_multi_attack, target_binary, target_multiclass, target_label"],
        ["event_sets.csv", "intermediate", "IDs, window times, flows per set, the 5 event counts, readable event text, is_empty"],
        ["event_set_keys.csv", "audit / alert details", "IDs, source_ip, destination_ip"],
        ["tfidf_event_vectors.csv, tfidf_model.json", "intermediate", "fitted on training sets"],
        ["event_thresholds.json, basepoints.csv, basepoints.json", "fitted parameters", "thresholds, basepoint vectors and selection trace"],
        ["event_profiles_metadata.json", "metadata", "model_input_columns, identifier columns, target columns, join key, settings"]]))
    L.append("")

    L.append("## 9. Join validation (profiles <-> targets, re-read from disk)\n")
    L.append(table(["Check", "Result", "Detail"], [[n, "PASS" if ok else "FAIL", d] for n, ok, d in info["checks"]]))
    L.append("")

    L.append("## 10. Warnings\n")
    L += [f"- {w}" for w in st["warnings"]] or ["- none"]
    L.append("\n## 11. Limitations\n")
    L += ["- Attack event sets are scarce and heavily overlapping: neighbouring windows share 9 of 10 minutes, so effective sample "
          "size is far smaller than the row count. Results from later models will be noisy, and valid only for this single day of traffic.",
          f"- Only {len(EVENT_NAMES)} event types exist, so many event sets share the same or near-identical vectors.",
          "- Many benign event sets are empty (no event fired); their profiles are all zeros and cannot be told apart.",
          "- TF-IDF vectors are L2-normalised: they keep the direction of an event pattern but not its volume.",
          "- Timestamps have minute resolution; flows inside a minute cannot be ordered.",
          "- Events are derived by percentile rules on flow features; they are not IDS alerts and the 95th/5th percentile "
          "rules guarantee some events fire on benign traffic.",
          "- Strict threshold comparisons on discrete or tied features (e.g. syn_flag_count) can fire on far fewer flows "
          "than the nominal 5% - see the trigger-share column.",
          "- Block-based splitting leaves few independent train/validation/test periods for a single day."]
    L.append(f"\n*Run time: {info['seconds']:.1f} s.*\n")
    return "\n".join(L)


def event_mapping_report(info):
    th = info["thresholds"]
    L = ["# Event Mapping (CICIDS2017 flows -> derived security events)\n",
         "The research paper works with **IDS/IPS alert names**. CICIDS2017 provides network-flow statistics instead, so we "
         "derive five event categories with transparent rules. **These are derived events, not original IDS alerts.**\n",
         table(["Event", "Level", "Source feature", "Unit / meaning (CICFlowMeter)", "Rule", "Threshold (this run)", "Counted as"],
               [["HIGH_FLOW_RATE", "source->destination event set", "number of flows in the set", "flows per 10-min window",
                 f"> {th['HIGH_FLOW_RATE']['percentile']}th pct of training event sets", f"{th['HIGH_FLOW_RATE']['threshold']:.6g} flows",
                 "0 or 1 per event set"],
                ["HIGH_PACKET_RATE", "flow", "flow_packets_s", "packets per second", f"> {th['HIGH_PACKET_RATE']['percentile']}th pct of training flows",
                 f"{th['HIGH_PACKET_RATE']['threshold']:.6g}", "number of flows that fired"],
                ["HIGH_BYTE_RATE", "flow", "flow_bytes_s", "bytes per second", f"> {th['HIGH_BYTE_RATE']['percentile']}th pct of training flows",
                 f"{th['HIGH_BYTE_RATE']['threshold']:.6g}", "number of flows that fired"],
                ["SYN_ACTIVITY", "flow", "syn_flag_count", "packets with the SYN flag in the flow", f"> {th['SYN_ACTIVITY']['percentile']}th pct of training flows",
                 f"{th['SYN_ACTIVITY']['threshold']:.6g}", "number of flows that fired"],
                ["SHORT_REPEATED_CONNECTIONS", "flow", "flow_duration", "microseconds", f"< {th['SHORT_REPEATED_CONNECTIONS']['percentile']}th pct of training flows",
                 f"{th['SHORT_REPEATED_CONNECTIONS']['threshold']:.6g} microseconds", "number of flows that fired"]]),
         "\n**Why 'repeated':** each flow is judged on its own; the repetition is the *count* of short flows between one "
         "source and one destination inside a window.\n",
         "**Event set:** all flows from one source IP to one destination IP inside one window. IPs only define the groups; "
         "they are never given to TF-IDF, basepoints or any model. Direction matters (A->B and B->A are separate sets).\n",
         "**Event vector / profile:** the 5 event counts -> TF-IDF (training-fitted) -> L2-normalised vector -> cosine "
         "similarity to each basepoint = event profile.\n",
         "**Leakage rules:** thresholds, IDF and basepoints use training data only; label, label_original, target_binary, "
         "target_multiclass, ports and Flow ID are never inputs to event generation.\n"]
    return "\n".join(L)


def paper_vs_implementation(info):
    rows = [
        ["Sliding window: 10-minute size, 60 s interval", "PAPER", "Same values, read from configs/config.yaml (window.size_seconds / step_seconds)."],
        ["Event sets aggregated by source and destination address inside each window", "PAPER", "One event set per source->destination pair per window."],
        ["Events are IDS/IPS alert names", "ADAPTATION", "Five derived, flow-based categories. Not IDS alerts."],
        ["Event counts per event set (frequency of each event)", "PAPER", "Counts for four events; HIGH_FLOW_RATE is 0/1 because it describes the whole set."],
        ["TF-IDF over event sets (set = document, event = term)", "PAPER", "Same roles."],
        ["IDF uses the total number of occurrences of an event", "ADAPTATION", "Document frequency with smoothing; total occurrences can exceed the number of sets with our flow-level counts and give negative weights."],
        ["Sublinear TF and L2 normalisation", "OURS", "Counts range from 1 to thousands."],
        ["Basepoint candidates: sets that contain rare events; redundant basepoints replaced iteratively", "PAPER", "Same idea."],
        ["Rare list of 10-20 events; k as a fraction of the number of event types", "ADAPTATION", "Only 5 event types: rare list of 2, up to 8 basepoints, deterministic greedy replacement of redundant ones."],
        ["Event profile = cosine similarity to each basepoint", "PAPER", "Same, with safe handling of empty sets (all zeros)."],
        ["Profile reduces dimensionality", "ADAPTATION", "8 basepoints over 5 event dimensions is a representation, not a reduction."],
        ["Labels from threat-detection reports (time + attacker IP)", "ADAPTATION", "Labels come from the CICIDS2017 flow labels; event-set targets defined from them, kept in a separate file."],
        ["Percentile thresholds from training data; blocked time split; window never crosses a split; join checks", "OURS", "Added to prevent leakage."],
    ]
    return "\n".join(["# Paper vs. Implementation\n",
                      "PAPER = follows the original paper. ADAPTATION = changed because CICIDS2017 differs from the paper's data. OURS = added by this project.\n",
                      "CICIDS2017 is one of the datasets the paper reports on, but our events, thresholds and targets are our own construction; "
                      "we do not claim to reproduce the paper's results.\n",
                      table(["Item", "Tag", "Our implementation"], rows),
                      "\nPhase 4 (FCNN / CNN / LSTM) is not implemented yet.\n"])


def write_reports(info, cfg, reports_dir):
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    paths = {"event_profile_report": reports_dir / "event_profile_report.md",
             "event_mapping": reports_dir / "event_mapping.md",
             "paper_vs_implementation": reports_dir / "paper_vs_implementation.md"}
    paths["event_profile_report"].write_text(profile_report(info, cfg), encoding="utf-8")
    paths["event_mapping"].write_text(event_mapping_report(info), encoding="utf-8")
    paths["paper_vs_implementation"].write_text(paper_vs_implementation(info), encoding="utf-8")
    return paths
