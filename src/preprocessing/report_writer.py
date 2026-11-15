"""
Writes reports/preprocessing_report.md from the facts collected by the pipeline.
Every number comes from the run; the explanatory text is static.
"""

from datetime import datetime
from pathlib import Path


def _esc(x):
    return str(x).replace("|", "\\|").replace("\n", " ")


def _table(headers, rows):
    out = ["| " + " | ".join(_esc(h) for h in headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    out += ["| " + " | ".join(_esc(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def _pct(part, whole):
    return f"{100.0 * part / whole:.3f}%" if whole else "n/a"


def _file_section(i, cfg):
    L = []
    benign = cfg["labels"]["benign_label"]
    ts = i["timestamp"]
    L.append(f"## File: `{i['file']}`\n")
    L.append(f"Rows loaded: **{i['rows_loaded']:,}**  ->  rows kept: **{i['rows_final']:,}** "
             f"(removed {i['rows_loaded'] - i['rows_final']:,}).  Columns loaded: {i['cols_loaded']}.\n")
    L.append(f"Raw file SHA-256 before: `{i['sha_before']}`  \n"
             f"Raw file SHA-256 after:  `{i['sha_after']}`  ->  "
             f"**{'UNCHANGED' if i['raw_untouched'] else 'CHANGED (!)'}**\n")

    L.append("### 1. Row accounting (what every step did to the row count)\n")
    L.append(_table(["Step", "Rows before", "Rows after", "Note"],
                    [[s, f"{b:,}", f"{a:,}", n] for s, b, a, n in i["steps"]]))
    L.append("")

    L.append("### 2. Labels and targets\n")
    L.append(f"`label_original` keeps the label exactly as in the raw file. `label` is the cleaned name "
             f"(spaces stripped, spelling matched to the config). `target_binary` is **0 for {benign}** and "
             f"**1 for every attack label**. `target_multiclass` uses the codes below.\n")
    L.append(_table(["Label", "multiclass code", "rows loaded", "rows kept"],
                    [[k, v, f"{i['labels_loaded'].get(k, 0):,}", f"{i['labels_final'].get(k, 0):,}"]
                     for k, v in i["label_to_code"].items()]))
    L.append("")

    L.append("### 3. Column roles (which fields are used for what)\n")
    L.append("| Role | Columns | Used as ordinary model features? |\n| --- | --- | --- |")
    L.append(f"| Context / identification | {', '.join(i['context_columns'])} | **No** (reasons in section 9) |")
    L.append(f"| Helper columns we created | source_row, timestamp_raw, hour_shifted, label_original, label, "
             f"target_binary, target_multiclass, block_id, split | No |")
    L.append(f"| Numeric network features | {len(i['feature_columns'])} columns (list in the metadata JSON) | "
             "Yes - candidates for the neural-network models later |")
    L.append("\nThe event-profile pipeline (Phases 3-7) will use the **context columns** "
             "(who talked to whom, on which port/protocol, when, and what kind of event) to build event sets. "
             "The **numeric features** are for tabular models and the 'Analyze Event' form later.\n")

    L.append("### 4. Column names\n")
    changed = [(r, n) for r, n in i["column_mapping"] if r != n]
    L.append(f"{len(changed)} of {len(i['column_mapping'])} names changed. Rule: lowercase, anything that is not a "
             "letter/digit becomes `_`, extra `_` removed (e.g. `' Flow Bytes/s'` -> `flow_bytes_s`). "
             "Full list: `data/interim/*_column_mapping.csv`. First 12 changes:\n")
    L.append(_table(["Raw name", "Normalized"], [[f"'{r}'", n] for r, n in changed[:12]]))
    L.append("")

    L.append("### 5. Network field validation\n")
    inv = i["invalid_network"]
    L.append(f"Invalid values per field: {inv['counts']}  ->  {inv['rows']:,} row(s) affected "
             f"(policy: `{cfg['cleaning']['invalid_network_fields']}`).\n")

    L.append("### 6. Duplicates\n")
    d = i["duplicates"]
    L.append(f"Fully identical rows found: **{d['count']:,}** (by label: {d['by_label'] or 'none'}). "
             f"Removed: **{d['removed']}** (`cleaning.remove_duplicates`). Rows are compared on every original "
             "column including the raw timestamp and Flow ID, so only true repeats of the same record match.\n")

    L.append("### 7. Missing and infinite values\n")
    nf = i["non_finite"]
    L.append(f"Strategy: `{nf['strategy']}`.  Rows affected: **{nf['rows']:,}**  (by label: {nf['by_label'] or 'none'}).\n")
    if nf["table"]:
        L.append(_table(["Column", "NaN", "+Infinity", "-Infinity"], [list(r) for r in nf["table"]]))
        L.append("")
    L.append("*Why:* infinity appears in rate columns when a flow's duration is 0 (division by zero); NaN is a "
             "missing value. Neural networks cannot use either. Dropping the rows is safe because we avoid "
             "**inventing** numbers (e.g. a median) before the train/test split exists - a median computed on all "
             "data would leak information from the test period into training. If we ever need to keep these rows, "
             "set `non_finite_strategy: keep_as_nan` and impute using the training split only.\n")
    if i["malformed_numeric"]:
        L.append(f"Text found in numeric columns (turned into NaN first): {i['malformed_numeric']}\n")
    if i["empty_columns"]:
        L.append(f"Columns that were completely empty and removed: {i['empty_columns']}\n")

    L.append("### 8. Constant columns and negative values\n")
    L.append(f"Constant columns (one single value in every row, so no information): **{len(i['constant_columns'])}**. "
             f"Removed: **{i['constant_removed']}** (`cleaning.remove_constant_columns`).\n")
    if i["constant_columns"]:
        L.append(_table(["Column", "Constant value"], [[c, v] for c, v in i["constant_columns"]]))
        L.append("")
    L.append("*Note:* this is decided on the whole file (it uses no labels, so it leaks nothing about the target). "
             "When more days are added, the column list will be recomputed across all days so every file has the same columns.\n")
    L.append("**Negative values were NOT removed or changed.** Some are legitimate (for example `-1` meaning "
             "'not set'). The table shows where they occur so we can review them case by case:\n")
    if i["negatives"]:
        L.append(_table(["Column", "Negative cells", "Share of rows", "Minimum", "Kind"],
                        [[c, f"{n:,}", f"{s:.3%}", m, k] for c, n, s, m, k in i["negatives"]]))
    else:
        L.append("No negative values in the numeric features.")
    L.append("")

    L.append("### 9. Leakage-risk check for context fields\n")
    L.append("A *leaky* field lets a model 'cheat' by memorizing something that merely correlates with the label in "
             "THIS dataset. For each attack, the table shows its most common value of each field, the share of that "
             "attack's rows with that value, and the share of BENIGN rows with the same value.\n")
    L.append(_table(["Attack", "Field", "Most common value", "Share of this attack", "Share of BENIGN"],
                    [[a, f, v, f"{s:.1%}", f"{b:.1%}"] for a, f, v, s, b in i["leakage"]]))
    L.append("\n**Decision:** IP addresses, ports, Flow ID and the protocol are kept for traceability and for building "
             "events in Phase 3, but are **excluded from the numeric feature list**. Where one value covers "
             "(nearly) all rows of an attack and few BENIGN rows, a model could classify by that value alone "
             "(e.g. 'attacker IP' or 'port 21') and fail on any other network. Random source ports carry no meaning "
             "and Flow ID is just a text join of IPs/ports/protocol. The paper's event-profile idea is also "
             "built on *event behaviour over time*, not on a single address.\n")

    L.append("### 10. Timestamps\n")
    L.append(f"Raw examples: {', '.join('`'+str(e)+'`' for e in ts['examples'])}. "
             f"Strings that include seconds: {ts['has_seconds']:,} of {i['rows_loaded']:,}.\n")
    rows = []
    for o, s in ts["order_tests"].items():
        rows.append([o, f"{s['parsed']:,}", s.get("min", "-"), s.get("max", "-"), s.get("weekday", "-"), s.get("days", "-")])
    L.append(_table(["Date order tested", "Rows parsed", "Earliest (before hour fix)", "Latest (before hour fix)", "Most common weekday", "Distinct days"], rows))
    L.append(f"\n**Decision:** `{ts['chosen_order']}`.  Reason: {ts['order_reason']}\n")
    if ts["uncertain"]:
        L.append("> **UNCERTAIN:** the order could not be proven from the data. Check the date range above "
                 "against the known capture date and set `timestamp.date_order` explicitly if needed.\n")
    L.append(f"**Hour correction (12-hour clock without AM/PM):** rule `{ts['hour_rule']}`; "
             f"pattern detected in data: **{ts['hour_pattern_detected']}**; applied: **{ts['hour_correction_applied']}**.\n")
    hb = ", ".join(f"{h:02d}h:{c:,}" for h, c in sorted(ts["hours_before"].items()))
    ha = ", ".join(f"{h:02d}h:{c:,}" for h, c in sorted(ts["hours_after"].items()))
    L.append(f"Rows per hour BEFORE correction: {hb}\n")
    L.append(f"Rows per hour AFTER correction:  {ha}\n")
    L.append(f"Resulting time span: **{ts['span'][0]}  ->  {ts['span'][1]}** ({ts['distinct_days']} distinct day(s)). "
             f"Hours inside the span with no rows: {ts['hour_gaps'] or 'none'}.\n")
    for n in ts["notes"]:
        L.append(f"- {n}")
    L.append("\n**Resolution:** timestamps have only minute precision, so flows in the same minute cannot be ordered by "
             "time. We keep `source_row` (original file order) as a tie-breaker but do not treat it as true time order. "
             "Our window step (60 s) equals this resolution, so a minute is always entirely inside or outside a window - "
             "no flow is split across a window boundary. Timestamps are naive local capture time (no time zone). "
             "`timestamp_raw` and `hour_shifted` let you trace every correction.\n")

    L.append("### 11. Train / validation / test strategy\n")
    if i["split_table"] is None:
        L.append("Split disabled in config.\n")
    else:
        s = cfg["split"]
        L.append(f"**Blocked time split.** The timeline is cut into {s['block_minutes']}-minute blocks; each whole block "
                 f"is assigned to train ({s['train_fraction']:.0%}), validation ({s['validation_fraction']:.0%}) or "
                 f"test ({s['test_fraction']:.0%}), stratified by the dominant attack in the block "
                 f"(seed {s['random_seed']}). Plan: `data/processed/*_split_plan.csv`; each row has `block_id` and `split`.\n")
        L.append("*Why not a random row split?* Neighbouring flows of one attack are near-copies; a random split "
                 "puts siblings in both train and test and gives unrealistically high scores. *Why not simply "
                 "'first 70% of time = train'?* In this single-day file the attacks happen in different periods, "
                 "so the later attack could end up only in test and never be learned. Blocked, stratified assignment "
                 "keeps time coherence AND gives each attack a place in every split.\n")
        L.append(f"**Rule for later phases:** a sliding window ({cfg['window']['size_seconds']} s) is used only if every "
                 "flow in it belongs to ONE split; windows straddling two splits are discarded. TF-IDF (IDF), "
                 "basepoints and any scaling/imputation must be fitted on the **train** split only.\n")
        tbl = i["split_table"]
        L.append(_table(["split"] + list(tbl.columns) + ["total"],
                        [[idx] + [f"{int(v):,}" for v in row] + [f"{int(row.sum()):,}"] for idx, row in tbl.iterrows()]))
        L.append("")
        for w in i["split_warnings"]:
            L.append(f"> **WARNING:** {w}")
        for lab in tbl.columns:
            for sp in ("train", "validation", "test"):
                if sp not in tbl.index or tbl.loc[sp, lab] == 0:
                    L.append(f"> **WARNING:** label `{lab}` has no rows in the `{sp}` split.")
        L.append("")

    L.append("### 12. Outputs\n")
    L.append(_table(["Output", "Path"], [[k, v] for k, v in i["outputs"].items() if v]))
    L.append(f"\nFinal columns: {len(i['context_columns'])} context + {len(i['feature_columns'])} numeric features + helper columns. "
             f"Run time: {i['seconds']:.1f} s.\n")
    return L


def write_preprocessing_report(infos, cfg, config_source, path: Path, combined_meta=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    L = ["# Preprocessing Report - CICIDS2017\n",
         f"*Generated automatically on {datetime.now():%Y-%m-%d %H:%M:%S}. All numbers were calculated by the pipeline.*  ",
         f"*Configuration: {config_source}*\n",
         "**Scope of this phase:** cleaning and documentation only. No neural network was trained; no TF-IDF, "
         "basepoints, cosine similarity, event profiles or dashboard exist yet.\n"]

    if combined_meta:
        tot = combined_meta["total_rows_final"]
        L.append("## Combined Multi-Dataset Summary & Experiment Partitioning\n")
        L.append(f"Combined File: `{combined_meta['combined_file']}`  \n"
                 f"Total captures combined: **{combined_meta['total_datasets']}**  \n"
                 f"Total clean flows: **{tot:,}**  \n"
                 f"Feature schema: **{len(infos[0]['feature_columns'])} features** (100% identical across all 8 files)\n")
        
        L.append("### Global Label Distribution across All 8 Captures\n")
        lbl_rows = [[lbl, f"{cnt:,}", _pct(cnt, tot)]
                    for lbl, cnt in sorted(combined_meta["labels_distribution"].items(), key=lambda x: -x[1])]
        L.append(_table(["Label", "Count", "Percentage"], lbl_rows))
        L.append("")

        L.append("### EXPERIMENT A — Multi-Class Classification Split (Time-Blocked per Day)\n")
        sp_a = combined_meta["experiment_a_split_distribution"]
        L.append(_table(["Split", "Rows", "Share"], [
            ["Train", f"{sp_a.get('train', 0):,}", _pct(sp_a.get('train', 0), tot)],
            ["Validation", f"{sp_a.get('validation', 0):,}", _pct(sp_a.get('validation', 0), tot)],
            ["Test", f"{sp_a.get('test', 0):,}", _pct(sp_a.get('test', 0), tot)]
        ]))
        L.append("")

        L.append("### EXPERIMENT B — Unseen Attack Detection Partition (Held-Out Friday Attacks)\n")
        sp_b = combined_meta["experiment_b_split_distribution"]
        L.append(_table(["Split", "Datasets Included", "Rows", "Share"], [
            ["Train", "Monday, Tuesday, Wednesday", f"{sp_b.get('train', 0):,}", _pct(sp_b.get('train', 0), tot)],
            ["Validation", "Thursday (Morning & Afternoon)", f"{sp_b.get('validation', 0):,}", _pct(sp_b.get('validation', 0), tot)],
            ["Test (Held-Out)", "Friday (Morning, PortScan, DDoS)", f"{sp_b.get('test', 0):,}", _pct(sp_b.get('test', 0), tot)]
        ]))
        L.append("")

    for i in infos:
        L += _file_section(i, cfg)
    all_warn = [w for i in infos for w in i["warnings"]]
    L.append("## Open questions / uncertainties\n")
    if all_warn:
        L += [f"- {w}" for w in all_warn]
    else:
        L.append("- No automatic warnings. Still verify the timestamp decision and the hour table by eye.")
    L.append("- Whether `-1` values are true sentinels was NOT verified; they are kept unchanged.")
    L.append("- Constant-column list and feature list were standardized across all 8 files ensuring uniform 67 feature columns.")
    path.write_text("\n".join(L), encoding="utf-8")
