"""
PHASE 1 - DATASET INSPECTION
============================
Reads the raw CICIDS2017 CSV file(s) from data/raw/ and writes a plain-text
(Markdown) report to reports/dataset_report.md.

What this script does NOT do:
  * It never modifies, renames, moves or deletes the raw CSV (read-only).
  * It never cleans or saves any data. Cleaning is Phase 2.
  * Column-name stripping happens only on the in-memory copy.

Every number in the report is calculated from your file - nothing is hard-coded.

Run from the project root:
    python src/preprocessing/inspect_dataset.py
"""

import argparse
import hashlib
import ipaddress
import re
import time
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

# ----------------------------------------------------------------------------
# Settings (Phase 2 will move these into configs/config.yaml)
# ----------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RAW_DIR = PROJECT_ROOT / "data" / "raw"
DEFAULT_REPORT = PROJECT_ROOT / "reports" / "dataset_report.md"
ENCODING = "latin-1"
BENIGN_LABEL = "BENIGN"
TOP_N = 10

# The same field is named differently in different CICIDS2017 releases.
COLUMN_ALIASES = {
    "flow_id": ["Flow ID"],
    "src_ip": ["Source IP", "Src IP"],
    "dst_ip": ["Destination IP", "Dst IP"],
    "src_port": ["Source Port", "Src Port"],
    "dst_port": ["Destination Port", "Dst Port"],
    "protocol": ["Protocol"],
    "timestamp": ["Timestamp"],
    "label": ["Label"],
}

# Timestamp formats we try. We do NOT assume which one is right - we measure.
TIMESTAMP_FORMATS = [
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
]
WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

# Display-only name lookups (IANA protocol numbers / common ports).
PROTOCOL_NAMES = {0: "HOPOPT", 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP"}
PORT_NAMES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS", 138: "NetBIOS",
    139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    3389: "RDP", 8080: "HTTP-alt",
}


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
def sha256_of(path: Path) -> str:
    """Fingerprint of the file, used to prove we did not change it."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def normalize_column_name(name: str) -> str:
    """Remove BOM leftovers, leading/trailing spaces and repeated inner spaces."""
    name = str(name).replace("\ufeff", "").replace("ï»¿", "")
    return " ".join(name.split())


def md_escape(x) -> str:
    return str(x).replace("|", "\\|").replace("\n", " ")


def md_table(headers, rows) -> str:
    lines = ["| " + " | ".join(md_escape(h) for h in headers) + " |",
             "| " + " | ".join("---" for _ in headers) + " |"]
    for r in rows:
        lines.append("| " + " | ".join(md_escape(c) for c in r) + " |")
    return "\n".join(lines)


def pct(part, whole) -> str:
    return f"{(100.0 * part / whole):.3f}%" if whole else "n/a"


def find_col(columns, key):
    """Return the real column name for a logical field, or None if absent."""
    lower = {c.lower(): c for c in columns}
    for cand in COLUMN_ALIASES[key]:
        if cand.lower() in lower:
            return lower[cand.lower()]
    return None


def top_table(series: pd.Series, n=TOP_N, names=None, total=None, value_header="Value"):
    total = total if total is not None else len(series)
    vc = series.value_counts(dropna=False).head(n)
    rows = []
    for v, c in vc.items():
        shown = v
        if names is not None:
            try:
                nm = names.get(int(float(v)))
                if nm:
                    shown = f"{v} ({nm})"
            except (ValueError, TypeError):
                pass
        rows.append([shown, f"{int(c):,}", pct(c, total)])
    return md_table([value_header, "Rows", "Share"], rows)


def classify_ips(counts: pd.Series):
    """Check each UNIQUE ip once (fast), weighted by how many rows use it."""
    valid = invalid = private = public = 0
    bad = []
    for ip, n in counts.items():
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            invalid += int(n)
            if len(bad) < 5:
                bad.append(str(ip))
            continue
        valid += int(n)
        if addr.is_private:
            private += int(n)
        else:
            public += int(n)
    return valid, invalid, private, public, bad


# ----------------------------------------------------------------------------
# Inspection of one file
# ----------------------------------------------------------------------------
def inspect_file(path: Path):
    t0 = time.time()
    L = []          # report lines
    problems = []   # auto-detected potential problems
    summary = {}    # printed in the terminal at the end

    print(f"\n[1/8] Fingerprinting raw file: {path.name}")
    hash_before = sha256_of(path)
    size_mb = path.stat().st_size / (1024 * 1024)

    print(f"[2/8] Reading full CSV with encoding={ENCODING} (this can take 10-60 s) ...")
    df = pd.read_csv(path, encoding=ENCODING, low_memory=False)
    n_rows, n_cols = df.shape
    mem_mb = df.memory_usage(deep=True).sum() / (1024 * 1024)
    print(f"      loaded {n_rows:,} rows x {n_cols} columns")

    # Normalize column names ONLY in memory
    raw_cols = list(df.columns)
    norm_cols = [normalize_column_name(c) for c in raw_cols]
    df.columns = norm_cols
    changed = [(r, n) for r, n in zip(raw_cols, norm_cols) if r != n]

    col = {k: find_col(norm_cols, k) for k in COLUMN_ALIASES}
    text_cols = {c for c in (col["flow_id"], col["src_ip"], col["dst_ip"],
                             col["timestamp"], col["label"]) if c}

    L.append(f"## File: `{path.name}`\n")
    L.append("### 1. Overview\n")
    L.append(md_table(["Item", "Value"], [
        ["File size on disk", f"{size_mb:,.1f} MB"],
        ["SHA-256 (before reading)", f"`{hash_before}`"],
        ["Encoding used", ENCODING],
        ["Rows", f"{n_rows:,}"],
        ["Columns", n_cols],
        ["Memory when loaded", f"{mem_mb:,.0f} MB"],
    ]))
    L.append("")

    # ---------------- Column names, dtypes, missing ----------------
    print("[3/8] Column names, data types, missing values ...")
    nulls = df.isna().sum()
    rows = []
    for i, (raw, norm) in enumerate(zip(raw_cols, norm_cols), start=1):
        rows.append([i, f"'{raw}'" if raw != norm else raw, norm if raw != norm else "(same)",
                     str(df[norm].dtype), f"{n_rows - int(nulls[norm]):,}",
                     f"{int(nulls[norm]):,}", pct(nulls[norm], n_rows)])
    L.append("### 2. Columns (raw name -> normalized name), data types, missing values\n")
    L.append("Raw names are shown in quotes only when they contain extra spaces. "
             "The raw file is NOT changed; normalization exists only in memory.\n")
    L.append(md_table(["#", "Raw name", "Normalized", "dtype", "Non-null", "Missing", "Missing %"], rows))
    L.append("")
    dt = df.dtypes.astype(str).value_counts()
    L.append("**dtype summary:** " + ", ".join(f"{k}: {v}" for k, v in dt.items()) + "\n")
    L.append(f"**Columns whose raw name needed cleaning:** {len(changed)} of {n_cols}\n")

    total_missing = int(nulls.sum())
    rows_with_missing = int(df.isna().any(axis=1).sum())
    cols_with_missing = [c for c in norm_cols if nulls[c] > 0]
    L.append("### 3. Missing values\n")
    L.append(md_table(["Item", "Value"], [
        ["Total missing cells", f"{total_missing:,}"],
        ["Rows with at least one missing value", f"{rows_with_missing:,} ({pct(rows_with_missing, n_rows)})"],
        ["Columns with missing values", ", ".join(cols_with_missing) if cols_with_missing else "none"],
    ]))
    L.append("")

    # ---------------- Infinite & malformed numerics ----------------
    print("[4/8] Infinite values, malformed numbers, duplicates ...")
    num_cols = [c for c in norm_cols if pd.api.types.is_numeric_dtype(df[c])]
    inf_rows = np.zeros(n_rows, dtype=bool)
    inf_info = []
    for c in num_cols:
        if pd.api.types.is_float_dtype(df[c]):
            v = df[c].to_numpy()
            pos, neg = int(np.isposinf(v).sum()), int(np.isneginf(v).sum())
            if pos or neg:
                inf_info.append([c, f"{pos:,}", f"{neg:,}"])
                inf_rows |= np.isinf(v)
    n_inf_rows = int(inf_rows.sum())
    L.append("### 4. Infinite values (+inf / -inf)\n")
    if inf_info:
        L.append(md_table(["Column", "+inf count", "-inf count"], inf_info))
        L.append(f"\n**Rows containing at least one infinite value:** {n_inf_rows:,} ({pct(n_inf_rows, n_rows)})\n")
    else:
        L.append("No infinite values found in numeric columns.\n")

    object_cols = [c for c in norm_cols if c not in num_cols]
    unexpected = []
    for c in object_cols:
        if c in text_cols:
            continue
        coerced = pd.to_numeric(df[c], errors="coerce")
        bad = int((coerced.isna() & df[c].notna()).sum())
        unexpected.append([c, f"{bad:,}", ", ".join(map(str, df[c][coerced.isna() & df[c].notna()].unique()[:3]))])
    L.append("### 5. Malformed values (text found in columns that should be numeric)\n")
    if unexpected:
        L.append("These columns were read as text although they are not ID/context fields:\n")
        L.append(md_table(["Column", "Non-numeric cells", "Examples"], unexpected))
        L.append("")
    else:
        L.append("All non-ID columns were read as numbers - no malformed text values.\n")

    dup_mask = df.duplicated()
    n_dup = int(dup_mask.sum())
    L.append("### 6. Duplicate rows\n")
    L.append(f"**Fully identical rows (all {n_cols} columns equal, first copy not counted):** "
             f"{n_dup:,} ({pct(n_dup, n_rows)})\n")
    if n_dup and col["label"]:
        L.append("Duplicates by label:\n")
        L.append(top_table(df.loc[dup_mask, col["label"]], n=50, total=n_dup, value_header="Label"))
        L.append("")
    if col["flow_id"]:
        n_flow_dup = int(df[col["flow_id"]].duplicated().sum())
        L.append(f"*Info:* `{col['flow_id']}` repeated values: {n_flow_dup:,}. "
                 "A Flow ID is just src/dst/ports/protocol, so repeats are normal "
                 "(the same connection can appear many times). It is NOT a unique row key.\n")

    # ---------------- Labels ----------------
    print("[5/8] Labels ...")
    L.append("### 7. Labels\n")
    labels_norm = None
    attack_labels = []
    if col["label"]:
        raw_labels = df[col["label"]].astype(str)
        labels_norm = raw_labels.str.strip()
        n_unclean = int((raw_labels != labels_norm).sum())
        uniq = sorted(raw_labels.unique())
        L.append(f"**Unique labels ({len(uniq)}):** " + ", ".join(f"`{u!r}`" for u in uniq) + "\n")
        L.append(f"Rows whose label has extra spaces: {n_unclean:,}\n")
        vc = labels_norm.value_counts()
        L.append(md_table(["Label", "Rows", "Share"],
                          [[k, f"{int(v):,}", pct(v, n_rows)] for k, v in vc.items()]))
        n_benign = int((labels_norm.str.upper() == BENIGN_LABEL).sum())
        n_attack = n_rows - n_benign
        attack_labels = [l for l in vc.index if l.upper() != BENIGN_LABEL]
        L.append(f"\n**{BENIGN_LABEL}:** {n_benign:,} ({pct(n_benign, n_rows)})  |  "
                 f"**Attack (all non-{BENIGN_LABEL}):** {n_attack:,} ({pct(n_attack, n_rows)})\n")
        summary["labels"] = {k: int(v) for k, v in vc.items()}
        if attack_labels:
            smallest = vc[attack_labels].min()
            if smallest / n_rows < 0.01 or n_benign / n_rows > 0.8:
                problems.append(f"Class imbalance: {BENIGN_LABEL} is {pct(n_benign, n_rows)} of rows; "
                                f"smallest attack class has {int(smallest):,} rows.")
        else:
            problems.append("No attack labels found - nothing to detect in this file.")
    else:
        L.append("**No `Label` column found.**\n")
        problems.append("No Label column - supervised training impossible with this file.")

    # ---------------- Timestamp ----------------
    print("[6/8] Timestamps ...")
    L.append("### 8. Timestamp\n")
    if col["timestamp"]:
        ts = df[col["timestamp"]].astype("string").str.strip()
        n_ts_missing = int(ts.isna().sum())
        has_sec = int((ts.str.count(":") >= 2).sum())
        sample = pd.concat([ts.head(3), ts.sample(min(3, n_rows), random_state=0), ts.tail(3)]).tolist()
        L.append(f"**Raw examples (first 3 / random 3 / last 3):** {', '.join(f'`{s}`' for s in sample)}\n")
        L.append(f"Missing timestamps: {n_ts_missing:,}  |  strings that include seconds: {has_sec:,} ({pct(has_sec, n_rows)})\n")

        fmt_rows, results = [], []
        wd_name = next((d for d in WEEKDAYS if d.lower() in path.name.lower()), None)
        for fmt in TIMESTAMP_FORMATS:
            parsed = pd.to_datetime(ts, format=fmt, errors="coerce")
            ok = int(parsed.notna().sum())
            if ok:
                pmin, pmax = parsed.min(), parsed.max()
                n_days = int(parsed.dt.normalize().nunique())
                wd = pmin.day_name()
            else:
                pmin = pmax = None
                n_days, wd = 0, "-"
            results.append((fmt, ok, n_days, wd, parsed))
            fmt_rows.append([fmt, f"{ok:,} ({pct(ok, n_rows)})", pmin, pmax, n_days, wd])
        L.append("The file does not say whether dates are day/month or month/day, so we test every "
                 "format and compare the results:\n")
        L.append(md_table(["Format tried", "Rows parsed OK", "Earliest", "Latest", "Distinct days", "Weekday of earliest"], fmt_rows))
        L.append("")

        best_ok = max(r[1] for r in results)
        if best_ok == 0:
            L.append("**No tested format could parse the timestamps.** Phase 2 needs a custom parser.\n")
            problems.append("Timestamps could not be parsed with any tested format.")
        else:
            cands = [r for r in results if r[1] == best_ok]
            chosen = None
            if wd_name:
                match = [r for r in cands if r[3] == wd_name]
                if len(match) >= 1:
                    chosen = match[0]
                    L.append(f"File name says **{wd_name}**; formats whose earliest date falls on a {wd_name}: "
                             f"{', '.join('`'+m[0]+'`' for m in match)}.\n")
            if chosen is None:
                chosen = min(cands, key=lambda r: r[2])
            fmt, ok, n_days, wd, parsed = chosen
            L.append(f"**Best-fitting format:** `{fmt}`  ->  range **{parsed.min()}** to **{parsed.max()}** "
                     f"({n_days} distinct day(s), earliest is a {wd}).\n")
            if len(cands) > 1:
                problems.append("Timestamp day/month order is ambiguous (several formats parse 100%). "
                                "We chose the one matching the weekday in the file name - please confirm it.")
            if has_sec < n_rows * 0.5:
                problems.append("Timestamps only have MINUTE resolution (no seconds). Our window step is 60 s, "
                                "so every event inside the same minute will look simultaneous.")
            hours = parsed.dt.hour.value_counts().sort_index()
            L.append("**Rows per hour of day (from the chosen format):** " +
                     ", ".join(f"{int(h):02d}h: {int(c):,}" for h, c in hours.items()) + "\n")
            hs = set(hours.index)
            if max(hs) < 13 and any(h in hs for h in range(8, 12)) and any(h in hs for h in range(1, 7)):
                problems.append("Hours look like a 12-hour clock without AM/PM (e.g. 8-11 and then 1-5, none "
                                "from 13-23). Afternoon traffic may be mis-dated by 12 hours. Phase 2 must fix this.")
            per_min = parsed.dt.floor("min").value_counts()
            L.append(f"**Flows per minute:** min {int(per_min.min()):,}, median {int(per_min.median()):,}, "
                     f"max {int(per_min.max()):,} (over {len(per_min):,} active minutes)\n")
            summary["time_range"] = f"{parsed.min()} -> {parsed.max()}"
    else:
        L.append("**No `Timestamp` column found.** Sliding windows are impossible without it.\n")
        problems.append("No Timestamp column - sliding windows cannot be built from this file.")

    # ---------------- Network fields ----------------
    print("[7/8] Source/Destination IP, ports, protocol ...")
    L.append("### 9. Network fields\n")
    for key, title in (("src_ip", "Source IP"), ("dst_ip", "Destination IP")):
        L.append(f"#### {title}\n")
        c = col[key]
        if not c:
            L.append(f"**Column not found.** Event grouping by IP is impossible.\n")
            problems.append(f"{title} column missing - this looks like the 'MachineLearningCVE' version, "
                            "which has no IPs/timestamps. We need the 'TrafficLabelling' version.")
            continue
        counts = df[c].astype("string").str.strip().value_counts(dropna=False)
        valid, invalid, priv, pub, bad = classify_ips(counts)
        L.append(f"Unique values: **{len(counts):,}**  |  valid IPv4/IPv6: {valid:,}  |  invalid/missing: {invalid:,}"
                 + (f" (examples: {bad})" if bad else "") + f"  |  private-range rows: {priv:,}  |  public rows: {pub:,}\n")
        L.append(top_table(df[c], value_header=title))
        L.append("")
        if invalid:
            problems.append(f"{invalid:,} rows have an invalid {title}.")

    for key, title in (("src_port", "Source Port"), ("dst_port", "Destination Port")):
        L.append(f"#### {title}\n")
        c = col[key]
        if not c:
            L.append("**Column not found.**\n")
            continue
        nump = pd.to_numeric(df[c], errors="coerce")
        non_num = int(nump.isna().sum())
        out_rng = int(((nump < 0) | (nump > 65535)).sum())
        L.append(f"Unique: **{nump.nunique():,}**  |  min {nump.min()}  |  max {nump.max()}  |  "
                 f"non-numeric/missing: {non_num:,}  |  outside 0-65535: {out_rng:,}\n")
        L.append(top_table(nump, names=PORT_NAMES, value_header=title))
        L.append("")
        if non_num or out_rng:
            problems.append(f"{title}: {non_num:,} non-numeric and {out_rng:,} out-of-range values.")

    L.append("#### Protocol\n")
    if col["protocol"]:
        pr = pd.to_numeric(df[col["protocol"]], errors="coerce")
        L.append(f"Unique protocol numbers: **{pr.nunique()}**  |  non-numeric/missing: {int(pr.isna().sum()):,}\n")
        L.append(top_table(pr, n=20, names=PROTOCOL_NAMES, value_header="Protocol number"))
        L.append("")
    else:
        L.append("**Column not found.**\n")

    # ---------------- Per-attack view ----------------
    if attack_labels and labels_norm is not None:
        L.append("### 10. What each attack label looks like (helps design events in Phase 3)\n")
        for lab in attack_labels:
            sub = df[labels_norm == lab]
            L.append(f"#### {lab} ({len(sub):,} rows)\n")
            for key, title, names in (("src_ip", "Top Source IPs", None), ("dst_ip", "Top Destination IPs", None),
                                      ("dst_port", "Top Destination Ports", PORT_NAMES),
                                      ("protocol", "Protocols", PROTOCOL_NAMES)):
                if col[key]:
                    series = pd.to_numeric(sub[col[key]], errors="coerce") if names else sub[col[key]]
                    L.append(f"**{title}**\n")
                    L.append(top_table(series, n=5, names=names, total=len(sub), value_header="Value"))
                    L.append("")

    # ---------------- Feature quality ----------------
    print("[8/8] Constant columns, negatives, final checks ...")
    L.append("### 11. Numeric feature quality\n")
    const = [c for c in norm_cols if df[c].nunique(dropna=False) <= 1]
    L.append(f"**Constant columns (carry no information):** {', '.join(const) if const else 'none'}\n")
    neg_rows = []
    for c in num_cols:
        n_neg = int((df[c] < 0).sum())
        if n_neg:
            neg_rows.append([c, f"{n_neg:,}", pct(n_neg, n_rows), df[c].min()])
    if neg_rows:
        L.append("Columns containing negative values (some are legitimate, e.g. a flag value of -1):\n")
        L.append(md_table(["Column", "Negative cells", "Share", "Minimum"], neg_rows))
        L.append("")
    else:
        L.append("No negative values in numeric columns.\n")

    # ---------------- Auto-detected problems ----------------
    if changed:
        problems.append(f"{len(changed)} column names have leading/trailing/extra spaces (fixed in memory only).")
    mangled = [c for c in norm_cols if re.search(r"\.\d+$", c) and re.sub(r"\.\d+$", "", c) in norm_cols]
    if mangled:
        problems.append("Duplicate column names were auto-renamed by pandas: " + ", ".join(mangled) + ".")
    if n_inf_rows:
        problems.append(f"{n_inf_rows:,} rows contain infinite values (columns: {', '.join(r[0] for r in inf_info)}).")
    if rows_with_missing:
        problems.append(f"{rows_with_missing:,} rows contain missing values (columns: {', '.join(cols_with_missing)}).")
    if n_dup:
        problems.append(f"{n_dup:,} fully duplicated rows.")
    if unexpected and any(u[1] != "0" for u in unexpected):
        problems.append("Some numeric columns contain text values (see section 5).")
    if const:
        problems.append(f"{len(const)} constant column(s) carry no information: {', '.join(const)}.")
    if neg_rows:
        problems.append(f"{len(neg_rows)} numeric column(s) contain negative values (need case-by-case review).")

    L.append("### 12. Potential problems found automatically\n")
    if problems:
        for p in problems:
            L.append(f"- {p}")
    else:
        L.append("- none detected")
    L.append("")

    # ---------------- Proof raw file untouched ----------------
    hash_after = sha256_of(path)
    ok = hash_after == hash_before
    L.append("### 13. Raw file integrity check\n")
    L.append(f"SHA-256 after inspection: `{hash_after}`  ->  **{'UNCHANGED' if ok else 'CHANGED (!)'}**\n")

    summary.update(rows=n_rows, cols=n_cols, duplicates=n_dup, inf_rows=n_inf_rows,
                   missing_rows=rows_with_missing, problems=len(problems),
                   untouched=ok, seconds=time.time() - t0)
    return L, summary


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Phase 1: inspect raw CICIDS2017 CSV file(s).")
    ap.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR, help="folder with the raw CSVs")
    ap.add_argument("--file", type=str, default=None, help="inspect only this file name inside raw-dir")
    ap.add_argument("--report", type=Path, default=DEFAULT_REPORT, help="where to write the Markdown report")
    args = ap.parse_args()

    if not args.raw_dir.exists():
        raise SystemExit(f"Folder not found: {args.raw_dir}\nCreate it and put the CSV inside.")
    files = [args.raw_dir / args.file] if args.file else sorted(args.raw_dir.glob("*.csv"))
    files = [f for f in files if f.exists()]
    if not files:
        raise SystemExit(f"No .csv files found in {args.raw_dir}\n"
                         "Copy Tuesday-WorkingHours.pcap_ISCX.csv into that folder and run again.")

    report = ["# Dataset Report - CICIDS2017\n",
              f"*Generated automatically by `inspect_dataset.py` on {datetime.now():%Y-%m-%d %H:%M:%S}.*  ",
              "*All values below were calculated from the raw file(s); none were typed in by hand.*\n",
              "## Files used\n"]
    report += [f"- `{f.name}`" for f in files]
    report.append("")

    all_summaries = []
    for f in files:
        lines, summ = inspect_file(f)
        report += lines
        all_summaries.append((f.name, summ))

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text("\n".join(report), encoding="utf-8")

    print("\n" + "=" * 60)
    for name, s in all_summaries:
        print(f"FILE: {name}")
        print(f"  rows / columns        : {s['rows']:,} / {s['cols']}")
        print(f"  label counts          : {s.get('labels')}")
        print(f"  time range            : {s.get('time_range', 'n/a')}")
        print(f"  duplicate rows        : {s['duplicates']:,}")
        print(f"  rows with +/-inf      : {s['inf_rows']:,}")
        print(f"  rows with missing     : {s['missing_rows']:,}")
        print(f"  problems flagged      : {s['problems']}")
        print(f"  raw file untouched    : {s['untouched']}")
        print(f"  time taken            : {s['seconds']:.1f} s")
    print("=" * 60)
    print(f"Report written to: {args.report}")


if __name__ == "__main__":
    main()
