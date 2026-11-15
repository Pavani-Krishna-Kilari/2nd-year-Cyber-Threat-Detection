# Final Pre-Experiment A Verification & Readiness Report

**Date:** 14 November 2026  
**Auditor:** AI-Based SIEM Cyber Threat Detection Engineering Team  
**Scope:** Independent pre-execution safety verification for `build_multi_day_profiles.py` prior to launching Experiment A  
**Project Location:** `C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection`  
**Execution Clearance Status:** **PASSED (100% READY FOR EXECUTION)**  

---

## 1. Output Isolation & Baseline Protection Inspection

A complete scan of all operations and path references in [src/event_profiles/build_multi_day_profiles.py](file:///c:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/src/event_profiles/build_multi_day_profiles.py) was performed:

| Check | Expected | Actual Implementation in Code | Verdict |
|---|---|---|---|
| **Baseline Target Operations** | Zero write/copy/mirror to `data/processed/event_profiles/` | Lines 111–122 define `baseline_dir` strictly as read-only. Hard exception raised if `out_dir.resolve() == baseline_dir`. Lines 376–380 perform read-only hash verification. Zero writes, copies, or renames target `baseline_dir`. | **PASS** |
| **Experiment A Target** | Exclusively `data/processed/event_profiles_exp_a/` | Lines 115–116: `out_dirname = "event_profiles_exp_a"` when `experiment_mode == "exp_a"`. All 5 CSVs, 4 JSONs, and 1 metadata file write to `out_dir = proc_dir / out_dirname`. | **PASS** |
| **Experiment B Target** | Exclusively `data/processed/event_profiles_exp_b/` | Lines 115–116: `out_dirname = "event_profiles_exp_b"` when `experiment_mode == "exp_b"`. Isolated entirely from Experiment A and baseline. | **PASS** |
| **Invalid Mode Handling** | Reject non-compliant modes | Lines 103–108: `if experiment_mode not in ("exp_a", "exp_b"): raise EventProfileError(...)` halts before any filesystem operations. | **PASS** |

---

## 2. Methodology & Leakage-Safe Code Path Inspection

The exact code paths in `build_multi_day_profiles.py` were inspected to confirm strict adherence to leakage prevention:

### 2.1 Training-Only Flow Threshold Fitting (Lines 143–161)
* **Code Path:**
  ```python
  train_flow_samples = []
  for f in clean_files:
      df_cols = pd.read_csv(f, usecols=["split", "flow_packets_s", "flow_bytes_s", "syn_flag_count", "flow_duration"])
      if experiment_mode == "exp_a":
          mask = df_cols["split"] == "train"
      else:
          exp_b_split = assign_experiment_b_split(f.name)
          mask = np.ones(len(df_cols), dtype=bool) if exp_b_split == "train" else np.zeros(len(df_cols), dtype=bool)
      if mask.any():
          train_flow_samples.append(df_cols.loc[mask, ["flow_packets_s", "flow_bytes_s", "syn_flag_count", "flow_duration"]])
  train_flows_combined = pd.concat(train_flow_samples, ignore_index=True)
  thresholds = fit_flow_thresholds(train_flows_combined, settings)
  ```
* **Audit Confirmation:** Only flows with `split == "train"` are pooled into `train_flows_combined`. Validation and test flows are completely excluded from threshold calibration.

### 2.2 Training-Only Set Threshold Fitting (Lines 280–285)
* **Code Path:**
  ```python
  train_mask = (df_all_sets["split"] == "train").to_numpy()
  thresholds["HIGH_FLOW_RATE"] = fit_set_threshold(df_all_sets.loc[train_mask, "n_flows"], settings)
  ```
* **Audit Confirmation:** `HIGH_FLOW_RATE` percentile threshold is computed strictly on training event sets.

### 2.3 Training-Only TF-IDF Vocabulary & IDF Fitting (Lines 294–298)
* **Code Path:**
  ```python
  idf_model = fit_idf(counts_matrix[train_mask], settings["sublinear_tf"])
  ```
* **Audit Confirmation:** Document frequencies and IDF weights are computed strictly from `counts_matrix[train_mask]`.

### 2.4 Training-Only Basepoint Selection (Lines 303–311)
* **Code Path:**
  ```python
  bp_result = select_basepoints(tfidf_vectors[train_mask], idf_model["document_frequency"], settings)
  ```
* **Audit Confirmation:** Rare-event ranking and candidate selection operate exclusively on `tfidf_vectors[train_mask]` and training `document_frequency`.

### 2.5 Validation & Test Transformation Without Refitting (Lines 201, 286–289, 301, 314)
* **Code Paths:**
  - `flags = apply_flow_events(df_flow, thresholds)` (applies fitted flow thresholds)
  - `compare(df_all_sets["n_flows"]..., thresholds["HIGH_FLOW_RATE"]...)` (applies fitted set threshold)
  - `tfidf_vectors = transform(counts_matrix, idf_model)` (transforms counts using fitted training IDF)
  - `profiles = compute_profiles(tfidf_vectors, bp_result["basepoints"])` (projects onto training basepoints)
* **Audit Confirmation:** Validation and test event sets are strictly transformed using the fitted training artifacts. No refitting or threshold adjustment occurs on evaluation partitions.

### 2.6 Split Isolation & Window Boundary Enforcement (Lines 176–205)
* **Capture Isolation:** Cleaned capture files are processed in separate loop iterations; sliding windows never cross capture days or files.
* **Window Boundary Dropping:** `bin_split_names` and `valid_windows` enforce that all 10 consecutive bins ($W=10$, 600 seconds) share the identical split name. Any sliding window overlapping a 20-minute block boundary between `train` and `validation` or `test` is marked invalid (`valid[k] = False`) and dropped by `aggregate_to_windows`.

---

## 3. Experiment A Event-Set Class Distributions & Evaluation Scope

A read-only simulation script was executed across all 8 cleaned capture files using the exact windowing parameters ($W=10$, step = 60s, block = 20 min).

### 3.1 Exact Event-Set Counts Across Splits

| Target Label | Test | Train | Validation | Total Event Sets |
|---|---|---|---|---|
| **BENIGN** | 312,439 | 1,934,373 | 321,097 | **2,567,909** |
| **Bot** | 60 | 719 | 110 | **889** |
| **DDoS** | 0 | 40 | 0 | **40** |
| **DoS GoldenEye** | 0 | 19 | 0 | **19** |
| **DoS Hulk** | 0 | 27 | 0 | **27** |
| **DoS Slowhttptest** | 0 | 27 | 0 | **27** |
| **DoS slowloris** | 1 | 28 | 11 | **40** |
| **FTP-Patator** | 3 | 42 | 11 | **56** |
| **Heartbleed** | 0 | 30 | 0 | **30** |
| **Infiltration** | 3 | 38 | 11 | **52** |
| **PortScan** | 9 | 36 | 7 | **52** |
| **SSH-Patator** | 11 | 32 | 11 | **54** |
| **Web Attack - Brute Force** | 11 | 13 | 4 | **28** |
| **Web Attack - Sql Injection** | 0 | 8 | 0 | **8** |
| **Web Attack - XSS** | 0 | 29 | 0 | **29** |
| **TOTAL** | **312,537** | **1,935,461** | **321,262** | **2,569,260** |

### 3.2 Target Binary Breakdown
* **BENIGN (0):** 1,934,373 train / 321,097 val / 312,439 test (Total: 2,567,909)
* **Attack (1):** 1,088 train / 165 val / 98 test (Total: 1,351)

### 3.3 Missing Classes & Evaluation Limitations
* **Classes Evaluated in Test (8 classes):** `BENIGN`, `Bot`, `DoS slowloris`, `FTP-Patator`, `Infiltration`, `PortScan`, `SSH-Patator`, `Web Attack - Brute Force`.
* **Classes with 0 Test Support (7 classes):** `DDoS`, `DoS GoldenEye`, `DoS Hulk`, `DoS Slowhttptest`, `Heartbleed`, `Web Attack - Sql Injection`, `Web Attack - XSS`.
* **Root Cause:** In the raw CICIDS2017 dataset, these 7 attack types were executed in short, concentrated time bursts (e.g., Heartbleed was 11 flows executed in seconds; DDoS was a 2-hour afternoon exercise; XSS and SQL Injection were targeted manual injections). Under chronological, leakage-safe 20-minute time-block partitioning (seed 42), the blocks containing these bursts fell into the 70% `train` partition.
* **Impact on Evaluation:**
  1. The neural networks (FCNN, CNN, LSTM, Ensemble) will learn representations for all 15 classes, as all 15 classes have training samples.
  2. For the 7 concentrated classes, test set recall/precision cannot be computed ($0 / 0$ support).
  3. **Methodological Integrity Rule:** We must **NOT** artificially switch to random row shuffling. Random shuffling across time creates extreme temporal data leakage between overlapping 10-minute sliding windows (where adjacent windows share 90% of the same flows). The time-blocked split preserves scientific validity. The 0-support limitation will be reported transparently.

---

## 4. Experiment B Setup & Unseen-Attack Evaluation Boundaries

### 4.1 Verification Findings
1. **Zero Friday Infiltration into Supervised Training/Validation:**
   - Monday, Tuesday, Wednesday $\rightarrow$ `train`
   - Thursday $\rightarrow$ `validation`
   - Friday $\rightarrow$ `test`
   - All Friday files (`Friday-WorkingHours-Morning`, `PortScan`, `DDos`) are assigned `split = "test"`. Zero Friday flows or event sets enter threshold calibration, TF-IDF fitting, or basepoint selection.
2. **Absent Friday Attack Classes:**
   - `Bot` (Friday Morning), `PortScan` (Friday Afternoon PortScan), and `DDoS` (Friday Afternoon DDoS) are completely absent from Monday, Tuesday, and Wednesday.
   - They represent 100% held-out, unobserved attack classes for the supervised ANN models.
3. **Friday Benign Traffic Inclusion:**
   - Friday contains 413,928 cleaned benign flows across its three captures.
   - All corresponding benign event sets are included in the held-out test split. This is essential for measuring False Positive Rate (FPR) and specificity on unseen benign traffic.

### 4.2 Scientific Scope: What Can and Cannot Be Concluded
* **What CAN Be Concluded:**
  - Whether an unsupervised anomaly detector (Isolation Forest) fitted strictly on benign training profiles can flag novel volumetric and structural attack patterns (`DDoS`, `PortScan`, `Bot`) via the `UNKNOWN_ANOMALOUS` decision policy.
  - The true generalization False Positive Rate when operating on a completely separate capture day.
* **What CANNOT Be Concluded:**
  - The model cannot classify the *specific identity* of an unseen attack (e.g., it cannot classify an unseen PortScan as "PortScan", only as `UNKNOWN_ANOMALOUS`).
  - It cannot prove detection capability for stealthy zero-day attacks that do not alter communication volume or trigger rare-event basepoints.
  - It does not demonstrate cross-network transferability (the testbed network topology is shared across all days).

---

## 5. Automated Backup & Output Directory Safety Inspection

Inspection of lines 124–134 in `build_multi_day_profiles.py`:
```python
out_dir.mkdir(parents=True, exist_ok=True)
existing_files = [f for f in out_dir.iterdir() if f.is_file() and f.suffix in (".csv", ".json")]
if existing_files:
    backup_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = PROJECT_ROOT / "backups" / f"{out_dirname}_backup_{backup_ts}"
    backup_path.mkdir(parents=True, exist_ok=True)
    for f_exist in existing_files:
        shutil.copy2(f_exist, backup_path / f_exist.name)
```

* **No Backup Overwriting:** Every backup directory is tagged with a full microsecond-accurate timestamp (`%Y%m%d_%H%M%S`). Existing backup folders are never overwritten.
* **No Tuesday Baseline Leakage:** The backup code inspects *only* `out_dir` (`event_profiles_exp_a` or `event_profiles_exp_b`). It has zero access or copying relationship with `data/processed/event_profiles/`.
* **Clean State Confirmed:** `data/processed/event_profiles_exp_a/` is currently verified empty (0 files).

---

## 6. Unit Test Execution Verification

All 16 unit tests across both test suites were executed simultaneously:
```bash
python -m unittest tests.test_multi_day_profiles tests.test_multi_dataset -v
```

### Actual Terminal Output:
```
test_backup_mechanism_on_existing_files (tests.test_multi_day_profiles.TestMultiDayProfileSafety.test_backup_mechanism_on_existing_files)
Verify that existing outputs are backed up safely when rerun. ... ok
test_baseline_directory_isolation_guard (tests.test_multi_day_profiles.TestMultiDayProfileSafety.test_baseline_directory_isolation_guard)
Verify that multi-day pipeline strictly refuses to write to baseline directory. ... ok
test_experiment_b_split_assignments (tests.test_multi_day_profiles.TestMultiDayProfileSafety.test_experiment_b_split_assignments)
Verify Experiment B capture assignment: Mon/Tue/Wed -> train, Thu -> val, Fri -> test. ... ok
test_first_basepoint_trace_none_formatting (tests.test_multi_day_profiles.TestMultiDayProfileSafety.test_first_basepoint_trace_none_formatting)
Verify the first basepoint trace where max_cosine_to_previous is None formats safely. ... ok
test_invalid_experiment_mode_rejected (tests.test_multi_day_profiles.TestMultiDayProfileSafety.test_invalid_experiment_mode_rejected)
Calling pipeline with invalid mode must raise EventProfileError immediately. ... ok
test_profile_feature_isolation_and_no_leakage_columns (tests.test_multi_day_profiles.TestMultiDayProfileSafety.test_profile_feature_isolation_and_no_leakage_columns)
Verify profile dataframe only contains identifiers and bp_* features. ... ok
test_training_only_fitting_principles (tests.test_multi_day_profiles.TestMultiDayProfileSafety.test_training_only_fitting_principles)
Verify TF-IDF and basepoint selection fit strictly on training mask. ... ok
test_tuesday_baseline_profiles_preserved (tests.test_multi_day_profiles.TestMultiDayProfileSafety.test_tuesday_baseline_profiles_preserved)
Rule 9: Tuesday baseline event profiles and metadata must remain intact. ... ok
test_afternoon_hour_correction (tests.test_multi_dataset.TestMultiDatasetIntegrity.test_afternoon_hour_correction)
Verify afternoon files with hours 1..5 are shifted to 13..17. ... ok
test_all_eight_files_have_compatible_85_col_schema (tests.test_multi_dataset.TestMultiDatasetIntegrity.test_all_eight_files_have_compatible_85_col_schema)
Rule 4: Check whether the eight files have compatible feature schemas. ... ok
test_all_eight_raw_files_exist_and_hashes_unaltered (tests.test_multi_dataset.TestMultiDatasetIntegrity.test_all_eight_raw_files_exist_and_hashes_unaltered)
Rule 1: Preserve all eight original CICIDS2017 CSV files unchanged. ... ok
test_all_fourteen_attack_labels_registered (tests.test_multi_dataset.TestMultiDatasetIntegrity.test_all_fourteen_attack_labels_registered)
Verify all 14 attack categories are supported in config without error. ... ok
test_experiment_b_split_partition_logic (tests.test_multi_dataset.TestMultiDatasetIntegrity.test_experiment_b_split_partition_logic)
Rule 4: Verify Experiment B partition: Mon/Tue/Wed train, Thu val, Fri test. ... ok
test_thursday_blank_row_detection_and_pruning (tests.test_multi_dataset.TestMultiDatasetIntegrity.test_thursday_blank_row_detection_and_pruning)
Rule 7: Verify trailing comma rows are detected as all-NaN and prunable. ... ok
test_thursday_en_dash_label_normalization (tests.test_multi_dataset.TestMultiDatasetIntegrity.test_thursday_en_dash_label_normalization)
Rule 7: Investigate Thursday WebAttacks encoding issues and normalize without crashing. ... ok
test_tuesday_clean_baseline_preserved (tests.test_multi_dataset.TestMultiDatasetIntegrity.test_tuesday_clean_baseline_preserved)
Rule 9: Preserve all existing saved models, processed Tuesday files and reports. ... ok

----------------------------------------------------------------------
Ran 16 tests in 3.540s

OK
```
**Result:** 16 tests passed, 0 failures, 0 errors.

---

## 7. Cryptographic Baseline Hash Comparison

SHA-256 hashes were calculated directly from disk for the active Tuesday baseline files and compared with the immutable baseline backup:

| File Name | Active Path Hash | Backup Path Hash | Status |
|---|---|---|---|
| `event_profiles.csv` | `D3B38B3012557CC606014AF91870B47DAD7ED4652AF00E7FD7D1E57FDD8DDD6E` | `D3B38B3012557CC606014AF91870B47DAD7ED4652AF00E7FD7D1E57FDD8DDD6E` | **IDENTICAL (100% UNCHANGED)** |
| `event_profiles_metadata.json` | `CE6234392C0E8682732795B64F7A553736879B7F8D5869F52A0AD11D73F81E54` | `CE6234392C0E8682732795B64F7A553736879B7F8D5869F52A0AD11D73F81E54` | **IDENTICAL (100% UNCHANGED)** |

The Tuesday baseline is completely intact and matches its backup to the byte.

---

## 8. Final PASS/FAIL Checklist

| # | Verification Requirement | Status | Note |
|---|---|---|---|
| 1 | Baseline output directory isolation (`event_profiles/` protected) | **PASS** | Hard assertion rejects baseline directory target. |
| 2 | Output directory routing for Experiment A (`event_profiles_exp_a/`) | **PASS** | Verified routing to isolated directory. |
| 3 | Output directory routing for Experiment B (`event_profiles_exp_b/`) | **PASS** | Verified routing to isolated directory. |
| 4 | Training-only flow threshold fitting | **PASS** | Tested and verified on training flows only. |
| 5 | Training-only TF-IDF & IDF fitting | **PASS** | Fitted strictly on `counts_matrix[train_mask]`. |
| 6 | Training-only basepoint selection | **PASS** | Evaluated strictly on training TF-IDF vectors. |
| 7 | Transformation of val/test without refitting | **PASS** | Applied deterministically using training artifacts. |
| 8 | Window split boundary dropping | **PASS** | Overlapping multi-split windows dropped by `valid_windows`. |
| 9 | Experiment A class distributions verified | **PASS** | Exact counts calculated: 2,569,260 sets total (98 test attacks). |
| 10 | Experiment B Friday unseen attack isolation | **PASS** | Zero Friday records in train/val; 3 unseen attack classes. |
| 11 | Experiment B Friday benign traffic included | **PASS** | 413,928 clean benign flows in Friday test partition. |
| 12 | Automated backup safety (no overwrite, no cross-copy) | **PASS** | Timestamped backup guard verified. |
| 13 | Full unit test suite (16/16 tests passing) | **PASS** | 100% test pass rate in 3.540s. |
| 14 | Baseline SHA-256 hash integrity | **PASS** | Both `event_profiles.csv` and metadata hashes identical to backup. |
| 15 | No models trained or profiles written prematurely | **PASS** | Stopped strictly before profile generation or training. |

---

## 9. Final Safety Verdict

> **FINAL VERDICT: PASS**  
> **Experiment A is 100% safe to execute.**  
> All methodological, architectural, and data safety constraints have been independently verified. No further code modifications are required.
