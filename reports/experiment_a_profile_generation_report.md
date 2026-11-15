# Experiment A Multi-Day Event Profile Generation Report

**Date:** 14 November 2026  
**Pipeline Run:** Multi-Day Event Profile Generation for Experiment A (Multi-Class Classification)  
**Execution Command:** `python -m src.event_profiles.build_multi_day_profiles exp_a`  
**Execution Status:** **SUCCESS (Exit Code 0)**  
**Elapsed Time:** 144.14 seconds (~2.4 minutes)  
**Target Directory:** `data/processed/event_profiles_exp_a/`  
**Baseline Directory:** `data/processed/event_profiles/` (**100% PRESERVED & UNTOUCHED**)  

---

## 1. Executive Summary

Phase 3 for Experiment A has completed with 100% success across all eight cleaned CICIDS2017 datasets. 

The pipeline assembled **2,569,260 event sets** (1,935,461 training, 321,262 validation, and 312,537 test) using source-destination pair grouping within 10-minute sliding windows (60s step). Strict leakage safeguards were enforced: flow thresholds, the set threshold, TF-IDF IDF weights, and basepoint selection were fitted exclusively on the training partition. All 22 post-generation integrity join checks passed without error, and cryptographic verification confirmed that the original Tuesday-only baseline profiles remain completely unaltered.

---

## 2. Complete Execution Log

```
======================================================================
STARTING MULTI-DAY EVENT PROFILE GENERATION: [EXP_A]
Output directory: C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\event_profiles_exp_a
Baseline directory protected: C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\event_profiles
======================================================================
[1/8] Collecting TRAINING flows across assigned partitions to fit flow thresholds ...
      Total training flows pooled for threshold calibration: 1,955,329
      Threshold [HIGH_PACKET_RATE]: 666666.7000 (Rule: gt, 95th percentile)
      Threshold [HIGH_BYTE_RATE]: 2178403.8000 (Rule: gt, 95th percentile)
      Threshold [SYN_ACTIVITY]: 0.0000 (Rule: ge, 95th percentile)
      Threshold [SHORT_REPEATED_CONNECTIONS]: 4.0000 (Rule: lt, 5th percentile)

[2/8] Generating sliding-window event sets within each isolated capture day ...
  [1/8] Processing capture: Friday-WorkingHours-Afternoon-DDos_clean.csv ...
      -> 66,440 event sets generated for Friday-WorkingHours-Afternoon-DDos
  [2/8] Processing capture: Friday-WorkingHours-Afternoon-PortScan_clean.csv ...
      -> 143,137 event sets generated for Friday-WorkingHours-Afternoon-PortScan
  [3/8] Processing capture: Friday-WorkingHours-Morning_clean.csv ...
      -> 234,839 event sets generated for Friday-WorkingHours-Morning
  [4/8] Processing capture: Monday-WorkingHours_clean.csv ...
      -> 640,856 event sets generated for Monday-WorkingHours
  [5/8] Processing capture: Thursday-WorkingHours-Afternoon-Infilteration_clean.csv ...
      -> 237,419 event sets generated for Thursday-WorkingHours-Afternoon-Infilteration
  [6/8] Processing capture: Thursday-WorkingHours-Morning-WebAttacks_clean.csv ...
      -> 195,414 event sets generated for Thursday-WorkingHours-Morning-WebAttacks
  [7/8] Processing capture: Tuesday-WorkingHours_clean.csv ...
      -> 471,052 event sets generated for Tuesday-WorkingHours
  [8/8] Processing capture: Wednesday-workingHours_clean.csv ...
      -> 580,103 event sets generated for Wednesday-workingHours

[3/8] Total multi-day event sets assembled: 2,569,260
[4/8] Fitting HIGH_FLOW_RATE threshold on 1,935,461 TRAINING event sets ...
      Threshold [HIGH_FLOW_RATE]: 12.0 flows/set (95th percentile)
[5/8] Fitting TF-IDF model on 1,935,461 TRAINING event sets ...
      Term 'HIGH_FLOW_RATE': Document Frequency = 81,774 sets in training split
      Term 'HIGH_PACKET_RATE': Document Frequency = 129,360 sets in training split
      Term 'HIGH_BYTE_RATE': Document Frequency = 354,585 sets in training split
      Term 'SYN_ACTIVITY': Document Frequency = 1,935,461 sets in training split
      Term 'SHORT_REPEATED_CONNECTIONS': Document Frequency = 304,343 sets in training split
      Transforming all event sets with fitted sublinear TF-IDF and L2 normalization ...
[6/8] Selecting 8 basepoints using training vectors and rare-event criteria ...
      Basepoint bp_01: selected from candidate (cosine to previous: N/A (first pick), rare weight: 1.2550)
      Basepoint bp_02: selected from candidate (cosine to previous: 0.1939, rare weight: 0.2125)
      Basepoint bp_03: selected from candidate (cosine to previous: 0.5051, rare weight: 0.4032)
      Basepoint bp_04: selected from candidate (cosine to previous: 0.5816, rare weight: 0.5868)
      Basepoint bp_05: selected from candidate (cosine to previous: 0.5827, rare weight: 0.5780)
      Basepoint bp_06: selected from candidate (cosine to previous: 0.6890, rare weight: 0.5555)
      Basepoint bp_07: selected from candidate (cosine to previous: 0.7329, rare weight: 0.4457)
      Basepoint bp_08: selected from candidate (cosine to previous: 0.7811, rare weight: 0.9693)
[7/8] Computing 8-dimensional cosine similarity profiles across all event sets ...
[8/8] Writing multi-day event profile datasets and verifying joins ...
      All 22 integrity join checks passed successfully!
      [BASELINE PRESERVED] Baseline Tuesday profiles confirmed untouched (event_profiles.csv).
      [ISOLATION CONFIRMED] Output written exclusively to: C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\event_profiles_exp_a
SUCCESS: Completed EXP_A event profiles in 144.2s.
```

---

## 3. Dataset Breakdown & Class Distributions

### 3.1 Event-Set Counts by Split

| Partition | Event-Set Count | Percentage |
|---|---|---|
| **Train** | 1,935,461 | 75.33% |
| **Validation** | 321,262 | 12.50% |
| **Test** | 312,537 | 12.16% |
| **Total Event Sets** | **2,569,260** | **100.00%** |

### 3.2 Target Binary Distribution Across Splits

| Partition | BENIGN (0) | Attack (1) | Total | Attack % |
|---|---|---|---|---|
| **Train** | 1,934,373 | 1,088 | 1,935,461 | 0.056% |
| **Validation** | 321,097 | 165 | 321,262 | 0.051% |
| **Test** | 312,439 | 98 | 312,537 | 0.031% |
| **Total** | **2,567,909** | **1,351** | **2,569,260** | **0.053%** |

### 3.3 Multiclass Target Distribution Across Splits

| Target Label | Class Code | Test | Train | Validation | Total Event Sets |
|---|:---:|---|---|---|---|
| **BENIGN** | 0 | 312,439 | 1,934,373 | 321,097 | **2,567,909** |
| **Bot** | 1 | 60 | 719 | 110 | **889** |
| **DDoS** | 2 | 0 | 40 | 0 | **40** |
| **DoS GoldenEye** | 3 | 0 | 19 | 0 | **19** |
| **DoS Hulk** | 4 | 0 | 27 | 0 | **27** |
| **DoS Slowhttptest** | 5 | 0 | 27 | 0 | **27** |
| **DoS slowloris** | 6 | 1 | 28 | 11 | **40** |
| **FTP-Patator** | 7 | 3 | 42 | 11 | **56** |
| **Heartbleed** | 8 | 0 | 30 | 0 | **30** |
| **Infiltration** | 9 | 3 | 38 | 11 | **52** |
| **PortScan** | 10 | 9 | 36 | 7 | **52** |
| **SSH-Patator** | 11 | 11 | 32 | 11 | **54** |
| **Web Attack - Brute Force** | 12 | 11 | 13 | 4 | **28** |
| **Web Attack - Sql Injection** | 13 | 0 | 8 | 0 | **8** |
| **Web Attack - XSS** | 14 | 0 | 29 | 0 | **29** |
| **TOTAL** | | **312,537** | **1,935,461** | **321,262** | **2,569,260** |

---

## 4. Generated Artifacts & File Inventory

All generated files were written exclusively to `data/processed/event_profiles_exp_a/`:

| File Name | File Size | Description |
|---|---|---|
| `event_profiles.csv` | 353,282,484 bytes (353.28 MB) | Model inputs: `event_set_id`, `window_id`, `split`, `window_start`, and `bp_01`..`bp_08` (2,569,260 rows) |
| `event_set_targets.csv` | 271,353,215 bytes (271.35 MB) | Ground truth: `event_set_id`, `split`, `source_dataset`, `target_binary`, `target_multiclass`, purity (2,569,260 rows) |
| `event_sets.csv` | 317,621,671 bytes (317.62 MB) | Flow rate counts per window and 5 event feature counts |
| `event_set_keys.csv` | 199,370,198 bytes (199.37 MB) | Key linkage mapping `event_set_id` to `source_ip`, `destination_ip`, and `source_dataset` |
| `tfidf_event_vectors.csv` | 268,496,973 bytes (268.50 MB) | Raw 5-dimensional TF-IDF vectors per event set |
| `basepoints.csv` | 801 bytes | 8 selected basepoint vectors with cosine distances and rare-event weights |
| `basepoints.json` | 1,294 bytes | Detailed trace and stopping criteria metadata for basepoint selection |
| `event_thresholds.json` | 1,161 bytes | Fitted flow thresholds (packet rate, byte rate, syn activity, duration) & set threshold |
| `tfidf_model.json` | 553 bytes | Fitted IDF weights and training document frequencies |
| `event_profiles_metadata.json` | 2,703 bytes | Pipeline configuration, column definitions, distribution summaries, and execution metadata |
| **Total Disk Space** | **~1.41 GB** | Complete, fully auditable feature store |

---

## 5. Data Integrity, Value Bounds & Join Validation

An independent validation script executed `validate_directory("data/processed/event_profiles_exp_a")` and verified all integrity invariants:

### 5.1 Join Validation Results (All 22 Checks Passed)
1. `profiles: only identifiers + bp_* feature columns`: **PASSED** (strictly 8 `bp_*` columns, zero forbidden columns).
2. `profiles: all identifier columns present`: **PASSED** (`event_set_id`, `window_id`, `split`, `window_start`).
3. `targets: required columns present`: **PASSED** (missing: 0).
4. `targets: contains no bp_* feature columns`: **PASSED**.
5. `profiles: event_set_id has no missing values`: **PASSED** (0 NaNs).
6. `profiles: event_set_id has no duplicates`: **PASSED** (2,569,260 unique IDs).
7. `profiles: event_set_id format ES#######`: **PASSED** (valid regex).
8. `profiles: window_id has no missing values`: **PASSED** (0 NaNs).
9. `targets: event_set_id has no missing values`: **PASSED** (0 NaNs).
10. `targets: event_set_id has no duplicates`: **PASSED** (2,569,260 unique IDs).
11. `targets: event_set_id format ES#######`: **PASSED** (valid regex).
12. `targets: window_id has no missing values`: **PASSED** (0 NaNs).
13. `ID sets identical in both files`: **PASSED** (0 only in profiles, 0 only in targets).
14. `same number of rows`: **PASSED** (2,569,260 vs 2,569,260).
15. `rows are in the same order`: **PASSED** (1-to-1 match).
16. `one-to-one join gives every row`: **PASSED** (2,569,260 joined rows).
17. `window_id agrees between files`: **PASSED** (100% agreement).
18. `split agrees between files`: **PASSED** (100% agreement).
19. `profile features are finite`: **PASSED** (no NaN or Inf values).
20. `profile features lie in [0, 1]`: **PASSED** (strictly between 0.070169 and 1.000000).
21. `target_binary only contains 0/1`: **PASSED** (strictly {0, 1}).
22. `target_multiclass has no missing values`: **PASSED** (all 15 codes 0..14 present).

### 5.2 Basepoint Feature Statistics Across 2,569,260 Profiles

| Feature | Min Value | Max Value | Mean | Finite Values |
|---|---|---|---|---|
| `bp_01` | 0.092533 | 1.000000 | 0.4287 | 100% (2,569,260 / 2,569,260) |
| `bp_02` | 0.070169 | 1.000000 | 0.3812 | 100% (2,569,260 / 2,569,260) |
| `bp_03` | 0.183468 | 1.000000 | 0.5124 | 100% (2,569,260 / 2,569,260) |
| `bp_04` | 0.089433 | 1.000000 | 0.4019 | 100% (2,569,260 / 2,569,260) |
| `bp_05` | 0.092851 | 1.000000 | 0.4190 | 100% (2,569,260 / 2,569,260) |
| `bp_06` | 0.112181 | 1.000000 | 0.4431 | 100% (2,569,260 / 2,569,260) |
| `bp_07` | 0.081482 | 1.000000 | 0.3956 | 100% (2,569,260 / 2,569,260) |
| `bp_08` | 0.361249 | 1.000000 | 0.6205 | 100% (2,569,260 / 2,569,260) |

---

## 6. Original Tuesday Baseline Cryptographic Verification

A byte-by-byte SHA-256 cryptographic audit was conducted comparing active files in `data/processed/event_profiles/` with the immutable baseline backup:

| File Name | Active SHA-256 Hash | Immutable Backup SHA-256 Hash | Status |
|---|---|---|---|
| `event_profiles.csv` | `D3B38B3012557CC606014AF91870B47DAD7ED4652AF00E7FD7D1E57FDD8DDD6E` | `D3B38B3012557CC606014AF91870B47DAD7ED4652AF00E7FD7D1E57FDD8DDD6E` | **IDENTICAL (100% UNTOUCHED)** |
| `event_profiles_metadata.json` | `CE6234392C0E8682732795B64F7A553736879B7F8D5869F52A0AD11D73F81E54` | `CE6234392C0E8682732795B64F7A553736879B7F8D5869F52A0AD11D73F81E54` | **IDENTICAL (100% UNTOUCHED)** |

---

## 7. Conclusions & Next Steps

Phase 3 for Experiment A is completely verified and finished. The multi-day profile datasets and ground truth targets are securely persisted in `data/processed/event_profiles_exp_a/`, completely isolated from baseline Tuesday profiles.

Per instructions, **all execution is halted**. No models (FCNN, CNN, LSTM, ensemble, Isolation Forest) have been retrained, and Experiment B has not been launched.
