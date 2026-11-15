# Event Profile Report (Phase 3)

*Generated automatically on 2026-11-10 15:14:45. Every number was computed by the run; none were typed by hand.*

**Scope:** event generation, TF-IDF, basepoints, cosine-similarity event profiles and ground-truth targets. No neural network was trained, and no Phase 4 or dashboard work was done. The events are **derived from network-flow features; they are not real IDS/IPS alerts.**

## 1. Input and integrity

| Item | Value |
| --- | --- |
| Cleaned dataset (read-only) | Tuesday-WorkingHours_clean.csv |
| SHA-256 before / after | `09c2b409e8f17f649adf8b39bef7992576bd2348fe2da031939bd0bdc233c2f5` / `09c2b409e8f17f649adf8b39bef7992576bd2348fe2da031939bd0bdc233c2f5`  ->  **UNCHANGED** |
| Flows read | 445,641 |
| Flows per split | train: 246,471, validation: 99,486, test: 99,684 |
| Block length (for split check) | 20 min (from Phase 2 metadata (Tuesday-WorkingHours_metadata.json)) |
| Columns the event stage was allowed to read | source_row, timestamp, split, block_id, source_ip, destination_ip, flow_duration, flow_packets_s, flow_bytes_s, syn_flag_count |
| Columns it never read | label, label_original, target_binary, target_multiclass, source_port, destination_port, flow_id, protocol |

The label columns are loaded by a different function, only after all profiles are written, and only to build targets.

## 2. Windows

Window size 600 s, step 60 s (10 one-minute bins per window, overlap 540 s). Time origin 2017-07-04 01:00:00. A flow lies in exactly one bin and is counted once per window (but in up to 10 overlapping windows).

| Item | Count |
| --- | --- |
| Possible windows in the timeline | 711 |
| Valid windows (all bins in ONE split) | 385 |
| Dropped (cross a split boundary or an unknown block) | 326 |

## 3. Event sets and empty event sets

An event set is one source->destination pair inside one window (the paper's grouping). **Empty** = none of the 5 events occurred in the set.

| Split | Valid windows | Windows with >= 1 set | Event sets | Empty sets | Empty % | Median flows/set | Max flows/set |
| --- | --- | --- | --- | --- | --- | --- | --- |
| train | 266 | 256 | 306,936 | 203,588 | 66.33% | 2.0 | 3,079 |
| validation | 55 | 51 | 77,285 | 48,641 | 62.94% | 2.0 | 3,683 |
| test | 64 | 64 | 86,831 | 56,950 | 65.59% | 2.0 | 2,552 |
| **all** |  |  | 471,052 | 309,179 | 65.64% |  |  |

Distinct source->destination pairs in the data: 35,018. Empty sets get an all-zero TF-IDF vector and an all-zero profile (cosine similarity 0 to every basepoint); they are never dropped, and `event_sets.csv` has an `is_empty` flag.

## 4. Thresholds (fitted on TRAINING data only)

| Event | Level | Feature | Percentile | Rule | Threshold | Training values | Trigger share train / val / test |
| --- | --- | --- | --- | --- | --- | --- | --- |
| HIGH_FLOW_RATE | event_set | flows in the source->destination event set | 95th | gt | 12 | 306,936 | 4.77% / 5.49% / 4.80% |
| HIGH_PACKET_RATE | flow | flow_packets_s | 95th | gt | 500000 | 246,471 | 4.57% / 4.95% / 4.11% |
| HIGH_BYTE_RATE | flow | flow_bytes_s | 95th | gt | 1.84337e+06 | 246,471 | 5.00% / 6.48% / 5.23% |
| SYN_ACTIVITY | flow | syn_flag_count | 95th | ge | 1 | 246,471 | 6.10% / 6.86% / 5.16% |
| SHORT_REPEATED_CONNECTIONS | flow | flow_duration | 5th | lt | 4 | 246,471 | 3.94% / 4.26% / 3.48% |

Percentile = `numpy.quantile` with linear interpolation. `flow_duration` is in **microseconds** (CICFlowMeter). Trigger share is the % of flows (flow-level events) or event sets (HIGH_FLOW_RATE) for which the event fired. HIGH_FLOW_RATE's threshold is the percentile of flows-per-event-set over training event sets; it measures the source->destination event set, not the whole window.

**Share of event sets in which each event occurred at least once:**

| Event | train | validation | test |
| --- | --- | --- | --- |
| HIGH_FLOW_RATE | 4.77% | 5.49% | 4.80% |
| HIGH_PACKET_RATE | 17.18% | 19.69% | 17.30% |
| HIGH_BYTE_RATE | 10.19% | 11.63% | 9.77% |
| SYN_ACTIVITY | 19.17% | 21.89% | 19.65% |
| SHORT_REPEATED_CONNECTIONS | 15.08% | 17.57% | 14.99% |

## 5. TF-IDF (training event sets only)

Training documents: 306,936. `tf = 1+ln(count) if sublinear else count; idf = ln((1+N)/(1+df))+1; vector = L2_normalize(tf*idf)`.

| Term (event) | Document frequency | IDF |
| --- | --- | --- |
| HIGH_FLOW_RATE | 14,649 | 4.0422 |
| HIGH_PACKET_RATE | 52,733 | 2.7614 |
| HIGH_BYTE_RATE | 31,275 | 3.2838 |
| SYN_ACTIVITY | 58,831 | 2.6520 |
| SHORT_REPEATED_CONNECTIONS | 46,288 | 2.8917 |


## 6. Basepoints (training vectors only, no labels)

Rare-event list (2 lowest training document frequency): **HIGH_FLOW_RATE, HIGH_BYTE_RATE**. Non-empty training event sets: 103,348; distinct candidate vectors containing a rare event: 1,020. Selected **8** of 8 requested (redundancy threshold 0.95). Stop reason: reached the requested number of basepoints.

| Order | Max cosine to earlier basepoints | Weight on rare events | HIGH_FLOW_RATE | HIGH_PACKET_RATE | HIGH_BYTE_RATE | SYN_ACTIVITY | SHORT_REPEATED_CONNECTIONS |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | - | 1.4067 | 0.7762 | 0.0000 | 0.6305 | 0.0000 | 0.0000 |
| 2 | 0.1208 | 0.1556 | 0.1556 | 0.6822 | 0.0000 | 0.0000 | 0.7144 |
| 3 | 0.2032 | 0.3223 | 0.0000 | 0.2710 | 0.3223 | 0.9070 | 0.0000 |
| 4 | 0.4826 | 0.7654 | 0.0000 | 0.6436 | 0.7654 | 0.0000 | 0.0000 |
| 5 | 0.6179 | 0.6540 | 0.6540 | 0.7565 | 0.0000 | 0.0000 | 0.0000 |
| 6 | 0.6313 | 0.8133 | 0.8133 | 0.0000 | 0.0000 | 0.0000 | 0.5818 |
| 7 | 0.6741 | 0.6691 | 0.6691 | 0.0000 | 0.0000 | 0.7432 | 0.0000 |
| 8 | 0.6770 | 0.6418 | 0.0000 | 0.0000 | 0.6418 | 0.5183 | 0.5652 |

> **Representation, not dimensionality reduction.** There are only 5 event dimensions and 8 basepoints, so the event profile has 8 numbers per event set - not fewer than the event vector. In the paper the profile *reduces* thousands of event types to a few basepoint similarities; here it is a similarity-based re-encoding of the TF-IDF vector.

## 7. Targets and mixed event sets (ground truth, kept in a separate file)

Policy: `target_binary = 1` if the set holds at least **1** attack flow(s) and an attack fraction of at least **0.0**; `target_multiclass` = attack class with the most flows in the set (ties -> lower code), BENIGN otherwise. **Mixed set** = contains both benign and attack flows.

Class codes: 0 = BENIGN, 1 = FTP-Patator, 2 = SSH-Patator

| Split | Event sets | Attack sets (target 1) | Attack % | Mixed sets | Mixed % of all | Mixed % of attack sets | Attack sets with attack fraction < 0.5 | Multi-attack sets |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **all** | 471,052 | 110 | 0.023% | 0 | 0.000% | 0.00% | 0 (0.00%) | 0 |
| test | 86,831 | 14 | 0.016% | 0 | 0.000% | 0.00% | 0 (0.00%) | 0 |
| train | 306,936 | 74 | 0.024% | 0 | 0.000% | 0.00% | 0 (0.00%) | 0 |
| validation | 77,285 | 22 | 0.028% | 0 | 0.000% | 0.00% | 0 (0.00%) | 0 |

**Event sets per target class and split:**

| Split | BENIGN | FTP-Patator | SSH-Patator |
| --- | --- | --- | --- |
| test | 86,817 | 3 | 11 |
| train | 306,862 | 42 | 32 |
| validation | 77,263 | 11 | 11 |

Under this policy every mixed set is labelled attack, so label noise is concentrated in mixed sets where the attack fraction is small (counted above).

## 8. Output files

| File | Role | Contains |
| --- | --- | --- |
| event_profiles.csv | **MODEL INPUT** | event_set_id, window_id, split, window_start, bp_01, bp_02, bp_03, bp_04, bp_05, bp_06, bp_07, bp_08  (no IPs, labels, targets) |
| event_set_targets.csv | **GROUND TRUTH** | event_set_id, window_id, split, n_flows, n_attack_flows, attack_fraction, label_purity, is_mixed, is_multi_attack, target_binary, target_multiclass, target_label |
| event_sets.csv | intermediate | IDs, window times, flows per set, the 5 event counts, readable event text, is_empty |
| event_set_keys.csv | audit / alert details | IDs, source_ip, destination_ip |
| tfidf_event_vectors.csv, tfidf_model.json | intermediate | fitted on training sets |
| event_thresholds.json, basepoints.csv, basepoints.json | fitted parameters | thresholds, basepoint vectors and selection trace |
| event_profiles_metadata.json | metadata | model_input_columns, identifier columns, target columns, join key, settings |

## 9. Join validation (profiles <-> targets, re-read from disk)

| Check | Result | Detail |
| --- | --- | --- |
| profiles: only identifiers + bp_* feature columns (no IPs, labels, targets, counts) | PASS | 8 bp_* columns |
| profiles: all identifier columns present | PASS |  |
| targets: required columns present | PASS | missing: [] |
| targets: contains no bp_* feature columns | PASS |  |
| profiles: event_set_id has no missing values | PASS |  |
| profiles: event_set_id has no duplicates | PASS | 471,052 unique |
| profiles: event_set_id format ES####### | PASS |  |
| profiles: window_id has no missing values | PASS |  |
| targets: event_set_id has no missing values | PASS |  |
| targets: event_set_id has no duplicates | PASS | 471,052 unique |
| targets: event_set_id format ES####### | PASS |  |
| targets: window_id has no missing values | PASS |  |
| ID sets identical in both files | PASS | only in profiles: 0, only in targets: 0 |
| same number of rows | PASS | 471,052 vs 471,052 |
| rows are in the same order | PASS |  |
| one-to-one join gives every row | PASS | 471,052 joined rows |
| window_id agrees between files | PASS |  |
| split agrees between files | PASS |  |
| profile features are finite (no NaN/inf) | PASS |  |
| profile features lie in [0, 1] | PASS |  |
| target_binary only contains 0/1 | PASS |  |
| target_multiclass has no missing values | PASS |  |

## 10. Warnings

- none

## 11. Limitations

- Attack event sets are scarce and heavily overlapping: neighbouring windows share 9 of 10 minutes, so effective sample size is far smaller than the row count. Results from later models will be noisy, and valid only for this single day of traffic.
- Only 5 event types exist, so many event sets share the same or near-identical vectors.
- Many benign event sets are empty (no event fired); their profiles are all zeros and cannot be told apart.
- TF-IDF vectors are L2-normalised: they keep the direction of an event pattern but not its volume.
- Timestamps have minute resolution; flows inside a minute cannot be ordered.
- Events are derived by percentile rules on flow features; they are not IDS alerts and the 95th/5th percentile rules guarantee some events fire on benign traffic.
- Strict threshold comparisons on discrete or tied features (e.g. syn_flag_count) can fire on far fewer flows than the nominal 5% - see the trigger-share column.
- Block-based splitting leaves few independent train/validation/test periods for a single day.

*Run time: 22.5 s.*
