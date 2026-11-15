# Diagnostic Report: Investigation of All-NORMAL Classification on Uploaded CSV

**Date:** 2026-11-15  
**Project:** `C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection`  
**Investigation Mode:** STRICT READ-ONLY DIAGNOSTIC  
**Target File:** `C:\Users\pavani krishna\Desktop\cyber\synthetic_ddos_siem_compatible.csv`  
**Execution Environment:** Python 3.13 / TensorFlow 2.20 / scikit-learn 1.7 / FastAPI 0.115  

---

## Executive Summary

Following the completion and verification of the Stage 2 implementation (which passed all 214 regression tests), an upload of `synthetic_ddos_siem_compatible.csv` via the web dashboard produced 148 event sets where **100% (148/148) were classified as NORMAL**, resulting in 0 detected threats and 0 campaigns.

A comprehensive end-to-end diagnostic trace was conducted across the parser, raw flow aggregator, TF-IDF transformer, basepoint cosine projection, deep neural ensemble (FCNN, CNN, LSTM), Isolation Forest anomaly detector, tri-state decision policy, database persistence, and frontend presentation.

### Primary Diagnostic Conclusion
**Finding Classification: CONFIRMED**

The all-NORMAL classification is **not caused by a bug in the inference pipeline, parser, model weights, thresholds, campaign coalescer, database, or frontend**. Every stage of the pipeline executed with 100% mathematical fidelity.

The all-NORMAL result is directly caused by **data-scale and volume characteristics of the synthetic CSV file**:
1. **Zero `HIGH_FLOW_RATE` Activation (CONFIRMED):** In the Experiment B methodology, flows are strictly grouped by directional communication pair `(source_ip, destination_ip)`. The synthetic dataset contains only 40 flows spread across 10 distinct source-destination pairs over a 39-minute span. The maximum number of flows for any single pair in any 10-minute sliding window is **4 flows**, whereas the calibrated Experiment B threshold requires **strictly greater than 12.0 flows**.
2. **Zero `HIGH_PACKET_RATE` Activation (CONFIRMED):** In the synthetic dataset, the maximum `flow_packets_s` is **256,339.39 packets/s**, whereas the calibrated CICIDS2017 95th percentile training threshold is **666,666.7 packets/s**.
3. **Zero `SHORT_REPEATED_CONNECTIONS` Activation (CONFIRMED):** In the synthetic dataset, the minimum `flow_duration` is **8,492.0 microseconds**, whereas the calibrated CICIDS2017 5th percentile training threshold is **strictly less than 3.0 microseconds**.
4. **Basepoint Profile Collapse (CONFIRMED):** Because 3 out of 5 security events (`HIGH_FLOW_RATE`, `HIGH_PACKET_RATE`, `SHORT_REPEATED_CONNECTIONS`) never activated (0.0%), dimensions `bp_01`, `bp_03`, and `bp_08` collapsed to exactly 0.0000 across all 148 profiles. The resulting profiles occupied a sparse benign subspace where the ensemble neural network predicted threat probabilities between $0.0015\%$ and $29.40\%$ (well below the alert threshold $\tau = 65.61\%$), and Isolation Forest computed anomaly scores between $-0.2716$ and $-0.0802$ (well below the anomaly threshold $\tau = -0.012676$). Consequently, 100% of the event sets correctly fell into Decision Policy Priority 3 (Benign Network Traffic).

---

## 1. Exact Uploaded File Identity and Properties

| Property | Value | Status |
| :--- | :--- | :--- |
| **Absolute File Path** | `C:\Users\pavani krishna\Desktop\cyber\synthetic_ddos_siem_compatible.csv` | CONFIRMED |
| **File Size** | 5,584 bytes | CONFIRMED |
| **SHA-256 Checksum** | `a62f2586cfe1ead9f71bc80ebfbdb4f9d848ce2dcc1d1065ea075a3fad6ee8a5` | CONFIRMED |
| **Total Lines in File** | 41 lines (1 header line + 40 data rows) | CONFIRMED |
| **Ingestion Type Detected** | `flow` (Raw network-flow CSV) | CONFIRMED |
| **Parser Function Executed** | `backend.parser.parse_csv_bytes()` via `parse_uploaded_file()` | CONFIRMED |
| **Most Recent Analysis Session** | `SESS-20261115130632-34ef60` / `SESS-20261115131013-22f574` | CONFIRMED |
| **Database Records Generated** | 148 detection records, 0 campaign records | CONFIRMED |

### Execution Path Verification
The uploaded CSV was processed through the following exact execution path:
1. `backend/main.py`: `POST /api/upload` received `synthetic_ddos_siem_compatible.csv`.
2. `backend/service.py`: `SIEMService.process_file_upload()` called `backend.parser.parse_uploaded_file(contents, filename)`.
3. `backend/parser.py`: Verified file does not contain `bp_01`..`bp_08`; recognized it as raw flow telemetry (`file_type = "flow"`).
4. `backend/service.py`: Branch `if file_type == "flow":` initialized `RawFlowAggregator(experiment_id="B")`.
5. `backend/aggregator.py`: `RawFlowAggregator.aggregate_flows()` parsed timestamps, constructed 60-second bins, formed 600-second sliding windows, grouped by `(source_ip, destination_ip)`, evaluated flow-level events, aggregated counts, applied TF-IDF transform, and computed 8D basepoint profiles.
6. `src/inference/predict.py`: Vectorized `predict_profiles_batch()` evaluated the 148 profiles through FCNN, CNN, LSTM, soft-voting ensemble, and Isolation Forest.
7. `src/inference/decision_policy.py`: `classify_detection_outcome()` applied Experiment B Priority 1 $\to$ Priority 2 $\to$ Priority 3 logic.
8. `backend/campaign.py`: `coalesce_campaigns()` evaluated detections (0 threats found $\to$ 0 campaigns formed).
9. `backend/database.py`: Inserted session metadata into `analysis_sessions` and 148 rows into `detections`.
10. `frontend/js/app.js`: Displayed batch summary cards, detection table, and campaign panel.

---

## 2. Uploaded Dataset Characteristics

| Dataset Characteristic | Measured Value | Requirement / Reference | Status |
| :--- | :--- | :--- | :--- |
| **Raw Data Rows** | 40 flows | Valid input ($>0$) | CONFIRMED |
| **Required Schema Columns Found** | 18 columns (`timestamp`, `source_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`, `flow_duration`, `total_fwd_packets`, `total_backward_packets`, `fwd_packet_length_total`, `bwd_packet_length_total`, `flow_bytes_s`, `flow_packets_s`, `syn_flag_count`, `ack_flag_count`, `packet_length_mean`, `label`, `attack_type`) | All required columns present | CONFIRMED |
| **Missing Schema Columns** | None | 0 missing | CONFIRMED |
| **Timestamp Parsing Rate** | 100% (40 / 40 flows valid) | Valid ISO / standard timestamps | CONFIRMED |
| **Minimum Timestamp ($t_0$)** | `2026-11-15 10:00:00` | Baseline anchor | CONFIRMED |
| **Maximum Timestamp ($t_{\max}$)** | `2026-11-15 10:39:00` | End of stream | CONFIRMED |
| **Elapsed Temporal Span** | 2,340.0 seconds (39 minutes) | Exceeds minimum window (600s) | CONFIRMED |
| **Total 60-second Bins** | 40 bins constructed | Bins 0 through 39 | CONFIRMED |
| **Occupied 60-second Bins** | 40 occupied bins | Satisfies $\ge 10$ occupied bins | CONFIRMED |
| **Directional Pairs `(src, dst)`** | 10 distinct communication pairs | Grouped by direction | CONFIRMED |
| **Generated Event Sets** | 148 event sets | $(40 - 10 + 1) = 31$ windows $\times$ active pairs | CONFIRMED |
| **Flows Assigned to Windows** | 40 flows (100% assigned) | Overlapping sliding windows | CONFIRMED |
| **Flows Excluded** | 0 flows excluded | No invalid rows or missing IPs | CONFIRMED |
| **Ground-Truth Label Column** | `{"BENIGN": 20, "DDoS": 20}` | Diagnostic inspection only (never input to model) | CONFIRMED |

---

## 3. Event Activation Statistics

In Experiment B, raw flows are transformed into behavioral event sets by evaluating five security event criteria calibrated from CICIDS2017 training distributions:

| Event Name | Level | Feature Used | Comparison | Training Threshold | Upload Min | Upload Median | Upload P95 | Upload Max | Event Sets Activated | % Sets Activated | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **HIGH_FLOW_RATE** | Event Set | Flows per `(src, dst)` pair in 10-min window | `>` (`gt`) | **12.0** flows | 1 | 2.0 | 4.0 | **4** | **0** | **0.00%** | **CONFIRMED INACTIVE** |
| **HIGH_PACKET_RATE** | Flow | `flow_packets_s` | `>` (`gt`) | **666,666.7** pkts/s | 41.07 | 9,468.51 | 213,699.32 | **256,339.39** | **0** | **0.00%** | **CONFIRMED INACTIVE** |
| **HIGH_BYTE_RATE** | Flow | `flow_bytes_s` | `>` (`gt`) | **2,485,351.05** B/s | 1,956.34 | 625,838.99 | 9,188,693.18 | **37,189,472.44** | **73** | **49.32%** | **CONFIRMED ACTIVE** |
| **SYN_ACTIVITY** | Flow | `syn_flag_count` | `>=` (`ge`) | **1.0** | 0.0 | 63.5 | 790.60 | **865.0** | **140** | **94.59%** | **CONFIRMED ACTIVE** |
| **SHORT_REPEATED_CONNECTIONS** | Flow | `flow_duration` | `<` (`lt`) | **3.0** $\mu$s | **8,492.0** | 77,758.5 | 2,339,081.20 | 2,373,315.0 | **0** | **0.00%** | **CONFIRMED INACTIVE** |

### Event Evaluation Findings
- **Zero Event Sets:** Exactly 8 event sets (5.41%) had zero event activations across all five features.
- **Evaluation Level Verification:** Confirmed that `HIGH_FLOW_RATE` is evaluated strictly at the event-set level (`cap_sets["n_flows"] > 12.0`), matching the training pipeline implementation in `src/event_profiles/events.py`.
- **Root Cause of Inactivity:**
  - `HIGH_FLOW_RATE` requires volumetric flow concentration ($> 12$ flows between a specific source and destination IP within 10 minutes). The synthetic generator emitted at most 1 flow per minute globally across 10 different IP pairs, yielding a maximum of 4 flows per pair per window.
  - `HIGH_PACKET_RATE` requires packet rates $> 666,666.7$ pkts/s. The synthetic dataset peaked at $256,339.39$ pkts/s.
  - `SHORT_REPEATED_CONNECTIONS` requires sub-3-microsecond durations. The synthetic dataset durations were all $\ge 8,492.0$ microseconds.

---

## 4. Generated Event-Profile Distribution Comparison

The 8-dimensional event profile vectors $\mathbf{p} = [bp_{01}, \dots, bp_{08}]^T$ represent cosine similarities between the TF-IDF-transformed event counts and 8 pre-calibrated cluster centroids (basepoints).

### Uploaded CSV Profile Distributions (148 Event Sets)
| Basepoint | Min | Median | P95 | Max | Std Dev | Zero Count | Zero % | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **bp_01** | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | **148** | **100.0%** | **COLLAPSED TO ZERO** |
| **bp_02** | 0.0000 | 0.8148 | 0.9840 | 0.9840 | 0.2153 | 8 | 5.4% | Active |
| **bp_03** | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | **148** | **100.0%** | **COLLAPSED TO ZERO** |
| **bp_04** | 0.0000 | 0.0000 | 0.5586 | 0.5586 | 0.2693 | 75 | 50.7% | Active |
| **bp_05** | 0.0000 | 0.5331 | 0.6267 | 0.6267 | 0.1504 | 8 | 5.4% | Active |
| **bp_06** | 0.0000 | 0.0000 | 0.5439 | 0.5439 | 0.2622 | 75 | 50.7% | Active |
| **bp_07** | 0.0000 | 0.4611 | 0.5420 | 0.5420 | 0.1301 | 8 | 5.4% | Active |
| **bp_08** | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | **148** | **100.0%** | **COLLAPSED TO ZERO** |

### Training Baseline Profile Distributions (Sample of 100,000 Profiles from Experiment B)
| Basepoint | Training Min | Training Median | Training P95 | Training Max | Training Std Dev | Training Zero % |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **bp_01** | 0.0000 | 0.0000 | **0.4405** | **1.0000** | 0.1465 | 91.8% |
| **bp_02** | 0.0000 | 0.0000 | 0.8587 | 0.9871 | 0.3471 | 64.4% |
| **bp_03** | 0.0000 | 0.0000 | **0.5077** | **0.9615** | 0.1488 | 90.0% |
| **bp_04** | 0.0000 | 0.0000 | 0.7734 | 1.0000 | 0.3013 | 79.3% |
| **bp_05** | 0.0000 | 0.0000 | 0.6267 | 0.9999 | 0.2663 | 75.3% |
| **bp_06** | 0.0000 | 0.0000 | 0.7524 | 1.0000 | 0.2677 | 77.2% |
| **bp_07** | 0.0000 | 0.0000 | 0.5420 | 1.0000 | 0.2321 | 75.8% |
| **bp_08** | 0.0000 | 0.0000 | 0.0000 | **0.7334** | 0.1252 | 95.3% |

### Profile Distribution Findings
- In the training corpus, basepoints `bp_01`, `bp_03`, and `bp_08` are associated with high-frequency volumetric traffic, high packet rates, and short burst connections.
- In the uploaded dataset, because `HIGH_FLOW_RATE`, `HIGH_PACKET_RATE`, and `SHORT_REPEATED_CONNECTIONS` are completely absent, the event count vectors possess non-zero counts exclusively for `HIGH_BYTE_RATE` and `SYN_ACTIVITY`.
- The TF-IDF cosine projections along `bp_01`, `bp_03`, and `bp_08` evaluate to **exactly zero** ($148 / 148$ zero values).
- The generated vectors fall into a restricted subspace of the benign profile distribution rather than an out-of-distribution anomaly region.

---

## 5. Model Score Distributions Before Final Classification

Inference was evaluated on all 148 profiles using both the vectorized `predict_profiles_batch()` implementation and individual `predict_profile()` calls.

### Score Distributions Across 148 Event Sets
| Model / Score | Minimum | Median | P95 | Maximum | Calibrated Threshold ($\tau$) | Sets Exceeding $\tau$ | Exceedance % |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **FCNN Probability** | $1.14 \times 10^{-5}$ | $3.35 \times 10^{-5}$ | 0.1833 | 0.2813 | 0.8582 | 0 | 0.0% |
| **CNN Probability** | $7.39 \times 10^{-8}$ | $6.47 \times 10^{-6}$ | 0.1776 | 0.2732 | 0.3439 | 0 | 0.0% |
| **LSTM Probability** | $1.18 \times 10^{-5}$ | $6.67 \times 10^{-5}$ | 0.2130 | 0.3275 | 0.7663 | 0 | 0.0% |
| **Ensemble Soft-Voting ($p_{\text{threat}}$)** | $1.51 \times 10^{-5}$ | $2.82 \times 10^{-5}$ | 0.1913 | **0.2940** | **0.6561** | **0** | **0.0%** |
| **Isolation Forest Score ($- \text{decision\_function}$)** | -0.2716 | -0.2184 | -0.1219 | **-0.0802** | **-0.012676** | **0** | **0.0%** |

### Individual Submodel Verdicts
- **FCNN Alone:** Max probability = $0.2813 < 0.8582 \implies 0$ alerts.
- **CNN Alone:** Max probability = $0.2732 < 0.3439 \implies 0$ alerts.
- **LSTM Alone:** Max probability = $0.3275 < 0.7663 \implies 0$ alerts.
- **Ensemble ($1/3 \text{FCNN} + 1/3 \text{CNN} + 1/3 \text{LSTM}$):** Max probability = $0.2940 < 0.6561 \implies 0$ alerts.
- **Isolation Forest:** Max anomaly score = $-0.0802 < -0.012676 \implies 0$ anomalies.

### Decision Policy Branch Evaluation
1. **Priority 1 (ANN Threat Alert):**  
   Rule: $p_{\text{threat}} \ge 0.656122$  
   Evaluation: $0.294032 < 0.656122 \implies$ **FALSE** for all 148 event sets.
2. **Priority 2 (Unknown / Out-of-Distribution Anomaly):**  
   Rule: $\text{anomaly\_score} \ge -0.012676$  
   Evaluation: $-0.080200 < -0.012676 \implies$ **FALSE** for all 148 event sets.
3. **Priority 3 (Benign Network Traffic):**  
   Rule: Otherwise  
   Evaluation: **TRUE** for 148 / 148 event sets $\implies$ 100% assigned `verdict = "NORMAL"`, `prediction_status = "NORMAL"`.

---

## 6. Threshold Comparison & Inference Parity Verification

### Policy Logic Verification
Inspection of `src/inference/decision_policy.py`:
- **Priority 1 Comparison:** Evaluates `if p_threat >= th_threat:`. This uses `>=` consistently.
- **Priority 2 Comparison:** Evaluates `elif is_anomaly or (anomaly_score >= th_anomaly):`. This uses `>=` consistently.
- **Isolation Forest Score Convention:** `src/models/anomaly.py` computes `raw = model.decision_function(X)` and inverts it as `anomaly_score = -raw`. Under this convention, larger positive numbers denote outliers, and negative numbers denote inliers. The calibrated threshold is $\tau = -0.012676$. Inliers have scores $< -0.012676$. For the uploaded file, scores ranged from $-0.2716$ to $-0.0802$, all strictly below threshold.
- **Threshold Provenance:** Loaded directly from `models/saved_exp_b/ensemble_config.json` and `models/saved_exp_b/anomaly_config.json`, calibrated strictly on the Thursday validation split.

### Vectorized Batch vs. Single-Profile Parity
A side-by-side execution of `predict_profiles_batch(profiles)` vs. looping `predict_profile(p)` across all 148 event sets confirmed:
- **Verdict Mismatches:** **0**
- **Confidence Differences:** **0.000000** ($< 10^{-6}$ numerical tolerance)
- **Status:** CONFIRMED 100% PARITY.

---

## 7. Systematic Evaluation of Hypotheses (A through H)

| Hypothesis | Description | Audit Finding | Status |
| :--- | :--- | :--- | :--- |
| **A. Incorrect CSV Parsing** | CSV parser drops rows, misaligns columns, or truncates timestamps. | All 40 rows and 18 columns parsed without loss; timestamps parsed to exact nanoseconds. | **REJECTED (CONFIRMED NOT CAUSE)** |
| **B. Incorrect Feature Mapping or Units** | Synthetic values provided in incompatible units (e.g. ms vs $\mu$s, or unrealistic rates). | Synthetic `flow_duration` was in milliseconds/microseconds range ($>8,492 \mu$s), failing the $<3.0 \mu$s threshold; `flow_packets_s` peaked at 256k pkts/s, failing the 666k threshold. | **CONFIRMED CONTRIBUTING CAUSE** |
| **C. Event-Generation Rules Not Activating** | Security event flags fail to trigger due to data sparsity or low rates. | 3 out of 5 event types had 0.0% activation (`HIGH_FLOW_RATE`, `HIGH_PACKET_RATE`, `SHORT_REPEATED_CONNECTIONS`). `HIGH_FLOW_RATE` had max 4 flows/pair vs required $>12.0$. | **CONFIRMED PRIMARY CAUSE** |
| **D. Profiles Outside Training Distribution** | Generated profiles fall far outside CICIDS2017 distribution causing unpredictable behavior. | Profiles collapsed into an interior benign subspace of the training distribution, not an anomaly region. | **REJECTED (CONFIRMED NOT CAUSE)** |
| **E. ANN Confidence Below Calibrated Threshold** | Neural networks output sub-threshold probabilities for benign-resembling vectors. | Max ensemble probability reached 0.2940, well below $\tau = 0.6561$. | **CONFIRMED IMMEDIATE CONSEQUENCE** |
| **F. Isolation Forest Score Below Threshold** | Unsupervised detector identifies the profiles as standard inliers. | Anomaly scores ranged from -0.2716 to -0.0802, well below threshold $\tau = -0.012676$. | **CONFIRMED IMMEDIATE CONSEQUENCE** |
| **G. Incorrect Decision-Policy Behavior** | Decision logic incorrectly routes alerts or anomalies to NORMAL. | Policy evaluated Priority 1 (False) $\to$ Priority 2 (False) $\to$ Priority 3 (True) correctly. | **REJECTED (CONFIRMED NOT CAUSE)** |
| **H. Campaign Filtering or Dashboard Presentation** | API or frontend drops threats or overwrites verdicts with NORMAL. | Detections table in SQLite DB and raw API payload contain 148 NORMAL records. UI accurately reflects backend data. | **REJECTED (CONFIRMED NOT CAUSE)** |

---

## 8. API and Frontend Verification

The integration between backend and frontend was inspected to confirm whether any verdicts were masked:
1. **Raw API Ingestion Response:**  
   The `POST /api/upload` endpoint returned an HTTP 200 payload containing 148 items in `detections`. Every item contained `verdict: "NORMAL"`, `predicted_class: "Benign Network Traffic"`, and `requires_investigation: false`.
2. **Database Ingestion Integrity:**  
   Querying `detections WHERE session_id = 'SESS-20261115130632-34ef60'` returned 148 rows:
   - `verdict = 'NORMAL'`: 148
   - `verdict = 'KNOWN_THREAT'`: 0
   - `verdict = 'UNKNOWN_ANOMALOUS'`: 0
3. **Campaign Table:**  
   Querying `campaigns WHERE session_id = 'SESS-20261115130632-34ef60'` returned 0 rows. Under Experiment B methodology, campaigns coalesce only threat and anomalous detections (`verdict IN ('KNOWN_THREAT', 'UNKNOWN_ANOMALOUS')`). Because there were 0 threats, 0 campaigns were generated.
4. **Dashboard Frontend Display:**  
   - SOC Overview Metric Cards: `Total Analyses: 148`, `Threats Detected: 0`, `Active Campaigns: 0`.
   - Threat Ratio: `0.0%`.
   - Campaign Table: Displays clean empty state ("No security campaigns detected for the active session.").
   - Detection Table: Displays benign records with green badges ("Benign Network Traffic").
   - Verdict Translation Check: Verified in `frontend/js/app.js` that the frontend does not alter or default verdicts to NORMAL. It renders whatever string is delivered by `record.verdict`.

---

## 9. Root Cause Summary and Evidence Classification

| Finding | Classification | Supporting Evidence |
| :--- | :--- | :--- |
| **Pipeline & Engine Soundness** | **CONFIRMED** | 214/214 unit and integration tests passing; identical results between batch and single-profile inference; zero runtime exceptions. |
| **Flow Dispersion Precluding `HIGH_FLOW_RATE`** | **CONFIRMED** | Only 40 flows across 10 directional pairs over 39 minutes. Maximum flows for any pair in any 10-minute window is 4 flows. Threshold is $> 12.0$ flows. Activation rate = 0.0% (0/148). |
| **Packet Rate Scale Mismatch** | **CONFIRMED** | Maximum `flow_packets_s` in synthetic CSV is $256,339.39$ pkts/s. Training 95th percentile threshold is $666,666.7$ pkts/s. Activation rate = 0.0% (0/148). |
| **Flow Duration Scale Mismatch** | **CONFIRMED** | Minimum `flow_duration` in synthetic CSV is $8,492.0$ microseconds. Training 5th percentile threshold is $< 3.0$ microseconds. Activation rate = 0.0% (0/148). |
| **Basepoint Dimension Collapse** | **CONFIRMED** | Dimensions `bp_01`, `bp_03`, and `bp_08` are identically zero across all 148 profiles. Event count vectors contain only `SYN_ACTIVITY` and `HIGH_BYTE_RATE`. |
| **Mathematical Normal Verdict** | **CONFIRMED** | Neural ensemble threat probability peaks at 0.2940 (threshold 0.6561). Isolation Forest anomaly score peaks at -0.0802 (threshold -0.012676). Both models mathematically confirm the profiles are normal. |
| **Frontend/Database Transparency** | **CONFIRMED** | Database records and raw API responses contain 148 NORMAL verdicts. Frontend displays exact backend verdicts without translation. |

---

## 10. Recommended Corrective Actions

To validate threat detection and campaign coalescence on uploaded CSV files, the test dataset must reflect the calibrated statistical characteristics of actual volumetric and DDoS attacks from the CICIDS2017 benchmark.

### Recommendations for Synthetic Attack Telemetry Generation
1. **Volumetric Concentration (`HIGH_FLOW_RATE`):**
   - Ensure that the attack source IP sends **at least 15 to 50 flows** to the target destination IP within a single 10-minute (600-second) window.
   - Example: Have attacker `192.168.10.50` send 30 HTTP flows to victim `192.168.10.1` within bins 0 through 9 ($t = 0$ to $t = 540$s). This will trigger `n_flows = 30 > 12.0`, activating `HIGH_FLOW_RATE = 1`.
2. **High Packet Rate (`HIGH_PACKET_RATE`):**
   - For flood flows, generate `flow_packets_s` values exceeding **700,000 to 1,000,000 packets/s** (e.g. 50,000 packets over a 0.05-second flow). This will satisfy `flow_packets_s > 666,666.7`, activating `HIGH_PACKET_RATE = 1`.
3. **Short Repeated Connections (`SHORT_REPEATED_CONNECTIONS`):**
   - For SYN/ACK scan or rapid connection attempts, generate `flow_duration` values of **1 to 2 microseconds**. This will satisfy `flow_duration < 3.0`, activating `SHORT_REPEATED_CONNECTIONS = 1`.
4. **High Byte Rate (`HIGH_BYTE_RATE`):**
   - For volumetric exfiltration or UDP/HTTP floods, generate `flow_bytes_s` values exceeding **3,000,000 to 10,000,000 bytes/s**.
5. **SYN Flood Activity (`SYN_ACTIVITY`):**
   - Retain `syn_flag_count >= 1.0` (already properly represented in the current synthetic file).

### Benchmark Replay Alternative
Alternatively, test uploads using genuine slices from the CICIDS2017 Friday DDoS capture (`data/raw/Friday-WorkingHours.pcap_ISCX.csv` or `data/processed/Friday-WorkingHours_clean.csv`), which natively contain real volumetric attacks that activate all five event categories and trigger both ANN threat alerts and campaigns.

---
*Report completed under strict read-only diagnostic authorization. No production code, model weights, or calibrated thresholds were modified.*
