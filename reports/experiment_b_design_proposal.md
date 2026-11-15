# Experiment B: Unseen Attack Detection Under Temporal and Domain Shift
## Revised Experimental Design and Methodology Proposal

**Project Title:** AI-Based SIEM System for Cyber Threat Detection Using Event Profiles  
**Research Reference:** Lee et al., *"Cyber Threat Detection Based on Artificial Neural Networks Using Event Profiles"*, IEEE Access, 2019  
**Document Type:** Formal Experimental Design Proposal (Pre-Execution Revision)  
**Deliverable Path:** `reports/experiment_b_design_proposal.md`  
**Date & Timestamp:** 2017-07-07 / Revised 2026-11-14 18:00:00  

---

## 1. Executive Summary & Revised Research Claim

### A. The Scientific Reality: Temporal and Domain Shift
In the CICIDS2017 benchmark dataset, cyberattack categories were executed on distinct calendar days during the recording week (July 3–7, 2017). Consequently, partitioning the dataset chronologically—training on Monday, Tuesday, and Wednesday, validating on Thursday, and evaluating on Friday—introduces two concurrent experimental factors:
1. **Unseen Attack Categories:** Friday introduces attack mechanisms (`Bot`, `PortScan`, `DDoS`) that are absent from Monday–Wednesday training data.
2. **Temporal and Domain Shift:** Friday traffic was recorded on a different calendar day with natural variations in network background traffic, host activity schedules, DNS query patterns, and connection counts.

> **Revised Scientific Claim:**  
> Experiment B must NOT be characterized as an idealized or isolated "zero-shot" learning experiment. Instead, it is rigorously designated as:  
> **"Unseen Attack Detection Under Temporal and Domain Shift."**  
> Any observed drop or success in detection performance must be evaluated as the combined effect of novel attack signatures and background temporal distribution shift.

### B. Core Research Questions
1. **Supervised Model Fragility:** How severely does the supervised Artificial Neural Network (ANN) ensemble (FCNN + CNN + LSTM) degrade when evaluating novel attack classes under temporal shift?
2. **Inductive Transferability:** Does the supervised ANN generalize from single-source DoS attacks (trained on Wednesday) to distributed volumetric DDoS attacks (evaluated on Friday)?
3. **Unsupervised Anomaly Detection:** Can an Isolation Forest—fitted strictly on benign training profiles and calibrated on benign Thursday validation traffic without attack label leakage—flag out-of-distribution unseen attacks as anomalous?
4. **Tri-State SIEM Routing:** Does the decision policy successfully route unseen threats into `UNKNOWN_ANOMALOUS` for Tier-2 SOC investigation, rather than permitting silent false negatives (`NORMAL`)?
5. **False Alarm Burden on Normal Traffic:** Given Friday's 443,435 benign event profiles, what is the operational false alarm rate (FPR) and precision when attempting to detect unseen attacks?

---

## 2. Methodological Evolution: Paper vs Existing vs Experiment B

To ensure complete transparency, the methodology is compared across its foundational stages:

| Dimension | Paper Methodology (Lee et al., 2019) | Existing Project Pipeline (Tuesday & Exp A) | Proposed Experiment B Adaptation |
| :--- | :--- | :--- | :--- |
| **Dataset Scope** | KDD Cup 99 / DARPA (Single synthetic environment) | CICIDS2017 (Tuesday baseline; Exp A: All 8 captures) | CICIDS2017 All 8 captures across full 5-day week |
| **Splitting Strategy** | Random hold-out split (risk of temporal leakage) | Exp A: 20-minute cyclical blocked splits across all 5 days | Chronological day-based partitions (Mon–Wed train, Thu val, Fri test) |
| **Attack Generalization** | Evaluated on known attacks present in training | Exp A: Multi-class evaluation across 15 categories | Unseen attack detection under temporal and domain shift |
| **Temporal Grouping** | Sliding windows (10 min size, 60 s step) by IP pair | 600 s window, 60 s step, pair grouping `(src_ip, dst_ip)` | Preserved: 600 s window, 60 s step, pair grouping |
| **Feature Space** | 8 Basepoint cosine similarities via TF-IDF | 8 Basepoint cosine similarities (`bp_01` .. `bp_08`) | Preserved: Exact 8-dimensional cosine profile schema |
| **Derived Flow Events** | 5 Statistical events (HFR, HPR, HBR, SYN, SRC) | 5 Statistical events fitted on training partition only | Fitted strictly on Monday–Wednesday training flows |
| **Unsupervised Model** | Not included (ANN-only supervised classification) | Isolation Forest fitted on benign baseline | Fitted on Mon–Wed benign profiles; calibrated on Thu benign |
| **Decision Policy** | Binary thresholding ($\tau = 0.50$) | Tri-state: `NORMAL`, `KNOWN_THREAT`, `UNKNOWN_ANOMALOUS` | Calibrated tri-state with predeclared false alarm budget |
| **Known-Attack Control** | Not separated from test set | Exp A test set evaluated all classes jointly | **Separately reported:** Eval A (Unseen) vs Eval B (Control) |

---

## 3. Ground Truth Data Distribution Across Capture Days

The entire cleaned multi-day CICIDS2017 dataset comprises 2,827,677 flows, aggregating into 2,569,260 sliding-window event profiles across the five capture days:

### Master Flow and Event Profile Inventory

| Traffic Category | Training Days (Mon, Tue, Wed) Flows | Validation Day (Thu) Flows | Testing Day (Fri) Flows | Training Days Profiles | Validation Day Profiles | Testing Day Profiles | Behavioral Nature & Attack Kill-Chain |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **BENIGN** | **1,400,927** | **456,267** | **413,928** | **1,691,758** | **432,716** | **443,435** | Benign baseline network traffic across all 5 days |
| **Bot** | 0 | 0 | **1,956** | 0 | 0 | **889** | Friday Morning: ARES Botnet periodic HTTP C2 beaconing |
| **PortScan** | 0 | 0 | **158,804** | 0 | 0 | **52** | Friday Afternoon: Nmap/Firewalk horizontal & vertical probing |
| **DDoS** | 0 | 0 | **128,025** | 0 | 0 | **40** | Friday Afternoon: LOIC multi-source HTTP flooding |
| **FTP-Patator** | **7,935** | 0 | 0 | **56** | 0 | 0 | Tuesday: Hydra network authentication brute-force (port 21) |
| **SSH-Patator** | **5,897** | 0 | 0 | **54** | 0 | 0 | Tuesday: Hydra network authentication brute-force (port 22) |
| **DoS Hulk** | **230,123** | 0 | 0 | **27** | 0 | 0 | Wednesday: High-rate randomized HTTP request flood |
| **DoS GoldenEye** | **10,293** | 0 | 0 | **19** | 0 | 0 | Wednesday: HTTP Keep-Alive connection exhaustion DoS |
| **DoS slowloris** | **5,796** | 0 | 0 | **40** | 0 | 0 | Wednesday: Slow HTTP partial header starvation DoS |
| **DoS Slowhttptest** | **5,499** | 0 | 0 | **27** | 0 | 0 | Wednesday: Slow POST body transmission DoS |
| **Heartbleed** | **11** | 0 | 0 | **30** | 0 | 0 | Wednesday: OpenSSL TLS heartbeat buffer over-read exploit |
| **Infiltration** | 0 | **36** | 0 | 0 | **52** | 0 | Thursday Afternoon: Malicious file execution + Metasploit pivot |
| **Web Attack - Brute Force** | 0 | **1,507** | 0 | 0 | **28** | 0 | Thursday Morning: Web application credential brute-force |
| **Web Attack - XSS** | 0 | **652** | 0 | 0 | **29** | 0 | Thursday Morning: Cross-Site Scripting parameter injection |
| **Web Attack - Sql Injection**| 0 | **21** | 0 | 0 | **8** | 0 | Thursday Morning: SQL database query manipulation exploit |
| **Total Attack Records** | **265,554** | **2,216** | **288,785** | **253** | **117** | **981** | Total multi-day attack profile count: **1,351** |
| **Total All Records** | **1,666,481** | **458,483** | **702,713** | **1,692,011** | **432,833** | **444,416** | Combined dataset: **2,827,677 flows / 2,569,260 profiles** |

---

## 4. Reassessment of the Three Candidate Withheld Categories

Evaluation sample sizes must be measured in **event profiles** (the 8-dimensional unit processed by the models), rather than raw flows:

```
[ Friday Held-Out Attack Categories: 981 Event Profiles ]
                         |
      +------------------+------------------+
      |                  |                  |
      v                  v                  v
    [ Bot ]          [ PortScan ]        [ DDoS ]
  889 Profiles       52 Profiles        40 Profiles
 (90.6% support)    (5.3% support)     (4.1% support)
      |                  |                  |
 Primary Unseen      Secondary          Transfer
  Novel Beacon      Reconnaissance     Generalization
```

### 1. `Bot` — Primary Unseen Attack Category
- **Evaluation Sample Size:** **889 event profiles** (1,956 flows).
- **Justification:** `Bot` represents 90.6% of all attack profiles in the test period, providing robust statistical power.
- **Behavioral Mechanics:** Periodic, low-rate outbound HTTP communication from compromised hosts (`192.168.10.15`, `192.168.10.9`) to an external Command and Control (C2) server.
- **Challenge:** Does not trigger `HIGH_PACKET_RATE` or `HIGH_BYTE_RATE`. Tests whether `SHORT_REPEATED_CONNECTIONS` and cosine basepoints capture periodic C2 beaconing.

### 2. `PortScan` — Secondary Unseen Attack Category (Reconnaissance)
- **Evaluation Sample Size:** **52 event profiles** (158,804 flows).
- **Sample Support Analysis:** Although `PortScan` has the highest raw flow count (158,804 flows), it coalesces into only 52 event profiles. This occurs because the scans were conducted rapidly in a concentrated time window across thousands of destination ports from a single attacker IP.
- **Behavioral Mechanics:** Rapid transmission of TCP SYN packets across port ranges with low payload sizes.
- **Challenge:** Tests whether reconnaissance probing—which lacks malicious payload data—is recognized as an anomalous deviation.

### 3. `DDoS` — Structural Transferability Test (Not Wholly Novel)
- **Evaluation Sample Size:** **40 event profiles** (128,025 flows).
- **Scientific Caveat:** `DDoS` cannot be classified as a completely novel attack mechanism because the training set (Wednesday) already contains multiple Denial of Service variants (`DoS Hulk`, `DoS GoldenEye`, `DoS slowloris`, `DoS Slowhttptest`).
- **Research Role:** `DDoS` serves as an **Inductive Transferability Test**: *Can models trained on single-source DoS attacks detect multi-source distributed LOIC floods?*

---

## 5. Dual Evaluation Protocol: Unseen vs Known Control

To prevent conflation of novel attack detection with baseline classification accuracy, Experiment B establishes **two independent, non-aggregated evaluation reports**:

```
====================================================================================================
EXPERIMENT B EVALUATION ARCHITECTURE (NON-AGGREGATED)
====================================================================================================

               +-------------------------------------------------------------+
               | Trained Models: FCNN, CNN, LSTM, Ensemble, Isolation Forest |
               | Fitted strictly on Mon-Wed Training Profiles                |
               +-------------------------------------------------------------+
                                      |
         +----------------------------+----------------------------+
         |                                                         |
         v                                                         v
========================================  ==========================================================
EVALUATION A: UNSEEN ATTACK TEST          EVALUATION B: KNOWN-ATTACK CONTROL TEST
- Dataset: Friday Held-Out Split          - Dataset: Chronologically Reserved Blocks from Tue & Wed
- Normal Profiles: 443,435                - Normal Profiles: Partition-isolated control benign
- Attack Profiles: 981 (Unseen)           - Attack Profiles: Chronologically reserved known attacks
  * Bot (889)                               * SSH-Patator (Chronologically reserved block)
  * PortScan (52)                           * FTP-Patator (Chronologically reserved block)
  * DDoS (40)                             - Role: Control group measuring temporal degradation on
- Role: Primary evaluation of zero-shot             attacks the model was trained to recognize
        generalization & anomaly detection- Metrics: REPORTED COMPLETELY INDEPENDENTLY
- Metrics: REPORTED COMPLETELY SEPARATELY ==========================================================
========================================
```

### A. Evaluation A — Friday Unseen Attack Detection
- **Purpose:** Primary evaluation of model behavior on out-of-distribution threats.
- **Test Set Composition:** 444,416 event profiles (443,435 Benign, 981 Attack).
- **Reporting Requirements:**
  - Full Confusion Matrix ($TN, FP, FN, TP$).
  - Precision, Recall, $F_1$-Score, False Positive Rate (FPR), Balanced Accuracy.
  - Continuous scoring curves: PR-AUC (with positive prevalence baseline $0.2207\%$) and ROC-AUC.
  - Per-category recall for `Bot`, `PortScan`, and `DDoS`.
  - Tri-state distribution: % `KNOWN_THREAT` (ANN generalization), % `UNKNOWN_ANOMALOUS` (Isolation Forest capture), and % `NORMAL` (silent misses).

### B. Evaluation B — Reserved Known-Attack Control Test
- **Purpose:** Establish a baseline measuring how well the models perform on known attacks under temporal delay, isolating temporal degradation from attack novelty.
- **Design Feasibility Analysis:**
  - **Tuesday Feasibility (PASS):** Tuesday attacks (`SSH-Patator` and `FTP-Patator`) each spanned over 1 hour across 26 blocks. Chronologically reserving the final 20-minute block of each attack allows a scientifically valid, leakage-free control test set.
  - **Wednesday Feasibility (LIMITATION DOCUMENTED):** Wednesday attacks (`DoS GoldenEye`, `DoS Hulk`, `DoS Slowhttptest`, `Heartbleed`) were short bursts lasting between 9 and 24 minutes. Reserving a whole block would leave zero training data for that attack. Therefore, Wednesday DoS attacks **cannot support an internal chronological control split without eliminating their training support**.
  - **Adopted Control Design:** The known-attack control test is constructed using chronologically reserved test blocks from Tuesday (`FTP-Patator` and `SSH-Patator`) plus the validated Experiment A baseline performance as the verified control reference.
- **Reporting Requirements:** Reported separately with full metrics ($CM, P, R, F_1, FPR, \text{Bal Acc}, \text{ROC-AUC}, \text{PR-AUC}$). **Under no circumstances will Evaluation A and Evaluation B metrics be averaged or combined into a single score.**

---

## 6. Overlapping-Window Leakage Audit

A comprehensive inspection of the actual pipeline implementation (`src/event_profiles/build_multi_day_profiles.py`, `windows.py`, `events.py`) was performed to verify data isolation safeguards:

| Safeguard Requirement | Implementation Mechanism in Codebase | Audit Verification |
| :--- | :--- | :---: |
| **1. Pre-Aggregation Splitting** | `df_flow["split"]` is assigned in lines 188–198 of `build_multi_day_profiles.py` prior to computing time bins, sliding window boundaries, or event set aggregations. On Tuesday, Block 4 and Block 27 are assigned `control_test` via `TUESDAY_CONTROL_BLOCKS`. | **IMPLEMENTED & VERIFIED** |
| **2. Boundary Window Invalidation** | `valid_windows()` in `windows.py` uses `view.min(axis=1) == view.max(axis=1)` across all 10 consecutive bins. All 9 transition windows bridging Tuesday `train` and `control_test` partitions are marked invalid and discarded. | **IMPLEMENTED & VERIFIED** |
| **3. Capture-Day Isolation** | Sliding windows are computed within the loop over individual cleaned capture files (lines 181–276). Windows never cross across calendar days or capture files. | **IMPLEMENTED & VERIFIED** |
| **4. Event-Set ID Uniqueness** | `global_set_counter` increments monotonically across all captures (lines 225–230), guaranteeing unique identifiers (`ES0000001` .. `ES2569260`). | **IMPLEMENTED & VERIFIED** |
| **5. Source-Destination Independence** | Aggregations sum flow counts within window $k$ for specific `(src_ip, dst_ip)` pairs. No cross-window memory, lag terms, or stateful features exist. | **IMPLEMENTED & VERIFIED** |
| **6. Training-Only Transformations** | Flow thresholds (lines 162–177 exclude Tuesday control blocks), `HIGH_FLOW_RATE` (line 285), TF-IDF vocabulary/IDF weights (line 300), and Basepoints (line 310) are fitted strictly on `train_mask` (Mon–Wed non-control). | **IMPLEMENTED & VERIFIED** |

---

## 7. Corrected Isolation Forest Calibration Protocol

### A. The Flaw in Attack-Label Optimization
In Experiment A, the Isolation Forest threshold was tuned to maximize $F_1$ against ground-truth attack labels. While mathematically valid for benchmark tuning on known classes, **optimizing an anomaly detector on unseen test attack labels is scientifically invalid**:
1. In production, security teams do not possess labels for zero-day or unseen attacks.
2. Optimizing $\tau$ on Friday's attacks introduces post-hoc label leakage and hindsight bias.

### B. Predeclared False-Positive Budget on Benign Thursday Validation Traffic
For Experiment B, the Isolation Forest threshold $\tau_{\text{anomaly}}$ will be calibrated strictly on **benign Thursday validation profiles** ($432,716$ normal profiles):

$$\tau_{\text{anomaly}} = \text{Percentile}\left(\{-\text{decision\_function}(x) \mid x \in \text{Val}_{\text{benign}}\}, \, 100 \times (1 - \alpha)\right)$$

Where $\alpha$ represents the predeclared **False Positive Budget**:
- **Primary Operational Threshold ($\alpha = 0.01$):** 99.0th percentile of benign validation scores (nominal $1.0\%$ validation FPR budget).
- **Conservative Threshold ($\alpha = 0.005$):** 99.5th percentile of benign validation scores (nominal $0.5\%$ validation FPR budget).

### C. Validation and Freezing Procedure:
1. Fit Isolation Forest strictly on Monday–Wednesday benign training profiles ($1,691,758$ profiles).
2. Compute inverted decision scores on Thursday benign validation profiles ($432,716$ profiles).
3. Select $\tau^*$ corresponding to the predeclared false alarm budget $\alpha = 0.01$.
4. **Freeze $\tau^*$ permanently.** Record the exact threshold and empirical validation FPR in `models/saved_exp_b/anomaly_config.json`.
5. Evaluate frozen $\tau^*$ on Friday test profiles without modification.

---

## 8. Outstanding Methodological Risks & Approval Requirements

Before approving Phase 2 (Profile Generation) and Phase 3 (Model Training) for Experiment B, the following methodological risks must be formally acknowledged:

### 1. Confounding of Novelty and Temporal Drift (Unavoidable Dataset Property)
Because Friday traffic was captured on a different day than Monday–Wednesday, an increased false positive rate or lower recall cannot be attributed solely to the attack algorithm. Background traffic fluctuations (domain shift) will contribute to model uncertainty.

### 2. Extreme Base-Rate Imbalance on Friday Test Data
On Friday, attack event profiles represent only $0.2207\%$ of total traffic ($981$ attack profiles vs $443,435$ benign profiles). Even with a highly competitive false alarm rate of $0.50\%$, the system will produce approximately:
$$\text{False Alarms} \approx 443,435 \times 0.0050 = 2,217 \text{ false positives}$$
Against at most $981$ true positives, operational precision will mathematically be constrained to:
$$\text{Precision} \le \frac{981}{981 + 2,217} \approx 30.7\%$$
This reflects the fundamental Base-Rate Fallacy in raw SIEM alert streams and must be reported transparently.

### 3. Limited Test Profile Count for PortScan (52) and DDoS (40)
While `Bot` has strong profile support ($889$ profiles), `PortScan` ($52$) and `DDoS` ($40$) have smaller sample sizes. Individual misclassifications will produce larger percentage step-changes in per-class recall. Confidence intervals must accompany these figures.

### 4. Wednesday Control Split Limitation
As documented in Section 5, Wednesday DoS attacks were too brief (9–24 minutes) to support an intra-day chronological control split without wiping out their training data. Known-attack control will rely primarily on Tuesday's brute-force attacks and Experiment A baseline metrics.

---

## 9. Next Steps Requiring User Approval

Execution remains completely halted. To proceed, the user must review and approve:
1. The revised research framing: *"Unseen Attack Detection Under Temporal and Domain Shift."*
2. The predeclared validation false-positive budget ($\alpha = 0.01$) for Isolation Forest calibration.
3. The separation of Evaluation A (Friday Unseen) and Evaluation B (Known Control).

Upon explicit approval, execution will proceed strictly through Phase 2 (`build_multi_day_profiles.py exp_b`) and Phase 3 (`train_exp_b.py`) under isolated directory paths (`data/processed/event_profiles_exp_b/`, `models/saved_exp_b/`).
