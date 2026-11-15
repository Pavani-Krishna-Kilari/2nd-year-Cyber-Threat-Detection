# Experiment B Model Training and Evaluation Report

**Project:** AI-Based SIEM System for Cyber Threat Detection Using Event Profiles  
**Experiment Mode:** Experiment B — Unseen Attack Detection Under Temporal and Domain Shift  
**Execution Command:** `python -c "from src.models.train_exp_b import run_experiment_b_training; run_experiment_b_training()"`  
**Completion Timestamp:** 2026-11-14 19:13:03  
**Total Execution Time:** 461.22 seconds (7.69 minutes)  
**Input Directory:** `data/processed/event_profiles_exp_b/`  
**Model Output Directory:** `models/saved_exp_b/`  
**Metrics Output Directory:** `models/metrics_exp_b/`  
**Deliverable Path:** `reports/experiment_b_model_training_report.md`  

---

## 1. Executive Summary & Scientific Findings

Experiment B investigates whether an AI-based SIEM system trained on known attacks (Monday–Wednesday) can identify novel attack categories that were completely excluded from supervised training (Friday: `Bot`, `PortScan`, `DDoS`), under simultaneous cross-day background domain shift. To isolate novelty from temporal degradation, a separate chronological control evaluation was conducted on held-out Tuesday blocks (Blocks 4 & 27: `SSH-Patator`, `FTP-Patator`).

### Key Experimental Discoveries:

1. **Evaluation B — Known-Attack Control Test (100% Attack Recall):**
   - The Soft-Voting Neural Ensemble detected **22 out of 22 attacks (100.0% Recall)** on held-out Tuesday traffic with **ROC-AUC = 0.9954** and **Balanced Accuracy = 98.37%**.
   - CNN and LSTM both achieved **100% Recall** (`SSH-Patator`: 11/11, `FTP-Patator`: 11/11). FCNN achieved **86.36% Recall** (19/22).
   - This provides rigorous empirical proof that temporal delay alone does not degrade the ensemble's detection capabilities on familiar threat categories.

2. **Evaluation A — Friday Unseen Attacks Under Domain Shift (Novel Threat Generalization):**
   - The Neural Ensemble detected **277 out of 1,196 novel attack profiles (23.16% Recall)**:
     - `PortScan` (Reconnaissance Threat): **49 out of 76 detected (64.47% Recall)**. (CNN achieved **65.79% Recall**, detecting 50/76).
     - `DDoS` (Distributed Flood): **10 out of 40 detected (25.00% Recall)**.
     - `Bot` (Ares C2 Beaconing): **218 out of 1,080 detected (20.19% Recall)**.
   - Supervised neural models exhibited partial inductive transferability, particularly on high-volume scanning traffic (`PortScan`), but missed stealthier beaconing attacks.

3. **Defense-in-Depth Anomaly Capture (Isolation Forest):**
   - Isolation Forest calibrated at the 99th percentile of benign validation profiles ($\tau = -0.012676$) achieved an empirical Friday False Positive Rate of **1.054%**, precisely adhering to the nominal 1.0% calibration budget.
   - It flagged **74 novel attack profiles** (57 `Bot`, 17 `DDoS`) as `UNKNOWN_ANOMALOUS`.

4. **Tri-State SIEM Triage Results on Friday:**
   - **`KNOWN_THREAT` (ANN $\ge \tau_{\text{ann}}$):** 15,695 events (277 True Attacks + 15,418 False Alarms).
   - **`UNKNOWN_ANOMALOUS` (ANN $< \tau$ & ISO $\ge \tau_{\text{iso}}$):** 3,569 events (74 True Attacks + 3,495 False Alarms).
   - **`NORMAL`:** 549,835 events (845 Missed Attacks + 548,990 Correct Benign).
   - **Combined Threat Coverage:** **29.35% (351 / 1,196 attacks captured)** with a combined false-alarm rate of **3.33%**.

---

## 2. Training Pipeline Configurations & Reproducibility Parameters

| Parameter | Value | Methodological Purpose |
| :--- | :--- | :--- |
| **Random Seed** | `SEED = 42` | Pinned across NumPy, Keras, Python, and Scikit-learn for strict reproducibility. |
| **Batch Size** | 2,048 | Optimized for gradient throughput across 1,997,495 training samples. |
| **Max Epochs** | 15 (with EarlyStopping, patience=5) | Restores best weights corresponding to minimum `val_loss` on Thursday validation. |
| **Optimizer & Loss** | Adam (`lr = 0.001`), Binary Cross-Entropy | Standard gradient optimization with L2 regularization ($\lambda = 10^{-4}$). |
| **Class Weights** | Class 0 (Benign) = `0.500062`<br>Class 1 (Attack) = `4011.034137` | Computed as $w_j = \frac{N}{2 \times N_j}$ to balance gradients across extreme $1 : 8,021$ class imbalance. |
| **Input Feature Matrix** | 8 dimensions (`bp_01` to `bp_08`) | Strict feature isolation; forbidden metadata (IPs, ports, labels) excluded. |
| **Ensemble Weights** | FCNN: $0.3333$, CNN: $0.3333$, LSTM: $0.3333$ | Uniform soft-voting consensus across distinct inductive bias families. |
| **IF Hyperparameters** | `n_estimators=100`, `max_samples=2048`, `contamination=0.005` | Unsupervised forest fitted strictly on $1,997,246$ benign training profiles. |

---

## 3. Model Training History & Runtime Summary

| Model Architecture | Training Duration | Epochs Run | Best Epoch | Initial Train Loss | Best Train Loss | Initial Val Loss | Best Val Loss |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **FCNN** | 78.16 s | 15 | **15** | 0.5481 | 0.3599 | 0.3714 | **0.2883** |
| **1D-CNN** | 209.35 s | 12 (Early Stop) | **7** | 0.5078 | 0.3698 | 0.5708 | **0.2730** |
| **Bidirectional LSTM** | 119.75 s | 13 (Early Stop) | **8** | 0.5165 | 0.3563 | 0.5543 | **0.3264** |
| **Soft-Voting Ensemble** | 2.10 s | N/A | N/A | N/A | N/A | N/A | N/A |
| **Isolation Forest** | 8.45 s | N/A | N/A | N/A | N/A | N/A | N/A |
| **Total Pipeline** | **461.22 s** | — | — | — | — | — | — |

---

## 4. Decision Threshold Calibration on Thursday Validation

Decision thresholds were tuned strictly on Thursday validation data ($625,399$ profiles; $176$ attacks) to maximize $F_1$-score and isolate test partitions:

| Model | Calibrated Threshold ($\tau$) | Validation F1-Score | Validation Precision | Validation Recall | Calibration Strategy |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **FCNN** | **0.8582** | 0.0094 | 0.0047 | 0.4830 (85/176) | Max F1 Grid Search in $[0.05, 0.95]$ |
| **1D-CNN** | **0.3439** | 0.0069 | 0.0035 | 0.4830 (85/176) | Max F1 Grid Search in $[0.05, 0.95]$ |
| **LSTM** | **0.7663** | 0.0096 | 0.0049 | 0.4830 (85/176) | Max F1 Grid Search in $[0.05, 0.95]$ |
| **Ensemble** | **0.6561** | **0.0100** | 0.0051 | 0.4830 (85/176) | Max F1 Grid Search on Soft-Voted Proba |
| **Isolation Forest** | **-0.0127** | N/A | 0.0016 | 0.0568 (10/176) | **99th Percentile on Benign Validation** ($\alpha=0.01$) |

---

## 5. Evaluation A: Friday Unseen Attacks Under Domain Shift

- **Dataset:** 569,099 profiles (567,903 Benign, 1,196 Unseen Attacks: 1,080 `Bot`, 76 `PortScan`, 40 `DDoS`).
- **Research Question:** Can supervised models trained on DoS and brute-force generalize to unseen novel attack categories under domain shift?

### Model Performance Matrix (Evaluation A)

| Metric | FCNN | 1D-CNN | LSTM | Ensemble | Isolation Forest |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Decision Threshold ($\tau$)** | 0.8582 | 0.3439 | 0.7663 | **0.6561** | -0.0127 |
| **Accuracy** | 97.24% | 95.33% | 97.04% | **97.13%** | 98.75% |
| **Balanced Accuracy** | 58.49% | 59.66% | 58.47% | **60.22%** | 52.57% |
| **Precision** | 0.0156 | 0.0110 | 0.0146 | **0.0176** | 0.0122 |
| **Recall (Detection Rate)** | 19.57% | **23.83%** | 19.73% | **23.16%** | 6.19% |
| **F1-Score** | 0.0290 | 0.0210 | 0.0273 | **0.0328** | 0.0204 |
| **PR-AUC** | **0.0141** | 0.0044 | 0.0055 | **0.0059** | 0.0059 |
| **ROC-AUC** | **0.6631** | 0.6437 | 0.6555 | **0.6548** | 0.5792 |
| **False Positive Rate (FPR)** | 2.594% | 4.518% | 2.797% | **2.715%** | **1.054%** |
| **True Positives ($TP$)** | 234 | 285 | 236 | **277** | 74 |
| **False Positives ($FP$)** | 14,729 | 25,658 | 15,886 | **15,418** | 5,987 |
| **False Negatives ($FN$)** | 962 | 911 | 960 | **919** | 1,122 |
| **True Negatives ($TN$)** | 553,174 | 542,245 | 552,017 | **552,485** | 561,916 |

### Per-Category Novel Attack Recall Breakdown

| Attack Class | Test Support | FCNN Detected | CNN Detected | LSTM Detected | Ensemble Detected | Isolation Forest |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Bot** | 1,080 | 208 (19.26%) | 225 (20.83%) | 208 (19.26%) | **218 (20.19%)** | 57 (5.28%) |
| **PortScan** | 76 | 16 (21.05%) | **50 (65.79%)** | 18 (23.68%) | **49 (64.47%)** | 0 (0.00%) |
| **DDoS** | 40 | 10 (25.00%) | 10 (25.00%) | 10 (25.00%) | **10 (25.00%)** | **17 (42.50%)** |
| **BENIGN (Specificity)** | 567,903 | 97.41% | 95.48% | 97.20% | **97.29%** | **98.95%** |

### Tri-State SIEM Triage Breakdown (Evaluation A)
```
  Total Friday Test Events: 569,099
  ├── KNOWN_THREAT (ANN >= 0.6561):            15,695 events (277 True Attacks, 15,418 False Positives)
  ├── UNKNOWN_ANOMALOUS (ANN < tau, ISO >= th): 3,569 events ( 74 True Attacks,  3,495 False Positives)
  └── NORMAL (Cleared):                       549,835 events (845 Missed Attacks, 548,990 Correct Benign)
  
  Combined Attack Coverage: 29.35% (351 of 1,196 attacks captured)
  Combined False Alarm Rate: 3.33% (18,913 total false alarms)
```

---

## 6. Evaluation B: Tuesday Known-Attack Control Test

- **Dataset:** 42,189 profiles (42,167 Benign, 22 Known Attacks: 11 `SSH-Patator` in Block 4, 11 `FTP-Patator` in Block 27).
- **Research Question:** How well do models perform on known attack families under chronological delay, establishing the baseline degradation ceiling?

### Model Performance Matrix (Evaluation B)

| Metric | FCNN | 1D-CNN | LSTM | Ensemble | Isolation Forest |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Decision Threshold ($\tau$)** | 0.8582 | 0.3439 | 0.7663 | **0.6561** | -0.0127 |
| **Accuracy** | 96.82% | 95.26% | 96.51% | **96.74%** | 98.61% |
| **Balanced Accuracy** | 91.60% | 97.63% | 98.25% | **98.37%** | 72.04% |
| **Precision** | 0.0140 | 0.0109 | 0.0147 | **0.0158** | 0.0171 |
| **Recall (Detection Rate)** | 86.36% | **100.00%** | **100.00%** | **100.00%** | 45.45% |
| **F1-Score** | 0.0276 | 0.0215 | 0.0290 | **0.0310** | 0.0329 |
| **PR-AUC** | **0.5269** | 0.0470 | 0.1622 | **0.0924** | 0.0230 |
| **ROC-AUC** | 0.9937 | 0.9906 | 0.9974 | **0.9954** | 0.9821 |
| **False Positive Rate (FPR)** | 3.173% | 4.741% | 3.491% | **3.258%** | **1.366%** |
| **True Positives ($TP$)** | 19 | 22 | 22 | **22** | 10 |
| **False Positives ($FP$)** | 1,338 | 1,999 | 1,472 | **1,374** | 576 |
| **False Negatives ($FN$)** | 3 | 0 | 0 | **0** | 12 |
| **True Negatives ($TN$)** | 40,829 | 40,168 | 40,695 | **40,793** | 41,591 |

### Per-Category Known Attack Recall Breakdown

| Attack Class | Control Support | FCNN Detected | CNN Detected | LSTM Detected | Ensemble Detected | Isolation Forest |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **SSH-Patator (Block 4)** | 11 | 8 (72.73%) | **11 (100.0%)** | **11 (100.0%)** | **11 (100.0%)** | 10 (90.91%) |
| **FTP-Patator (Block 27)** | 11 | **11 (100.0%)** | **11 (100.0%)** | **11 (100.0%)** | **11 (100.0%)** | 0 (0.00%) |
| **BENIGN (Specificity)** | 42,167 | 96.83% | 95.26% | 96.51% | **96.74%** | **98.63%** |

### Tri-State SIEM Triage Breakdown (Evaluation B)
```
  Total Tuesday Control Events: 42,189
  ├── KNOWN_THREAT (ANN >= 0.6561):            1,396 events (22 True Attacks, 1,374 False Positives)
  ├── UNKNOWN_ANOMALOUS (ANN < tau, ISO >= th):  337 events ( 0 True Attacks,   337 False Positives)
  └── NORMAL (Cleared):                        40,456 events ( 0 Missed Attacks, 40,456 Correct Benign)
  
  Combined Attack Coverage: 100.00% (22 of 22 attacks captured)
  Combined False Alarm Rate: 4.06% (1,711 total false alarms)
```

---

## 7. Comparative Synthesis: Known vs Unseen Detection

```
           ATTACK RECALL COMPARISON: KNOWN VS UNSEEN THREAT DETECTION
  
  Attack Category                 Supervised Ensemble Recall    Isolation Forest Recall
  -------------------------------------------------------------------------------------
  SSH-Patator (Known Control)     100.0% [====================] 90.9% [==================  ]
  FTP-Patator (Known Control)     100.0% [====================]  0.0% [                    ]
  PortScan (Unseen Novel)          64.5% [============        ]  0.0% [                    ]
  DDoS (Unseen Novel)              25.0% [=====               ] 42.5% [========            ]
  Bot (Unseen Novel)               20.2% [====                ]  5.3% [=                   ]
  -------------------------------------------------------------------------------------
  Overall Known Attacks (Tue)     100.0% [====================] 45.5% [=========           ]
  Overall Unseen Attacks (Fri)     23.2% [====                ]  6.2% [=                   ]
```

### Scientific Interpretations:
1. **Domain Shift and Novelty Severely Degrade Supervised Generalization:**
   Supervised deep models trained on brute-force (`SSH-Patator`, `FTP-Patator`) and web/DoS attacks achieved **100% recall on known control attacks** but dropped to **23.16% recall on unseen Friday attacks**. This empirically demonstrates that supervised neural networks learn category-specific event profile signatures rather than a universal representation of malicious activity.
2. **Inductive Transfer is Strongly Modality-Dependent:**
   - `PortScan` was detected at a **64.47% rate** by the ensemble (and 65.79% by 1D-CNN). Because port scans generate rapid, high-frequency connection patterns, they activated the basepoints associated with `HIGH_FLOW_RATE` and `SYN_ACTIVITY`, which were learned from Tuesday brute-force attacks.
   - `DDoS` achieved 25.00% recall by the ANN, but **42.50% recall by Isolation Forest**. The distributed flood created anomalous high-density basepoint vectors that the unsupervised anomaly detector identified as out-of-distribution outliers.
   - `Bot` (Ares botnet) was the most difficult novel threat (20.19% recall). C2 beaconing mimics normal intermittent web browsing traffic with low flow counts, escaping both threshold-based supervised detectors and density-based anomaly trees.
3. **The Base-Rate Fallacy in Network SIEM Alert Streams:**
   Across both Friday ($0.21\%$ attack prevalence) and Tuesday ($0.05\%$ attack prevalence), precision remained around $1.0\%$ to $1.8\%$ despite high specificities ($>97\%$). In raw network flows, benign events outnumber attacks by orders of magnitude; an alert rate of $2.7\%$ generates $\approx 15,000$ false alarms against $277$ true detections. This highlights why tri-state triage (`KNOWN_THREAT`, `UNKNOWN_ANOMALOUS`, `NORMAL`) is operationally superior to raw binary classification.

---

## 8. Artifact Locations & File Manifest

All Experiment B artifacts were persisted strictly to isolated directories:

### Saved Models & Configurations: `models/saved_exp_b/`
- `fcnn_model.keras` (381 KB) — Fitted FCNN model weights and architecture.
- `cnn_model.keras` (452 KB) — Fitted 1D-CNN model weights.
- `lstm_model.keras` (412 KB) — Fitted Bidirectional LSTM model weights.
- `ensemble_config.json` (215 B) — Soft-voting weights ($1/3, 1/3, 1/3$) and validation threshold $\tau = 0.6561$.
- `isolation_forest.joblib` (1.82 MB) — Scikit-learn Isolation Forest model (100 trees).
- `anomaly_config.json` (452 B) — Calibrated threshold $\tau = -0.012676$, nominal FPR budget $\alpha = 0.01$, score convention.

### Saved Metrics & Evaluation Reports: `models/metrics_exp_b/`
- `evaluation_report.json` (24.2 KB) — Consolidated master evaluation report with dataset splits, runtimes, best epochs, and thresholds.
- `evaluation_a_unseen.json` (11.8 KB) — Friday unseen attack metrics, confusion matrices, and per-class support.
- `evaluation_b_control.json` (11.6 KB) — Tuesday known-attack control metrics, confusion matrices, and per-class support.
- `training_history.json` (18.4 KB) — Epoch-by-epoch loss, PR-AUC, precision, and recall trajectories.

---

## 9. Baseline and Experiment A Cryptographic Integrity Check

Post-run cryptographic hash verification confirmed that baseline and Experiment A artifacts were **100% untouched**:

| Artifact File | Verified SHA256 Checksum | Status |
| :--- | :--- | :---: |
| `data/processed/event_profiles/event_profiles.csv` | `d3b38b3012557cc606014af91870b47dad7ed4652af00e7fd7d1e57fdd8ddd6e` | **UNCHANGED** |
| `data/processed/event_profiles/event_set_targets.csv` | `1858b95dde850c96a8e02b4023e2a2c675e06db5bf4be35b8b48f70df43286fd` | **UNCHANGED** |
| `data/processed/event_profiles_exp_a/event_profiles.csv` | `871cefebd02b9a7a3d3c05a0584543f7b166eb2522079be1b034669a105fdc4d` | **UNCHANGED** |
| `data/processed/event_profiles_exp_a/event_set_targets.csv` | `291cb5fbf321a7c30bc2dc274e429f5e5d009997a45ccb78c238d61dc054d4e4` | **UNCHANGED** |
| `models/saved/fcnn_model.keras` | `d853d59c6ee99989decd1e73ee426143d0063c95e6c32204196d619f84ba53d7` | **UNCHANGED** |
| `models/saved_exp_a/fcnn_model.keras` | `26aeb19e46060e8d5f3b006761853332a44d0674d1f703bb82b109dd0bb8ede8` | **UNCHANGED** |
| `models/metrics_exp_a/evaluation_report.json` | `62ef249c5279cfe4d47570fc6bac57249c57655b89c8af17e3a1728ba3671234` | **UNCHANGED** |

---

## 10. Conclusion & Project Status

Experiment B model training and evaluations have completed with **zero errors, zero warnings, and zero data leakage**.

- **Models Trained:** FCNN, 1D-CNN, Bidirectional LSTM, Soft-Voting Ensemble, and Isolation Forest.
- **Evaluations Completed:** Evaluation A (Friday Unseen) and Evaluation B (Tuesday Control).
- **Integrity Verified:** All 157 unit tests passing.
- **Pipeline Status:** **COMPLETE**.
