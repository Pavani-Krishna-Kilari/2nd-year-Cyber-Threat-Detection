# Experiment A: Controlled Model Training and Benchmark Report

**Project:** AI-Based SIEM System for Cyber Threat Detection Using Event Profiles  
**Execution Timestamp:** 2026-11-14 12:24:23  
**Pipeline Runtime:** 251.47 seconds (~4.2 minutes)  
**Input Feature Store:** `data/processed/event_profiles_exp_a/`  
**Saved Models Directory:** `models/saved_exp_a/`  
**Saved Metrics Directory:** `models/metrics_exp_a/`  

---

## 1. Executive Summary

Controlled model training and empirical evaluation have completed for **Experiment A** (Multi-Day Time-Blocked Classification) across the full CICIDS2017 5-day capture corpus. Five threat detection architectures were trained and evaluated under strict methodological safeguards:
1. **FCNN (Fully Connected Neural Network):** Tabular baseline MLP.
2. **1D-CNN (1D Convolutional Neural Network):** Prototype spatial-feature comparison.
3. **LSTM (Bidirectional LSTM):** Recurrent prototype baseline.
4. **Soft-Voting Ensemble:** Probability-weighted consensus of FCNN, CNN, and LSTM.
5. **Isolation Forest:** Unsupervised anomaly detector fitted strictly on 1,934,373 benign training profiles.

All supervised models were trained on 1,935,461 training event sets using balanced class weighting ($w_0 = 0.5003, w_1 = 889.4582$) to counter severe class imbalance ($1 : 1,778.9$). Decision thresholds ($\tau$) were calibrated exclusively on 321,262 validation profiles to maximize validation $F_1$-score, and final benchmark metrics were computed on 312,537 held-out test profiles.

### Key Benchmark Takeaways:
- **Best Overall Threat Recall & Detection:** **LSTM** and **FCNN** tied with the highest attack recall on the held-out test set (**24.49%**, detecting 24 of 98 attack profiles) while maintaining $>98.3\%$ accuracy.
- **Lowest Operational False-Alarm Rate:** **1D-CNN** achieved the lowest False Positive Rate (**1.14%**, 3,574 false alarms out of 312,439 normal profiles) and highest ROC-AUC (**0.7025**), detecting 15 of 98 attacks (**15.31%** recall).
- **Consensus Behavior:** The **Soft-Voting Ensemble** detected 17 of 98 attacks (**17.35%** recall) with a 1.84% FPR (5,750 false alarms).
- **Targeted Class Sensitivity:** All supervised neural architectures demonstrated **100% detection recall on Web Attack – Brute Force** (11/11 profiles) and strong detection on **SSH-Patator** (up to 100% recall for FCNN and LSTM).
- **Unsupervised Anomaly Boundary Collapse:** **Isolation Forest** failed to isolate threats on the 8-dimensional cosine similarity space ($\text{Recall} = 0.00\%$, detecting 0 of 98 attacks), confirming that unsupervised volumetric distance on normalized TF-IDF cosine basepoints is inadequate for high-dimensional cyber threat boundary separation without supervision.
- **Baseline Integrity:** Crytographic validation confirmed that the Tuesday baseline profiles (`data/processed/event_profiles/`) and baseline models (`models/saved/`) remained **100% untouched** (SHA-256 verified).

---

## 2. Experimental Methodology & Safeguard Compliance

| Safeguard / Constraint | Implementation Verification | Status |
| :--- | :--- | :--- |
| **Input Directory Isolation** | Inputs loaded exclusively from `data/processed/event_profiles_exp_a/` | Verified |
| **Model Output Isolation** | Saved weights written exclusively to `models/saved_exp_a/` | Verified |
| **Metrics Output Isolation** | Evaluation outputs written exclusively to `models/metrics_exp_a/` | Verified |
| **Feature Boundary Enforcement** | Strict restriction: only `bp_01` through `bp_08` enter models. All IDs, IPs, ports, timestamps excluded | Verified |
| **Target Separation** | Targets loaded from separate `event_set_targets.csv` via validated 1-to-1 inner join on `event_set_id` | Verified |
| **Split Isolation** | Chronological 5-day time-blocked partitions; training used for fitting only | Verified |
| **Threshold Calibration** | Optimal decision thresholds $\tau$ tuned strictly on validation split; zero test data used | Verified |
| **No Test Oversampling** | Validation and test sets evaluated in their natural, unmodified class distributions | Verified |
| **Class Weighting** | Inverse frequency class weights applied in cross-entropy loss ($w_0 = 0.500281, w_1 = 889.458180$) | Verified |
| **Isolation Forest Scope** | Fitted exclusively on $N = 1,934,373$ benign training profiles (`target_binary == 0`) | Verified |
| **Baseline Preservation** | SHA-256 hash validation before and after training on Tuesday baseline files | Verified |

### Dataset Partitioning Summary:
- **Training Set:** 1,935,461 event sets (1,934,373 Benign [99.94%], 1,088 Attack [0.06%]). Imbalance ratio $1 : 1,778.9$.
- **Validation Set:** 321,262 event sets (321,097 Benign, 165 Attack).
- **Held-Out Test Set:** 312,537 event sets (312,439 Benign, 98 Attack).

---

## 3. Model Architecture & Training Dynamics

All neural models were implemented in Keras 3 with TensorFlow backend, optimized using Adam ($\text{lr} = 0.001$), binary cross-entropy loss with class weights, batch size 2,048, and early stopping on validation loss (patience 5):

```
+---------------------------------------------------------------------------------------------------+
| Model Architectures                                                                               |
+-------------------+-------------------------------------------------------------------------------+
| FCNN (Tabular)    | Input(8) -> Dense(64, ReLU, L2) -> BatchNorm -> Dropout(0.3)                  |
|                   |          -> Dense(32, ReLU, L2) -> BatchNorm -> Dropout(0.2)                  |
|                   |          -> Dense(16, ReLU) -> Dense(1, Sigmoid)                             |
+-------------------+-------------------------------------------------------------------------------+
| 1D-CNN            | Input(8) -> Reshape(8, 1) -> Conv1D(32, k=3, ReLU, L2) -> BatchNorm           |
|                   |                           -> Conv1D(64, k=3, ReLU, L2) -> GlobalMaxPool1D     |
|                   |                           -> Dense(32, ReLU) -> Dropout(0.2) -> Dense(1, Sig) |
+-------------------+-------------------------------------------------------------------------------+
| LSTM              | Input(8) -> Reshape(1, 8) -> Bidirectional(LSTM(32, L2)) -> BatchNorm         |
|                   |                           -> Dense(16, ReLU) -> Dropout(0.2) -> Dense(1, Sig) |
+-------------------+-------------------------------------------------------------------------------+
| Soft-Voting Ens.  | P_ens = (1/3)*P_FCNN + (1/3)*P_CNN + (1/3)*P_LSTM                             |
+-------------------+-------------------------------------------------------------------------------+
| Isolation Forest  | 100 Isolation Trees, max_samples=2048, contamination=0.005, Benign-only       |
+-------------------+-------------------------------------------------------------------------------+
```

### Training Convergence and Compute Runtimes:

| Model | Training Time (s) | Best Epoch | Val Loss at Best Epoch | Calibrated Threshold ($\tau$) |
| :--- | :---: | :---: | :---: | :---: |
| **FCNN** | 40.60 s | Epoch 5 / 15 | 0.5057 | 0.8949 |
| **1D-CNN** | 100.76 s | Epoch 6 / 15 | 0.4468 | 0.8582 |
| **LSTM** | 82.84 s | Epoch 11 / 15 | 0.4537 | 0.8398 |
| **Soft-Voting Ensemble** | 0.80 s | N/A (Composite) | N/A | 0.8398 |
| **Isolation Forest** | 6.22 s | N/A (Unsupervised) | N/A | 0.0500 |
| **Total Pipeline** | **251.47 s** | — | — | — |

---

## 4. Validation Performance & Threshold Optimization

Decision thresholds $\tau \in [0.05, 0.95]$ were tuned strictly on the 321,262 validation profiles to optimize the SIEM detection trade-off. Because class weighting heavily scales positive gradients during training, raw sigmoid probabilities naturally shift toward higher values. The validation calibration selected optimal thresholds between 0.8398 and 0.8949:

| Model | Val Accuracy | Val Balanced Acc | Val Precision | Val Recall | Val $F_1$ | Val PR-AUC | Val ROC-AUC | Val FPR | False Alarms |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **FCNN** | 97.88% | 57.44% | 0.0042 | 16.97% | 0.0081 | 0.0010 | 0.6277 | 2.08% | 6,681 |
| **1D-CNN** | 98.33% | 57.67% | 0.0053 | 16.97% | 0.0103 | 0.0013 | 0.6338 | 1.63% | 5,220 |
| **LSTM** | 98.11% | 57.82% | 0.0047 | 17.58% | 0.0092 | 0.0012 | 0.6267 | 1.85% | 5,938 |
| **Ensemble** | 97.60% | 57.61% | 0.0038 | 17.58% | 0.0075 | 0.0011 | 0.6228 | 2.36% | 7,588 |
| **Isolation Forest** | 99.91% | 49.98% | 0.0000 | 0.00% | 0.0000 | 0.0007 | 0.4763 | 0.04% | 134 |

---

## 5. Held-Out Test Split Benchmark Evaluation

The held-out test split comprises **312,537 event profiles** (312,439 Benign and 98 Attack). Models were evaluated using the frozen thresholds calibrated on validation.

### Comprehensive Model Benchmark Comparison Table:

| Metric | FCNN | 1D-CNN | LSTM | Soft-Voting Ensemble | Isolation Forest |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Optimal Threshold ($\tau$)** | `0.8949` | `0.8582` | `0.8398` | `0.8398` | `0.0500` |
| **Accuracy** | 98.36% | **98.83%** | 98.44% | 98.13% | 99.89% |
| **Balanced Accuracy** | 61.44% | 57.08% | **61.47%** | 57.75% | 49.96% |
| **Precision** | 0.0047 | 0.0042 | **0.0050** | 0.0029 | 0.0000 |
| **Recall (Detection Rate)** | **24.49%** | 15.31% | **24.49%** | 17.35% | 0.00% |
| **True Positives (Attacks Detected)** | **24 / 98** | 15 / 98 | **24 / 98** | 17 / 98 | 0 / 98 |
| **False Positives (False Alarms)** | 5,040 | **3,574** | 4,815 | 5,750 | 252 |
| **False Positive Rate (FPR)** | 1.6131% | **1.1439%** | 1.5411% | 1.8404% | **0.0807%** |
| **$F_1$-Score** | 0.0093 | 0.0081 | **0.0097** | 0.0058 | 0.0000 |
| **Macro $F_1$** | 0.5005 | **0.5011** | 0.5009 | 0.4982 | 0.4997 |
| **Weighted $F_1$** | 0.9914 | **0.9938** | 0.9918 | 0.9903 | 0.9991 |
| **PR-AUC** | 0.0013 | **0.0021** | 0.0020 | 0.0016 | 0.0024 |
| **ROC-AUC** | 0.6981 | **0.7025** | 0.6964 | 0.6952 | 0.5697 |
| **True Negatives (TN)** | 307,399 | 308,865 | 307,624 | 306,689 | 312,187 |
| **False Negatives (FN)** | 74 | 83 | 74 | 81 | 98 |

### Confusion Matrices:

```
FCNN Confusion Matrix:
               Predicted Benign    Predicted Attack
Actual Benign       307,399              5,040
Actual Attack            74                 24

1D-CNN Confusion Matrix:
               Predicted Benign    Predicted Attack
Actual Benign       308,865              3,574
Actual Attack            83                 15

LSTM Confusion Matrix:
               Predicted Benign    Predicted Attack
Actual Benign       307,624              4,815
Actual Attack            74                 24

Ensemble Confusion Matrix:
               Predicted Benign    Predicted Attack
Actual Benign       306,689              5,750
Actual Attack            81                 17

Isolation Forest Confusion Matrix:
               Predicted Benign    Predicted Attack
Actual Benign       312,187                252
Actual Attack            98                  0
```

---

## 6. Per-Class Attack Support and Detection Breakdown

In accordance with strict evaluation integrity, all 15 known CICIDS2017 classes are documented below. For the 7 attack classes that were entirely absorbed into the training partition due to raw capture burst durations, their status is transparently marked as `UNTESTED_IN_SPLIT` with `N/A (0 test support)`:

| Attack Class | Test Support | FCNN Recall | 1D-CNN Recall | LSTM Recall | Ensemble Recall | Isolation Forest Recall | Evaluation Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **BENIGN** | 312,439 | 98.39% (307,399) | **98.86%** (308,865) | 98.46% (307,624) | 98.16% (306,689) | **99.92%** (312,187) | `EVALUATED` |
| **Bot** | 60 | 0.00% (0/60) | 0.00% (0/60) | 0.00% (0/60) | 0.00% (0/60) | 0.00% (0/60) | `EVALUATED` |
| **DDoS** | 0 | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | `UNTESTED_IN_SPLIT` |
| **DoS GoldenEye** | 0 | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | `UNTESTED_IN_SPLIT` |
| **DoS Hulk** | 0 | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | `UNTESTED_IN_SPLIT` |
| **DoS Slowhttptest** | 0 | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | `UNTESTED_IN_SPLIT` |
| **DoS slowloris** | 1 | 0.00% (0/1) | 0.00% (0/1) | 0.00% (0/1) | 0.00% (0/1) | 0.00% (0/1) | `EVALUATED` |
| **FTP-Patator** | 3 | **33.33%** (1/3) | **33.33%** (1/3) | **33.33%** (1/3) | **33.33%** (1/3) | 0.00% (0/3) | `EVALUATED` |
| **Heartbleed** | 0 | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | `UNTESTED_IN_SPLIT` |
| **Infiltration** | 3 | 0.00% (0/3) | 0.00% (0/3) | 0.00% (0/3) | 0.00% (0/3) | 0.00% (0/3) | `EVALUATED` |
| **PortScan** | 9 | 11.11% (1/9) | 11.11% (1/9) | 11.11% (1/9) | **33.33%** (3/9) | 0.00% (0/9) | `EVALUATED` |
| **SSH-Patator** | 11 | **100.00%** (11/11) | 18.18% (2/11) | **100.00%** (11/11) | 18.18% (2/11) | 0.00% (0/11) | `EVALUATED` |
| **Web Attack - Brute Force**| 11 | **100.00%** (11/11) | **100.00%** (11/11) | **100.00%** (11/11) | **100.00%** (11/11) | 0.00% (0/11) | `EVALUATED` |
| **Web Attack - Sql Inj.** | 0 | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | `UNTESTED_IN_SPLIT` |
| **Web Attack - XSS** | 0 | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | N/A (0 test support) | `UNTESTED_IN_SPLIT` |

---

## 7. SIEM Operational Analysis & Methodology Findings

### A. Attack Detection Profile Analysis:
1. **Web Attack - Brute Force (100% Recall across all supervised models):**
   - Profile structure: Generates distinct high-frequency token bursts across HTTP flows. Because the training partition contained representative web attack patterns from Thursday morning, the basepoint similarity vectors for brute force attacks were distinct and consistent, allowing FCNN, CNN, LSTM, and Ensemble to flag all 11 test instances without omission.
2. **SSH-Patator (100% Recall for FCNN and LSTM):**
   - High-volume authentication attempts triggered high-flow and high-packet rate tokens. FCNN and LSTM captured this signature cleanly. CNN, due to local convolution kernels treating basepoints as 1D sequence neighbours, only detected 2/11, underscoring that basepoint ordering does not inherently possess 1D translation invariance.
3. **Bot Traffic (0% Recall across all models, 0/60):**
   - Ares Botnet traffic mimics benign web requests with low flow volumes spread across wide intervals. In a 10-minute sliding window with 60s step, the TF-IDF representation of Bot traffic closely resembles routine background HTTP activity, resulting in cosine similarity profiles that blend directly into normal distributions.
4. **Infiltration (0% Recall, 0/3):**
   - As noted in the methodology audit, Infiltration represents an extremely subtle meta-exploit followed by port scanning on a single machine. Its volumetric and token footprint is indistinguishable from administrative activity in 10-minute windows.

### B. The Base-Rate Fallacy in SIEM Threat Detection:
- While an accuracy of **98.83%** and a False Positive Rate of **1.14%** appear statistically strong, in a SIEM production environment monitoring 312,537 flow windows, a 1.14% FPR generates **3,574 false alarms** against 98 true attacks.
- Consequently, the **Precision** is bounded between **0.29% and 0.50%** (roughly 1 true threat for every 200 alerts).
- This is a direct mathematical consequence of the extreme base-rate imbalance ($0.031\%$ true threat prevalence in test) and highlights why event profile similarity scores must be combined with downstream SIEM correlation engines rather than treated as autonomous blocking signals.

### C. Isolation Forest Failure Analysis:
- Isolation Forest fitted on benign profiles achieved **0.00% recall** on attacks in the test split.
- Because basepoint dimensions `bp_01` through `bp_08` are bounded cosine similarities ($\in [0, 1]$), benign profiles densely span the multi-dimensional unit hypercube. Attack event sets, being sparse and low-volume, do not manifest as isolated geometric outliers; instead, their cosine similarities to the selected basepoints fall directly inside the high-density benign cloud.
- Unsupervised tree partitioning on basepoints alone is therefore incapable of separating subtle attacks without supervision.

---

## 8. Cryptographic Baseline Verification & Storage Integrity

All models and benchmark outputs for Experiment A are stored in isolated directories. Cryptographic integrity checks confirmed that the baseline Tuesday event profiles and saved models were completely untouched.

### Output Artifacts Generated:

| Directory | File | Size | Description |
| :--- | :--- | :---: | :--- |
| `models/saved_exp_a/` | `fcnn_model.keras` | 92.8 KB | Trained FCNN Keras weights and architecture |
| `models/saved_exp_a/` | `cnn_model.keras` | 150.4 KB | Trained 1D-CNN Keras weights and architecture |
| `models/saved_exp_a/` | `lstm_model.keras` | 194.5 KB | Trained LSTM Keras weights and architecture |
| `models/saved_exp_a/` | `ensemble_config.json` | 214 B | Soft-voting consensus weights and calibrated $\tau$ |
| `models/saved_exp_a/` | `isolation_forest.joblib` | 2.26 MB | Fitted benign-only Isolation Forest scikit-learn model |
| `models/metrics_exp_a/` | `evaluation_report.json` | 34.5 KB | Complete JSON benchmark results and per-class metrics |
| `models/metrics_exp_a/` | `training_history.json` | 10.9 KB | Per-epoch loss, accuracy, PR-AUC, precision, recall |

### Baseline Cryptographic Hash Verification:

| Target File | Verified SHA-256 Hash | Preservation Status |
| :--- | :--- | :---: |
| `data/processed/event_profiles/event_profiles.csv` | `D3B38B3012557CC606014AF91870B47DAD7ED4652AF00E7FD7D1E57FDD8DDD6E` | **FROZEN & UNTOUCHED** |
| `data/processed/event_profiles/event_profiles_metadata.json` | `CE6234392C0E8682732795B64F7A553736879B7F8D5869F52A0AD11D73F81E54` | **FROZEN & UNTOUCHED** |
| `models/saved/` | Original baseline files preserved | **FROZEN & UNTOUCHED** |

---

## 9. Conclusion & Project Next Steps

**Experiment A has completed with 100% safeguard compliance.**
All models are fully trained, validated, benchmarked, and serialized under `models/saved_exp_a/` and `models/metrics_exp_a/`.

In accordance with strict project instructions, **all operations are now HALTED before Experiment B**. Model training and profile generation for Experiment B (Unseen Attack Detection on Friday holdout) require explicit user approval.
