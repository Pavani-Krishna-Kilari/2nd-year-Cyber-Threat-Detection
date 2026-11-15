# Experiment A: Model Evaluation and Inference Pipeline Audit Report

**Project Title:** AI-Based SIEM System for Cyber Threat Detection Using Event Profiles  
**Audit Type:** Read-Only Post-Training Evaluation and Inference Audit  
**Date & Timestamp:** 2026-11-14 13:20:00  
**Scope:** Experiment A (Multi-Day Evaluation), Model Artifacts, Inference Engine, Backend Integration  
**Audited Artifacts:**
- Reports: `reports/experiment_a_model_training_report.md`
- Metrics: `models/metrics_exp_a/evaluation_report.json`, `models/metrics_exp_a/training_history.json`
- Baseline Artifacts: `models/metrics/evaluation_report.json`, `models/saved/`
- Training Code: `src/models/train_exp_a.py`, `src/models/train.py`
- Model Definitions: `src/models/fcnn.py`, `src/models/cnn.py`, `src/models/lstm.py`, `src/models/ensemble.py`, `src/models/anomaly.py`
- Inference & Backend: `src/inference/predict.py`, `src/inference/decision_policy.py`, `backend/service.py`, `backend/main.py`, `backend/parser.py`

---

## 1. Executive Summary

A comprehensive, read-only audit of the model training outputs, statistical evaluation metrics, inference engine, and backend service integration for **Experiment A** was conducted.

### Major Audit Findings:
1. **Mathematical Accuracy of Published Metrics (PASS):**
   Independent recalculation of all metrics (Confusion Matrices, Accuracy, Balanced Accuracy, Precision, Recall, $F_1$, PR-AUC, ROC-AUC, FPR) from the serialized model weights on the 312,537 held-out test profiles verified that the published benchmark report is **100% accurate down to the last decimal place**.
2. **Backend / Dashboard Model Loading Disconnect (CRITICAL FINDING):**
   The live FastAPI backend (`backend/service.py`) and inference engine (`src/inference/predict.py`) currently load the **Tuesday baseline models** (`models/saved/`) and **Tuesday metadata** (`models/metrics/`, `Tuesday-WorkingHours_metadata.json`), **NOT** the newly trained Experiment A models (`models/saved_exp_a/`).
3. **Attack Subclass Classification via Port Heuristics (METHODOLOGICAL FINDING):**
   The neural network models are **pure binary classifiers** (`Sigmoid` output). Specific attack subclasses (such as "FTP-Patator" vs "SSH-Patator") are **not predicted by the ANN**; instead, they are inferred through rule-based heuristics on the destination port (`port == 21` or `port == 22`) in `src/inference/decision_policy.py`.
4. **Isolation Forest Zero-Recall Cause Identified (CONFIRMED BUG):**
   The Isolation Forest achieved 0% attack recall because the threshold optimization function in `train_exp_a.py` searched only in $[0.05, 0.95]$ (treating scores as probabilities). In reality, the inverted decision function values for all test attacks maxed out at $+0.0086$, so a threshold of $0.0500$ mathematically guaranteed zero attack detections.
5. **Ensemble Sub-optimality Explained:**
   The soft-voting ensemble performed worse than the individual FCNN and LSTM models ($17.35\%$ recall vs $24.49\%$, with higher false alarms: 5,750 vs 5,040). This occurred because the CNN underperformed on several attack types, dragging the consensus probability below the high decision threshold ($\tau = 0.8398$).

---

## 2. Independent Metric Recalculation & Verification

Using a standalone, read-only verification script, the saved models (`fcnn_model.keras`, `cnn_model.keras`, `lstm_model.keras`, `ensemble_config.json`, `isolation_forest.joblib`) were loaded and evaluated on the exact held-out test split of 312,537 profiles (312,439 Benign, 98 Attack).

### Verification Results Table:

| Metric | Published FCNN | Recalculated FCNN | Published CNN | Recalculated CNN | Published LSTM | Recalculated LSTM | Published Ensemble | Recalculated Ensemble | Published IsoForest | Recalculated IsoForest | Audit Check |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Threshold ($\tau$)** | 0.8949 | 0.8949 | 0.8582 | 0.8582 | 0.8398 | 0.8398 | 0.8398 | 0.8398 | 0.0500 | 0.0500 | **MATCH** |
| **Accuracy** | 98.36% | 98.36% | 98.83% | 98.83% | 98.44% | 98.44% | 98.13% | 98.13% | 99.89% | 99.89% | **MATCH** |
| **Balanced Acc** | 61.44% | 61.44% | 57.08% | 57.08% | 61.47% | 61.47% | 57.75% | 57.75% | 49.96% | 49.96% | **MATCH** |
| **Precision** | 0.0047 | 0.0047 | 0.0042 | 0.0042 | 0.0050 | 0.0050 | 0.0029 | 0.0029 | 0.0000 | 0.0000 | **MATCH** |
| **Recall** | 24.49% | 24.49% | 15.31% | 15.31% | 24.49% | 24.49% | 17.35% | 17.35% | 0.00% | 0.00% | **MATCH** |
| **$F_1$-Score** | 0.0093 | 0.0093 | 0.0081 | 0.0081 | 0.0097 | 0.0097 | 0.0058 | 0.0058 | 0.0000 | 0.0000 | **MATCH** |
| **ROC-AUC** | 0.6981 | 0.6981 | 0.7025 | 0.7025 | 0.6964 | 0.6964 | 0.6952 | 0.6952 | 0.5697 | 0.5697 | **MATCH** |
| **PR-AUC** | 0.001287 | 0.001287 | 0.002059 | 0.002059 | 0.002010 | 0.002010 | 0.001583 | 0.001583 | 0.002350 | 0.002350 | **MATCH** |
| **FPR** | 1.6131% | 1.6131% | 1.1439% | 1.1439% | 1.5411% | 1.5411% | 1.8404% | 1.8404% | 0.0807% | 0.0807% | **MATCH** |
| **True Positives (TP)**| 24 | 24 | 15 | 15 | 24 | 24 | 17 | 17 | 0 | 0 | **MATCH** |
| **False Positives (FP)**| 5,040 | 5,040 | 3,574 | 3,574 | 4,815 | 4,815 | 5,750 | 5,750 | 252 | 252 | **MATCH** |
| **True Negatives (TN)**| 307,399 | 307,399 | 308,865 | 308,865 | 307,624 | 307,624 | 306,689 | 306,689 | 312,187 | 312,187 | **MATCH** |
| **False Negatives (FN)**| 74 | 74 | 83 | 83 | 74 | 74 | 81 | 81 | 98 | 98 | **MATCH** |

**Conclusion on Recalculation:** **PASS**. There is zero metric fabrication or reporting discrepancy.

---

## 3. Analysis of PR-AUC, ROC-AUC, and the Base-Rate Fallacy

### A. Positive Class Prevalence (Random Guessing Baseline)
In binary classification, while ROC-AUC has a random baseline of $0.5000$, the baseline for **PR-AUC (Precision-Recall AUC)** is equal to the **positive class prevalence**:
$$\text{Baseline PR-AUC} = \frac{P}{P + N} = \frac{98}{312,537} = 0.00031356 \quad (0.03136\%)$$

### B. Comparison to Baseline:
- **FCNN:** PR-AUC $= 0.001287$ ($4.1\times$ above random guessing).
- **1D-CNN:** PR-AUC $= 0.002059$ ($6.6\times$ above random guessing).
- **LSTM:** PR-AUC $= 0.002010$ ($6.4\times$ above random guessing).
- **Ensemble:** PR-AUC $= 0.001583$ ($5.0\times$ above random guessing).
- **Isolation Forest:** PR-AUC $= 0.002350$ ($7.5\times$ above random guessing).

Both ROC-AUC and PR-AUC were verified to be calculated on **continuous probability scores** (`roc_auc_score(y_test, p_scores)` and `average_precision_score(y_test, p_scores)`), not binary thresholded values.

### C. Why Precision Is So Low ($0.29\% - 0.50\%$):
A beginner might ask: *"How can a model have 98.83% accuracy and a 1.14% false positive rate, but only 0.42% precision?"*
This is the classic **Base-Rate Fallacy in Cybersecurity**:
1. True attacks are extremely rare ($98$ out of $312,537$, or $0.031\%$).
2. Normal traffic is vast ($312,439$ flows).
3. Even a very small False Positive Rate of $1.14\%$ on $312,439$ normal flows produces:
   $$\text{False Positives} = 312,439 \times 0.011439 = 3,574 \text{ false alarms}$$
4. Against $15$ True Positives:
   $$\text{Precision} = \frac{15}{15 + 3,574} = \frac{15}{3,589} \approx 0.00418 \quad (0.42\%)$$
For every $1$ real attack flagged by the CNN, security analysts receive $\approx 238$ false alarms. This is an unavoidable mathematical reality of extreme base-rate imbalance when classification is performed on single windows without multi-stage SIEM aggregation.

---

## 4. Binary vs Multiclass Evaluation & Port Heuristic Analysis

### A. Network Architecture vs Problem Definition:
- All models (FCNN, CNN, LSTM) were constructed with a single sigmoid output:
  `outputs = layers.Dense(1, activation="sigmoid", name="threat_probability")(x)`
- The models are **purely binary**: they classify an event profile as `0 (BENIGN)` or `1 (THREAT)`.
- In `train_exp_a.py`, per-class recall was evaluated by grouping the test set by `target_label` and measuring what percentage received a binary prediction of `1`. This was implemented correctly and consistently.

### B. Destination Port Heuristic for Attack Naming:
An inspection of `src/inference/decision_policy.py` reveals lines 104–112:
```python
if destination_port == 21:
    cls_name = "FTP-Patator Brute Force"
elif destination_port == 22:
    cls_name = "SSH-Patator Brute Force"
elif dominant_basepoint in ["bp_03", "bp_07"]:
    cls_name = "SYN/Port Scan"
else:
    cls_name = "Known Patator Threat Pattern"
```
**Audit Finding:**
- The system **does not use a multiclass neural network** to identify the specific attack type.
- Instead, when the binary neural network flags a profile as a threat, the system inspects `destination_port`:
  - Port 21 $\rightarrow$ labelled "FTP-Patator Brute Force"
  - Port 22 $\rightarrow$ labelled "SSH-Patator Brute Force"
  - Otherwise $\rightarrow$ "SYN/Port Scan" or "Known Patator Threat Pattern".
- In `backend/service.py` (line 232), if an uploaded profile CSV lacks destination port information, the code substitutes a default:
  `dst_port = int(row.get("destination_port", 21 if pred["verdict"] in ["THREAT", "KNOWN_THREAT"] else 443))`
  This artificially forces threats without port metadata to display as "FTP-Patator Brute Force" on the dashboard.
- **Rule Verification:** While ports are **never** fed into the neural network feature inputs (preserving feature boundary integrity), using port heuristics to name the attack category is brittle and misleading in a multi-attack dataset containing Web Attacks, DoS, and Botnets.

---

## 5. Threshold Calibration & Class Weighting Audit

### A. Threshold Calibration:
- **Leakage Prevention:** CONFIRMED. All thresholds were calibrated strictly on the validation set (`y_val` and `val_probas`) by maximizing $F_1$. No test data was accessed during calibration.
- **Limitation of $F_1$ Optimization:** Because $F_1$ is sensitive to extreme class imbalance, the optimization pushed thresholds into the high range ($\tau \in [0.8398, 0.8949]$). This suppressed false alarms to $\approx 1.5\%$, but at the cost of capping attack recall at $\approx 24.5\%$.

### B. Class Weighting Implementation:
- In `train_exp_a.py`, class weights were calculated as:
  $$w_0 = \frac{N}{2 \times N_0} = 0.500281, \quad w_1 = \frac{N}{2 \times N_1} = 889.458180$$
- Passed to Keras as `model.fit(..., class_weight={0: w0, 1: w1})`.
- In Keras 3 / TensorFlow, passing a dictionary mapping integer class labels `{0: w0, 1: w1}` to `class_weight` during binary cross-entropy applies cost scaling directly to the loss gradients of the positive class.
- **Double Weighting Check:** No sample weights, oversampling, or duplicate samplers were applied. There was **no double weighting**.

---

## 6. Isolation Forest Deep-Dive: Root Cause of Zero Detections

The test evaluation reported:
$$\text{Isolation Forest Recall} = 0.00\% \quad (0 / 98 \text{ attacks detected})$$

### Empirical Distribution Analysis:
To determine why zero attacks were detected, the exact distribution of the inverted decision function scores ($- \text{decision\_function}(X)$) on the test set was analyzed:
- **Normal Flow Scores:**
  - Min: $-0.2676$, Median: $-0.2676$, 95th Percentile: $-0.0679$, 99th Percentile: $-0.0103$, Max: $+0.0868$
- **Attack Flow Scores:**
  - Min: $-0.2676$, Median: $-0.2676$, 95th Percentile: $+0.0055$, Max: $\mathbf{+0.0086}$
- **Selected Threshold:** $\tau = \mathbf{0.0500}$

### Root Cause Explanation:
1. **The Grid Search Range Bug:**
   In `train_exp_a.py`, the threshold optimization routine was defined as:
   ```python
   def find_optimal_threshold(y_true, y_proba, num_steps=50):
       for thresh in np.linspace(0.05, 0.95, num_steps):
           ...
   ```
   This function assumed all model outputs are probabilities bounded in $[0.0, 1.0]$. However, Isolation Forest decision scores are **unbounded real numbers centered around 0**, not probabilities.
   The lowest threshold tested was $0.0500$.
2. **Mathematical Impossibility:**
   Because the highest score achieved by **any attack** in the test set was $+0.0086$, and the threshold was set at $0.0500$, it was mathematically impossible for any attack to be detected ($0.0086 < 0.0500$).
3. **Representation Overlap:**
   Even if the threshold had been set at $0.0000$ (catching attacks with positive scores), normal traffic also spans positive scores up to $+0.0868$. In the 8-dimensional cosine similarity space, attack profiles do not form distant spatial outliers from normal traffic; instead, they sit directly inside the dense cluster of normal cosine vectors.

---

## 7. Ensemble Performance Analysis

The Soft-Voting Ensemble achieved:
- Test Recall: **17.35%** (17 / 98), lower than FCNN (24.49%) and LSTM (24.49%).
- False Positives: **5,750**, higher than FCNN (5,040), CNN (3,574), or LSTM (4,815).
- $F_1$-Score: **0.0058**, the lowest among all supervised models.

### Mechanism of Degradation:
1. **Divergent Detection:**
   FCNN and LSTM detected 24 attacks, while CNN detected only 15. For the 9 attacks where CNN failed, its predicted threat probability was low ($\approx 0.10 - 0.30$).
2. **Probability Dilution:**
   When averaging $\frac{P_{\text{FCNN}} + P_{\text{CNN}} + P_{\text{LSTM}}}{3}$, CNN's low probability dragged the average score below the ensemble threshold ($\tau = 0.8398$) for 7 attacks. Consequently, True Positives dropped from 24 to 17.
3. **Additive False Alarms:**
   Because the three models misclassified different, non-overlapping subsets of normal flows, the ensemble accumulated false positives whenever any two models agreed on an error or one model produced a strong spike, yielding 5,750 false alarms.

---

## 8. Dashboard and Backend Integration Audit

A line-by-line inspection of `backend/service.py`, `backend/main.py`, and `src/inference/predict.py` revealed four architectural disconnects between the current dashboard and Experiment A:

```
[Current System Architecture & Disconnects]

  Actual Dashboard Request
            │
            ▼
    backend/service.py
            │
            ├──> ThreatInferenceEngine() ──> Loads models/saved/ (Tuesday Baseline, NOT Exp A)
            │                                Loads data/processed/event_profiles/ (Tuesday Baseline)
            │
            ├──> AnomalyDetector() ─────────> Loads models/saved/isolation_forest.joblib (Tuesday Baseline)
            │
            ├──> get_model_benchmarks() ────> Reads models/metrics/evaluation_report.json (Tuesday Baseline)
            │
            └──> decision_policy.py ────────> Uses hardcoded Tuesday thresholds:
                                                tau_threat = 0.95
                                                tau_normal = 0.30
                                                tau_anomaly = -0.0148
```

### Specific Disconnects:
1. **Model Loading Target:**
   `ThreatInferenceEngine.__init__` in `src/inference/predict.py` defaults to `PROJECT_ROOT / "models" / "saved"`. It does not load `models/saved_exp_a/`.
2. **Ensemble Config Key Mismatch:**
   In `src/inference/predict.py` (lines 93–94):
   ```python
   weights = cfg.get("weights", weights)
   threshold = float(cfg.get("threshold", threshold))
   ```
   However, `train_exp_a.py` serialized `models/saved_exp_a/ensemble_config.json` with keys `"model_weights"` and `"optimal_threshold"`. If `predict.py` were directed to `models/saved_exp_a`, it would fail to find these keys and silently fall back to `threshold = 0.50`.
3. **Anomaly Detector Target:**
   `AnomalyDetector` in `src/models/anomaly.py` hardcodes `MODEL_PATH = PROJECT_ROOT / "models" / "saved" / "isolation_forest.joblib"`. It does not load the Experiment A Isolation Forest.
4. **Historical Telemetry Mismatch:**
   `backend/service.py` functions `get_dataset_stats()` and `get_profile_stats()` read `Tuesday-WorkingHours_metadata.json` and report 471,052 profiles (Tuesday only) instead of the 2,569,260 profiles generated in Experiment A.

---

## 9. Model Architecture Suitability for Event Profiles

| Architecture | Theoretical Justification | Empirical Fit for 8D Basepoints | Audit Verdict |
| :--- | :--- | :--- | :---: |
| **FCNN (MLP)** | Models non-linear interactions across unordered tabular features. | Highest recall (24.49%), fastest training (40.6s), robust to lack of spatial order. | **SUITABLE** |
| **1D-CNN** | Assumes spatial translation invariance across adjacent basepoints. | Questionable. Basepoints `bp_01`..`bp_08` are concurrent prototype coordinates, not adjacent pixels. Missed 9 attacks caught by FCNN. | **MARGINAL** |
| **LSTM** | Designed for temporal sequences over time ($t_1, t_2, \dots, t_T$). | For single-window triage ($T=1$), the recurrence degenerate into a single linear projection. Does not capture temporal transitions across windows. | **MARGINAL** |
| **Isolation Forest** | Isolates anomalies via random hyper-plane cuts. | Ineffective on 8D cosine similarity vectors where attack vectors fall inside the dense convex hull of normal traffic. | **UNSUITABLE ON 8D COSINE** |

---

## 10. Audit Checklist (PASS / FAIL)

| Audit Item | Verification Method | Result | Notes |
| :--- | :--- | :---: | :--- |
| **Metric Recalculation** | Recomputed from test set & model files | **PASS** | 100% exact numerical match across all models |
| **Data Leakage Isolation** | Split check, threshold source check | **PASS** | Train-only fitting, validation-only threshold tuning |
| **Feature Boundary Integrity**| Input schema verification | **PASS** | Strictly `bp_01`..`bp_08`. Zero IPs, ports, labels in inputs |
| **Continuous AUC Scoring** | Code inspection of ROC/PR-AUC calls | **PASS** | Continuous probability scores used correctly |
| **Class Weighting Application**| Keras API inspect and weight formula | **PASS** | Correct balanced weights, no double weighting |
| **Baseline Preservation** | SHA-256 validation of Tuesday files | **PASS** | Hashes match baseline backup identically |
| **Dashboard Model Alignment** | Backend service inspection | **FAIL** | Dashboard loads Tuesday baseline, not Experiment A |
| **Isolation Forest Threshold** | Optimization function inspection | **FAIL** | Search grid $[0.05, 0.95]$ caused 0% recall bug |
| **Multiclass Authenticity** | Output layer and decision logic inspect | **FAIL** | Binary model only; attack subclasses faked via port |
| **Ensemble Config Key Match** | Config JSON schema vs loader check | **FAIL** | `weights` vs `model_weights` key mismatch |

---

## 11. Answers to User Questions

1. **Does the dashboard load Experiment A models or Tuesday baseline models?**
   It loads the **Tuesday baseline models** (`models/saved/`).
2. **Is the Isolation Forest model from Experiment A actually connected to inference?**
   **No.** `AnomalyDetector` loads from `models/saved/isolation_forest.joblib`.
3. **Are thresholds loaded from the correct Experiment A evaluation/configuration files?**
   **No.** They are either hardcoded in `decision_policy.py` or read from Tuesday config files.
4. **Are the eight input columns always in the correct order?**
   **Yes.** All code uniformly enforces `bp_01` through `bp_08` in ascending order.
5. **Does the inference pipeline support NORMAL, KNOWN_THREAT, and UNKNOWN_ANOMALOUS?**
   **Yes.** The logic exists in `src/inference/decision_policy.py`.
6. **Does any code use IP addresses, ports, timestamps or target labels as model input?**
   **No.** Strict feature boundary integrity is maintained.
7. **Does any code infer attack subclasses using destination ports rather than model predictions?**
   **Yes.** In `decision_policy.py`, attack names are derived from `destination_port == 21` or `22`, rather than a multiclass ANN.
8. **Does the current inference code correctly handle unfamiliar patterns?**
   **Partially in logic, but broken in data.** The logic routes uncertain predictions to `UNKNOWN_ANOMALOUS`, but because the Isolation Forest threshold is miscalibrated and the models are Tuesday baseline, novel multi-day attacks are not reliably flagged.
9. **Are the model architectures appropriate for concurrency-based event profiles?**
   FCNN is appropriate. 1D-CNN and LSTM have weak theoretical alignment for static, single-window 8D cosine similarity vectors.

---

## 12. Assessment: Trustworthiness & Demonstration Suitability

### Are the saved evaluation results trustworthy?
**YES.** The evaluation report in `models/metrics_exp_a/evaluation_report.json` is completely honest, mathematically verified, and free of data leakage. The results accurately reflect the true, unvarnished difficulty of detecting rare cyber attacks in massive network traffic.

### Are the models suitable for dashboard demonstration?
**CONDITIONALLY SUITABLE, with clear disclosures:**
- They should **not** be presented as autonomous blocking systems (due to $0.42\%$ precision and 3,574 false alarms).
- They **can** be demonstrated as a **Phase 1 AI-Assisted Triage Engine**, highlighting how the ANN successfully detected 100% of Web Brute Force and SSH-Patator attacks, while pointing out that low-rate botnets require secondary correlation.
- The backend must be updated to point to `models/saved_exp_a/` before demonstrating Experiment A.

---

## 13. Prioritized Improvement Plan (Recommendations Only - Not Implemented)

1. **Priority 1: Connect Backend to Experiment A Models (Configuration Fix)**
   - Update `src/inference/predict.py` and `backend/service.py` to optionally accept `models_dir=models/saved_exp_a` and `metrics_dir=models/metrics_exp_a`.
   - Reconcile `ensemble_config.json` keys (`model_weights` vs `weights`, `optimal_threshold` vs `threshold`).
2. **Priority 2: Fix Isolation Forest Threshold Calibration (Methodology Fix)**
   - Calibrate Isolation Forest using percentile-based thresholds (e.g. 95th or 99th percentile of normal scores) rather than a fixed probability grid $[0.05, 0.95]$.
   - Consider fitting Isolation Forest on raw TF-IDF flow vectors rather than post-cosine 8D vectors.
3. **Priority 3: Replace Port Heuristics with True Multiclass Classification (Research Fix)**
   - Train a true 15-class Softmax classifier (`Dense(15, activation="softmax")`) so that attack classifications are produced by the neural network rather than hardcoded port rules.
4. **Priority 4: Operational Threshold Tuning (SIEM Triage Fix)**
   - Instead of unconstrained $F_1$ optimization, select decision thresholds constrained by a maximum allowable False Positive Rate (e.g. $\text{FPR} \le 0.1\%$).
