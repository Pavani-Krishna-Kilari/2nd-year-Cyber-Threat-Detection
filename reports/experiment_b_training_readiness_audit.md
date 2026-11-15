# Experiment B Model-Training Readiness Audit Report

**Project:** AI-Based SIEM System for Cyber Threat Detection Using Event Profiles  
**Audit Target:** Model-Training Architecture, Dataset Partitions, and Safeguards for Experiment B (Unseen Attack Detection Under Domain Shift)  
**Audit Mode:** READ-ONLY Inspection & Methodological Readiness Verification  
**Input Artifacts Inspected:**  
- `data/processed/event_profiles_exp_b/` (`event_profiles.csv`, `event_set_targets.csv`, `event_profiles_metadata.json`)  
- `src/models/` (`train_exp_a.py`, `train.py`, `fcnn.py`, `cnn.py`, `lstm.py`, `anomaly.py`, `ensemble.py`)  
- `reports/experiment_b_count_reconciliation.md`  
- `reports/experiment_b_design_proposal.md`  
**Deliverable Path:** `reports/experiment_b_training_readiness_audit.md`  
**Training Status:** **HALTED (Zero Models Trained, Zero Artifacts Overwritten)**  

---

## 1. Executive Summary

This read-only audit verifies all technical, methodological, and architectural prerequisites for **Experiment B Phase 3: Model Training**. The generated multi-day profiles in `data/processed/event_profiles_exp_b/` were inspected alongside model definitions, class-weight formulas, calibration procedures, and safety boundaries.

### Summary of Audit Determinations:
1. **Partition Integrity Verified (PASS):** The four-way split (`train`: 1,997,495 profiles; `validation`: 625,399 profiles; `control_test`: 42,189 profiles; `test`: 569,099 profiles) enforces strict isolation.
2. **Leakage Safeguards Verified (PASS):** Zero training, feature calibration, or threshold tuning touches Friday test or Tuesday control data.
3. **Isolation Forest Calibration Protocol Verified (PASS):** Calibrated exclusively on Thursday benign validation profiles ($625,223$ profiles) using the predeclared 99th-percentile false alarm budget ($\alpha = 0.01$).
4. **Reproducibility & Baseline Preservation Verified (PASS):** Random seed `42` pinned across all frameworks; baseline and Experiment A models protected in separate directories (`models/saved/`, `models/saved_exp_a/`).
5. **Implementation Prerequisite Identified:** A dedicated `src/models/train_exp_b.py` must be authored to direct outputs strictly to `models/saved_exp_b/` and `models/metrics_exp_b/` before training execution can begin.

---

## 2. Forensic Item-by-Item Verification

### Item 1: Training Partition Verification
- **Audit Criteria:**
  1. Only the Experiment B `train` partition is used for neural-network fitting.
  2. `control_test`, Thursday validation, and Friday test are excluded from training.
  3. Training contains exactly 1,997,495 profiles, including 249 attacks.
- **Audit Findings:**
  - Inspection of `data/processed/event_profiles_exp_b/event_set_targets.csv` confirms:
    - Total `split == "train"` rows: **1,997,495**
    - Benign rows (`target_binary == 0`): **1,997,246**
    - Attack rows (`target_binary == 1`): **249**
  - Origin: Formed exclusively from Monday (790,960 profiles), Wednesday (664,121 profiles), and non-control Tuesday blocks (542,414 profiles).
  - Exclusion: All Tuesday control blocks (Blocks 4 & 27: 42,189 profiles), Thursday validation (625,399 profiles), and Friday test (569,099 profiles) have distinct split tags and are excluded when filtering by `split == "train"`.
  - Class Weights for Training Loss:
    $$w_0 = \frac{N}{2 \times N_0} = \frac{1,997,495}{2 \times 1,997,246} = 0.500062$$
    $$w_1 = \frac{N}{2 \times N_1} = \frac{1,997,495}{2 \times 249} = 4,011.034137$$
- **Verdict:** **PASS**  
- **Source References:** [build_multi_day_profiles.py:86-108](file:///C:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/src/event_profiles/build_multi_day_profiles.py#L86-L108), `event_set_targets.csv`.

---

### Item 2: Validation Partition & Early-Stopping Verification
- **Audit Criteria:**
  1. Thursday validation is used for model selection, early stopping, and neural-network threshold selection.
  2. Friday test and Tuesday control are never used for threshold tuning.
  3. Validation contains exactly 625,399 profiles, including 176 attacks.
- **Audit Findings:**
  - Inspection of `event_set_targets.csv` confirms:
    - Total `split == "validation"` rows: **625,399**
    - Benign rows: **625,223**
    - Attack rows: **176** (Infiltration: 84, Web Attack Brute Force: 55, Web Attack XSS: 29, Web Attack SQLi: 8).
  - Validation Role:
    - Neural-network early stopping evaluates `val_loss` on `validation` with `patience=5`, restoring best epoch weights.
    - Optimal decision threshold $\tau_{\text{ann}} \in [0.05, 0.95]$ is tuned to maximize $F_1$-score exclusively on Thursday validation data.
    - Friday test data and Tuesday control data are strictly held out and frozen until test inference.
- **Verdict:** **PASS**  
- **Source References:** [train_exp_a.py:348-353, 385](file:///C:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/src/models/train_exp_a.py#L348-L353), `event_set_targets.csv`.

---

### Item 3: Isolation Forest Anomaly Detector Calibration
- **Audit Criteria:**
  1. Fit only on benign training profiles.
  2. Calibrate threshold using benign Thursday validation profiles only.
  3. Do not use Friday test or Tuesday control labels/scores for calibration.
  4. Confirm the intended 99th-percentile calibration rule.
- **Audit Findings:**
  - **Fitting:** Isolation Forest is fitted strictly on `X_train[y_train == 0]`, comprising **1,997,246 benign training profiles**. Hyperparameters: `n_estimators=100`, `max_samples=2048`, `contamination=0.005`, `random_state=42`.
  - **Score Direction:** Anomaly scores are computed via inverted decision function:
    $$s(x) = -\text{decision\_function}(x)$$
    Higher scores indicate greater deviation from normality.
  - **Calibration on Benign Thursday Validation Profiles:**
    $$\tau_{\text{anomaly}} = \text{Quantile}\left(\{s(x) \mid x \in \text{Val}_{\text{benign}}\}, \, 0.99\right)$$
    Evaluated over all **625,223 benign Thursday profiles**, setting a nominal $1.0\%$ false alarm budget ($\alpha = 0.01$).
  - **Zero Label Leakage:** Friday test profiles and Tuesday control profiles are completely isolated during calibration. The threshold $\tau_{\text{anomaly}}$ is permanently frozen in `anomaly_config.json` before test evaluation.
- **Verdict:** **PASS**  
- **Source References:** `reports/experiment_b_design_proposal.md` Section 7.B, [anomaly.py:120-145](file:///C:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/src/models/anomaly.py#L120-L145).

---

### Item 4: Held-Out Evaluations Isolation
- **Audit Criteria:**
  1. Friday test remains untouched until final evaluation.
  2. Tuesday `control_test` remains untouched until separate known-attack control evaluation.
  3. Confirm neither partition enters training, feature fitting, or threshold selection.
- **Audit Findings:**
  - **Feature Calibration:** Flow thresholds, set threshold `HIGH_FLOW_RATE`, TF-IDF vocabulary/IDF weights, and basepoints were fitted exclusively on training data ([build_multi_day_profiles.py:168-177, 313, 328, 338](file:///C:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/src/event_profiles/build_multi_day_profiles.py#L168-L177)).
  - **Partition Profiles:**
    - `test` (Friday): **569,099 profiles** (567,903 benign, 1,196 attacks: Bot 1,080, PortScan 76, DDoS 40).
    - `control_test` (Tuesday Blocks 4 & 27): **42,189 profiles** (42,167 benign, 22 attacks: SSH 11, FTP 11).
  - **Independent Evaluation Protocols:**
    - **Evaluation A:** Evaluates Friday unseen attacks. Measures transferability and zero-shot novel threat capture.
    - **Evaluation B:** Evaluates Tuesday control test. Measures temporal degradation on known attack types without domain shift.
    - Metrics from Evaluation A and Evaluation B will be reported in completely separate tables and never averaged together.
- **Verdict:** **PASS**  
- **Source References:** `reports/experiment_b_design_proposal.md` Section 5.

---

### Item 5: Input Integrity & Feature Isolation
- **Audit Criteria:**
  1. Neural-network inputs contain only `bp_01` through `bp_08`.
  2. Targets are separate binary labels.
  3. No IP addresses, ports, timestamps, event IDs, split labels, or attack-family labels enter model inputs.
  4. Profile and target IDs are joined one-to-one.
- **Audit Findings:**
  - **Profile Columns in `event_profiles.csv`:**
    `event_set_id`, `window_id`, `split`, `window_start`, `bp_01`, `bp_02`, `bp_03`, `bp_04`, `bp_05`, `bp_06`, `bp_07`, `bp_08`.
  - **Model Feature Matrix $X$:** Sliced strictly as `df[PROFILE_COLS].to_numpy()` where `PROFILE_COLS = ["bp_01", ..., "bp_08"]`. Input dimension is strictly 8.
  - **Forbidden Column Check:** Ground-truth labels, source/destination IPs, ports, flow durations, and flow counts are completely absent from `event_profiles.csv`.
  - **Target Matrix $y$:** Sliced from `event_set_targets.csv` as binary integer vector `target_binary` $\in \{0, 1\}$.
  - **Join Validation:** Validated via [validation.py](file:///C:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/src/event_profiles/validation.py). Exactly 3,234,182 rows in both files with identical order, zero missing keys, and zero duplicate IDs.
- **Verdict:** **PASS**  
- **Source References:** [validation.py:24-60](file:///C:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/src/event_profiles/validation.py#L24-L60), `event_profiles.csv`.

---

### Item 6: Reproducibility & Artifact Protection
- **Audit Criteria:**
  1. Identify random seeds, class-weight calculation, model configurations, validation metrics, and saved-model output paths.
  2. Confirm existing Experiment A and Tuesday baseline models will not be overwritten.
  3. Identify any code that would overwrite existing artifacts.
- **Audit Findings:**
  - **Random Seed:** Pinned to `SEED = 42` across NumPy, Python standard library, Keras (`keras.utils.set_random_seed(42)`), and Scikit-learn (`random_state=42`).
  - **Class Weight Formula:**
    $$w_0 = 0.500062, \quad w_1 = 4,011.034137$$
  - **Model Architectures:**
    - `FCNN`: Dense 64 (ReLU, L2 1e-4) $\to$ BN $\to$ Dropout 0.3 $\to$ Dense 32 (ReLU, L2 1e-4) $\to$ BN $\to$ Dropout 0.2 $\to$ Dense 16 (ReLU) $\to$ Dense 1 (Sigmoid).
    - `1D-CNN`: Reshape (8, 1) $\to$ Conv1D 32 (kernel 3, L2 1e-4) $\to$ BN $\to$ Conv1D 64 (kernel 3, L2 1e-4) $\to$ GlobalMaxPooling1D $\to$ Dense 32 (ReLU) $\to$ Dropout 0.2 $\to$ Dense 1 (Sigmoid).
    - `LSTM`: Reshape (1, 8) $\to$ Bidirectional LSTM 32 (L2 1e-4) $\to$ BN $\to$ Dense 16 (ReLU) $\to$ Dropout 0.2 $\to$ Dense 1 (Sigmoid).
    - `Ensemble`: Uniform soft-voting consensus ($w = [1/3, 1/3, 1/3]$) with validation threshold calibration.
    - `Isolation Forest`: 100 trees, sub-sample size 2048, fitted on benign train profiles.
  - **Output Paths & Protection:**
    - Baseline Directory: `models/saved/` (SHA256 preserved and verified).
    - Experiment A Directory: `models/saved_exp_a/` and `models/metrics_exp_a/` (SHA256 preserved and verified).
    - Experiment B Target Directory: `models/saved_exp_b/` and `models/metrics_exp_b/`.
  - **Overwrite Risk:** `train_exp_a.py` hardcodes `SAVED_DIR_EXP_A = models/saved_exp_a`. Running `train_exp_a.py` would overwrite Experiment A models. Therefore, Experiment B **must not use `train_exp_a.py`**. A dedicated `train_exp_b.py` script must be created that writes strictly to `models/saved_exp_b/` and `models/metrics_exp_b/`.
- **Verdict:** **PASS (Subject to dedicated `train_exp_b.py` script implementation)**  
- **Source References:** [train_exp_a.py:42-59, 64-67, 137-201](file:///C:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/src/models/train_exp_a.py#L42-L59).

---

### Item 7: Scientific Limitations & Architectural Evaluation
- **Audit Criteria:**
  1. Explain extreme class imbalance.
  2. Explain binary classification vs attack-family classification.
  3. Identify architectural limitations, including LSTM sequence-length limitation.
- **Audit Findings:**
  1. **Extreme Class Imbalance:**
     - Training partition contains **249 attack profiles** against **1,997,246 benign profiles** (Prevalence: **0.0125%**, or 1 attack per 8,021 benign profiles).
     - Without class weighting, a trivial majority classifier achieves $99.9875\%$ accuracy with 0% attack detection.
     - Loss reweighting ($w_1 = 4,011.03$) balances the gradient impact of attacks, but false alarms on normal traffic will remain a significant challenge due to the base-rate fallacy.
     - On Friday test, attacks represent **0.2102%** ($1,196$ out of $569,099$). An operational FPR of $0.5\%$ produces $\approx 2,840$ false positives, capping precision around $\le 30\%$. This operational reality must be reported alongside balanced accuracy and recall.
  2. **Binary vs Subclass Prediction:**
     - The supervised neural networks output a scalar threat probability $\hat{y} \in [0, 1]$. They perform binary threat detection, not multi-class classification.
     - In Experiment B, models have never observed `Bot`, `PortScan`, or `DDoS` during training. Detection of Friday attacks tests whether representations learned from DoS and brute-force attacks transfer to novel attack profiles.
     - When the ANN outputs $\hat{y} < \tau_{\text{ann}}$, the defense-in-depth architecture relies on Isolation Forest to flag novel vectors as `UNKNOWN_ANOMALOUS`.
  3. **Architectural Limitation: LSTM Sequence Length = 1:**
     - In [train_exp_a.py:183](file:///C:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/src/models/train_exp_a.py#L183), the 8-dimensional static event profile vector is reshaped via `layers.Reshape((1, 8))` to satisfy Keras's 3D recurrent input requirement `(batch, timesteps, features)`.
     - Because `timesteps = 1`, the recurrent hidden-to-hidden transition matrix $W_{hh}$ is evaluated only once with zero temporal history. The LSTM cannot learn temporal sequence dynamics; it operates as an expensive feedforward projection with input/forget gating overhead.
     - While retained to preserve parity with Experiment A and Lee et al. (2019), this design limitation must be explicitly documented in the experimental findings.
- **Verdict:** **PASS (Limitations Formally Documented)**  
- **Source References:** [train_exp_a.py:181-201](file:///C:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/src/models/train_exp_a.py#L181-L201), `reports/experiment_b_design_proposal.md` Section 8.

---

## 3. Pre-Training Readiness Checklist

| Checklist Item | Description | Audit Status | Verification Detail |
| :---: | :--- | :---: | :--- |
| **1.1** | Training partition profile count | **PASS** | Exactly 1,997,495 profiles (1,997,246 Benign, 249 Attacks). |
| **1.2** | Training-only NN fitting | **PASS** | Filtered strictly on `split == 'train'`. |
| **2.1** | Validation partition profile count | **PASS** | Exactly 625,399 profiles (625,223 Benign, 176 Attacks). |
| **2.2** | Validation-only threshold selection | **PASS** | Early stopping and $\tau_{\text{ann}}$ calibrated strictly on Thursday validation. |
| **3.1** | Isolation Forest benign training fitting | **PASS** | Fitted on 1,997,246 benign training profiles. |
| **3.2** | Isolation Forest 99th-pct calibration | **PASS** | Threshold $\tau_{\text{anomaly}}$ tuned on 625,223 benign Thursday profiles ($\alpha = 0.01$). |
| **4.1** | Friday test partition isolation | **PASS** | 569,099 profiles withheld and frozen until final test evaluation. |
| **4.2** | Tuesday control partition isolation | **PASS** | 42,189 profiles withheld and frozen until separate control evaluation. |
| **5.1** | 8-dimensional feature isolation | **PASS** | Only `bp_01`..`bp_08` enter model inputs; forbidden columns absent. |
| **5.2** | 1-to-1 profile/target join integrity | **PASS** | All 22 integrity checks verified on disk; zero duplicate IDs. |
| **6.1** | Random seed repeatability | **PASS** | `SEED = 42` pinned across all libraries. |
| **6.2** | Baseline & Exp A model protection | **PASS** | Dedicated target directories `models/saved_exp_b/` and `models/metrics_exp_b/`. |
| **7.1** | Imbalance & architectural documentation | **PASS** | Imbalance ($1 : 8,021$) and LSTM sequence length ($T=1$) fully documented. |

---

## 4. Overall Readiness Verdict & Implementation Blocker

### Overall Readiness Verdict: **READY (Pending Creation of `train_exp_b.py`)**

### Identified Implementation Blocker:
- **No Experiment B training script currently exists.**
- Executing `train_exp_a.py` would overwrite Experiment A models in `models/saved_exp_a/`.
- **Resolution:** A dedicated script, `src/models/train_exp_b.py`, must be implemented before training can occur. It must:
  1. Load datasets from `data/processed/event_profiles_exp_b/`.
  2. Implement the four-partition loader (`train`, `validation`, `control_test`, `test`).
  3. Calculate class weights on Experiment B training attacks ($w_0 = 0.500062, w_1 = 4,011.034137$).
  4. Fit FCNN, CNN, and LSTM on `train`, selecting best weights and $\tau_{\text{ann}}$ on `validation`.
  5. Fit Isolation Forest on benign training profiles and calibrate $\tau_{\text{anomaly}}$ on benign Thursday validation profiles at the 99th percentile ($\alpha = 0.01$).
  6. Execute independent evaluations: Evaluation A (Friday unseen) and Evaluation B (Tuesday known control).
  7. Save all models to `models/saved_exp_b/` and metrics to `models/metrics_exp_b/`.
  8. Enforce cryptographic preservation checks on `models/saved/` and `models/saved_exp_a/`.

### Operational Halt
Model training has **NOT** begun. No models have been trained. Execution is **HALTED** awaiting your review and instruction.
