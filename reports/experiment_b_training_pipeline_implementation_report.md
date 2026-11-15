# Experiment B Training Pipeline Implementation Report

**Project:** AI-Based SIEM System for Cyber Threat Detection Using Event Profiles  
**Task:** Implementation and Unit Testing of Dedicated Model Training Pipeline for Experiment B  
**Deliverable Path:** `reports/experiment_b_training_pipeline_implementation_report.md`  
**Pipeline Source Path:** `src/models/train_exp_b.py`  
**Test Suite Path:** `tests/test_train_exp_b.py`  
**Execution Status:** **IMPLEMENTED & UNIT TESTED (TRAINING NOT EXECUTED)**  

---

## 1. Executive Summary

In accordance with the Experiment B research design (`reports/experiment_b_design_proposal.md`) and training readiness audit (`reports/experiment_b_training_readiness_audit.md`), the dedicated training pipeline for Experiment B has been authored in `src/models/train_exp_b.py` and validated by 10 new unit tests in `tests/test_train_exp_b.py`.

### Safety & Invariance Confirmations:
1. **Script NOT Executed:** `src/models/train_exp_b.py` has **not been run**. No neural networks or anomaly models were trained.
2. **Directory Isolation:** Experiment B outputs are strictly targeted to `models/saved_exp_b/` and `models/metrics_exp_b/`.
3. **Preservation of Baseline & Experiment A:** All models in `models/saved/` and `models/saved_exp_a/` remain untouched. Cryptographic SHA256 hashes of baseline and Experiment A profiles and targets match their original fingerprints.
4. **Parity with Approved Architectures:** Uses standard FCNN, 1D-CNN, and LSTM model architectures, loss-weighting calculations, and early stopping protocols.
5. **Separation of Evaluations:** Implements Evaluation A (Friday unseen attacks: `Bot`, `PortScan`, `DDoS`) and Evaluation B (Tuesday known control: `SSH-Patator`, `FTP-Patator`) with separate metrics persistence.

---

## 2. Implementation Details of `src/models/train_exp_b.py`

### Requirement A: Four-Way Partition Loading (`load_exp_b_datasets`)
- Slices the unified multi-day profile dataset into four disjoint partitions:
  - `train`: Monday, Wednesday, and non-held-out Tuesday profiles (**1,997,495 profiles**; 249 attacks).
  - `validation`: Thursday Morning and Afternoon profiles (**625,399 profiles**; 176 attacks).
  - `control_test`: Tuesday Block 4 and Block 27 profiles (**42,189 profiles**; 22 attacks).
  - `test`: Friday Morning, PortScan, and DDoS profiles (**569,099 profiles**; 1,196 attacks).
- Validates 1-to-1 join against `event_set_targets.csv` and asserts that zero forbidden fields exist in the feature matrix.

### Requirement B: Approved Neural Network Architectures
- Implements `build_fcnn(input_dim=8)`, `build_cnn(input_dim=8)`, and `build_lstm(input_dim=8)`.
- Models are trained strictly on `X_train` with `validation_data=(X_val, y_val)` and `callbacks=[EarlyStopping(monitor="val_loss", patience=5, restore_best_weights=True)]`.

### Requirement C: Class Weighting
- Computed exclusively on training partition labels:
  $$w_0 = \frac{N}{2 \times N_0} = 0.500062, \quad w_1 = \frac{N}{2 \times N_1} = 4,011.034137$$
- Handles extreme class imbalance ($1 : 8,021$) during gradient backpropagation without synthetic data distortion.

### Requirement D: Thursday Validation Threshold Calibration
- Grid search over 50 intervals in $[0.05, 0.95]$ selects $\tau_{\text{ann}}$ to maximize $F_1$-score on Thursday validation data (`X_val`, `y_val`).
- Soft-Voting Ensemble ($w = [1/3, 1/3, 1/3]$) calibrated similarly on validation probabilities and saved to `models/saved_exp_b/ensemble_config.json`.

### Requirement E: Isolation Forest 99th-Percentile Calibration
- Fitted strictly on benign training profiles (`X_train[y_train == 0]`, $1,997,246$ samples).
- Anomaly score convention: $s(x) = -\text{decision\_function}(x)$ (higher = more anomalous).
- Calibrated exclusively on benign Thursday validation profiles (`X_val[y_val == 0]`, $625,223$ samples) at the 99th percentile ($\alpha = 0.01$).
- Saved to `models/saved_exp_b/isolation_forest.joblib` and `models/saved_exp_b/anomaly_config.json`.
- Friday test and Tuesday control data are strictly excluded from fitting and calibration.

### Requirement F: Held-Out Dual Evaluations (Separate Reporting)
- **Evaluation A (Friday Unseen Attacks):** Evaluates models on Friday test data ($569,099$ samples) for zero-shot novel threat detection (`Bot`, `PortScan`, `DDoS`). Saved to `models/metrics_exp_b/evaluation_a_unseen.json`.
- **Evaluation B (Tuesday Known-Attack Control):** Evaluates models on Tuesday held-out blocks ($42,189$ samples) for temporal degradation on known threats (`SSH-Patator`, `FTP-Patator`). Saved to `models/metrics_exp_b/evaluation_b_control.json`.
- **Tri-State SIEM Triage:** Computes triage distribution (`KNOWN_THREAT`, `UNKNOWN_ANOMALOUS`, `NORMAL`) for both evaluations.
- Metrics from Evaluation A and Evaluation B are never averaged or combined.

### Requirement G: Strict Feature & Input Isolation
- Features strictly restricted to `bp_01` through `bp_08` ($8$ dimensions).
- Binary targets $y \in \{0, 1\}$ kept separate.
- An automatic exception is raised if forbidden fields (`source_ip`, `destination_ip`, `source_port`, `destination_port`, `label`, `flow_duration`, `n_flows`, `split`) are present in $X$.

### Requirement H: Reproducibility Persistence
- Saves complete training history to `models/metrics_exp_b/training_history.json`.
- Saves consolidated evaluation report to `models/metrics_exp_b/evaluation_report.json` with random seeds, class weights, architecture configurations, threshold values, and validation benchmarks.

---

## 3. Test Suite Verification

A dedicated unit test module was implemented in `tests/test_train_exp_b.py` containing 10 test cases:

```text
test_actual_exp_b_targets_counts_match_specification ... ok
test_isolation_forest_calibration_strictly_on_benign_validation ... ok
test_tri_state_verdicts_computation ... ok
test_forbidden_columns_in_profiles_raises_error ... ok
test_four_way_partition_loading_success ... ok
test_missing_partition_raises_error ... ok
test_class_weights_calculation_formula ... ok
test_experiment_a_and_baseline_models_protected ... ok
test_output_path_isolation ... ok
test_profile_feature_column_isolation ... ok

----------------------------------------------------------------------
Ran 10 tests in 3.850s

OK
```

### Full Repository Test Suite Verification:
- Command: `python -m unittest discover -s tests -v`
- Discovered: **157 tests** (147 existing + 10 new Experiment B training pipeline tests).
- Results: **157 passed, 0 failures, 0 errors in 23.686 seconds**.

---

## 4. Modified and Created Files Summary

| File Path | Action | Description |
| :--- | :---: | :--- |
| `src/models/train_exp_b.py` | **Created** | Dedicated Experiment B training pipeline script with 4-way partition loader, neural models, Isolation Forest 99th-percentile calibration, dual evaluations, and safety guards. |
| `tests/test_train_exp_b.py` | **Created** | Unit test suite verifying four-way loading, feature isolation, calibration isolation, class weights, tri-state logic, and artifact protection. |
| `reports/experiment_b_training_pipeline_implementation_report.md` | **Created** | This formal implementation and test verification report. |

*No existing source code, models, metrics, or datasets were modified.*

---

## 5. Final Readiness Verdict

The Experiment B model training pipeline is **100% IMPLEMENTED, ISOLATED, AND UNIT-TESTED**.

- Direct execution is guarded (`if __name__ == "__main__":` prints a safety message and exits without training).
- Output paths are isolated to `models/saved_exp_b/` and `models/metrics_exp_b/`.
- The pipeline is fully prepared for a separate, explicit user approval to execute model training.

**Current Operational Status:** **STOPPED**. Awaiting explicit user approval before model training begins.
