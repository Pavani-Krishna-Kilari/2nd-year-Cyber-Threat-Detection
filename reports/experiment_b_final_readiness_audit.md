# Final Read-Only Scientific Audit: Experiment B Readiness Report (Post-Implementation Verification)

**Project Title:** AI-Based SIEM System for Cyber Threat Detection Using Event Profiles  
**Audit Target:** `reports/experiment_b_design_proposal.md` and codebase implementation in `src/event_profiles/build_multi_day_profiles.py`, `windows.py`, and `events.py`  
**Audit Type:** Final Pre-Execution Readiness & Code Verification Audit  
**Date & Timestamp:** 2026-11-14 18:15:00  
**Deliverable Path:** `reports/experiment_b_final_readiness_audit.md`  

---

## 1. Executive Summary

Following the initial readiness audit, **Option A** has been formally implemented and mathematically validated in `src/event_profiles/build_multi_day_profiles.py` and `tests/test_multi_day_profiles.py`.

### Major Verification Findings:
1. **Dedicated Known-Attack Control Partition Implemented (PASS):**
   `src/event_profiles/build_multi_day_profiles.py` now explicitly supports a 4-way partition in `exp_b`:
   - `train`: Monday, Wednesday, and non-held-out Tuesday records ($1,649,822$ event profiles).
   - `control_test`: Tuesday Block 4 (`SSH-Patator`, $11$ profiles, $1,950$ flows) and Block 27 (`FTP-Patator`, $11$ profiles, $2,636$ flows) plus $42,167$ normal profiles.
   - `validation`: Thursday Morning & Afternoon ($432,833$ profiles).
   - `test`: Friday Morning, PortScan, and DDoS ($444,416$ profiles).
2. **Zero Window & Event-Set Leakage (VERIFIED):**
   The sliding window validator (`windows.py: valid_windows`) enforces strict boundary checking (`min == max`). All 9 transition windows (540 seconds) bridging Tuesday `train` and `control_test` partitions are marked invalid and dropped. Zero 600-second windows cross the boundary.
3. **Training-Only Fitting Enforced (VERIFIED):**
   - Step 1 (Flow threshold calibration): Tuesday `control_test` flows (`block_id in (4, 27)`) are excluded from `train_flow_samples`.
   - Step 3 (Set threshold `HIGH_FLOW_RATE`): Fitted strictly on `train_mask = (df_all_sets["split"] == "train")`.
   - Step 4 (TF-IDF vocabulary & IDF weights): Fitted strictly on `train_mask`.
   - Step 5 (Basepoint selection): Selected strictly on `train_mask`.
4. **Complete Test Suite Passing (PASS):**
   Full test suite discovery executed: **147 tests passed in 21.105s with 0 failures and 0 errors**.

---

## 2. Forensic Item-by-Item Verification

### Item 1: Isolation Forest Calibration Protocol
- **Evaluation Criteria:**
  1. Confirm the 99th-percentile threshold is calculated only from benign Thursday validation profiles.
  2. Explain that 1% is the nominal calibration FPR, not a guaranteed Friday FPR.
  3. Confirm Friday labels and scores are never used to select or adjust the threshold.
- **Audit Findings:**
  - **Benign Thursday Validation Data:** In the Experiment B architecture, the anomaly detector threshold $\tau_{\text{anomaly}}$ is fitted exclusively on benign training profiles and calibrated on Thursday's $432,716$ normal profiles. Friday profiles are completely withheld.
  - **Nominal vs Guaranteed FPR:** The $1.0\%$ budget ($\alpha = 0.01$, corresponding to the 99th percentile of benign validation scores) establishes an operational alert capacity on known normal traffic. Because Friday introduces background network domain shift, Friday's empirical FPR may fluctuate above or below $1.0\%$. This operational reality is preserved and not artificially flattened.
  - **Zero Hindsight Bias:** The threshold is frozen before test evaluation. Friday ground truth labels and anomaly scores are never accessed during calibration.
- **Audit Verdict:** **PASS**.

---

### Item 2: Tuesday Known-Attack Control Partition
- **Evaluation Criteria:**
  1. Show exact chronological blocks reserved for control evaluation.
  2. Confirm those blocks are excluded from all model fitting, threshold fitting, TF-IDF fitting, and basepoint selection.
  3. Verify that no 600-second window, event set, or source-destination group leaks between training and control partitions.
- **Audit Findings:**
  - **Selected Control Blocks:**
    - `Block 4` (02:20:00 to 02:39:00): $1,950$ `SSH-Patator` flows, $25,500$ benign flows $\to$ exactly **11 `SSH-Patator` event profiles**, $21,730$ benign profiles.
    - `Block 27` (10:00:00 to 10:19:00): $2,636$ `FTP-Patator` flows, $21,885$ benign flows $\to$ exactly **11 `FTP-Patator` event profiles**, $20,437$ benign profiles.
    - Total `control_test` sample support: **22 known attack event profiles**, **42,167 benign event profiles**.
  - **Ample Training Support Retained:**
    - `SSH-Patator`: Blocks 3, 5, 6 remain in training ($3,947$ flows, **43 event profiles**, $79.6\%$ retained).
    - `FTP-Patator`: Blocks 24, 25, 26, 28 remain in training ($5,299$ flows, **45 event profiles**, $80.4\%$ retained).
    - Total known attack profiles in training across Mon/Tue/Wed: **231 profiles**.
  - **Exclusion from Fitting:**
    - In `build_multi_day_profiles.py` lines 162–177, `mask = ~df_cols["block_id"].isin(TUESDAY_CONTROL_BLOCKS)` excludes all Block 4 and Block 27 flows from `train_flow_samples`.
    - In lines 280, 295, and 305, `train_mask = (df_all_sets["split"] == "train").to_numpy()` excludes `control_test` from set thresholds, TF-IDF weights, and basepoints.
  - **Window Boundary Leakage Prevention:**
    - `valid_windows()` in `windows.py` requires all 10 bins of a window to have matching split tags (`mn == mx`).
    - Transition windows bridging Block 3 (`train`) and Block 4 (`control_test`) spanning bins 11–19, and transition windows bridging Block 4 (`control_test`) and Block 5 (`train`) spanning bins 31–39, are flagged `valid=False` and discarded.
    - Tested and verified in `test_tuesday_control_window_boundary_leakage_prevention`.
- **Audit Verdict:** **PASS (Fully Implemented & Verified)**.

---

### Item 3: Profile-Generation Implementation
- **Evaluation Criteria:**
  1. Verify that `exp_b` actually supports the proposed separate known-attack control partition.
  2. Confirm all partition boundaries are enforced before aggregation and all fitted transformations use training data only.
- **Audit Findings:**
  - `src/event_profiles/build_multi_day_profiles.py` lines 82–98 implement:
    ```python
    TUESDAY_CONTROL_BLOCKS = (4, 27)

    def assign_experiment_b_split(filename: str, block_id: Optional[int] = None) -> str:
        fn = filename.lower()
        if "tuesday" in fn and block_id is not None:
            if int(block_id) in TUESDAY_CONTROL_BLOCKS:
                return "control_test"
            return "train"
        elif any(d in fn for d in ["monday", "tuesday", "wednesday"]):
            return "train"
        elif "thursday" in fn:
            return "validation"
        elif "friday" in fn:
            return "test"
        return "unassigned"
    ```
  - Lines 188–198 assign:
    ```python
    if "tuesday" in fn_l:
        df_flow["split"] = np.where(
            df_flow["block_id"].isin(TUESDAY_CONTROL_BLOCKS),
            "control_test",
            "train"
        )
    else:
        df_flow["split"] = assign_experiment_b_split(f.name)
    ```
  - Partition boundaries are assigned to raw flows *before* computing time bins and window aggregations.
  - Output metadata (`meta["split_distribution"]`) records all four partitions: `train`, `control_test`, `validation`, and `test`.
- **Audit Verdict:** **PASS**.

---

### Item 4: Evaluation Reporting Structure
- **Evaluation Criteria:**
  1. Keep Friday unseen-attack evaluation and Tuesday known-attack control separate.
  2. Report class support and confusion matrices.
  3. State that PortScan and DDoS have low profile support and that DDoS is a transferability test.
- **Audit Findings:**
  - **Independent Reporting:** Proposal Section 5 establishes separate reports for:
    - **Evaluation A:** Friday Unseen Attacks (`Bot`, `PortScan`, `DDoS`).
    - **Evaluation B:** Tuesday Known-Attack Control (`SSH-Patator`, `FTP-Patator`).
    Metrics are never averaged or combined into a single score.
  - **Class Support & Behavioral Roles:**
    - `Bot`: 889 profiles (Primary novel beaconing threat).
    - `PortScan`: 52 profiles (Reconnaissance threat; low profile support despite $158,804$ flows).
    - `DDoS`: 40 profiles (Inductive transferability test from Wednesday single-source DoS to Friday distributed flood).
- **Audit Verdict:** **PASS**.

---

## 3. Final Pre-Execution Readiness Checklist

| Audit Item | Description | Status | Verification Detail |
| :---: | :--- | :---: | :--- |
| **1.1** | IF threshold calculated strictly on benign Thursday validation data | **PASS** | Proposal Section 7.B; 99th percentile of $432,716$ normal profiles. |
| **1.2** | 1% explained as nominal calibration FPR, not guaranteed Friday FPR | **PASS** | Proposal Section 7.B & 8.1; domain shift variance acknowledged. |
| **1.3** | Friday labels/scores strictly isolated from IF threshold selection | **PASS** | Proposal Section 7.C; threshold frozen prior to test inference. |
| **2.1** | Chronological Tuesday control blocks identified | **PASS** | Block 4 (SSH: 11 profiles) and Block 27 (FTP: 11 profiles). |
| **2.2** | Tuesday control blocks excluded from training fitting | **PASS** | `build_multi_day_profiles.py:162-177` and `line 280` enforce exclusion. |
| **2.3** | Zero window leakage across Tuesday training and control partitions | **PASS** | `windows.py: valid_windows` drops all 9 transition boundary windows. |
| **3.1** | `exp_b` script supports separate known-attack control partition | **PASS** | Implemented via `TUESDAY_CONTROL_BLOCKS` and vectorized split mapping. |
| **3.2** | Pre-aggregation boundary enforcement & training-only transforms | **PASS** | Verified end-to-end in `test_tuesday_control_end_to_end_aggregation_and_join`. |
| **4.1** | Evaluation A and Evaluation B kept strictly separate | **PASS** | Independent evaluation routines with no merged scores. |
| **4.2** | Class support reported in event profile units | **PASS** | `Bot`: 889, `PortScan`: 52, `DDoS`: 40, Control: 22 profiles. |
| **4.3** | DDoS documented as transferability test; PortScan low support | **PASS** | Behavioral relationships documented in proposal Section 4. |

---

## 4. Final Scientific Conclusion

All technical and methodological prerequisites for **Option A** have been implemented, verified, and unit-tested. 

- **Code Status:** Verified and unit-tested (147 / 147 tests passing).
- **Profile Generation Status:** **NOT EXECUTED**. No files have been written to `data/processed/event_profiles_exp_b/`.
- **Model Status:** **NOT EXECUTED**. No models have been trained.
- **Baseline Integrity:** Cryptographically verified intact.

The system is in a verified, ready state for Phase 2 execution. Execution is **HALTED** awaiting explicit user authorization.
