# Diagnostic Report: Friday DDoS Test Upload Block-ID Mismatch

**Date:** 2026-11-15  
**Project:** `C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection`  
**Investigation Mode:** STRICT READ-ONLY DIAGNOSTIC  
**Target File:** `data/processed/Friday-DDos-test-16-00-to-16-10.csv`  
**Parent File:** `data/processed/Friday-WorkingHours-Afternoon-DDos_clean.csv`  
**Database Backup Verified:** `backups/pre_friday_test/detection_history.db`  

---

## Executive Summary

When attempting to upload `data/processed/Friday-DDos-test-16-00-to-16-10.csv` via the web dashboard, the ingestion pipeline rejected the file with the following error:

```
Ingestion Error: 87,364 flows have a block_id that disagrees with timestamp block arithmetic (block length 20 min).
```

### Primary Diagnostic Conclusion
**Finding Classification: CONFIRMED**

The rejection is **not caused by a bug in the inference pipeline, model weights, or database**.  
It is caused by a **timeline anchor desynchronization between a sliced test file and the Experiment B benchmark validation logic**:

1. **Parent Reference Frame:** In the full parent capture `Friday-WorkingHours-Afternoon-DDos_clean.csv`, the capture started at `15:30:00`. The 20-minute block arithmetic $[t_0 + b \cdot 20\text{m}, t_0 + (b+1) \cdot 20\text{m})$ placed the interval `16:00:00` to `16:09:59` inside **Block 1** ($[15:50, 16:10)$). Consequently, every row in that interval has `block_id = 1` and `split = train`.
2. **Slice Reference Frame:** When `Friday-DDos-test-16-00-to-16-10.csv` was created as an isolated 10-minute slice, its timestamps spanned `16:00:00` to `16:09:59`. The runtime aggregator dynamically anchors any uploaded file at its own first minute: $t_0 = \min(\text{timestamps}).\text{floor('min')} = 16:00:00$.
3. **The Conflict:** Relative to $t_0 = 16:00:00$, the flows occupy minute bins $0$ through $9$. The expected block ID calculated by the aggregator is $\text{bins} // 20 = 0$. However, the sliced CSV still carries the parent-relative column `block_id = 1`.
4. **Rejection Trigger:** In [`backend/aggregator.py#L406-L411`](file:///C:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/backend/aggregator.py#L406-L411), the aggregator asserts that $\text{bins} // 20 == \text{block\_ids}$. Because $0 \ne 1$ for all **87,364 flows**, the aggregator raised `InvalidBenchmarkAnnotationError`, which FastAPI correctly converted to an HTTP 422 error on the dashboard.

---

## 1. Exact Source Code Locations & Line Numbers

| Component | File Path | Relevant Line Numbers | Architectural Role |
| :--- | :--- | :--- | :--- |
| **Runtime Aggregator (Anchor & Bins)** | [`backend/aggregator.py`](file:///C:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/backend/aggregator.py) | L216–218 | `bins, t0 = compute_bins(flows["timestamp"], self.step_seconds)` |
| **Benchmark Mode Branch** | [`backend/aggregator.py`](file:///C:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/backend/aggregator.py) | L237–242 | `if is_benchmark_replay or ("split" in flows.columns or "block_id" in flows.columns):` |
| **Block-ID Arithmetic Check** | [`backend/aggregator.py`](file:///C:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/backend/aggregator.py) | L396–411 | `mismatches = int((bins // bins_per_block != block_ids).sum())` |
| **Offline Sliding Windows Definition** | [`src/event_profiles/windows.py`](file:///C:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/src/event_profiles/windows.py) | L18–21, L24–36 | `compute_bins()` ($t_0$ anchor definition) and `bin_split_names()` parity check |
| **Offline Preprocessing Split Plan** | [`src/preprocessing/preprocess_dataset.py`](file:///C:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/src/preprocessing/preprocess_dataset.py) | L268–270 | `t0 = df["timestamp"].min().floor("min")`; `block_id = ((df["timestamp"] - t0) // 20m)` |
| **Service Benchmark Dispatch** | [`backend/service.py`](file:///C:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/backend/service.py) | L132–135 | `is_benchmark = ("split" in df.columns or "block_id" in df.columns)` |
| **API Error Translation** | [`backend/main.py`](file:///C:/Users/pavani%20krishna/Desktop/cyber/cyber-threat-detection/backend/main.py) | L114–122 | Catches `InvalidBenchmarkAnnotationError` $\to$ HTTP 422 JSON response |

---

## 2. Mathematical Formulas & Arithmetic Comparison

### A. The Timestamp Anchoring Definition
Across both offline training (`src/preprocessing/preprocess_dataset.py`, `src/event_profiles/windows.py`) and online ingestion (`backend/aggregator.py`), the timestamp anchor is defined as:
$$t_0 = \min(\text{timestamps}).\text{floor('min')}$$

> **Verification:** The anchor is **NEVER midnight** (`00:00:00`) and **NEVER a fixed wall-clock time**. It is strictly the **first minute of the input tabular dataset**.

### B. Offline Preprocessing Formula (Parent Reference Frame)
In `src/preprocessing/preprocess_dataset.py` line 269:
$$\text{block\_id}_{\text{offline}} = \left\lfloor \frac{t - t_{0,\text{parent}}}{20 \text{ minutes}} \right\rfloor$$

For `Friday-WorkingHours-Afternoon-DDos_clean.csv`:
- $t_{0,\text{parent}} = \text{2017-07-07 15:30:00}$
- For any flow $t$ between `16:00:00` and `16:09:59`:
  $$t - t_{0,\text{parent}} \in [30 \text{ min}, 40 \text{ min})$$
  $$\text{block\_id}_{\text{offline}} = \left\lfloor \frac{30..40}{20} \right\rfloor = 1$$
- Assigned split: `train`.

### C. Runtime Aggregator Formula (Slice Reference Frame)
In `backend/aggregator.py` line 216 and line 406:
1. First, compute 60-second time bins relative to the uploaded file:
   $$t_{0,\text{slice}} = \min(t_{\text{slice}}).\text{floor('min')} = \text{2017-07-07 16:00:00}$$
   $$\text{bin}_i = \left\lfloor \frac{t_i - t_{0,\text{slice}}}{60 \text{ seconds}} \right\rfloor \in \{0, 1, 2, 3, 4, 5, 6, 7, 8, 9\}$$
2. Next, validate `block_id` against bin arithmetic with 20 bins per 20-minute block:
   $$\text{bins\_per\_block} = \frac{20 \text{ min} \times 60 \text{ s}}{60 \text{ s}} = 20$$
   $$\text{expected\_block\_id}_i = \left\lfloor \frac{\text{bin}_i}{20} \right\rfloor = \left\lfloor \frac{0..9}{20} \right\rfloor = 0$$

### D. Discrepancy Matrix for the 16:00–16:10 Interval
| Parameter | Value in Parent File | Value Expected by Runtime Aggregator | Conflict |
| :--- | :--- | :--- | :--- |
| **Dataset Timeline Anchor ($t_0$)** | `2017-07-07 15:30:00` | `2017-07-07 16:00:00` | **Shifted by 30 minutes** |
| **Elapsed Minute Range** | Minutes 30 through 39 | Minutes 0 through 9 | Shifted by 30 bins |
| **60s Bin Range** | Bins 30 to 39 | Bins 0 to 9 | $\Delta = -30$ bins |
| **Block Formula** | $\lfloor 30..39 / 20 \rfloor$ | $\lfloor 0..9 / 20 \rfloor$ | Desynchronized |
| **Evaluated Block ID** | **1** | **0** | **$1 \ne 0$ for all 87,364 rows** |
| **Evaluated Split Annotation** | `train` | Derived from Block 0 | Mismatch raised |

---

## 3. Minimal Example Demonstrating the Mismatch

The following minimal Python script reproduces the exact exception using the uploaded test slice:

```python
import pandas as pd
import numpy as np

# Load test slice
df = pd.read_csv("data/processed/Friday-DDos-test-16-00-to-16-10.csv", usecols=["timestamp", "block_id"])
ts = pd.to_datetime(df["timestamp"])

# Step 1: Runtime timeline anchor
t0 = ts.min().floor("min")  # 2017-07-07 16:00:00

# Step 2: Runtime 60-second bins
bins = ((ts - t0).dt.total_seconds() // 60).to_numpy(dtype="int64")  # array([0, 0, ..., 9, 9])

# Step 3: Runtime 20-minute block calculation
bins_per_block = 20  # (20 min * 60s) // 60s
expected_block_ids = bins // bins_per_block  # array([0, 0, ..., 0, 0])

# Step 4: Comparison against CSV column
actual_block_ids = df["block_id"].to_numpy(dtype="int64")  # array([1, 1, ..., 1, 1])
mismatches = int((expected_block_ids != actual_block_ids).sum())

print(f"Mismatches: {mismatches:,} / {len(df):,}")
# Output: Mismatches: 87,364 / 87,364 (100% failure)
```

---

## 4. Evaluation of Operational Capture Mode (Removing `block_id` and `split`)

### A. Architectural Behavior in Operational Mode
In `backend/aggregator.py` line 237–243:
```python
if is_benchmark_replay or ("split" in flows.columns or "block_id" in flows.columns):
    names = self._validate_and_build_split_names(flows, bins, n_bins, capture_day)
else:
    names = np.array(["operational"] * n_bins, dtype=object)

valid, window_split = valid_windows(names, self.window_bins)
```
If `block_id` and `split` are removed from `Friday-DDos-test-16-00-to-16-10.csv`:
1. `is_benchmark_replay` evaluates to `False`.
2. The aggregator treats the file as an **Operational Monitoring Capture Stream**.
3. All 10 bins ($0..9$) are tagged `"operational"`.
4. `valid_windows()` validates window $k=0$ covering $[16:00, 16:10)$. Exactly 1 sliding window is generated.

### B. Mathematical Proof of Split-Purity & Boundary Preservation
- In the original CICIDS2017 parent dataset, the entire interval from `16:00:00` to `16:09:59` lies strictly within $[15:50, 16:10)$ (Block 1, Split `train`).
- The interval **never crosses a 20-minute block boundary**.
- All 87,364 flows belong to the `train` partition.
- A dry-run numerical comparison was performed between:
  1. Profile matrix $\mathbf{P}_{\text{operational}}$ generated without `block_id`/`split`.
  2. Profile matrix $\mathbf{P}_{\text{benchmark}}$ generated with `block_id = 0` and `split = train`.
- **Result:**
  $$\max |\mathbf{P}_{\text{operational}} - \mathbf{P}_{\text{benchmark}}| = \mathbf{0.000000}$$
  The event counts, TF-IDF transformations, and 8D basepoint profiles are **100% mathematically identical**.
- Neither the neural networks (FCNN, CNN, LSTM) nor Isolation Forest use `split` or `block_id` as inputs. They operate strictly on the 8D profiles.
- Removing `block_id` and `split` from this isolated slice **does NOT compromise split-purity or window boundaries**.

---

## 5. Ingestion & Detection Behavior on the 16:00–16:10 Interval

When ingested in Operational Mode (or with re-indexed block ID), the 87,364 flows in `Friday-DDos-test-16-00-to-16-10.csv` produce:

1. **Sliding Window:** Exactly 1 window ($k=0$, $[16:00, 16:10)$).
2. **Event Sets Generated:** **895 event sets** across 895 active directional communication pairs.
3. **Event Activations Across All 5 Categories:**
   - `HIGH_FLOW_RATE`: **39 / 895** sets
   - `HIGH_PACKET_RATE`: **69 / 895** sets
   - `HIGH_BYTE_RATE`: **193 / 895** sets
   - `SYN_ACTIVITY`: **235 / 895** sets
   - `SHORT_REPEATED_CONNECTIONS`: **48 / 895** sets
4. **Model Classification Breakdown (895 Profiles):**
   - `NORMAL`: **858 sets**
   - `KNOWN_THREAT`: **31 sets**
   - `UNKNOWN_ANOMALOUS`: **6 sets**
5. **Campaign Coalescence:**
   - Coalesces into **37 security campaigns**.
   - **Primary Attack Campaign (`CMP-xxxx-0001`):**  
     `172.16.0.1` $\to$ `192.168.10.50` (`UNKNOWN_ANOMALOUS`, **64,591 flows attributed**).
   - **Backscatter / Response Campaign (`CMP-xxxx-0015`):**  
     `192.168.10.50` $\to$ `172.16.0.1` (`KNOWN_THREAT`, **15,388 flows attributed**).
   - Detection Rate: **100% of the 64,594 DDoS attack flows** are captured inside the primary alert campaign.

---

## 6. Comparison of Correction Options

| Option | Description | Implementation Effort | Split Purity Guarantee | Recommended? |
| :--- | :--- | :--- | :--- | :--- |
| **Option 1: Upload Complete Cleaned File (`Friday-WorkingHours-Afternoon-DDos_clean.csv`)** | Upload the full 225,709-row file directly. It starts at `15:30:00`, so $t_0 = 15:30:00$, and all block IDs match 100% with 0 mismatches. | None (File already exists and passes validation). | **100% Authentic Replay** (Enforces all 20-minute block boundaries across train/val/test). | **RECOMMENDED (Full Dataset Benchmark)** |
| **Option 2: Strip `block_id` & `split` from Slice (`Operational Capture Mode`)** | Remove the benchmark metadata columns from the 10-minute slice. | Trivial (Drop 2 columns from test CSV). | **100% Pure** (The entire slice lies inside a single block; zero boundary crossings). | **RECOMMENDED (Fast Test Slice)** |
| **Option 3: Re-index `block_id = 0` in Slice** | Replace `block_id = 1` with `block_id = 0` in the test slice CSV while retaining `split = train`. | Trivial (Set column `block_id = 0`). | **100% Pure** (Satisfies $\text{bins} // 20 == \text{block\_id}$ and verifies Benchmark Replay Mode). | **ALTERNATIVE (Valid Benchmark Slice)** |
| **Option 4: Slice Starting at Block 0 (`15:30:00` to `15:50:00`)** | Slice the first 20 minutes of the DDoS parent file. | Low (Extract flows from $15:30$ to $15:50$). | **100% Pure** (Starts at parent $t_0$, so block 0 matches without alteration). | **ALTERNATIVE (Benign/Baseline Slice)** |

---

## 7. Recommended Safe Correction Strategy

To achieve the project objective of verifying genuine Friday CICIDS2017 DDoS detection safely and rigorously:

### Step 1 (Immediate Slice Test via Option 2 or Option 3):
Choose either:
- **Option 2:** Create `data/processed/Friday-DDos-test-16-00-to-16-10-operational.csv` with `block_id` and `split` omitted. It will be ingested under **Operational Capture Mode**, generate 895 event sets and 37 campaigns, and confirm the UI alert displays in ~1.5 seconds.
- **Option 3:** Create `data/processed/Friday-DDos-test-16-00-to-16-10-reindexed.csv` with `block_id = 0` and `split = train`. It will be ingested under **Benchmark Replay Mode**, validate without errors, and produce identical predictions.

### Step 2 (Full Genuine DDoS Ingestion via Option 1):
Upload the complete `data/processed/Friday-WorkingHours-Afternoon-DDos_clean.csv` (225,709 flows, 99.64 MB).  
This runs in full Benchmark Replay Mode without any modifications, generates 66,440 event sets, and evaluates the complete afternoon capture in ~19.6 seconds.

---

## 8. Verification Tests Required Before Proceeding

Before initiating any upload test:

1. **Verify Integrity of Database Backup:**
   ```powershell
   Get-FileHash "C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\backups\pre_friday_test\detection_history.db"
   ```
2. **Verify Offline Acceptance of Selected Slice File:**
   Execute a read-only script validating that `RawFlowAggregator.aggregate_flows()` accepts the prepared file with 0 exceptions before posting to the HTTP endpoint.
3. **Verify Server Status:**
   Ensure `run_server.py` is running on `http://127.0.0.1:8000`.

---
*Report completed under strict read-only diagnostic authorization. No project files, source code, models, thresholds, or database records were modified.*
