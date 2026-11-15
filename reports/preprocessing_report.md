# Preprocessing Report - CICIDS2017

*Generated automatically on 2026-11-14 10:44:32. All numbers were calculated by the pipeline.*  
*Configuration: C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\configs\config.yaml (missing keys filled from built-in defaults)*

**Scope of this phase:** cleaning and documentation only. No neural network was trained; no TF-IDF, basepoints, cosine similarity, event profiles or dashboard exist yet.

## Combined Multi-Dataset Summary & Experiment Partitioning

Combined File: `CICIDS2017_combined_clean.csv`  
Total captures combined: **8**  
Total clean flows: **2,827,677**  
Feature schema: **67 features** (100% identical across all 8 files)

### Global Label Distribution across All 8 Captures

| Label | Count | Percentage |
| --- | --- | --- |
| BENIGN | 2,271,122 | 80.318% |
| DoS Hulk | 230,123 | 8.138% |
| PortScan | 158,804 | 5.616% |
| DDoS | 128,025 | 4.528% |
| DoS GoldenEye | 10,293 | 0.364% |
| FTP-Patator | 7,935 | 0.281% |
| SSH-Patator | 5,897 | 0.209% |
| DoS slowloris | 5,796 | 0.205% |
| DoS Slowhttptest | 5,499 | 0.194% |
| Bot | 1,956 | 0.069% |
| Web Attack - Brute Force | 1,507 | 0.053% |
| Web Attack - XSS | 652 | 0.023% |
| Infiltration | 36 | 0.001% |
| Web Attack - Sql Injection | 21 | 0.001% |
| Heartbleed | 11 | 0.000% |

### EXPERIMENT A — Multi-Class Classification Split (Time-Blocked per Day)

| Split | Rows | Share |
| --- | --- | --- |
| Train | 1,955,329 | 69.150% |
| Validation | 399,179 | 14.117% |
| Test | 473,169 | 16.733% |

### EXPERIMENT B — Unseen Attack Detection Partition (Held-Out Friday Attacks)

| Split | Datasets Included | Rows | Share |
| --- | --- | --- | --- |
| Train | Monday, Tuesday, Wednesday | 1,666,481 | 58.935% |
| Validation | Thursday (Morning & Afternoon) | 458,483 | 16.214% |
| Test (Held-Out) | Friday (Morning, PortScan, DDoS) | 702,713 | 24.851% |

## File: `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`

Rows loaded: **225,745**  ->  rows kept: **225,709** (removed 36).  Columns loaded: 85.

Raw file SHA-256 before: `1f779b4f0d78f9225554c4de53b5a2c07912b60dcd136ee4c5c1d0d2496b7cc4`  
Raw file SHA-256 after:  `1f779b4f0d78f9225554c4de53b5a2c07912b60dcd136ee4c5c1d0d2496b7cc4`  ->  **UNCHANGED**

### 1. Row accounting (what every step did to the row count)

| Step | Rows before | Rows after | Note |
| --- | --- | --- | --- |
| Load + rename columns | 225,745 | 225,745 | 85 columns renamed to snake_case |
| Validate IP/port/protocol | 225,745 | 225,745 | no invalid values |
| Numeric conversion | 225,745 | 225,745 | 0 column(s) had text values; 0 empty column(s) removed |
| Remove duplicate rows | 225,745 | 225,743 | keep=first |
| Drop rows with NaN/Infinity | 225,743 | 225,709 | 34 rows |
| Parse timestamps | 225,709 | 225,709 | order=day_first |
| Remove constant columns | 225,709 | 225,709 | 10 columns removed |

### 2. Labels and targets

`label_original` keeps the label exactly as in the raw file. `label` is the cleaned name (spaces stripped, spelling matched to the config). `target_binary` is **0 for BENIGN** and **1 for every attack label**. `target_multiclass` uses the codes below.

| Label | multiclass code | rows loaded | rows kept |
| --- | --- | --- | --- |
| BENIGN | 0 | 97,718 | 97,684 |
| DDoS | 1 | 128,027 | 128,025 |

### 3. Column roles (which fields are used for what)

| Role | Columns | Used as ordinary model features? |
| --- | --- | --- |
| Context / identification | flow_id, source_ip, destination_ip, source_port, destination_port, protocol, timestamp | **No** (reasons in section 9) |
| Helper columns we created | source_row, timestamp_raw, hour_shifted, label_original, label, target_binary, target_multiclass, block_id, split | No |
| Numeric network features | 67 columns (list in the metadata JSON) | Yes - candidates for the neural-network models later |

The event-profile pipeline (Phases 3-7) will use the **context columns** (who talked to whom, on which port/protocol, when, and what kind of event) to build event sets. The **numeric features** are for tabular models and the 'Analyze Event' form later.

### 4. Column names

85 of 85 names changed. Rule: lowercase, anything that is not a letter/digit becomes `_`, extra `_` removed (e.g. `' Flow Bytes/s'` -> `flow_bytes_s`). Full list: `data/interim/*_column_mapping.csv`. First 12 changes:

| Raw name | Normalized |
| --- | --- |
| 'Flow ID' | flow_id |
| ' Source IP' | source_ip |
| ' Source Port' | source_port |
| ' Destination IP' | destination_ip |
| ' Destination Port' | destination_port |
| ' Protocol' | protocol |
| ' Timestamp' | timestamp |
| ' Flow Duration' | flow_duration |
| ' Total Fwd Packets' | total_fwd_packets |
| ' Total Backward Packets' | total_backward_packets |
| 'Total Length of Fwd Packets' | total_length_of_fwd_packets |
| ' Total Length of Bwd Packets' | total_length_of_bwd_packets |

### 5. Network field validation

Invalid values per field: {'source_ip': 0, 'destination_ip': 0, 'source_port': 0, 'destination_port': 0, 'protocol': 0}  ->  0 row(s) affected (policy: `drop`).

### 6. Duplicates

Fully identical rows found: **2** (by label: {'BENIGN': 2}). Removed: **True** (`cleaning.remove_duplicates`). Rows are compared on every original column including the raw timestamp and Flow ID, so only true repeats of the same record match.

### 7. Missing and infinite values

Strategy: `drop_rows`.  Rows affected: **34**  (by label: {'BENIGN': 32, 'DDoS': 2}).

| Column | NaN | +Infinity | -Infinity |
| --- | --- | --- | --- |
| flow_bytes_s | 4 | 30 | 0 |
| flow_packets_s | 0 | 34 | 0 |

*Why:* infinity appears in rate columns when a flow's duration is 0 (division by zero); NaN is a missing value. Neural networks cannot use either. Dropping the rows is safe because we avoid **inventing** numbers (e.g. a median) before the train/test split exists - a median computed on all data would leak information from the test period into training. If we ever need to keep these rows, set `non_finite_strategy: keep_as_nan` and impute using the training split only.

### 8. Constant columns and negative values

Constant columns (one single value in every row, so no information): **10**. Removed: **True** (`cleaning.remove_constant_columns`).

| Column | Constant value |
| --- | --- |
| bwd_psh_flags | 0 |
| fwd_urg_flags | 0 |
| bwd_urg_flags | 0 |
| cwe_flag_count | 0 |
| fwd_avg_bytes_bulk | 0 |
| fwd_avg_packets_bulk | 0 |
| fwd_avg_bulk_rate | 0 |
| bwd_avg_bytes_bulk | 0 |
| bwd_avg_packets_bulk | 0 |
| bwd_avg_bulk_rate | 0 |

*Note:* this is decided on the whole file (it uses no labels, so it leaks nothing about the target). When more days are added, the column list will be recomputed across all days so every file has the same columns.

**Negative values were NOT removed or changed.** Some are legitimate (for example `-1` meaning 'not set'). The table shows where they occur so we can review them case by case:

| Column | Negative cells | Share of rows | Minimum | Kind |
| --- | --- | --- | --- | --- |
| flow_duration | 2 | 0.001% | -1.0 | min is -1 (possible 'not set' marker) |
| flow_bytes_s | 2 | 0.001% | -12000000.0 | other negative values |
| flow_packets_s | 2 | 0.001% | -2000000.0 | other negative values |
| flow_iat_mean | 2 | 0.001% | -1.0 | min is -1 (possible 'not set' marker) |
| flow_iat_max | 2 | 0.001% | -1.0 | min is -1 (possible 'not set' marker) |
| flow_iat_min | 108 | 0.048% | -12.0 | other negative values |
| fwd_iat_min | 6 | 0.003% | -12.0 | other negative values |
| init_win_bytes_forward | 32,925 | 14.587% | -1.0 | min is -1 (possible 'not set' marker) |
| init_win_bytes_backward | 88,272 | 39.109% | -1.0 | min is -1 (possible 'not set' marker) |

### 9. Leakage-risk check for context fields

A *leaky* field lets a model 'cheat' by memorizing something that merely correlates with the label in THIS dataset. For each attack, the table shows its most common value of each field, the share of that attack's rows with that value, and the share of BENIGN rows with the same value.

| Attack | Field | Most common value | Share of this attack | Share of BENIGN |
| --- | --- | --- | --- | --- |
| DDoS | source_ip | 172.16.0.1 | 100.0% | 0.2% |
| DDoS | destination_ip | 192.168.10.50 | 100.0% | 0.8% |
| DDoS | source_port | 49734 | 0.0% | 0.0% |
| DDoS | destination_port | 80 | 100.0% | 9.1% |
| DDoS | protocol | 6 | 100.0% | 66.3% |

**Decision:** IP addresses, ports, Flow ID and the protocol are kept for traceability and for building events in Phase 3, but are **excluded from the numeric feature list**. Where one value covers (nearly) all rows of an attack and few BENIGN rows, a model could classify by that value alone (e.g. 'attacker IP' or 'port 21') and fail on any other network. Random source ports carry no meaning and Flow ID is just a text join of IPs/ports/protocol. The paper's event-profile idea is also built on *event behaviour over time*, not on a single address.

### 10. Timestamps

Raw examples: `7/7/2017 3:30`, `7/7/2017 3:31`, `7/7/2017 3:32`, `7/7/2017 3:33`, `7/7/2017 3:34`. Strings that include seconds: 0 of 225,745.

| Date order tested | Rows parsed | Earliest (before hour fix) | Latest (before hour fix) | Most common weekday | Distinct days |
| --- | --- | --- | --- | --- | --- |
| day_first | 225,709 | 2017-07-07 03:30:00 | 2017-07-07 05:02:00 | Friday | 1 |
| month_first | 225,709 | 2017-07-07 03:30:00 | 2017-07-07 05:02:00 | Friday | 1 |

**Decision:** `day_first`.  Reason: Both day/month orders parse every row and the weekday check could not decide. FALLBACK to 'day_first' (config). PLEASE VERIFY.

> **UNCERTAIN:** the order could not be proven from the data. Check the date range above against the known capture date and set `timestamp.date_order` explicitly if needed.

**Hour correction (12-hour clock without AM/PM):** rule `auto`; pattern detected in data: **True**; applied: **True**.

Rows per hour BEFORE correction: 03h:52,486, 04h:171,671, 05h:1,552

Rows per hour AFTER correction:  15h:52,486, 16h:171,671, 17h:1,552

Resulting time span: **2017-07-07 15:30:00  ->  2017-07-07 17:02:00** (1 distinct day(s)). Hours inside the span with no rows: none.

- Hours 1-7 were shifted by +12h (assumption: the capture ran in working hours, so '2:00' means 14:00). VERIFY against the two hour tables above.

**Resolution:** timestamps have only minute precision, so flows in the same minute cannot be ordered by time. We keep `source_row` (original file order) as a tie-breaker but do not treat it as true time order. Our window step (60 s) equals this resolution, so a minute is always entirely inside or outside a window - no flow is split across a window boundary. Timestamps are naive local capture time (no time zone). `timestamp_raw` and `hour_shifted` let you trace every correction.

### 11. Train / validation / test strategy

**Blocked time split.** The timeline is cut into 20-minute blocks; each whole block is assigned to train (70%), validation (15%) or test (15%), stratified by the dominant attack in the block (seed 42). Plan: `data/processed/*_split_plan.csv`; each row has `block_id` and `split`.

*Why not a random row split?* Neighbouring flows of one attack are near-copies; a random split puts siblings in both train and test and gives unrealistically high scores. *Why not simply 'first 70% of time = train'?* In this single-day file the attacks happen in different periods, so the later attack could end up only in test and never be learned. Blocked, stratified assignment keeps time coherence AND gives each attack a place in every split.

**Rule for later phases:** a sliding window (600 s) is used only if every flow in it belongs to ONE split; windows straddling two splits are discarded. TF-IDF (IDF), basepoints and any scaling/imputation must be fitted on the **train** split only.

| split | BENIGN | DDoS | total |
| --- | --- | --- | --- |
| test | 8,399 | 0 | 8,399 |
| train | 79,378 | 128,025 | 207,403 |
| validation | 9,907 | 0 | 9,907 |

> **WARNING:** Stratum 'DDoS' has only 2 block(s): it cannot appear in all of train/validation/test. Use a smaller split.block_minutes.
> **WARNING:** label `DDoS` has no rows in the `validation` split.
> **WARNING:** label `DDoS` has no rows in the `test` split.

### 12. Outputs

| Output | Path |
| --- | --- |
| processed data | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Friday-WorkingHours-Afternoon-DDos_clean.csv |
| sample | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Friday-WorkingHours-Afternoon-DDos_sample.csv |
| metadata | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Friday-WorkingHours-Afternoon-DDos_metadata.json |
| split plan | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Friday-WorkingHours-Afternoon-DDos_split_plan.csv |
| column mapping | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\interim\Friday-WorkingHours-Afternoon-DDos_column_mapping.csv |

Final columns: 7 context + 67 numeric features + helper columns. Run time: 13.6 s.

## File: `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`

Rows loaded: **286,467**  ->  rows kept: **286,095** (removed 372).  Columns loaded: 85.

Raw file SHA-256 before: `7e2ddaa80a5849ba629463296b6128436c161b4a32e8034bb5beae06b0c45e08`  
Raw file SHA-256 after:  `7e2ddaa80a5849ba629463296b6128436c161b4a32e8034bb5beae06b0c45e08`  ->  **UNCHANGED**

### 1. Row accounting (what every step did to the row count)

| Step | Rows before | Rows after | Note |
| --- | --- | --- | --- |
| Load + rename columns | 286,467 | 286,467 | 85 columns renamed to snake_case |
| Validate IP/port/protocol | 286,467 | 286,467 | no invalid values |
| Numeric conversion | 286,467 | 286,467 | 0 column(s) had text values; 0 empty column(s) removed |
| Remove duplicate rows | 286,467 | 286,466 | keep=first |
| Drop rows with NaN/Infinity | 286,466 | 286,095 | 371 rows |
| Parse timestamps | 286,095 | 286,095 | order=day_first |
| Remove constant columns | 286,095 | 286,095 | 10 columns removed |

### 2. Labels and targets

`label_original` keeps the label exactly as in the raw file. `label` is the cleaned name (spaces stripped, spelling matched to the config). `target_binary` is **0 for BENIGN** and **1 for every attack label**. `target_multiclass` uses the codes below.

| Label | multiclass code | rows loaded | rows kept |
| --- | --- | --- | --- |
| BENIGN | 0 | 127,537 | 127,291 |
| PortScan | 1 | 158,930 | 158,804 |

### 3. Column roles (which fields are used for what)

| Role | Columns | Used as ordinary model features? |
| --- | --- | --- |
| Context / identification | flow_id, source_ip, destination_ip, source_port, destination_port, protocol, timestamp | **No** (reasons in section 9) |
| Helper columns we created | source_row, timestamp_raw, hour_shifted, label_original, label, target_binary, target_multiclass, block_id, split | No |
| Numeric network features | 67 columns (list in the metadata JSON) | Yes - candidates for the neural-network models later |

The event-profile pipeline (Phases 3-7) will use the **context columns** (who talked to whom, on which port/protocol, when, and what kind of event) to build event sets. The **numeric features** are for tabular models and the 'Analyze Event' form later.

### 4. Column names

85 of 85 names changed. Rule: lowercase, anything that is not a letter/digit becomes `_`, extra `_` removed (e.g. `' Flow Bytes/s'` -> `flow_bytes_s`). Full list: `data/interim/*_column_mapping.csv`. First 12 changes:

| Raw name | Normalized |
| --- | --- |
| 'Flow ID' | flow_id |
| ' Source IP' | source_ip |
| ' Source Port' | source_port |
| ' Destination IP' | destination_ip |
| ' Destination Port' | destination_port |
| ' Protocol' | protocol |
| ' Timestamp' | timestamp |
| ' Flow Duration' | flow_duration |
| ' Total Fwd Packets' | total_fwd_packets |
| ' Total Backward Packets' | total_backward_packets |
| 'Total Length of Fwd Packets' | total_length_of_fwd_packets |
| ' Total Length of Bwd Packets' | total_length_of_bwd_packets |

### 5. Network field validation

Invalid values per field: {'source_ip': 0, 'destination_ip': 0, 'source_port': 0, 'destination_port': 0, 'protocol': 0}  ->  0 row(s) affected (policy: `drop`).

### 6. Duplicates

Fully identical rows found: **1** (by label: {'BENIGN': 1}). Removed: **True** (`cleaning.remove_duplicates`). Rows are compared on every original column including the raw timestamp and Flow ID, so only true repeats of the same record match.

### 7. Missing and infinite values

Strategy: `drop_rows`.  Rows affected: **371**  (by label: {'BENIGN': 245, 'PortScan': 126}).

| Column | NaN | +Infinity | -Infinity |
| --- | --- | --- | --- |
| flow_bytes_s | 15 | 356 | 0 |
| flow_packets_s | 0 | 371 | 0 |

*Why:* infinity appears in rate columns when a flow's duration is 0 (division by zero); NaN is a missing value. Neural networks cannot use either. Dropping the rows is safe because we avoid **inventing** numbers (e.g. a median) before the train/test split exists - a median computed on all data would leak information from the test period into training. If we ever need to keep these rows, set `non_finite_strategy: keep_as_nan` and impute using the training split only.

### 8. Constant columns and negative values

Constant columns (one single value in every row, so no information): **10**. Removed: **True** (`cleaning.remove_constant_columns`).

| Column | Constant value |
| --- | --- |
| bwd_psh_flags | 0 |
| fwd_urg_flags | 0 |
| bwd_urg_flags | 0 |
| cwe_flag_count | 0 |
| fwd_avg_bytes_bulk | 0 |
| fwd_avg_packets_bulk | 0 |
| fwd_avg_bulk_rate | 0 |
| bwd_avg_bytes_bulk | 0 |
| bwd_avg_packets_bulk | 0 |
| bwd_avg_bulk_rate | 0 |

*Note:* this is decided on the whole file (it uses no labels, so it leaks nothing about the target). When more days are added, the column list will be recomputed across all days so every file has the same columns.

**Negative values were NOT removed or changed.** Some are legitimate (for example `-1` meaning 'not set'). The table shows where they occur so we can review them case by case:

| Column | Negative cells | Share of rows | Minimum | Kind |
| --- | --- | --- | --- | --- |
| flow_duration | 36 | 0.013% | -13.0 | other negative values |
| flow_bytes_s | 36 | 0.013% | -193000000.0 | other negative values |
| flow_packets_s | 36 | 0.013% | -2000000.0 | other negative values |
| flow_iat_mean | 36 | 0.013% | -13.0 | other negative values |
| flow_iat_max | 36 | 0.013% | -13.0 | other negative values |
| flow_iat_min | 176 | 0.062% | -13.0 | other negative values |
| init_win_bytes_forward | 60,210 | 21.045% | -1.0 | min is -1 (possible 'not set' marker) |
| init_win_bytes_backward | 76,888 | 26.875% | -1.0 | min is -1 (possible 'not set' marker) |

### 9. Leakage-risk check for context fields

A *leaky* field lets a model 'cheat' by memorizing something that merely correlates with the label in THIS dataset. For each attack, the table shows its most common value of each field, the share of that attack's rows with that value, and the share of BENIGN rows with the same value.

| Attack | Field | Most common value | Share of this attack | Share of BENIGN |
| --- | --- | --- | --- | --- |
| PortScan | source_ip | 172.16.0.1 | 100.0% | 0.0% |
| PortScan | destination_ip | 192.168.10.50 | 100.0% | 1.4% |
| PortScan | source_port | 59328 | 0.6% | 0.0% |
| PortScan | destination_port | 80 | 0.2% | 12.9% |
| PortScan | protocol | 6 | 100.0% | 52.7% |

**Decision:** IP addresses, ports, Flow ID and the protocol are kept for traceability and for building events in Phase 3, but are **excluded from the numeric feature list**. Where one value covers (nearly) all rows of an attack and few BENIGN rows, a model could classify by that value alone (e.g. 'attacker IP' or 'port 21') and fail on any other network. Random source ports carry no meaning and Flow ID is just a text join of IPs/ports/protocol. The paper's event-profile idea is also built on *event behaviour over time*, not on a single address.

### 10. Timestamps

Raw examples: `7/7/2017 1:00`, `7/7/2017 1:01`, `7/7/2017 1:02`, `7/7/2017 1:03`, `7/7/2017 1:04`. Strings that include seconds: 0 of 286,467.

| Date order tested | Rows parsed | Earliest (before hour fix) | Latest (before hour fix) | Most common weekday | Distinct days |
| --- | --- | --- | --- | --- | --- |
| day_first | 286,095 | 2017-07-07 01:00:00 | 2017-07-07 03:29:00 | Friday | 1 |
| month_first | 286,095 | 2017-07-07 01:00:00 | 2017-07-07 03:29:00 | Friday | 1 |

**Decision:** `day_first`.  Reason: Both day/month orders parse every row and the weekday check could not decide. FALLBACK to 'day_first' (config). PLEASE VERIFY.

> **UNCERTAIN:** the order could not be proven from the data. Check the date range above against the known capture date and set `timestamp.date_order` explicitly if needed.

**Hour correction (12-hour clock without AM/PM):** rule `auto`; pattern detected in data: **True**; applied: **True**.

Rows per hour BEFORE correction: 01h:43,020, 02h:191,296, 03h:51,779

Rows per hour AFTER correction:  13h:43,020, 14h:191,296, 15h:51,779

Resulting time span: **2017-07-07 13:00:00  ->  2017-07-07 15:29:00** (1 distinct day(s)). Hours inside the span with no rows: none.

- Hours 1-7 were shifted by +12h (assumption: the capture ran in working hours, so '2:00' means 14:00). VERIFY against the two hour tables above.

**Resolution:** timestamps have only minute precision, so flows in the same minute cannot be ordered by time. We keep `source_row` (original file order) as a tie-breaker but do not treat it as true time order. Our window step (60 s) equals this resolution, so a minute is always entirely inside or outside a window - no flow is split across a window boundary. Timestamps are naive local capture time (no time zone). `timestamp_raw` and `hour_shifted` let you trace every correction.

### 11. Train / validation / test strategy

**Blocked time split.** The timeline is cut into 20-minute blocks; each whole block is assigned to train (70%), validation (15%) or test (15%), stratified by the dominant attack in the block (seed 42). Plan: `data/processed/*_split_plan.csv`; each row has `block_id` and `split`.

*Why not a random row split?* Neighbouring flows of one attack are near-copies; a random split puts siblings in both train and test and gives unrealistically high scores. *Why not simply 'first 70% of time = train'?* In this single-day file the attacks happen in different periods, so the later attack could end up only in test and never be learned. Blocked, stratified assignment keeps time coherence AND gives each attack a place in every split.

**Rule for later phases:** a sliding window (600 s) is used only if every flow in it belongs to ONE split; windows straddling two splits are discarded. TF-IDF (IDF), basepoints and any scaling/imputation must be fitted on the **train** split only.

| split | BENIGN | PortScan | total |
| --- | --- | --- | --- |
| test | 17,810 | 138,386 | 156,196 |
| train | 92,850 | 20,231 | 113,081 |
| validation | 16,631 | 187 | 16,818 |

> **WARNING:** Stratum 'BENIGN' has only 2 block(s): it cannot appear in all of train/validation/test. Use a smaller split.block_minutes.

### 12. Outputs

| Output | Path |
| --- | --- |
| processed data | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Friday-WorkingHours-Afternoon-PortScan_clean.csv |
| sample | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Friday-WorkingHours-Afternoon-PortScan_sample.csv |
| metadata | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Friday-WorkingHours-Afternoon-PortScan_metadata.json |
| split plan | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Friday-WorkingHours-Afternoon-PortScan_split_plan.csv |
| column mapping | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\interim\Friday-WorkingHours-Afternoon-PortScan_column_mapping.csv |

Final columns: 7 context + 67 numeric features + helper columns. Run time: 16.1 s.

## File: `Friday-WorkingHours-Morning.pcap_ISCX.csv`

Rows loaded: **191,033**  ->  rows kept: **190,909** (removed 124).  Columns loaded: 85.

Raw file SHA-256 before: `c061cd98f39d8054aeaed6244a5129a20b3985983d0d022b860ae8aa07fe8d21`  
Raw file SHA-256 after:  `c061cd98f39d8054aeaed6244a5129a20b3985983d0d022b860ae8aa07fe8d21`  ->  **UNCHANGED**

### 1. Row accounting (what every step did to the row count)

| Step | Rows before | Rows after | Note |
| --- | --- | --- | --- |
| Load + rename columns | 191,033 | 191,033 | 85 columns renamed to snake_case |
| Validate IP/port/protocol | 191,033 | 191,033 | no invalid values |
| Numeric conversion | 191,033 | 191,033 | 0 column(s) had text values; 0 empty column(s) removed |
| Remove duplicate rows | 191,033 | 191,031 | keep=first |
| Drop rows with NaN/Infinity | 191,031 | 190,909 | 122 rows |
| Parse timestamps | 190,909 | 190,909 | order=day_first |
| Remove constant columns | 190,909 | 190,909 | 10 columns removed |

### 2. Labels and targets

`label_original` keeps the label exactly as in the raw file. `label` is the cleaned name (spaces stripped, spelling matched to the config). `target_binary` is **0 for BENIGN** and **1 for every attack label**. `target_multiclass` uses the codes below.

| Label | multiclass code | rows loaded | rows kept |
| --- | --- | --- | --- |
| BENIGN | 0 | 189,067 | 188,953 |
| Bot | 1 | 1,966 | 1,956 |

### 3. Column roles (which fields are used for what)

| Role | Columns | Used as ordinary model features? |
| --- | --- | --- |
| Context / identification | flow_id, source_ip, destination_ip, source_port, destination_port, protocol, timestamp | **No** (reasons in section 9) |
| Helper columns we created | source_row, timestamp_raw, hour_shifted, label_original, label, target_binary, target_multiclass, block_id, split | No |
| Numeric network features | 67 columns (list in the metadata JSON) | Yes - candidates for the neural-network models later |

The event-profile pipeline (Phases 3-7) will use the **context columns** (who talked to whom, on which port/protocol, when, and what kind of event) to build event sets. The **numeric features** are for tabular models and the 'Analyze Event' form later.

### 4. Column names

85 of 85 names changed. Rule: lowercase, anything that is not a letter/digit becomes `_`, extra `_` removed (e.g. `' Flow Bytes/s'` -> `flow_bytes_s`). Full list: `data/interim/*_column_mapping.csv`. First 12 changes:

| Raw name | Normalized |
| --- | --- |
| 'Flow ID' | flow_id |
| ' Source IP' | source_ip |
| ' Source Port' | source_port |
| ' Destination IP' | destination_ip |
| ' Destination Port' | destination_port |
| ' Protocol' | protocol |
| ' Timestamp' | timestamp |
| ' Flow Duration' | flow_duration |
| ' Total Fwd Packets' | total_fwd_packets |
| ' Total Backward Packets' | total_backward_packets |
| 'Total Length of Fwd Packets' | total_length_of_fwd_packets |
| ' Total Length of Bwd Packets' | total_length_of_bwd_packets |

### 5. Network field validation

Invalid values per field: {'source_ip': 0, 'destination_ip': 0, 'source_port': 0, 'destination_port': 0, 'protocol': 0}  ->  0 row(s) affected (policy: `drop`).

### 6. Duplicates

Fully identical rows found: **2** (by label: {'BENIGN': 2}). Removed: **True** (`cleaning.remove_duplicates`). Rows are compared on every original column including the raw timestamp and Flow ID, so only true repeats of the same record match.

### 7. Missing and infinite values

Strategy: `drop_rows`.  Rows affected: **122**  (by label: {'BENIGN': 112, 'Bot': 10}).

| Column | NaN | +Infinity | -Infinity |
| --- | --- | --- | --- |
| flow_bytes_s | 28 | 94 | 0 |
| flow_packets_s | 0 | 122 | 0 |

*Why:* infinity appears in rate columns when a flow's duration is 0 (division by zero); NaN is a missing value. Neural networks cannot use either. Dropping the rows is safe because we avoid **inventing** numbers (e.g. a median) before the train/test split exists - a median computed on all data would leak information from the test period into training. If we ever need to keep these rows, set `non_finite_strategy: keep_as_nan` and impute using the training split only.

### 8. Constant columns and negative values

Constant columns (one single value in every row, so no information): **10**. Removed: **True** (`cleaning.remove_constant_columns`).

| Column | Constant value |
| --- | --- |
| bwd_psh_flags | 0 |
| fwd_urg_flags | 0 |
| bwd_urg_flags | 0 |
| cwe_flag_count | 0 |
| fwd_avg_bytes_bulk | 0 |
| fwd_avg_packets_bulk | 0 |
| fwd_avg_bulk_rate | 0 |
| bwd_avg_bytes_bulk | 0 |
| bwd_avg_packets_bulk | 0 |
| bwd_avg_bulk_rate | 0 |

*Note:* this is decided on the whole file (it uses no labels, so it leaks nothing about the target). When more days are added, the column list will be recomputed across all days so every file has the same columns.

**Negative values were NOT removed or changed.** Some are legitimate (for example `-1` meaning 'not set'). The table shows where they occur so we can review them case by case:

| Column | Negative cells | Share of rows | Minimum | Kind |
| --- | --- | --- | --- | --- |
| flow_duration | 9 | 0.005% | -12.0 | other negative values |
| flow_bytes_s | 8 | 0.004% | -12000000.0 | other negative values |
| flow_packets_s | 9 | 0.005% | -2000000.0 | other negative values |
| flow_iat_mean | 9 | 0.005% | -12.0 | other negative values |
| flow_iat_max | 9 | 0.005% | -12.0 | other negative values |
| flow_iat_min | 225 | 0.118% | -13.0 | other negative values |
| init_win_bytes_forward | 95,834 | 50.199% | -1.0 | min is -1 (possible 'not set' marker) |
| init_win_bytes_backward | 118,355 | 61.996% | -1.0 | min is -1 (possible 'not set' marker) |

### 9. Leakage-risk check for context fields

A *leaky* field lets a model 'cheat' by memorizing something that merely correlates with the label in THIS dataset. For each attack, the table shows its most common value of each field, the share of that attack's rows with that value, and the share of BENIGN rows with the same value.

| Attack | Field | Most common value | Share of this attack | Share of BENIGN |
| --- | --- | --- | --- | --- |
| Bot | source_ip | 205.174.165.73 | 35.8% | 0.0% |
| Bot | destination_ip | 205.174.165.73 | 64.0% | 0.0% |
| Bot | source_port | 8080 | 35.8% | 0.0% |
| Bot | destination_port | 8080 | 64.2% | 0.0% |
| Bot | protocol | 6 | 100.0% | 49.3% |

**Decision:** IP addresses, ports, Flow ID and the protocol are kept for traceability and for building events in Phase 3, but are **excluded from the numeric feature list**. Where one value covers (nearly) all rows of an attack and few BENIGN rows, a model could classify by that value alone (e.g. 'attacker IP' or 'port 21') and fail on any other network. Random source ports carry no meaning and Flow ID is just a text join of IPs/ports/protocol. The paper's event-profile idea is also built on *event behaviour over time*, not on a single address.

### 10. Timestamps

Raw examples: `7/7/2017 8:59`, `7/7/2017 9:00`, `7/7/2017 9:01`, `7/7/2017 9:02`, `7/7/2017 9:03`. Strings that include seconds: 0 of 191,033.

| Date order tested | Rows parsed | Earliest (before hour fix) | Latest (before hour fix) | Most common weekday | Distinct days |
| --- | --- | --- | --- | --- | --- |
| day_first | 190,909 | 2017-07-07 08:59:00 | 2017-07-07 12:59:00 | Friday | 1 |
| month_first | 190,909 | 2017-07-07 08:59:00 | 2017-07-07 12:59:00 | Friday | 1 |

**Decision:** `day_first`.  Reason: Both day/month orders parse every row and the weekday check could not decide. FALLBACK to 'day_first' (config). PLEASE VERIFY.

> **UNCERTAIN:** the order could not be proven from the data. Check the date range above against the known capture date and set `timestamp.date_order` explicitly if needed.

**Hour correction (12-hour clock without AM/PM):** rule `auto`; pattern detected in data: **False**; applied: **False**.

Rows per hour BEFORE correction: 08h:2, 09h:49,935, 10h:71,535, 11h:55,394, 12h:14,043

Rows per hour AFTER correction:  08h:2, 09h:49,935, 10h:71,535, 11h:55,394, 12h:14,043

Resulting time span: **2017-07-07 08:59:00  ->  2017-07-07 12:59:00** (1 distinct day(s)). Hours inside the span with no rows: none.


**Resolution:** timestamps have only minute precision, so flows in the same minute cannot be ordered by time. We keep `source_row` (original file order) as a tie-breaker but do not treat it as true time order. Our window step (60 s) equals this resolution, so a minute is always entirely inside or outside a window - no flow is split across a window boundary. Timestamps are naive local capture time (no time zone). `timestamp_raw` and `hour_shifted` let you trace every correction.

### 11. Train / validation / test strategy

**Blocked time split.** The timeline is cut into 20-minute blocks; each whole block is assigned to train (70%), validation (15%) or test (15%), stratified by the dominant attack in the block (seed 42). Plan: `data/processed/*_split_plan.csv`; each row has `block_id` and `split`.

*Why not a random row split?* Neighbouring flows of one attack are near-copies; a random split puts siblings in both train and test and gives unrealistically high scores. *Why not simply 'first 70% of time = train'?* In this single-day file the attacks happen in different periods, so the later attack could end up only in test and never be learned. Blocked, stratified assignment keeps time coherence AND gives each attack a place in every split.

**Rule for later phases:** a sliding window (600 s) is used only if every flow in it belongs to ONE split; windows straddling two splits are discarded. TF-IDF (IDF), basepoints and any scaling/imputation must be fitted on the **train** split only.

| split | BENIGN | Bot | total |
| --- | --- | --- | --- |
| test | 24,541 | 81 | 24,622 |
| train | 145,252 | 1,707 | 146,959 |
| validation | 19,160 | 168 | 19,328 |

> **WARNING:** Stratum 'BENIGN' has only 2 block(s): it cannot appear in all of train/validation/test. Use a smaller split.block_minutes.

### 12. Outputs

| Output | Path |
| --- | --- |
| processed data | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Friday-WorkingHours-Morning_clean.csv |
| sample | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Friday-WorkingHours-Morning_sample.csv |
| metadata | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Friday-WorkingHours-Morning_metadata.json |
| split plan | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Friday-WorkingHours-Morning_split_plan.csv |
| column mapping | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\interim\Friday-WorkingHours-Morning_column_mapping.csv |

Final columns: 7 context + 67 numeric features + helper columns. Run time: 11.1 s.

## File: `Monday-WorkingHours.pcap_ISCX.csv`

Rows loaded: **529,918**  ->  rows kept: **529,450** (removed 468).  Columns loaded: 85.

Raw file SHA-256 before: `96f26aea87d513073769b48ce204c2921791149e1c6225f7db65a3fed7973820`  
Raw file SHA-256 after:  `96f26aea87d513073769b48ce204c2921791149e1c6225f7db65a3fed7973820`  ->  **UNCHANGED**

### 1. Row accounting (what every step did to the row count)

| Step | Rows before | Rows after | Note |
| --- | --- | --- | --- |
| Load + rename columns | 529,918 | 529,918 | 85 columns renamed to snake_case |
| Validate IP/port/protocol | 529,918 | 529,918 | no invalid values |
| Numeric conversion | 529,918 | 529,918 | 0 column(s) had text values; 0 empty column(s) removed |
| Remove duplicate rows | 529,918 | 529,884 | keep=first |
| Drop rows with NaN/Infinity | 529,884 | 529,450 | 434 rows |
| Parse timestamps | 529,450 | 529,450 | order=day_first |
| Remove constant columns | 529,450 | 529,450 | 10 columns removed |

### 2. Labels and targets

`label_original` keeps the label exactly as in the raw file. `label` is the cleaned name (spaces stripped, spelling matched to the config). `target_binary` is **0 for BENIGN** and **1 for every attack label**. `target_multiclass` uses the codes below.

| Label | multiclass code | rows loaded | rows kept |
| --- | --- | --- | --- |
| BENIGN | 0 | 529,918 | 529,450 |

### 3. Column roles (which fields are used for what)

| Role | Columns | Used as ordinary model features? |
| --- | --- | --- |
| Context / identification | flow_id, source_ip, destination_ip, source_port, destination_port, protocol, timestamp | **No** (reasons in section 9) |
| Helper columns we created | source_row, timestamp_raw, hour_shifted, label_original, label, target_binary, target_multiclass, block_id, split | No |
| Numeric network features | 67 columns (list in the metadata JSON) | Yes - candidates for the neural-network models later |

The event-profile pipeline (Phases 3-7) will use the **context columns** (who talked to whom, on which port/protocol, when, and what kind of event) to build event sets. The **numeric features** are for tabular models and the 'Analyze Event' form later.

### 4. Column names

85 of 85 names changed. Rule: lowercase, anything that is not a letter/digit becomes `_`, extra `_` removed (e.g. `' Flow Bytes/s'` -> `flow_bytes_s`). Full list: `data/interim/*_column_mapping.csv`. First 12 changes:

| Raw name | Normalized |
| --- | --- |
| 'Flow ID' | flow_id |
| ' Source IP' | source_ip |
| ' Source Port' | source_port |
| ' Destination IP' | destination_ip |
| ' Destination Port' | destination_port |
| ' Protocol' | protocol |
| ' Timestamp' | timestamp |
| ' Flow Duration' | flow_duration |
| ' Total Fwd Packets' | total_fwd_packets |
| ' Total Backward Packets' | total_backward_packets |
| 'Total Length of Fwd Packets' | total_length_of_fwd_packets |
| ' Total Length of Bwd Packets' | total_length_of_bwd_packets |

### 5. Network field validation

Invalid values per field: {'source_ip': 0, 'destination_ip': 0, 'source_port': 0, 'destination_port': 0, 'protocol': 0}  ->  0 row(s) affected (policy: `drop`).

### 6. Duplicates

Fully identical rows found: **34** (by label: {'BENIGN': 34}). Removed: **True** (`cleaning.remove_duplicates`). Rows are compared on every original column including the raw timestamp and Flow ID, so only true repeats of the same record match.

### 7. Missing and infinite values

Strategy: `drop_rows`.  Rows affected: **434**  (by label: {'BENIGN': 434}).

| Column | NaN | +Infinity | -Infinity |
| --- | --- | --- | --- |
| flow_bytes_s | 64 | 370 | 0 |
| flow_packets_s | 0 | 434 | 0 |

*Why:* infinity appears in rate columns when a flow's duration is 0 (division by zero); NaN is a missing value. Neural networks cannot use either. Dropping the rows is safe because we avoid **inventing** numbers (e.g. a median) before the train/test split exists - a median computed on all data would leak information from the test period into training. If we ever need to keep these rows, set `non_finite_strategy: keep_as_nan` and impute using the training split only.

### 8. Constant columns and negative values

Constant columns (one single value in every row, so no information): **10**. Removed: **True** (`cleaning.remove_constant_columns`).

| Column | Constant value |
| --- | --- |
| bwd_psh_flags | 0 |
| fwd_urg_flags | 0 |
| bwd_urg_flags | 0 |
| cwe_flag_count | 0 |
| fwd_avg_bytes_bulk | 0 |
| fwd_avg_packets_bulk | 0 |
| fwd_avg_bulk_rate | 0 |
| bwd_avg_bytes_bulk | 0 |
| bwd_avg_packets_bulk | 0 |
| bwd_avg_bulk_rate | 0 |

*Note:* this is decided on the whole file (it uses no labels, so it leaks nothing about the target). When more days are added, the column list will be recomputed across all days so every file has the same columns.

**Negative values were NOT removed or changed.** Some are legitimate (for example `-1` meaning 'not set'). The table shows where they occur so we can review them case by case:

| Column | Negative cells | Share of rows | Minimum | Kind |
| --- | --- | --- | --- | --- |
| flow_duration | 15 | 0.003% | -1.0 | min is -1 (possible 'not set' marker) |
| flow_bytes_s | 9 | 0.002% | -12000000.0 | other negative values |
| flow_packets_s | 15 | 0.003% | -2000000.0 | other negative values |
| flow_iat_mean | 15 | 0.003% | -1.0 | min is -1 (possible 'not set' marker) |
| flow_iat_max | 15 | 0.003% | -1.0 | min is -1 (possible 'not set' marker) |
| flow_iat_min | 512 | 0.097% | -14.0 | other negative values |
| fwd_header_length | 23 | 0.004% | -1929349973.0 | other negative values |
| bwd_header_length | 17 | 0.003% | -167770490.0 | other negative values |
| fwd_header_length_1 | 23 | 0.004% | -1929349973.0 | other negative values |
| init_win_bytes_forward | 224,482 | 42.399% | -1.0 | min is -1 (possible 'not set' marker) |
| init_win_bytes_backward | 298,839 | 56.443% | -1.0 | min is -1 (possible 'not set' marker) |
| min_seg_size_forward | 23 | 0.004% | -83885313.0 | other negative values |

### 9. Leakage-risk check for context fields

A *leaky* field lets a model 'cheat' by memorizing something that merely correlates with the label in THIS dataset. For each attack, the table shows its most common value of each field, the share of that attack's rows with that value, and the share of BENIGN rows with the same value.

| Attack | Field | Most common value | Share of this attack | Share of BENIGN |
| --- | --- | --- | --- | --- |

**Decision:** IP addresses, ports, Flow ID and the protocol are kept for traceability and for building events in Phase 3, but are **excluded from the numeric feature list**. Where one value covers (nearly) all rows of an attack and few BENIGN rows, a model could classify by that value alone (e.g. 'attacker IP' or 'port 21') and fail on any other network. Random source ports carry no meaning and Flow ID is just a text join of IPs/ports/protocol. The paper's event-profile idea is also built on *event behaviour over time*, not on a single address.

### 10. Timestamps

Raw examples: `03/07/2017 08:55:58`, `03/07/2017 08:56:22`, `03/07/2017 08:56:38`, `03/07/2017 08:56:46`, `03/07/2017 08:56:58`. Strings that include seconds: 529,450 of 529,918.

| Date order tested | Rows parsed | Earliest (before hour fix) | Latest (before hour fix) | Most common weekday | Distinct days |
| --- | --- | --- | --- | --- | --- |
| day_first | 529,450 | 2017-07-03 01:00:01 | 2017-07-03 12:59:58 | Monday | 1 |
| month_first | 529,450 | 2017-03-07 01:00:01 | 2017-03-07 12:59:58 | Tuesday | 1 |

**Decision:** `day_first`.  Reason: Both day/month orders parse every row (ambiguous). The file name says 'Monday'; only 'day_first' gives a Monday.

**Hour correction (12-hour clock without AM/PM):** rule `auto`; pattern detected in data: **True**; applied: **True**.

Rows per hour BEFORE correction: 01h:57,561, 02h:48,532, 03h:48,894, 04h:65,829, 05h:1,840, 08h:772, 09h:74,341, 10h:85,008, 11h:88,781, 12h:57,892

Rows per hour AFTER correction:  08h:772, 09h:74,341, 10h:85,008, 11h:88,781, 12h:57,892, 13h:57,561, 14h:48,532, 15h:48,894, 16h:65,829, 17h:1,840

Resulting time span: **2017-07-03 08:55:58  ->  2017-07-03 17:01:34** (1 distinct day(s)). Hours inside the span with no rows: none.

- Hours 1-7 were shifted by +12h (assumption: the capture ran in working hours, so '2:00' means 14:00). VERIFY against the two hour tables above.

**Resolution:** timestamps have only minute precision, so flows in the same minute cannot be ordered by time. We keep `source_row` (original file order) as a tie-breaker but do not treat it as true time order. Our window step (60 s) equals this resolution, so a minute is always entirely inside or outside a window - no flow is split across a window boundary. Timestamps are naive local capture time (no time zone). `timestamp_raw` and `hour_shifted` let you trace every correction.

### 11. Train / validation / test strategy

**Blocked time split.** The timeline is cut into 20-minute blocks; each whole block is assigned to train (70%), validation (15%) or test (15%), stratified by the dominant attack in the block (seed 42). Plan: `data/processed/*_split_plan.csv`; each row has `block_id` and `split`.

*Why not a random row split?* Neighbouring flows of one attack are near-copies; a random split puts siblings in both train and test and gives unrealistically high scores. *Why not simply 'first 70% of time = train'?* In this single-day file the attacks happen in different periods, so the later attack could end up only in test and never be learned. Blocked, stratified assignment keeps time coherence AND gives each attack a place in every split.

**Rule for later phases:** a sliding window (600 s) is used only if every flow in it belongs to ONE split; windows straddling two splits are discarded. TF-IDF (IDF), basepoints and any scaling/imputation must be fitted on the **train** split only.

| split | BENIGN | total |
| --- | --- | --- |
| test | 67,245 | 67,245 |
| train | 387,628 | 387,628 |
| validation | 74,577 | 74,577 |


### 12. Outputs

| Output | Path |
| --- | --- |
| processed data | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Monday-WorkingHours_clean.csv |
| sample | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Monday-WorkingHours_sample.csv |
| metadata | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Monday-WorkingHours_metadata.json |
| split plan | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Monday-WorkingHours_split_plan.csv |
| column mapping | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\interim\Monday-WorkingHours_column_mapping.csv |

Final columns: 7 context + 67 numeric features + helper columns. Run time: 34.0 s.

## File: `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`

Rows loaded: **288,602**  ->  rows kept: **288,253** (removed 349).  Columns loaded: 85.

Raw file SHA-256 before: `d74238e054023c8bd4d8056650463cadb25c100fb0e26ebd4272c07b5c022c4b`  
Raw file SHA-256 after:  `d74238e054023c8bd4d8056650463cadb25c100fb0e26ebd4272c07b5c022c4b`  ->  **UNCHANGED**

### 1. Row accounting (what every step did to the row count)

| Step | Rows before | Rows after | Note |
| --- | --- | --- | --- |
| Load + rename columns | 288,602 | 288,602 | 85 columns renamed to snake_case |
| Validate IP/port/protocol | 288,602 | 288,602 | no invalid values |
| Numeric conversion | 288,602 | 288,602 | 0 column(s) had text values; 0 empty column(s) removed |
| Remove duplicate rows | 288,602 | 288,460 | keep=first |
| Drop rows with NaN/Infinity | 288,460 | 288,253 | 207 rows |
| Parse timestamps | 288,253 | 288,253 | order=day_first |
| Remove constant columns | 288,253 | 288,253 | 10 columns removed |

### 2. Labels and targets

`label_original` keeps the label exactly as in the raw file. `label` is the cleaned name (spaces stripped, spelling matched to the config). `target_binary` is **0 for BENIGN** and **1 for every attack label**. `target_multiclass` uses the codes below.

| Label | multiclass code | rows loaded | rows kept |
| --- | --- | --- | --- |
| BENIGN | 0 | 288,566 | 288,217 |
| Infiltration | 1 | 36 | 36 |

### 3. Column roles (which fields are used for what)

| Role | Columns | Used as ordinary model features? |
| --- | --- | --- |
| Context / identification | flow_id, source_ip, destination_ip, source_port, destination_port, protocol, timestamp | **No** (reasons in section 9) |
| Helper columns we created | source_row, timestamp_raw, hour_shifted, label_original, label, target_binary, target_multiclass, block_id, split | No |
| Numeric network features | 67 columns (list in the metadata JSON) | Yes - candidates for the neural-network models later |

The event-profile pipeline (Phases 3-7) will use the **context columns** (who talked to whom, on which port/protocol, when, and what kind of event) to build event sets. The **numeric features** are for tabular models and the 'Analyze Event' form later.

### 4. Column names

85 of 85 names changed. Rule: lowercase, anything that is not a letter/digit becomes `_`, extra `_` removed (e.g. `' Flow Bytes/s'` -> `flow_bytes_s`). Full list: `data/interim/*_column_mapping.csv`. First 12 changes:

| Raw name | Normalized |
| --- | --- |
| 'Flow ID' | flow_id |
| ' Source IP' | source_ip |
| ' Source Port' | source_port |
| ' Destination IP' | destination_ip |
| ' Destination Port' | destination_port |
| ' Protocol' | protocol |
| ' Timestamp' | timestamp |
| ' Flow Duration' | flow_duration |
| ' Total Fwd Packets' | total_fwd_packets |
| ' Total Backward Packets' | total_backward_packets |
| 'Total Length of Fwd Packets' | total_length_of_fwd_packets |
| ' Total Length of Bwd Packets' | total_length_of_bwd_packets |

### 5. Network field validation

Invalid values per field: {'source_ip': 0, 'destination_ip': 0, 'source_port': 0, 'destination_port': 0, 'protocol': 0}  ->  0 row(s) affected (policy: `drop`).

### 6. Duplicates

Fully identical rows found: **142** (by label: {'BENIGN': 142}). Removed: **True** (`cleaning.remove_duplicates`). Rows are compared on every original column including the raw timestamp and Flow ID, so only true repeats of the same record match.

### 7. Missing and infinite values

Strategy: `drop_rows`.  Rows affected: **207**  (by label: {'BENIGN': 207}).

| Column | NaN | +Infinity | -Infinity |
| --- | --- | --- | --- |
| flow_bytes_s | 18 | 189 | 0 |
| flow_packets_s | 0 | 207 | 0 |

*Why:* infinity appears in rate columns when a flow's duration is 0 (division by zero); NaN is a missing value. Neural networks cannot use either. Dropping the rows is safe because we avoid **inventing** numbers (e.g. a median) before the train/test split exists - a median computed on all data would leak information from the test period into training. If we ever need to keep these rows, set `non_finite_strategy: keep_as_nan` and impute using the training split only.

### 8. Constant columns and negative values

Constant columns (one single value in every row, so no information): **8**. Removed: **True** (`cleaning.remove_constant_columns`).

| Column | Constant value |
| --- | --- |
| bwd_psh_flags | 0 |
| bwd_urg_flags | 0 |
| fwd_avg_bytes_bulk | 0 |
| fwd_avg_packets_bulk | 0 |
| fwd_avg_bulk_rate | 0 |
| bwd_avg_bytes_bulk | 0 |
| bwd_avg_packets_bulk | 0 |
| bwd_avg_bulk_rate | 0 |

*Note:* this is decided on the whole file (it uses no labels, so it leaks nothing about the target). When more days are added, the column list will be recomputed across all days so every file has the same columns.

**Negative values were NOT removed or changed.** Some are legitimate (for example `-1` meaning 'not set'). The table shows where they occur so we can review them case by case:

| Column | Negative cells | Share of rows | Minimum | Kind |
| --- | --- | --- | --- | --- |
| flow_duration | 4 | 0.001% | -2.0 | other negative values |
| flow_bytes_s | 4 | 0.001% | -12000000.0 | other negative values |
| flow_packets_s | 4 | 0.001% | -2000000.0 | other negative values |
| flow_iat_mean | 4 | 0.001% | -2.0 | other negative values |
| flow_iat_max | 4 | 0.001% | -2.0 | other negative values |
| flow_iat_min | 353 | 0.122% | -12.0 | other negative values |
| init_win_bytes_forward | 102,433 | 35.536% | -1.0 | min is -1 (possible 'not set' marker) |
| init_win_bytes_backward | 164,031 | 56.905% | -1.0 | min is -1 (possible 'not set' marker) |

### 9. Leakage-risk check for context fields

A *leaky* field lets a model 'cheat' by memorizing something that merely correlates with the label in THIS dataset. For each attack, the table shows its most common value of each field, the share of that attack's rows with that value, and the share of BENIGN rows with the same value.

| Attack | Field | Most common value | Share of this attack | Share of BENIGN |
| --- | --- | --- | --- | --- |
| Infiltration | source_ip | 192.168.10.8 | 100.0% | 28.8% |
| Infiltration | destination_ip | 205.174.165.73 | 100.0% | 0.0% |
| Infiltration | source_port | 1260 | 50.0% | 0.0% |
| Infiltration | destination_port | 444 | 100.0% | 0.0% |
| Infiltration | protocol | 6 | 100.0% | 64.5% |

**Decision:** IP addresses, ports, Flow ID and the protocol are kept for traceability and for building events in Phase 3, but are **excluded from the numeric feature list**. Where one value covers (nearly) all rows of an attack and few BENIGN rows, a model could classify by that value alone (e.g. 'attacker IP' or 'port 21') and fail on any other network. Random source ports carry no meaning and Flow ID is just a text join of IPs/ports/protocol. The paper's event-profile idea is also built on *event behaviour over time*, not on a single address.

### 10. Timestamps

Raw examples: `6/7/2017 1:00`, `6/7/2017 1:01`, `6/7/2017 1:02`, `6/7/2017 1:03`, `6/7/2017 1:04`. Strings that include seconds: 0 of 288,602.

| Date order tested | Rows parsed | Earliest (before hour fix) | Latest (before hour fix) | Most common weekday | Distinct days |
| --- | --- | --- | --- | --- | --- |
| day_first | 288,253 | 2017-07-06 01:00:00 | 2017-07-06 05:04:00 | Thursday | 1 |
| month_first | 288,253 | 2017-06-07 01:00:00 | 2017-06-07 05:04:00 | Wednesday | 1 |

**Decision:** `day_first`.  Reason: Both day/month orders parse every row (ambiguous). The file name says 'Thursday'; only 'day_first' gives a Thursday.

**Hour correction (12-hour clock without AM/PM):** rule `auto`; pattern detected in data: **True**; applied: **True**.

Rows per hour BEFORE correction: 01h:50,087, 02h:57,665, 03h:129,228, 04h:48,807, 05h:2,466

Rows per hour AFTER correction:  13h:50,087, 14h:57,665, 15h:129,228, 16h:48,807, 17h:2,466

Resulting time span: **2017-07-06 13:00:00  ->  2017-07-06 17:04:00** (1 distinct day(s)). Hours inside the span with no rows: none.

- Hours 1-7 were shifted by +12h (assumption: the capture ran in working hours, so '2:00' means 14:00). VERIFY against the two hour tables above.

**Resolution:** timestamps have only minute precision, so flows in the same minute cannot be ordered by time. We keep `source_row` (original file order) as a tie-breaker but do not treat it as true time order. Our window step (60 s) equals this resolution, so a minute is always entirely inside or outside a window - no flow is split across a window boundary. Timestamps are naive local capture time (no time zone). `timestamp_raw` and `hour_shifted` let you trace every correction.

### 11. Train / validation / test strategy

**Blocked time split.** The timeline is cut into 20-minute blocks; each whole block is assigned to train (70%), validation (15%) or test (15%), stratified by the dominant attack in the block (seed 42). Plan: `data/processed/*_split_plan.csv`; each row has `block_id` and `split`.

*Why not a random row split?* Neighbouring flows of one attack are near-copies; a random split puts siblings in both train and test and gives unrealistically high scores. *Why not simply 'first 70% of time = train'?* In this single-day file the attacks happen in different periods, so the later attack could end up only in test and never be learned. Blocked, stratified assignment keeps time coherence AND gives each attack a place in every split.

**Rule for later phases:** a sliding window (600 s) is used only if every flow in it belongs to ONE split; windows straddling two splits are discarded. TF-IDF (IDF), basepoints and any scaling/imputation must be fitted on the **train** split only.

| split | BENIGN | Infiltration | total |
| --- | --- | --- | --- |
| test | 34,246 | 3 | 34,249 |
| train | 181,040 | 25 | 181,065 |
| validation | 72,931 | 8 | 72,939 |


### 12. Outputs

| Output | Path |
| --- | --- |
| processed data | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Thursday-WorkingHours-Afternoon-Infilteration_clean.csv |
| sample | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Thursday-WorkingHours-Afternoon-Infilteration_sample.csv |
| metadata | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Thursday-WorkingHours-Afternoon-Infilteration_metadata.json |
| split plan | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Thursday-WorkingHours-Afternoon-Infilteration_split_plan.csv |
| column mapping | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\interim\Thursday-WorkingHours-Afternoon-Infilteration_column_mapping.csv |

Final columns: 7 context + 67 numeric features + helper columns. Run time: 15.0 s.

## File: `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`

Rows loaded: **170,366**  ->  rows kept: **170,230** (removed 136).  Columns loaded: 85.

Raw file SHA-256 before: `e3deaff483d18b53b100a441dff9b8919416df8876b4edcc0f0d1e4bf48397d0`  
Raw file SHA-256 after:  `e3deaff483d18b53b100a441dff9b8919416df8876b4edcc0f0d1e4bf48397d0`  ->  **UNCHANGED**

### 1. Row accounting (what every step did to the row count)

| Step | Rows before | Rows after | Note |
| --- | --- | --- | --- |
| Load + rename columns | 170,366 | 170,366 | 85 columns renamed to snake_case |
| Validate IP/port/protocol | 170,366 | 170,366 | no invalid values |
| Numeric conversion | 170,366 | 170,366 | 0 column(s) had text values; 0 empty column(s) removed |
| Remove duplicate rows | 170,366 | 170,365 | keep=first |
| Drop rows with NaN/Infinity | 170,365 | 170,230 | 135 rows |
| Parse timestamps | 170,230 | 170,230 | order=day_first |
| Remove constant columns | 170,230 | 170,230 | 10 columns removed |

### 2. Labels and targets

`label_original` keeps the label exactly as in the raw file. `label` is the cleaned name (spaces stripped, spelling matched to the config). `target_binary` is **0 for BENIGN** and **1 for every attack label**. `target_multiclass` uses the codes below.

| Label | multiclass code | rows loaded | rows kept |
| --- | --- | --- | --- |
| BENIGN | 0 | 168,186 | 168,050 |
| Web Attack - Brute Force | 1 | 1,507 | 1,507 |
| Web Attack - Sql Injection | 2 | 21 | 21 |
| Web Attack - XSS | 3 | 652 | 652 |

### 3. Column roles (which fields are used for what)

| Role | Columns | Used as ordinary model features? |
| --- | --- | --- |
| Context / identification | flow_id, source_ip, destination_ip, source_port, destination_port, protocol, timestamp | **No** (reasons in section 9) |
| Helper columns we created | source_row, timestamp_raw, hour_shifted, label_original, label, target_binary, target_multiclass, block_id, split | No |
| Numeric network features | 67 columns (list in the metadata JSON) | Yes - candidates for the neural-network models later |

The event-profile pipeline (Phases 3-7) will use the **context columns** (who talked to whom, on which port/protocol, when, and what kind of event) to build event sets. The **numeric features** are for tabular models and the 'Analyze Event' form later.

### 4. Column names

85 of 85 names changed. Rule: lowercase, anything that is not a letter/digit becomes `_`, extra `_` removed (e.g. `' Flow Bytes/s'` -> `flow_bytes_s`). Full list: `data/interim/*_column_mapping.csv`. First 12 changes:

| Raw name | Normalized |
| --- | --- |
| 'Flow ID' | flow_id |
| ' Source IP' | source_ip |
| ' Source Port' | source_port |
| ' Destination IP' | destination_ip |
| ' Destination Port' | destination_port |
| ' Protocol' | protocol |
| ' Timestamp' | timestamp |
| ' Flow Duration' | flow_duration |
| ' Total Fwd Packets' | total_fwd_packets |
| ' Total Backward Packets' | total_backward_packets |
| 'Total Length of Fwd Packets' | total_length_of_fwd_packets |
| ' Total Length of Bwd Packets' | total_length_of_bwd_packets |

### 5. Network field validation

Invalid values per field: {'source_ip': 0, 'destination_ip': 0, 'source_port': 0, 'destination_port': 0, 'protocol': 0}  ->  0 row(s) affected (policy: `drop`).

### 6. Duplicates

Fully identical rows found: **1** (by label: {'BENIGN': 1}). Removed: **True** (`cleaning.remove_duplicates`). Rows are compared on every original column including the raw timestamp and Flow ID, so only true repeats of the same record match.

### 7. Missing and infinite values

Strategy: `drop_rows`.  Rows affected: **135**  (by label: {'BENIGN': 135}).

| Column | NaN | +Infinity | -Infinity |
| --- | --- | --- | --- |
| flow_bytes_s | 20 | 115 | 0 |
| flow_packets_s | 0 | 135 | 0 |

*Why:* infinity appears in rate columns when a flow's duration is 0 (division by zero); NaN is a missing value. Neural networks cannot use either. Dropping the rows is safe because we avoid **inventing** numbers (e.g. a median) before the train/test split exists - a median computed on all data would leak information from the test period into training. If we ever need to keep these rows, set `non_finite_strategy: keep_as_nan` and impute using the training split only.

### 8. Constant columns and negative values

Constant columns (one single value in every row, so no information): **10**. Removed: **True** (`cleaning.remove_constant_columns`).

| Column | Constant value |
| --- | --- |
| bwd_psh_flags | 0.0 |
| fwd_urg_flags | 0.0 |
| bwd_urg_flags | 0.0 |
| cwe_flag_count | 0.0 |
| fwd_avg_bytes_bulk | 0.0 |
| fwd_avg_packets_bulk | 0.0 |
| fwd_avg_bulk_rate | 0.0 |
| bwd_avg_bytes_bulk | 0.0 |
| bwd_avg_packets_bulk | 0.0 |
| bwd_avg_bulk_rate | 0.0 |

*Note:* this is decided on the whole file (it uses no labels, so it leaks nothing about the target). When more days are added, the column list will be recomputed across all days so every file has the same columns.

**Negative values were NOT removed or changed.** Some are legitimate (for example `-1` meaning 'not set'). The table shows where they occur so we can review them case by case:

| Column | Negative cells | Share of rows | Minimum | Kind |
| --- | --- | --- | --- | --- |
| flow_duration | 11 | 0.006% | -1.0 | min is -1 (possible 'not set' marker) |
| flow_bytes_s | 10 | 0.006% | -261000000.0 | other negative values |
| flow_packets_s | 11 | 0.006% | -2000000.0 | other negative values |
| flow_iat_mean | 11 | 0.006% | -1.0 | min is -1 (possible 'not set' marker) |
| flow_iat_max | 11 | 0.006% | -1.0 | min is -1 (possible 'not set' marker) |
| flow_iat_min | 263 | 0.154% | -12.0 | other negative values |
| init_win_bytes_forward | 81,908 | 48.116% | -1.0 | min is -1 (possible 'not set' marker) |
| init_win_bytes_backward | 102,308 | 60.100% | -1.0 | min is -1 (possible 'not set' marker) |

### 9. Leakage-risk check for context fields

A *leaky* field lets a model 'cheat' by memorizing something that merely correlates with the label in THIS dataset. For each attack, the table shows its most common value of each field, the share of that attack's rows with that value, and the share of BENIGN rows with the same value.

| Attack | Field | Most common value | Share of this attack | Share of BENIGN |
| --- | --- | --- | --- | --- |
| Web Attack - Brute Force | source_ip | 172.16.0.1 | 100.0% | 0.0% |
| Web Attack - Brute Force | destination_ip | 192.168.10.50 | 100.0% | 1.2% |
| Web Attack - Brute Force | source_port | 44380 | 0.1% | 0.0% |
| Web Attack - Brute Force | destination_port | 80 | 100.0% | 11.1% |
| Web Attack - Brute Force | protocol | 6 | 100.0% | 51.3% |
| Web Attack - Sql Injection | source_ip | 172.16.0.1 | 100.0% | 0.0% |
| Web Attack - Sql Injection | destination_ip | 192.168.10.50 | 100.0% | 1.2% |
| Web Attack - Sql Injection | source_port | 36196 | 9.5% | 0.0% |
| Web Attack - Sql Injection | destination_port | 80 | 100.0% | 11.1% |
| Web Attack - Sql Injection | protocol | 6 | 100.0% | 51.3% |
| Web Attack - XSS | source_ip | 172.16.0.1 | 100.0% | 0.0% |
| Web Attack - XSS | destination_ip | 192.168.10.50 | 100.0% | 1.2% |
| Web Attack - XSS | source_port | 52098 | 0.3% | 0.0% |
| Web Attack - XSS | destination_port | 80 | 100.0% | 11.1% |
| Web Attack - XSS | protocol | 6 | 100.0% | 51.3% |

**Decision:** IP addresses, ports, Flow ID and the protocol are kept for traceability and for building events in Phase 3, but are **excluded from the numeric feature list**. Where one value covers (nearly) all rows of an attack and few BENIGN rows, a model could classify by that value alone (e.g. 'attacker IP' or 'port 21') and fail on any other network. Random source ports carry no meaning and Flow ID is just a text join of IPs/ports/protocol. The paper's event-profile idea is also built on *event behaviour over time*, not on a single address.

### 10. Timestamps

Raw examples: `6/7/2017 8:59`, `6/7/2017 9:00`, `6/7/2017 9:01`, `6/7/2017 9:02`, `6/7/2017 9:03`. Strings that include seconds: 0 of 170,366.

| Date order tested | Rows parsed | Earliest (before hour fix) | Latest (before hour fix) | Most common weekday | Distinct days |
| --- | --- | --- | --- | --- | --- |
| day_first | 170,230 | 2017-07-06 08:59:00 | 2017-07-06 12:59:00 | Thursday | 1 |
| month_first | 170,230 | 2017-06-07 08:59:00 | 2017-06-07 12:59:00 | Wednesday | 1 |

**Decision:** `day_first`.  Reason: Both day/month orders parse every row (ambiguous). The file name says 'Thursday'; only 'day_first' gives a Thursday.

**Hour correction (12-hour clock without AM/PM):** rule `auto`; pattern detected in data: **False**; applied: **False**.

Rows per hour BEFORE correction: 08h:6, 09h:62,252, 10h:45,785, 11h:42,659, 12h:19,528

Rows per hour AFTER correction:  08h:6, 09h:62,252, 10h:45,785, 11h:42,659, 12h:19,528

Resulting time span: **2017-07-06 08:59:00  ->  2017-07-06 12:59:00** (1 distinct day(s)). Hours inside the span with no rows: none.


**Resolution:** timestamps have only minute precision, so flows in the same minute cannot be ordered by time. We keep `source_row` (original file order) as a tie-breaker but do not treat it as true time order. Our window step (60 s) equals this resolution, so a minute is always entirely inside or outside a window - no flow is split across a window boundary. Timestamps are naive local capture time (no time zone). `timestamp_raw` and `hour_shifted` let you trace every correction.

### 11. Train / validation / test strategy

**Blocked time split.** The timeline is cut into 20-minute blocks; each whole block is assigned to train (70%), validation (15%) or test (15%), stratified by the dominant attack in the block (seed 42). Plan: `data/processed/*_split_plan.csv`; each row has `block_id` and `split`.

*Why not a random row split?* Neighbouring flows of one attack are near-copies; a random split puts siblings in both train and test and gives unrealistically high scores. *Why not simply 'first 70% of time = train'?* In this single-day file the attacks happen in different periods, so the later attack could end up only in test and never be learned. Blocked, stratified assignment keeps time coherence AND gives each attack a place in every split.

**Rule for later phases:** a sliding window (600 s) is used only if every flow in it belongs to ONE split; windows straddling two splits are discarded. TF-IDF (IDF), basepoints and any scaling/imputation must be fitted on the **train** split only.

| split | BENIGN | Web Attack - Brute Force | Web Attack - Sql Injection | Web Attack - XSS | total |
| --- | --- | --- | --- | --- | --- |
| test | 37,290 | 781 | 0 | 0 | 38,071 |
| train | 95,870 | 717 | 21 | 652 | 97,260 |
| validation | 34,890 | 9 | 0 | 0 | 34,899 |

> **WARNING:** Stratum 'Web Attack - Sql Injection' has only 1 block(s): it cannot appear in all of train/validation/test. Use a smaller split.block_minutes.
> **WARNING:** Stratum 'Web Attack - XSS' has only 2 block(s): it cannot appear in all of train/validation/test. Use a smaller split.block_minutes.
> **WARNING:** label `Web Attack - Sql Injection` has no rows in the `validation` split.
> **WARNING:** label `Web Attack - Sql Injection` has no rows in the `test` split.
> **WARNING:** label `Web Attack - XSS` has no rows in the `validation` split.
> **WARNING:** label `Web Attack - XSS` has no rows in the `test` split.

### 12. Outputs

| Output | Path |
| --- | --- |
| processed data | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Thursday-WorkingHours-Morning-WebAttacks_clean.csv |
| sample | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Thursday-WorkingHours-Morning-WebAttacks_sample.csv |
| metadata | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Thursday-WorkingHours-Morning-WebAttacks_metadata.json |
| split plan | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Thursday-WorkingHours-Morning-WebAttacks_split_plan.csv |
| column mapping | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\interim\Thursday-WorkingHours-Morning-WebAttacks_column_mapping.csv |

Final columns: 7 context + 67 numeric features + helper columns. Run time: 13.8 s.

## File: `Tuesday-WorkingHours.pcap_ISCX.csv`

Rows loaded: **445,909**  ->  rows kept: **445,641** (removed 268).  Columns loaded: 85.

Raw file SHA-256 before: `ae9c88e10c41a8eb1ff454ae98bc513454925097d0b0b57180f94e79de445815`  
Raw file SHA-256 after:  `ae9c88e10c41a8eb1ff454ae98bc513454925097d0b0b57180f94e79de445815`  ->  **UNCHANGED**

### 1. Row accounting (what every step did to the row count)

| Step | Rows before | Rows after | Note |
| --- | --- | --- | --- |
| Load + rename columns | 445,909 | 445,909 | 85 columns renamed to snake_case |
| Validate IP/port/protocol | 445,909 | 445,909 | no invalid values |
| Numeric conversion | 445,909 | 445,909 | 0 column(s) had text values; 0 empty column(s) removed |
| Remove duplicate rows | 445,909 | 445,905 | keep=first |
| Drop rows with NaN/Infinity | 445,905 | 445,641 | 264 rows |
| Parse timestamps | 445,641 | 445,641 | order=day_first |
| Remove constant columns | 445,641 | 445,641 | 10 columns removed |

### 2. Labels and targets

`label_original` keeps the label exactly as in the raw file. `label` is the cleaned name (spaces stripped, spelling matched to the config). `target_binary` is **0 for BENIGN** and **1 for every attack label**. `target_multiclass` uses the codes below.

| Label | multiclass code | rows loaded | rows kept |
| --- | --- | --- | --- |
| BENIGN | 0 | 432,074 | 431,809 |
| FTP-Patator | 1 | 7,938 | 7,935 |
| SSH-Patator | 2 | 5,897 | 5,897 |

### 3. Column roles (which fields are used for what)

| Role | Columns | Used as ordinary model features? |
| --- | --- | --- |
| Context / identification | flow_id, source_ip, destination_ip, source_port, destination_port, protocol, timestamp | **No** (reasons in section 9) |
| Helper columns we created | source_row, timestamp_raw, hour_shifted, label_original, label, target_binary, target_multiclass, block_id, split | No |
| Numeric network features | 67 columns (list in the metadata JSON) | Yes - candidates for the neural-network models later |

The event-profile pipeline (Phases 3-7) will use the **context columns** (who talked to whom, on which port/protocol, when, and what kind of event) to build event sets. The **numeric features** are for tabular models and the 'Analyze Event' form later.

### 4. Column names

85 of 85 names changed. Rule: lowercase, anything that is not a letter/digit becomes `_`, extra `_` removed (e.g. `' Flow Bytes/s'` -> `flow_bytes_s`). Full list: `data/interim/*_column_mapping.csv`. First 12 changes:

| Raw name | Normalized |
| --- | --- |
| 'Flow ID' | flow_id |
| ' Source IP' | source_ip |
| ' Source Port' | source_port |
| ' Destination IP' | destination_ip |
| ' Destination Port' | destination_port |
| ' Protocol' | protocol |
| ' Timestamp' | timestamp |
| ' Flow Duration' | flow_duration |
| ' Total Fwd Packets' | total_fwd_packets |
| ' Total Backward Packets' | total_backward_packets |
| 'Total Length of Fwd Packets' | total_length_of_fwd_packets |
| ' Total Length of Bwd Packets' | total_length_of_bwd_packets |

### 5. Network field validation

Invalid values per field: {'source_ip': 0, 'destination_ip': 0, 'source_port': 0, 'destination_port': 0, 'protocol': 0}  ->  0 row(s) affected (policy: `drop`).

### 6. Duplicates

Fully identical rows found: **4** (by label: {'BENIGN': 4}). Removed: **True** (`cleaning.remove_duplicates`). Rows are compared on every original column including the raw timestamp and Flow ID, so only true repeats of the same record match.

### 7. Missing and infinite values

Strategy: `drop_rows`.  Rows affected: **264**  (by label: {'BENIGN': 261, 'FTP-Patator': 3}).

| Column | NaN | +Infinity | -Infinity |
| --- | --- | --- | --- |
| flow_bytes_s | 201 | 63 | 0 |
| flow_packets_s | 0 | 264 | 0 |

*Why:* infinity appears in rate columns when a flow's duration is 0 (division by zero); NaN is a missing value. Neural networks cannot use either. Dropping the rows is safe because we avoid **inventing** numbers (e.g. a median) before the train/test split exists - a median computed on all data would leak information from the test period into training. If we ever need to keep these rows, set `non_finite_strategy: keep_as_nan` and impute using the training split only.

### 8. Constant columns and negative values

Constant columns (one single value in every row, so no information): **10**. Removed: **True** (`cleaning.remove_constant_columns`).

| Column | Constant value |
| --- | --- |
| bwd_psh_flags | 0 |
| fwd_urg_flags | 0 |
| bwd_urg_flags | 0 |
| cwe_flag_count | 0 |
| fwd_avg_bytes_bulk | 0 |
| fwd_avg_packets_bulk | 0 |
| fwd_avg_bulk_rate | 0 |
| bwd_avg_bytes_bulk | 0 |
| bwd_avg_packets_bulk | 0 |
| bwd_avg_bulk_rate | 0 |

*Note:* this is decided on the whole file (it uses no labels, so it leaks nothing about the target). When more days are added, the column list will be recomputed across all days so every file has the same columns.

**Negative values were NOT removed or changed.** Some are legitimate (for example `-1` meaning 'not set'). The table shows where they occur so we can review them case by case:

| Column | Negative cells | Share of rows | Minimum | Kind |
| --- | --- | --- | --- | --- |
| flow_duration | 17 | 0.004% | -4.0 | other negative values |
| flow_packets_s | 17 | 0.004% | -2000000.0 | other negative values |
| flow_iat_mean | 17 | 0.004% | -4.0 | other negative values |
| flow_iat_max | 17 | 0.004% | -4.0 | other negative values |
| flow_iat_min | 504 | 0.113% | -13.0 | other negative values |
| fwd_header_length | 11 | 0.002% | -32212234632.0 | other negative values |
| bwd_header_length | 5 | 0.001% | -1073741320.0 | other negative values |
| fwd_header_length_1 | 11 | 0.002% | -32212234632.0 | other negative values |
| init_win_bytes_forward | 200,128 | 44.908% | -1.0 | min is -1 (possible 'not set' marker) |
| init_win_bytes_backward | 256,425 | 57.541% | -1.0 | min is -1 (possible 'not set' marker) |
| min_seg_size_forward | 11 | 0.002% | -536870661.0 | other negative values |

### 9. Leakage-risk check for context fields

A *leaky* field lets a model 'cheat' by memorizing something that merely correlates with the label in THIS dataset. For each attack, the table shows its most common value of each field, the share of that attack's rows with that value, and the share of BENIGN rows with the same value.

| Attack | Field | Most common value | Share of this attack | Share of BENIGN |
| --- | --- | --- | --- | --- |
| FTP-Patator | source_ip | 172.16.0.1 | 100.0% | 0.0% |
| FTP-Patator | destination_ip | 192.168.10.50 | 100.0% | 1.2% |
| FTP-Patator | source_port | 52108 | 0.0% | 0.0% |
| FTP-Patator | destination_port | 21 | 100.0% | 0.2% |
| FTP-Patator | protocol | 6 | 100.0% | 53.7% |
| SSH-Patator | source_ip | 172.16.0.1 | 100.0% | 0.0% |
| SSH-Patator | destination_ip | 192.168.10.50 | 100.0% | 1.2% |
| SSH-Patator | source_port | 46726 | 0.1% | 0.0% |
| SSH-Patator | destination_port | 22 | 100.0% | 0.5% |
| SSH-Patator | protocol | 6 | 100.0% | 53.7% |

**Decision:** IP addresses, ports, Flow ID and the protocol are kept for traceability and for building events in Phase 3, but are **excluded from the numeric feature list**. Where one value covers (nearly) all rows of an attack and few BENIGN rows, a model could classify by that value alone (e.g. 'attacker IP' or 'port 21') and fail on any other network. Random source ports carry no meaning and Flow ID is just a text join of IPs/ports/protocol. The paper's event-profile idea is also built on *event behaviour over time*, not on a single address.

### 10. Timestamps

Raw examples: `4/7/2017 8:54`, `4/7/2017 8:55`, `4/7/2017 8:53`, `4/7/2017 8:56`, `4/7/2017 8:57`. Strings that include seconds: 0 of 445,909.

| Date order tested | Rows parsed | Earliest (before hour fix) | Latest (before hour fix) | Most common weekday | Distinct days |
| --- | --- | --- | --- | --- | --- |
| day_first | 445,641 | 2017-07-04 01:00:00 | 2017-07-04 12:59:00 | Tuesday | 1 |
| month_first | 445,641 | 2017-04-07 01:00:00 | 2017-04-07 12:59:00 | Friday | 1 |

**Decision:** `day_first`.  Reason: Both day/month orders parse every row (ambiguous). The file name says 'Tuesday'; only 'day_first' gives a Tuesday.

**Hour correction (12-hour clock without AM/PM):** rule `auto`; pattern detected in data: **True**; applied: **True**.

Rows per hour BEFORE correction: 01h:36,779, 02h:72,614, 03h:48,111, 04h:62,969, 05h:165, 08h:1,677, 09h:89,635, 10h:58,487, 11h:57,138, 12h:18,066

Rows per hour AFTER correction:  08h:1,677, 09h:89,635, 10h:58,487, 11h:57,138, 12h:18,066, 13h:36,779, 14h:72,614, 15h:48,111, 16h:62,969, 17h:165

Resulting time span: **2017-07-04 08:53:00  ->  2017-07-04 17:00:00** (1 distinct day(s)). Hours inside the span with no rows: none.

- Hours 1-7 were shifted by +12h (assumption: the capture ran in working hours, so '2:00' means 14:00). VERIFY against the two hour tables above.

**Resolution:** timestamps have only minute precision, so flows in the same minute cannot be ordered by time. We keep `source_row` (original file order) as a tie-breaker but do not treat it as true time order. Our window step (60 s) equals this resolution, so a minute is always entirely inside or outside a window - no flow is split across a window boundary. Timestamps are naive local capture time (no time zone). `timestamp_raw` and `hour_shifted` let you trace every correction.

### 11. Train / validation / test strategy

**Blocked time split.** The timeline is cut into 20-minute blocks; each whole block is assigned to train (70%), validation (15%) or test (15%), stratified by the dominant attack in the block (seed 42). Plan: `data/processed/*_split_plan.csv`; each row has `block_id` and `split`.

*Why not a random row split?* Neighbouring flows of one attack are near-copies; a random split puts siblings in both train and test and gives unrealistically high scores. *Why not simply 'first 70% of time = train'?* In this single-day file the attacks happen in different periods, so the later attack could end up only in test and never be learned. Blocked, stratified assignment keeps time coherence AND gives each attack a place in every split.

**Rule for later phases:** a sliding window (600 s) is used only if every flow in it belongs to ONE split; windows straddling two splits are discarded. TF-IDF (IDF), basepoints and any scaling/imputation must be fitted on the **train** split only.

| split | BENIGN | FTP-Patator | SSH-Patator | total |
| --- | --- | --- | --- | --- |
| test | 96,144 | 1,748 | 1,897 | 99,789 |
| train | 272,870 | 5,217 | 3,632 | 281,719 |
| validation | 62,795 | 970 | 368 | 64,133 |


### 12. Outputs

| Output | Path |
| --- | --- |
| processed data | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Tuesday-WorkingHours_clean.csv |
| sample | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Tuesday-WorkingHours_sample.csv |
| metadata | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Tuesday-WorkingHours_metadata.json |
| split plan | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Tuesday-WorkingHours_split_plan.csv |
| column mapping | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\interim\Tuesday-WorkingHours_column_mapping.csv |

Final columns: 7 context + 67 numeric features + helper columns. Run time: 12.2 s.

## File: `Wednesday-workingHours.pcap_ISCX.csv`

Rows loaded: **692,703**  ->  rows kept: **691,390** (removed 1,313).  Columns loaded: 85.

Raw file SHA-256 before: `ed538e85b84181e8897dedb3d37d365982f44b27eccd67c477581a8b65f3d170`  
Raw file SHA-256 after:  `ed538e85b84181e8897dedb3d37d365982f44b27eccd67c477581a8b65f3d170`  ->  **UNCHANGED**

### 1. Row accounting (what every step did to the row count)

| Step | Rows before | Rows after | Note |
| --- | --- | --- | --- |
| Load + rename columns | 692,703 | 692,703 | 85 columns renamed to snake_case |
| Validate IP/port/protocol | 692,703 | 692,703 | no invalid values |
| Numeric conversion | 692,703 | 692,703 | 0 column(s) had text values; 0 empty column(s) removed |
| Remove duplicate rows | 692,703 | 692,686 | keep=first |
| Drop rows with NaN/Infinity | 692,686 | 691,390 | 1,296 rows |
| Parse timestamps | 691,390 | 691,390 | order=day_first |
| Remove constant columns | 691,390 | 691,390 | 10 columns removed |

### 2. Labels and targets

`label_original` keeps the label exactly as in the raw file. `label` is the cleaned name (spaces stripped, spelling matched to the config). `target_binary` is **0 for BENIGN** and **1 for every attack label**. `target_multiclass` uses the codes below.

| Label | multiclass code | rows loaded | rows kept |
| --- | --- | --- | --- |
| BENIGN | 0 | 440,031 | 439,668 |
| DoS GoldenEye | 1 | 10,293 | 10,293 |
| DoS Hulk | 2 | 231,073 | 230,123 |
| DoS Slowhttptest | 3 | 5,499 | 5,499 |
| DoS slowloris | 4 | 5,796 | 5,796 |
| Heartbleed | 5 | 11 | 11 |

### 3. Column roles (which fields are used for what)

| Role | Columns | Used as ordinary model features? |
| --- | --- | --- |
| Context / identification | flow_id, source_ip, destination_ip, source_port, destination_port, protocol, timestamp | **No** (reasons in section 9) |
| Helper columns we created | source_row, timestamp_raw, hour_shifted, label_original, label, target_binary, target_multiclass, block_id, split | No |
| Numeric network features | 67 columns (list in the metadata JSON) | Yes - candidates for the neural-network models later |

The event-profile pipeline (Phases 3-7) will use the **context columns** (who talked to whom, on which port/protocol, when, and what kind of event) to build event sets. The **numeric features** are for tabular models and the 'Analyze Event' form later.

### 4. Column names

85 of 85 names changed. Rule: lowercase, anything that is not a letter/digit becomes `_`, extra `_` removed (e.g. `' Flow Bytes/s'` -> `flow_bytes_s`). Full list: `data/interim/*_column_mapping.csv`. First 12 changes:

| Raw name | Normalized |
| --- | --- |
| 'Flow ID' | flow_id |
| ' Source IP' | source_ip |
| ' Source Port' | source_port |
| ' Destination IP' | destination_ip |
| ' Destination Port' | destination_port |
| ' Protocol' | protocol |
| ' Timestamp' | timestamp |
| ' Flow Duration' | flow_duration |
| ' Total Fwd Packets' | total_fwd_packets |
| ' Total Backward Packets' | total_backward_packets |
| 'Total Length of Fwd Packets' | total_length_of_fwd_packets |
| ' Total Length of Bwd Packets' | total_length_of_bwd_packets |

### 5. Network field validation

Invalid values per field: {'source_ip': 0, 'destination_ip': 0, 'source_port': 0, 'destination_port': 0, 'protocol': 0}  ->  0 row(s) affected (policy: `drop`).

### 6. Duplicates

Fully identical rows found: **17** (by label: {'BENIGN': 16, 'DoS Hulk': 1}). Removed: **True** (`cleaning.remove_duplicates`). Rows are compared on every original column including the raw timestamp and Flow ID, so only true repeats of the same record match.

### 7. Missing and infinite values

Strategy: `drop_rows`.  Rows affected: **1,296**  (by label: {'DoS Hulk': 949, 'BENIGN': 347}).

| Column | NaN | +Infinity | -Infinity |
| --- | --- | --- | --- |
| flow_bytes_s | 1007 | 289 | 0 |
| flow_packets_s | 0 | 1296 | 0 |

*Why:* infinity appears in rate columns when a flow's duration is 0 (division by zero); NaN is a missing value. Neural networks cannot use either. Dropping the rows is safe because we avoid **inventing** numbers (e.g. a median) before the train/test split exists - a median computed on all data would leak information from the test period into training. If we ever need to keep these rows, set `non_finite_strategy: keep_as_nan` and impute using the training split only.

### 8. Constant columns and negative values

Constant columns (one single value in every row, so no information): **10**. Removed: **True** (`cleaning.remove_constant_columns`).

| Column | Constant value |
| --- | --- |
| bwd_psh_flags | 0 |
| fwd_urg_flags | 0 |
| bwd_urg_flags | 0 |
| cwe_flag_count | 0 |
| fwd_avg_bytes_bulk | 0 |
| fwd_avg_packets_bulk | 0 |
| fwd_avg_bulk_rate | 0 |
| bwd_avg_bytes_bulk | 0 |
| bwd_avg_packets_bulk | 0 |
| bwd_avg_bulk_rate | 0 |

*Note:* this is decided on the whole file (it uses no labels, so it leaks nothing about the target). When more days are added, the column list will be recomputed across all days so every file has the same columns.

**Negative values were NOT removed or changed.** Some are legitimate (for example `-1` meaning 'not set'). The table shows where they occur so we can review them case by case:

| Column | Negative cells | Share of rows | Minimum | Kind |
| --- | --- | --- | --- | --- |
| flow_duration | 21 | 0.003% | -1.0 | min is -1 (possible 'not set' marker) |
| flow_bytes_s | 16 | 0.002% | -12000000.0 | other negative values |
| flow_packets_s | 21 | 0.003% | -2000000.0 | other negative values |
| flow_iat_mean | 21 | 0.003% | -1.0 | min is -1 (possible 'not set' marker) |
| flow_iat_max | 21 | 0.003% | -1.0 | min is -1 (possible 'not set' marker) |
| flow_iat_min | 749 | 0.108% | -14.0 | other negative values |
| fwd_iat_min | 11 | 0.002% | -8.0 | other negative values |
| fwd_header_length | 1 | 0.000% | -11.0 | other negative values |
| fwd_header_length_1 | 1 | 0.000% | -11.0 | other negative values |
| init_win_bytes_forward | 203,252 | 29.398% | -1.0 | min is -1 (possible 'not set' marker) |
| init_win_bytes_backward | 334,357 | 48.360% | -1.0 | min is -1 (possible 'not set' marker) |
| min_seg_size_forward | 1 | 0.000% | -1.0 | min is -1 (possible 'not set' marker) |

### 9. Leakage-risk check for context fields

A *leaky* field lets a model 'cheat' by memorizing something that merely correlates with the label in THIS dataset. For each attack, the table shows its most common value of each field, the share of that attack's rows with that value, and the share of BENIGN rows with the same value.

| Attack | Field | Most common value | Share of this attack | Share of BENIGN |
| --- | --- | --- | --- | --- |
| DoS GoldenEye | source_ip | 172.16.0.1 | 100.0% | 0.5% |
| DoS GoldenEye | destination_ip | 192.168.10.50 | 100.0% | 1.2% |
| DoS GoldenEye | source_port | 39620 | 0.0% | 0.0% |
| DoS GoldenEye | destination_port | 80 | 100.0% | 11.1% |
| DoS GoldenEye | protocol | 6 | 100.0% | 53.8% |
| DoS Hulk | source_ip | 172.16.0.1 | 100.0% | 0.5% |
| DoS Hulk | destination_ip | 192.168.10.50 | 100.0% | 1.2% |
| DoS Hulk | source_port | 47036 | 0.0% | 0.0% |
| DoS Hulk | destination_port | 80 | 100.0% | 11.1% |
| DoS Hulk | protocol | 6 | 100.0% | 53.8% |
| DoS Slowhttptest | source_ip | 172.16.0.1 | 100.0% | 0.5% |
| DoS Slowhttptest | destination_ip | 192.168.10.50 | 100.0% | 1.2% |
| DoS Slowhttptest | source_port | 35380 | 0.1% | 0.0% |
| DoS Slowhttptest | destination_port | 80 | 100.0% | 11.1% |
| DoS Slowhttptest | protocol | 6 | 100.0% | 53.8% |
| DoS slowloris | source_ip | 172.16.0.1 | 100.0% | 0.5% |
| DoS slowloris | destination_ip | 192.168.10.50 | 100.0% | 1.2% |
| DoS slowloris | source_port | 54074 | 0.2% | 0.0% |
| DoS slowloris | destination_port | 80 | 100.0% | 11.1% |
| DoS slowloris | protocol | 6 | 100.0% | 53.8% |
| Heartbleed | source_ip | 172.16.0.1 | 100.0% | 0.5% |
| Heartbleed | destination_ip | 192.168.10.51 | 100.0% | 1.4% |
| Heartbleed | source_port | 45022 | 100.0% | 0.0% |
| Heartbleed | destination_port | 444 | 100.0% | 0.0% |
| Heartbleed | protocol | 6 | 100.0% | 53.8% |

**Decision:** IP addresses, ports, Flow ID and the protocol are kept for traceability and for building events in Phase 3, but are **excluded from the numeric feature list**. Where one value covers (nearly) all rows of an attack and few BENIGN rows, a model could classify by that value alone (e.g. 'attacker IP' or 'port 21') and fail on any other network. Random source ports carry no meaning and Flow ID is just a text join of IPs/ports/protocol. The paper's event-profile idea is also built on *event behaviour over time*, not on a single address.

### 10. Timestamps

Raw examples: `5/7/2017 8:42`, `5/7/2017 8:43`, `5/7/2017 8:44`, `5/7/2017 8:45`, `5/7/2017 8:46`. Strings that include seconds: 0 of 692,703.

| Date order tested | Rows parsed | Earliest (before hour fix) | Latest (before hour fix) | Most common weekday | Distinct days |
| --- | --- | --- | --- | --- | --- |
| day_first | 691,390 | 2017-07-05 01:00:00 | 2017-07-05 12:59:00 | Wednesday | 1 |
| month_first | 691,390 | 2017-05-07 01:00:00 | 2017-05-07 12:59:00 | Sunday | 1 |

**Decision:** `day_first`.  Reason: Both day/month orders parse every row (ambiguous). The file name says 'Wednesday'; only 'day_first' gives a Wednesday.

**Hour correction (12-hour clock without AM/PM):** rule `auto`; pattern detected in data: **True**; applied: **True**.

Rows per hour BEFORE correction: 01h:48,867, 02h:63,799, 03h:66,094, 04h:44,853, 05h:3,531, 08h:14,095, 09h:54,263, 10h:300,911, 11h:71,002, 12h:23,975

Rows per hour AFTER correction:  08h:14,095, 09h:54,263, 10h:300,911, 11h:71,002, 12h:23,975, 13h:48,867, 14h:63,799, 15h:66,094, 16h:44,853, 17h:3,531

Resulting time span: **2017-07-05 08:42:00  ->  2017-07-05 17:10:00** (1 distinct day(s)). Hours inside the span with no rows: none.

- Hours 1-7 were shifted by +12h (assumption: the capture ran in working hours, so '2:00' means 14:00). VERIFY against the two hour tables above.

**Resolution:** timestamps have only minute precision, so flows in the same minute cannot be ordered by time. We keep `source_row` (original file order) as a tie-breaker but do not treat it as true time order. Our window step (60 s) equals this resolution, so a minute is always entirely inside or outside a window - no flow is split across a window boundary. Timestamps are naive local capture time (no time zone). `timestamp_raw` and `hour_shifted` let you trace every correction.

### 11. Train / validation / test strategy

**Blocked time split.** The timeline is cut into 20-minute blocks; each whole block is assigned to train (70%), validation (15%) or test (15%), stratified by the dominant attack in the block (seed 42). Plan: `data/processed/*_split_plan.csv`; each row has `block_id` and `split`.

*Why not a random row split?* Neighbouring flows of one attack are near-copies; a random split puts siblings in both train and test and gives unrealistically high scores. *Why not simply 'first 70% of time = train'?* In this single-day file the attacks happen in different periods, so the later attack could end up only in test and never be learned. Blocked, stratified assignment keeps time coherence AND gives each attack a place in every split.

**Rule for later phases:** a sliding window (600 s) is used only if every flow in it belongs to ONE split; windows straddling two splits are discarded. TF-IDF (IDF), basepoints and any scaling/imputation must be fitted on the **train** split only.

| split | BENIGN | DoS GoldenEye | DoS Hulk | DoS Slowhttptest | DoS slowloris | Heartbleed | total |
| --- | --- | --- | --- | --- | --- | --- | --- |
| test | 44,702 | 0 | 0 | 0 | 1 | 0 | 44,703 |
| train | 323,746 | 10,293 | 230,123 | 5,499 | 5,790 | 11 | 575,462 |
| validation | 71,220 | 0 | 0 | 0 | 5 | 0 | 71,225 |

> **WARNING:** Stratum 'DoS GoldenEye' has only 1 block(s): it cannot appear in all of train/validation/test. Use a smaller split.block_minutes.
> **WARNING:** Stratum 'DoS Hulk' has only 1 block(s): it cannot appear in all of train/validation/test. Use a smaller split.block_minutes.
> **WARNING:** Stratum 'DoS Slowhttptest' has only 1 block(s): it cannot appear in all of train/validation/test. Use a smaller split.block_minutes.
> **WARNING:** Stratum 'Heartbleed' has only 2 block(s): it cannot appear in all of train/validation/test. Use a smaller split.block_minutes.
> **WARNING:** label `DoS GoldenEye` has no rows in the `validation` split.
> **WARNING:** label `DoS GoldenEye` has no rows in the `test` split.
> **WARNING:** label `DoS Hulk` has no rows in the `validation` split.
> **WARNING:** label `DoS Hulk` has no rows in the `test` split.
> **WARNING:** label `DoS Slowhttptest` has no rows in the `validation` split.
> **WARNING:** label `DoS Slowhttptest` has no rows in the `test` split.
> **WARNING:** label `Heartbleed` has no rows in the `validation` split.
> **WARNING:** label `Heartbleed` has no rows in the `test` split.

### 12. Outputs

| Output | Path |
| --- | --- |
| processed data | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Wednesday-workingHours_clean.csv |
| sample | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Wednesday-workingHours_sample.csv |
| metadata | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Wednesday-workingHours_metadata.json |
| split plan | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\processed\Wednesday-workingHours_split_plan.csv |
| column mapping | C:\Users\pavani krishna\Desktop\cyber\cyber-threat-detection\data\interim\Wednesday-workingHours_column_mapping.csv |

Final columns: 7 context + 67 numeric features + helper columns. Run time: 51.7 s.

## Open questions / uncertainties

- Timestamp day/month order could not be confirmed - see section 'Timestamps'.
- Timestamp day/month order could not be confirmed - see section 'Timestamps'.
- Timestamp day/month order could not be confirmed - see section 'Timestamps'.
- Whether `-1` values are true sentinels was NOT verified; they are kept unchanged.
- Constant-column list and feature list were standardized across all 8 files ensuring uniform 67 feature columns.