# Dataset Report - CICIDS2017

*Generated automatically by `inspect_dataset.py` on 2026-11-02 14:39:56.*  
*All values below were calculated from the raw file(s); none were typed in by hand.*

## Files used

- `Tuesday-WorkingHours.pcap_ISCX.csv`

## File: `Tuesday-WorkingHours.pcap_ISCX.csv`

### 1. Overview

| Item | Value |
| --- | --- |
| File size on disk | 166.6 MB |
| SHA-256 (before reading) | `ae9c88e10c41a8eb1ff454ae98bc513454925097d0b0b57180f94e79de445815` |
| Encoding used | latin-1 |
| Rows | 445,909 |
| Columns | 85 |
| Memory when loaded | 411 MB |

### 2. Columns (raw name -> normalized name), data types, missing values

Raw names are shown in quotes only when they contain extra spaces. The raw file is NOT changed; normalization exists only in memory.

| # | Raw name | Normalized | dtype | Non-null | Missing | Missing % |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | Flow ID | (same) | str | 445,909 | 0 | 0.000% |
| 2 | ' Source IP' | Source IP | str | 445,909 | 0 | 0.000% |
| 3 | ' Source Port' | Source Port | int64 | 445,909 | 0 | 0.000% |
| 4 | ' Destination IP' | Destination IP | str | 445,909 | 0 | 0.000% |
| 5 | ' Destination Port' | Destination Port | int64 | 445,909 | 0 | 0.000% |
| 6 | ' Protocol' | Protocol | int64 | 445,909 | 0 | 0.000% |
| 7 | ' Timestamp' | Timestamp | str | 445,909 | 0 | 0.000% |
| 8 | ' Flow Duration' | Flow Duration | int64 | 445,909 | 0 | 0.000% |
| 9 | ' Total Fwd Packets' | Total Fwd Packets | int64 | 445,909 | 0 | 0.000% |
| 10 | ' Total Backward Packets' | Total Backward Packets | int64 | 445,909 | 0 | 0.000% |
| 11 | Total Length of Fwd Packets | (same) | int64 | 445,909 | 0 | 0.000% |
| 12 | ' Total Length of Bwd Packets' | Total Length of Bwd Packets | float64 | 445,909 | 0 | 0.000% |
| 13 | ' Fwd Packet Length Max' | Fwd Packet Length Max | int64 | 445,909 | 0 | 0.000% |
| 14 | ' Fwd Packet Length Min' | Fwd Packet Length Min | int64 | 445,909 | 0 | 0.000% |
| 15 | ' Fwd Packet Length Mean' | Fwd Packet Length Mean | float64 | 445,909 | 0 | 0.000% |
| 16 | ' Fwd Packet Length Std' | Fwd Packet Length Std | float64 | 445,909 | 0 | 0.000% |
| 17 | Bwd Packet Length Max | (same) | int64 | 445,909 | 0 | 0.000% |
| 18 | ' Bwd Packet Length Min' | Bwd Packet Length Min | int64 | 445,909 | 0 | 0.000% |
| 19 | ' Bwd Packet Length Mean' | Bwd Packet Length Mean | float64 | 445,909 | 0 | 0.000% |
| 20 | ' Bwd Packet Length Std' | Bwd Packet Length Std | float64 | 445,909 | 0 | 0.000% |
| 21 | Flow Bytes/s | (same) | float64 | 445,708 | 201 | 0.045% |
| 22 | ' Flow Packets/s' | Flow Packets/s | float64 | 445,909 | 0 | 0.000% |
| 23 | ' Flow IAT Mean' | Flow IAT Mean | float64 | 445,909 | 0 | 0.000% |
| 24 | ' Flow IAT Std' | Flow IAT Std | float64 | 445,909 | 0 | 0.000% |
| 25 | ' Flow IAT Max' | Flow IAT Max | float64 | 445,909 | 0 | 0.000% |
| 26 | ' Flow IAT Min' | Flow IAT Min | float64 | 445,909 | 0 | 0.000% |
| 27 | Fwd IAT Total | (same) | float64 | 445,909 | 0 | 0.000% |
| 28 | ' Fwd IAT Mean' | Fwd IAT Mean | float64 | 445,909 | 0 | 0.000% |
| 29 | ' Fwd IAT Std' | Fwd IAT Std | float64 | 445,909 | 0 | 0.000% |
| 30 | ' Fwd IAT Max' | Fwd IAT Max | float64 | 445,909 | 0 | 0.000% |
| 31 | ' Fwd IAT Min' | Fwd IAT Min | float64 | 445,909 | 0 | 0.000% |
| 32 | Bwd IAT Total | (same) | float64 | 445,909 | 0 | 0.000% |
| 33 | ' Bwd IAT Mean' | Bwd IAT Mean | float64 | 445,909 | 0 | 0.000% |
| 34 | ' Bwd IAT Std' | Bwd IAT Std | float64 | 445,909 | 0 | 0.000% |
| 35 | ' Bwd IAT Max' | Bwd IAT Max | float64 | 445,909 | 0 | 0.000% |
| 36 | ' Bwd IAT Min' | Bwd IAT Min | float64 | 445,909 | 0 | 0.000% |
| 37 | Fwd PSH Flags | (same) | int64 | 445,909 | 0 | 0.000% |
| 38 | ' Bwd PSH Flags' | Bwd PSH Flags | int64 | 445,909 | 0 | 0.000% |
| 39 | ' Fwd URG Flags' | Fwd URG Flags | int64 | 445,909 | 0 | 0.000% |
| 40 | ' Bwd URG Flags' | Bwd URG Flags | int64 | 445,909 | 0 | 0.000% |
| 41 | ' Fwd Header Length' | Fwd Header Length | int64 | 445,909 | 0 | 0.000% |
| 42 | ' Bwd Header Length' | Bwd Header Length | int64 | 445,909 | 0 | 0.000% |
| 43 | Fwd Packets/s | (same) | float64 | 445,909 | 0 | 0.000% |
| 44 | ' Bwd Packets/s' | Bwd Packets/s | float64 | 445,909 | 0 | 0.000% |
| 45 | ' Min Packet Length' | Min Packet Length | int64 | 445,909 | 0 | 0.000% |
| 46 | ' Max Packet Length' | Max Packet Length | int64 | 445,909 | 0 | 0.000% |
| 47 | ' Packet Length Mean' | Packet Length Mean | float64 | 445,909 | 0 | 0.000% |
| 48 | ' Packet Length Std' | Packet Length Std | float64 | 445,909 | 0 | 0.000% |
| 49 | ' Packet Length Variance' | Packet Length Variance | float64 | 445,909 | 0 | 0.000% |
| 50 | FIN Flag Count | (same) | int64 | 445,909 | 0 | 0.000% |
| 51 | ' SYN Flag Count' | SYN Flag Count | int64 | 445,909 | 0 | 0.000% |
| 52 | ' RST Flag Count' | RST Flag Count | int64 | 445,909 | 0 | 0.000% |
| 53 | ' PSH Flag Count' | PSH Flag Count | int64 | 445,909 | 0 | 0.000% |
| 54 | ' ACK Flag Count' | ACK Flag Count | int64 | 445,909 | 0 | 0.000% |
| 55 | ' URG Flag Count' | URG Flag Count | int64 | 445,909 | 0 | 0.000% |
| 56 | ' CWE Flag Count' | CWE Flag Count | int64 | 445,909 | 0 | 0.000% |
| 57 | ' ECE Flag Count' | ECE Flag Count | int64 | 445,909 | 0 | 0.000% |
| 58 | ' Down/Up Ratio' | Down/Up Ratio | int64 | 445,909 | 0 | 0.000% |
| 59 | ' Average Packet Size' | Average Packet Size | float64 | 445,909 | 0 | 0.000% |
| 60 | ' Avg Fwd Segment Size' | Avg Fwd Segment Size | float64 | 445,909 | 0 | 0.000% |
| 61 | ' Avg Bwd Segment Size' | Avg Bwd Segment Size | float64 | 445,909 | 0 | 0.000% |
| 62 | ' Fwd Header Length.1' | Fwd Header Length.1 | int64 | 445,909 | 0 | 0.000% |
| 63 | Fwd Avg Bytes/Bulk | (same) | int64 | 445,909 | 0 | 0.000% |
| 64 | ' Fwd Avg Packets/Bulk' | Fwd Avg Packets/Bulk | int64 | 445,909 | 0 | 0.000% |
| 65 | ' Fwd Avg Bulk Rate' | Fwd Avg Bulk Rate | int64 | 445,909 | 0 | 0.000% |
| 66 | ' Bwd Avg Bytes/Bulk' | Bwd Avg Bytes/Bulk | int64 | 445,909 | 0 | 0.000% |
| 67 | ' Bwd Avg Packets/Bulk' | Bwd Avg Packets/Bulk | int64 | 445,909 | 0 | 0.000% |
| 68 | Bwd Avg Bulk Rate | (same) | int64 | 445,909 | 0 | 0.000% |
| 69 | Subflow Fwd Packets | (same) | int64 | 445,909 | 0 | 0.000% |
| 70 | ' Subflow Fwd Bytes' | Subflow Fwd Bytes | int64 | 445,909 | 0 | 0.000% |
| 71 | ' Subflow Bwd Packets' | Subflow Bwd Packets | int64 | 445,909 | 0 | 0.000% |
| 72 | ' Subflow Bwd Bytes' | Subflow Bwd Bytes | int64 | 445,909 | 0 | 0.000% |
| 73 | Init_Win_bytes_forward | (same) | int64 | 445,909 | 0 | 0.000% |
| 74 | ' Init_Win_bytes_backward' | Init_Win_bytes_backward | int64 | 445,909 | 0 | 0.000% |
| 75 | ' act_data_pkt_fwd' | act_data_pkt_fwd | int64 | 445,909 | 0 | 0.000% |
| 76 | ' min_seg_size_forward' | min_seg_size_forward | int64 | 445,909 | 0 | 0.000% |
| 77 | Active Mean | (same) | float64 | 445,909 | 0 | 0.000% |
| 78 | ' Active Std' | Active Std | float64 | 445,909 | 0 | 0.000% |
| 79 | ' Active Max' | Active Max | float64 | 445,909 | 0 | 0.000% |
| 80 | ' Active Min' | Active Min | float64 | 445,909 | 0 | 0.000% |
| 81 | Idle Mean | (same) | float64 | 445,909 | 0 | 0.000% |
| 82 | ' Idle Std' | Idle Std | float64 | 445,909 | 0 | 0.000% |
| 83 | ' Idle Max' | Idle Max | float64 | 445,909 | 0 | 0.000% |
| 84 | ' Idle Min' | Idle Min | float64 | 445,909 | 0 | 0.000% |
| 85 | ' Label' | Label | str | 445,909 | 0 | 0.000% |

**dtype summary:** int64: 43, float64: 37, str: 5

**Columns whose raw name needed cleaning:** 70 of 85

### 3. Missing values

| Item | Value |
| --- | --- |
| Total missing cells | 201 |
| Rows with at least one missing value | 201 (0.045%) |
| Columns with missing values | Flow Bytes/s |

### 4. Infinite values (+inf / -inf)

| Column | +inf count | -inf count |
| --- | --- | --- |
| Flow Bytes/s | 63 | 0 |
| Flow Packets/s | 264 | 0 |

**Rows containing at least one infinite value:** 264 (0.059%)

### 5. Malformed values (text found in columns that should be numeric)

All non-ID columns were read as numbers - no malformed text values.

### 6. Duplicate rows

**Fully identical rows (all 85 columns equal, first copy not counted):** 4 (0.001%)

Duplicates by label:

| Label | Rows | Share |
| --- | --- | --- |
| BENIGN | 4 | 100.000% |

*Info:* `Flow ID` repeated values: 234,281. A Flow ID is just src/dst/ports/protocol, so repeats are normal (the same connection can appear many times). It is NOT a unique row key.

### 7. Labels

**Unique labels (3):** `'BENIGN'`, `'FTP-Patator'`, `'SSH-Patator'`

Rows whose label has extra spaces: 0

| Label | Rows | Share |
| --- | --- | --- |
| BENIGN | 432,074 | 96.897% |
| FTP-Patator | 7,938 | 1.780% |
| SSH-Patator | 5,897 | 1.322% |

**BENIGN:** 432,074 (96.897%)  |  **Attack (all non-BENIGN):** 13,835 (3.103%)

### 8. Timestamp

**Raw examples (first 3 / random 3 / last 3):** `4/7/2017 8:54`, `4/7/2017 8:54`, `4/7/2017 8:54`, `4/7/2017 10:50`, `4/7/2017 8:57`, `4/7/2017 10:06`, `4/7/2017 9:11`, `4/7/2017 12:48`, `4/7/2017 10:38`

Missing timestamps: 0  |  strings that include seconds: 0 (0.000%)

The file does not say whether dates are day/month or month/day, so we test every format and compare the results:

| Format tried | Rows parsed OK | Earliest | Latest | Distinct days | Weekday of earliest |
| --- | --- | --- | --- | --- | --- |
| %d/%m/%Y %H:%M:%S | 0 (0.000%) | None | None | 0 | - |
| %d/%m/%Y %H:%M | 445,909 (100.000%) | 2017-07-04 01:00:00 | 2017-07-04 12:59:00 | 1 | Tuesday |
| %m/%d/%Y %H:%M:%S | 0 (0.000%) | None | None | 0 | - |
| %m/%d/%Y %H:%M | 445,909 (100.000%) | 2017-04-07 01:00:00 | 2017-04-07 12:59:00 | 1 | Friday |

File name says **Tuesday**; formats whose earliest date falls on a Tuesday: `%d/%m/%Y %H:%M`.

**Best-fitting format:** `%d/%m/%Y %H:%M`  ->  range **2017-07-04 01:00:00** to **2017-07-04 12:59:00** (1 distinct day(s), earliest is a Tuesday).

**Rows per hour of day (from the chosen format):** 01h: 36,801, 02h: 72,649, 03h: 48,144, 04h: 63,007, 05h: 165, 08h: 1,683, 09h: 89,694, 10h: 58,516, 11h: 57,171, 12h: 18,079

**Flows per minute:** min 1, median 763, max 3,685 (over 488 active minutes)

### 9. Network fields

#### Source IP

Unique values: **7,192**  |  valid IPv4/IPv6: 445,909  |  invalid/missing: 0  |  private-range rows: 370,397  |  public rows: 75,512

| Source IP | Rows | Share |
| --- | --- | --- |
| 192.168.10.3 | 60,814 | 13.638% |
| 192.168.10.5 | 34,300 | 7.692% |
| 192.168.10.9 | 33,457 | 7.503% |
| 192.168.10.15 | 31,452 | 7.053% |
| 192.168.10.14 | 29,197 | 6.548% |
| 192.168.10.25 | 26,756 | 6.000% |
| 192.168.10.8 | 26,567 | 5.958% |
| 192.168.10.17 | 22,860 | 5.127% |
| 192.168.10.16 | 22,342 | 5.010% |
| 192.168.10.12 | 21,014 | 4.713% |

#### Destination IP

Unique values: **8,490**  |  valid IPv4/IPv6: 445,909  |  invalid/missing: 0  |  private-range rows: 296,999  |  public rows: 148,910

| Destination IP | Rows | Share |
| --- | --- | --- |
| 192.168.10.3 | 135,934 | 30.485% |
| 192.168.10.1 | 59,835 | 13.419% |
| 192.168.10.25 | 19,973 | 4.479% |
| 192.168.10.50 | 18,944 | 4.248% |
| 192.168.10.9 | 8,384 | 1.880% |
| 192.168.10.5 | 7,586 | 1.701% |
| 192.168.10.15 | 6,728 | 1.509% |
| 192.168.10.16 | 5,924 | 1.329% |
| 192.168.10.14 | 5,669 | 1.271% |
| 192.168.10.12 | 5,641 | 1.265% |

#### Source Port

Unique: **52,554**  |  min 0  |  max 65535  |  non-numeric/missing: 0  |  outside 0-65535: 0

| Source Port | Rows | Share |
| --- | --- | --- |
| 443 (HTTPS) | 58,628 | 13.148% |
| 80 (HTTP) | 16,791 | 3.766% |
| 123 (NTP) | 5,145 | 1.154% |
| 21 (FTP) | 2,133 | 0.478% |
| 137 (NetBIOS) | 1,905 | 0.427% |
| 22 (SSH) | 1,040 | 0.233% |
| 138 (NetBIOS) | 318 | 0.071% |
| 0 | 316 | 0.071% |
| 139 (NetBIOS) | 187 | 0.042% |
| 5353 | 149 | 0.033% |

#### Destination Port

Unique: **31,858**  |  min 0  |  max 65505  |  non-numeric/missing: 0  |  outside 0-65535: 0

| Destination Port | Rows | Share |
| --- | --- | --- |
| 53 (DNS) | 190,939 | 42.820% |
| 443 (HTTPS) | 97,276 | 21.815% |
| 80 (HTTP) | 45,676 | 10.243% |
| 21 (FTP) | 8,996 | 2.017% |
| 22 (SSH) | 8,033 | 1.801% |
| 123 (NTP) | 5,145 | 1.154% |
| 137 (NetBIOS) | 1,911 | 0.429% |
| 389 (LDAP) | 1,333 | 0.299% |
| 88 | 1,232 | 0.276% |
| 465 | 710 | 0.159% |

#### Protocol

Unique protocol numbers: **3**  |  non-numeric/missing: 0

| Protocol number | Rows | Share |
| --- | --- | --- |
| 6 (TCP) | 245,781 | 55.119% |
| 17 (UDP) | 199,812 | 44.810% |
| 0 (HOPOPT) | 316 | 0.071% |

### 10. What each attack label looks like (helps design events in Phase 3)

#### FTP-Patator (7,938 rows)

**Top Source IPs**

| Value | Rows | Share |
| --- | --- | --- |
| 172.16.0.1 | 7,938 | 100.000% |

**Top Destination IPs**

| Value | Rows | Share |
| --- | --- | --- |
| 192.168.10.50 | 7,938 | 100.000% |

**Top Destination Ports**

| Value | Rows | Share |
| --- | --- | --- |
| 21 (FTP) | 7,937 | 99.987% |
| 80 (HTTP) | 1 | 0.013% |

**Protocols**

| Value | Rows | Share |
| --- | --- | --- |
| 6 (TCP) | 7,938 | 100.000% |

#### SSH-Patator (5,897 rows)

**Top Source IPs**

| Value | Rows | Share |
| --- | --- | --- |
| 172.16.0.1 | 5,897 | 100.000% |

**Top Destination IPs**

| Value | Rows | Share |
| --- | --- | --- |
| 192.168.10.50 | 5,897 | 100.000% |

**Top Destination Ports**

| Value | Rows | Share |
| --- | --- | --- |
| 22 (SSH) | 5,897 | 100.000% |

**Protocols**

| Value | Rows | Share |
| --- | --- | --- |
| 6 (TCP) | 5,897 | 100.000% |

### 11. Numeric feature quality

**Constant columns (carry no information):** Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, CWE Flag Count, Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate

Columns containing negative values (some are legitimate, e.g. a flag value of -1):

| Column | Negative cells | Share | Minimum |
| --- | --- | --- | --- |
| Flow Duration | 17 | 0.004% | -4 |
| Flow Packets/s | 17 | 0.004% | -2000000.0 |
| Flow IAT Mean | 17 | 0.004% | -4.0 |
| Flow IAT Max | 17 | 0.004% | -4.0 |
| Flow IAT Min | 505 | 0.113% | -13.0 |
| Fwd Header Length | 11 | 0.002% | -32212234632 |
| Bwd Header Length | 5 | 0.001% | -1073741320 |
| Fwd Header Length.1 | 11 | 0.002% | -32212234632 |
| Init_Win_bytes_forward | 200,128 | 44.881% | -1 |
| Init_Win_bytes_backward | 256,599 | 57.545% | -1 |
| min_seg_size_forward | 11 | 0.002% | -536870661 |

### 12. Potential problems found automatically

- Class imbalance: BENIGN is 96.897% of rows; smallest attack class has 5,897 rows.
- Timestamp day/month order is ambiguous (several formats parse 100%). We chose the one matching the weekday in the file name - please confirm it.
- Timestamps only have MINUTE resolution (no seconds). Our window step is 60 s, so every event inside the same minute will look simultaneous.
- Hours look like a 12-hour clock without AM/PM (e.g. 8-11 and then 1-5, none from 13-23). Afternoon traffic may be mis-dated by 12 hours. Phase 2 must fix this.
- 70 column names have leading/trailing/extra spaces (fixed in memory only).
- Duplicate column names were auto-renamed by pandas: Fwd Header Length.1.
- 264 rows contain infinite values (columns: Flow Bytes/s, Flow Packets/s).
- 201 rows contain missing values (columns: Flow Bytes/s).
- 4 fully duplicated rows.
- 10 constant column(s) carry no information: Bwd PSH Flags, Fwd URG Flags, Bwd URG Flags, CWE Flag Count, Fwd Avg Bytes/Bulk, Fwd Avg Packets/Bulk, Fwd Avg Bulk Rate, Bwd Avg Bytes/Bulk, Bwd Avg Packets/Bulk, Bwd Avg Bulk Rate.
- 11 numeric column(s) contain negative values (need case-by-case review).

### 13. Raw file integrity check

SHA-256 after inspection: `ae9c88e10c41a8eb1ff454ae98bc513454925097d0b0b57180f94e79de445815`  ->  **UNCHANGED**
