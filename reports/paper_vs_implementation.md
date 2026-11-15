# Paper vs. Implementation

PAPER = follows the original paper. ADAPTATION = changed because CICIDS2017 differs from the paper's data. OURS = added by this project.

CICIDS2017 is one of the datasets the paper reports on, but our events, thresholds and targets are our own construction; we do not claim to reproduce the paper's results.

| Item | Tag | Our implementation |
| --- | --- | --- |
| Sliding window: 10-minute size, 60 s interval | PAPER | Same values, read from configs/config.yaml (window.size_seconds / step_seconds). |
| Event sets aggregated by source and destination address inside each window | PAPER | One event set per source->destination pair per window. |
| Events are IDS/IPS alert names | ADAPTATION | Five derived, flow-based categories. Not IDS alerts. |
| Event counts per event set (frequency of each event) | PAPER | Counts for four events; HIGH_FLOW_RATE is 0/1 because it describes the whole set. |
| TF-IDF over event sets (set = document, event = term) | PAPER | Same roles. |
| IDF uses the total number of occurrences of an event | ADAPTATION | Document frequency with smoothing; total occurrences can exceed the number of sets with our flow-level counts and give negative weights. |
| Sublinear TF and L2 normalisation | OURS | Counts range from 1 to thousands. |
| Basepoint candidates: sets that contain rare events; redundant basepoints replaced iteratively | PAPER | Same idea. |
| Rare list of 10-20 events; k as a fraction of the number of event types | ADAPTATION | Only 5 event types: rare list of 2, up to 8 basepoints, deterministic greedy replacement of redundant ones. |
| Event profile = cosine similarity to each basepoint | PAPER | Same, with safe handling of empty sets (all zeros). |
| Profile reduces dimensionality | ADAPTATION | 8 basepoints over 5 event dimensions is a representation, not a reduction. |
| Labels from threat-detection reports (time + attacker IP) | ADAPTATION | Labels come from the CICIDS2017 flow labels; event-set targets defined from them, kept in a separate file. |
| Percentile thresholds from training data; blocked time split; window never crosses a split; join checks | OURS | Added to prevent leakage. |

Phase 4 (FCNN / CNN / LSTM) is not implemented yet.
