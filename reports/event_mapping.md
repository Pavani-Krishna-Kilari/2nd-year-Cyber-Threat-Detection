# Event Mapping (CICIDS2017 flows -> derived security events)

The research paper works with **IDS/IPS alert names**. CICIDS2017 provides network-flow statistics instead, so we derive five event categories with transparent rules. **These are derived events, not original IDS alerts.**

| Event | Level | Source feature | Unit / meaning (CICFlowMeter) | Rule | Threshold (this run) | Counted as |
| --- | --- | --- | --- | --- | --- | --- |
| HIGH_FLOW_RATE | source->destination event set | number of flows in the set | flows per 10-min window | > 95th pct of training event sets | 12 flows | 0 or 1 per event set |
| HIGH_PACKET_RATE | flow | flow_packets_s | packets per second | > 95th pct of training flows | 500000 | number of flows that fired |
| HIGH_BYTE_RATE | flow | flow_bytes_s | bytes per second | > 95th pct of training flows | 1.84337e+06 | number of flows that fired |
| SYN_ACTIVITY | flow | syn_flag_count | packets with the SYN flag in the flow | > 95th pct of training flows | 1 | number of flows that fired |
| SHORT_REPEATED_CONNECTIONS | flow | flow_duration | microseconds | < 5th pct of training flows | 4 microseconds | number of flows that fired |

**Why 'repeated':** each flow is judged on its own; the repetition is the *count* of short flows between one source and one destination inside a window.

**Event set:** all flows from one source IP to one destination IP inside one window. IPs only define the groups; they are never given to TF-IDF, basepoints or any model. Direction matters (A->B and B->A are separate sets).

**Event vector / profile:** the 5 event counts -> TF-IDF (training-fitted) -> L2-normalised vector -> cosine similarity to each basepoint = event profile.

**Leakage rules:** thresholds, IDF and basepoints use training data only; label, label_original, target_binary, target_multiclass, ports and Flow ID are never inputs to event generation.
