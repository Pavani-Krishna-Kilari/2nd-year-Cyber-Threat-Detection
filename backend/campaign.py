"""
Production Campaign Coalescence and Flow Attribution Engine
============================================================
Implements research-aligned transitive campaign coalescence across overlapping
and contiguous sliding-window security alerts for the SIEM detection pipeline.

Core Requirements:
  1. Strict directional pair grouping: (source_ip, destination_ip).
  2. Chronological sorting by window start bin k.
  3. Half-open temporal intervals: [start_bin, end_bin) with W=10 bins (600s / 60s).
  4. Transitive merging: candidate merges if next_start_bin <= current_campaign_end_bin.
  5. Windows separated by >= 1 unalerted bin remain separate campaigns.
  6. Preserves all original window-level predictions.
  7. Campaign verdict hierarchy: KNOWN_THREAT > UNKNOWN_ANOMALOUS.
  8. Campaign confidence: maximum observed confidence across constituent alert windows.
  9. Collision-safe campaign IDs: CMP-<session_prefix>-<seq:04d>.
  10. Zero double-counting of flows across overlapping windows.
"""

from collections import defaultdict
from typing import Dict, Any, List, Set, Tuple, Optional
import pandas as pd
import numpy as np


def coalesce_campaigns(
    window_predictions: List[Dict[str, Any]],
    flow_attributions: Dict[str, List[int]],
    session_id: str,
    window_bins: int = 10,
    step_seconds: int = 60
) -> Dict[str, Any]:
    """
    Coalesces alerting windows into logical security campaigns and derives
    deduplicated unique flow-level attributions.

    Parameters:
        window_predictions: List of dicts, each representing an evaluated window/event set:
            - 'event_set_id': str (e.g. 'ES0000001')
            - 'window_id': str (e.g. 'W00000')
            - 'k': int (start bin index)
            - 'source_ip': str
            - 'destination_ip': str
            - 'window_start': Timestamp or str
            - 'window_end': Timestamp or str
            - 'verdict': 'KNOWN_THREAT' | 'UNKNOWN_ANOMALOUS' | 'NORMAL'
            - 'confidence': float
            - 'ensemble_score': float
            - 'anomaly_score': float
            - 'basepoint_profile': list or np.ndarray
        flow_attributions: Dict mapping event_set_id -> List of original flow row indices.
        session_id: Unique analysis session UUID for collision-safe campaign ID generation.
        window_bins: Number of bins per window (default 10 for 600s / 60s).
        step_seconds: Seconds per bin (default 60).

    Returns:
        Dict containing:
            - 'campaigns': List of campaign dicts
            - 'flow_statistics': Dict of deduplicated flow counts
            - 'event_set_statistics': Dict of window event set counts
            - 'campaign_statistics': Dict of campaign counts
            - 'flow_verdicts': Dict mapping flow_idx -> final flow verdict
    """
    session_prefix = str(session_id) if session_id else "default"

    # 1. Filter alerting windows (NORMAL windows do not initiate alert campaigns)
    alerting_windows = [
        w for w in window_predictions
        if w.get("verdict") in ("KNOWN_THREAT", "UNKNOWN_ANOMALOUS")
    ]

    # 2. Group alerting windows by directional pair (source_ip, destination_ip)
    by_pair = defaultdict(list)
    for w in alerting_windows:
        pair_key = (w["source_ip"], w["destination_ip"])
        by_pair[pair_key].append(w)

    campaigns: List[Dict[str, Any]] = []
    camp_counter = 1

    # 3. Transitive coalescence per directional pair
    for pair, windows in by_pair.items():
        # Sort chronologically by start bin index k
        windows.sort(key=lambda x: (x["k"], str(x.get("window_start", ""))))

        curr_campaign: Optional[Dict[str, Any]] = None

        for w in windows:
            w_start_k = int(w["k"])
            w_end_k = w_start_k + window_bins  # Half-open: [start, end)
            es_id = w["event_set_id"]
            w_flows = set(flow_attributions.get(es_id, []))

            if curr_campaign is None:
                # Start new campaign
                curr_campaign = {
                    "campaign_id": f"CMP-{session_prefix}-{camp_counter:04d}",
                    "source_ip": pair[0],
                    "destination_ip": pair[1],
                    "start_k": w_start_k,
                    "end_k": w_end_k,
                    "start_time": w["window_start"],
                    "end_time": w["window_end"],
                    "verdict": w["verdict"],
                    "max_confidence": float(w.get("confidence", 0.0)),
                    "constituent_windows": [w["window_id"]],
                    "constituent_event_set_ids": [es_id],
                    "window_predictions": [w],
                    "attributed_flow_indices": w_flows
                }
                camp_counter += 1
            else:
                # Overlapping or directly contiguous check:
                # w_start_k <= curr_campaign["end_k"]
                if w_start_k <= curr_campaign["end_k"]:
                    # Transitive extension
                    curr_campaign["end_k"] = max(curr_campaign["end_k"], w_end_k)
                    curr_campaign["end_time"] = max(curr_campaign["end_time"], w["window_end"])
                    curr_campaign["constituent_windows"].append(w["window_id"])
                    curr_campaign["constituent_event_set_ids"].append(es_id)
                    curr_campaign["window_predictions"].append(w)
                    curr_campaign["max_confidence"] = max(
                        curr_campaign["max_confidence"],
                        float(w.get("confidence", 0.0))
                    )
                    # Verdict hierarchy: KNOWN_THREAT takes precedence over UNKNOWN_ANOMALOUS
                    if w["verdict"] == "KNOWN_THREAT":
                        curr_campaign["verdict"] = "KNOWN_THREAT"
                    curr_campaign["attributed_flow_indices"].update(w_flows)
                else:
                    # Non-contiguous gap: finalize current campaign and start new
                    curr_campaign["window_count"] = len(curr_campaign["constituent_windows"])
                    curr_campaign["attributed_flow_count"] = len(curr_campaign["attributed_flow_indices"])
                    curr_campaign["attributed_flow_indices"] = sorted(list(curr_campaign["attributed_flow_indices"]))
                    campaigns.append(curr_campaign)

                    curr_campaign = {
                        "campaign_id": f"CMP-{session_prefix}-{camp_counter:04d}",
                        "source_ip": pair[0],
                        "destination_ip": pair[1],
                        "start_k": w_start_k,
                        "end_k": w_end_k,
                        "start_time": w["window_start"],
                        "end_time": w["window_end"],
                        "verdict": w["verdict"],
                        "max_confidence": float(w.get("confidence", 0.0)),
                        "constituent_windows": [w["window_id"]],
                        "constituent_event_set_ids": [es_id],
                        "window_predictions": [w],
                        "attributed_flow_indices": w_flows
                    }
                    camp_counter += 1

        if curr_campaign is not None:
            curr_campaign["window_count"] = len(curr_campaign["constituent_windows"])
            curr_campaign["attributed_flow_count"] = len(curr_campaign["attributed_flow_indices"])
            curr_campaign["attributed_flow_indices"] = sorted(list(curr_campaign["attributed_flow_indices"]))
            campaigns.append(curr_campaign)

    # 4. Global Deduplicated Flow Attribution & Statistics
    # Map each unique flow index to its highest-priority verdict
    # Priority order: KNOWN_THREAT (2) > UNKNOWN_ANOMALOUS (1) > NORMAL (0)
    flow_highest_verdict: Dict[int, str] = {}
    all_flow_indices: Set[int] = set()

    for w in window_predictions:
        es_id = w["event_set_id"]
        v = w["verdict"]
        flows_in_window = flow_attributions.get(es_id, [])
        all_flow_indices.update(flows_in_window)

        for f_idx in flows_in_window:
            prev_v = flow_highest_verdict.get(f_idx, "NORMAL")
            if v == "KNOWN_THREAT":
                flow_highest_verdict[f_idx] = "KNOWN_THREAT"
            elif v == "UNKNOWN_ANOMALOUS" and prev_v != "KNOWN_THREAT":
                flow_highest_verdict[f_idx] = "UNKNOWN_ANOMALOUS"
            elif f_idx not in flow_highest_verdict:
                flow_highest_verdict[f_idx] = "NORMAL"

    n_known_flows = sum(1 for v in flow_highest_verdict.values() if v == "KNOWN_THREAT")
    n_unknown_flows = sum(1 for v in flow_highest_verdict.values() if v == "UNKNOWN_ANOMALOUS")
    n_normal_flows = sum(1 for v in flow_highest_verdict.values() if v == "NORMAL")
    total_unique_flows = len(all_flow_indices)

    flow_statistics = {
        "total_raw_flows": total_unique_flows,
        "unique_flows_analysed": total_unique_flows,
        "benign_flows": n_normal_flows,
        "known_threat_flows": n_known_flows,
        "unknown_anomalous_flows": n_unknown_flows,
        "invalid_flows": 0
    }

    # 5. Event Set Statistics
    n_total_sets = len(window_predictions)
    n_normal_sets = sum(1 for w in window_predictions if w["verdict"] == "NORMAL")
    n_threat_sets = sum(1 for w in window_predictions if w["verdict"] == "KNOWN_THREAT")
    n_anom_sets = sum(1 for w in window_predictions if w["verdict"] == "UNKNOWN_ANOMALOUS")

    event_set_statistics = {
        "total_event_sets": n_total_sets,
        "normal_event_sets": n_normal_sets,
        "ann_alert_sets": n_threat_sets,
        "unknown_anomalous_sets": n_anom_sets
    }

    # 6. Campaign Statistics
    n_total_camps = len(campaigns)
    n_threat_camps = sum(1 for c in campaigns if c["verdict"] == "KNOWN_THREAT")
    n_anom_camps = sum(1 for c in campaigns if c["verdict"] == "UNKNOWN_ANOMALOUS")

    campaign_statistics = {
        "total_campaigns": n_total_camps,
        "known_threat_campaigns": n_threat_camps,
        "unknown_anomalous_campaigns": n_anom_camps
    }

    return {
        "campaigns": campaigns,
        "flow_statistics": flow_statistics,
        "event_set_statistics": event_set_statistics,
        "campaign_statistics": campaign_statistics,
        "flow_verdicts": flow_highest_verdict
    }
