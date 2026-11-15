"""
Stage 2 Integration Test Suite: Campaign Coalescence and Ingestion Integration
==============================================================================
Validates:
  1. End-to-end raw-flow CSV ingestion (W=10 bins, 600s window, 60s step).
  2. Runtime aggregator to vectorized inference integration.
  3. Campaign transitive merging across overlapping and contiguous windows.
  4. Contiguous window merging (next_start_bin <= current_campaign_end_bin).
  5. Non-contiguous windows (separated by >= 1 unalerted bin) remaining separate.
  6. Different directional pairs remaining separate campaigns.
  7. Collision-safe campaign IDs across multiple upload sessions.
  8. Preservation of all original window-level predictions.
  9. Unique flow attribution across overlapping windows (zero double-counting).
  10. Campaign verdict priority (KNOWN_THREAT > UNKNOWN_ANOMALOUS).
  11. Rejection of empty/invalid uploads (never falling back to single-flow).
  12. Benchmark annotation validation.
  13. Preaggregated event-profile CSV compatibility (bp_01..bp_08).
  14. Manual classification remaining independent of batch results.
  15. SOC Overview updating only from uploaded batches (second batch replaces first).
  16. Detection-history persistence and retrieval.
"""

import io
import json
import shutil
import sqlite3
import time
import unittest
from pathlib import Path
from typing import Dict, Any, List

import numpy as np
import pandas as pd

from src.config import PROJECT_ROOT
from backend.service import SIEMService
from backend.campaign import coalesce_campaigns
from backend.aggregator import (
    RawFlowAggregator,
    InsufficientTemporalSpanError,
    MissingFeatureColumnsError,
    InvalidTimestampError,
    InvalidBenchmarkAnnotationError,
    AggregatorError
)
from backend.database import (
    init_db,
    insert_session,
    insert_detections,
    insert_campaigns,
    get_campaigns,
    get_detections,
    clear_all_history,
    DB_PATH
)


def _generate_synthetic_flow_csv(
    n_bins: int = 12,
    flows_per_bin: int = 15,
    src_ip: str = "172.16.0.1",
    dst_ip: str = "192.168.10.50",
    start_time: str = "2017-07-04 09:00:00"
) -> bytes:
    """Helper to generate a valid synthetic raw network-flow CSV."""
    t0 = pd.Timestamp(start_time)
    records = []
    for b in range(n_bins):
        for f in range(flows_per_bin):
            flow_ts = t0 + pd.Timedelta(seconds=b * 60 + f * 2)
            records.append({
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": 1024 + f,
                "destination_port": 21,
                "protocol": "TCP",
                "timestamp": flow_ts.strftime("%Y-%m-%d %H:%M:%S"),
                "flow_duration": 1500.0,
                "flow_packets_s": 500000.0,
                "flow_bytes_s": 2000000.0,
                "syn_flag_count": 1
            })
    df = pd.DataFrame(records)
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    return buf.getvalue().encode("utf-8")


class TestStage2Integration(unittest.TestCase):
    """16 Targeted Integration Tests for Phase 2 Stage 2."""

    @classmethod
    def setUpClass(cls):
        # Create a backup of detection_history.db before running tests
        cls.db_backup_path = DB_PATH.with_suffix(".db.test_backup")
        if DB_PATH.exists():
            shutil.copy2(DB_PATH, cls.db_backup_path)

        # Initialize SIEMService in Experiment B
        cls.service = SIEMService(experiment_id="B")

    @classmethod
    def tearDownClass(cls):
        # Restore detection_history.db to pre-test state
        if cls.db_backup_path.exists():
            shutil.copy2(cls.db_backup_path, DB_PATH)
            cls.db_backup_path.unlink()

    def setUp(self):
        # Clear database for test isolation
        clear_all_history()
        self.service.current_analysis_summary = None

    # -------------------------------------------------------------------------
    # Test 1: End-to-end raw-flow CSV ingestion
    # -------------------------------------------------------------------------
    def test_01_end_to_end_raw_flow_ingestion(self):
        csv_bytes = _generate_synthetic_flow_csv(n_bins=12, flows_per_bin=15)
        summary = self.service.process_file_upload(csv_bytes, "test_raw_flows.csv")

        self.assertTrue(summary["has_data"])
        self.assertEqual(summary["detected_type"], "flow")
        self.assertIn("flow_statistics", summary)
        self.assertIn("event_set_statistics", summary)
        self.assertIn("campaign_statistics", summary)
        self.assertIn("campaigns", summary)

        # 12 bins with W=10 bins gives 3 sliding windows (k=0, 1, 2)
        event_stats = summary["event_set_statistics"]
        self.assertEqual(event_stats["total_event_sets"], 3)

        # Flow statistics must reflect all 180 flows (12 * 15)
        flow_stats = summary["flow_statistics"]
        self.assertEqual(flow_stats["total_raw_flows"], 180)
        self.assertEqual(flow_stats["unique_flows_analysed"], 180)
        self.assertEqual(flow_stats["invalid_flows"], 0)

    # -------------------------------------------------------------------------
    # Test 2: Runtime aggregator to vectorized inference integration
    # -------------------------------------------------------------------------
    def test_02_aggregator_to_vectorized_inference_integration(self):
        csv_bytes = _generate_synthetic_flow_csv(n_bins=12, flows_per_bin=15)
        df = pd.read_csv(io.BytesIO(csv_bytes))

        agg_res = self.service.aggregator.aggregate_flows(df)
        profiles = agg_res["profiles"]
        self.assertIsInstance(profiles, np.ndarray)
        self.assertEqual(profiles.shape, (3, 8))

        preds = self.service.engine.predict_profiles_batch(profiles)
        self.assertEqual(len(preds), 3)
        for p in preds:
            self.assertIn("verdict", p)
            self.assertIn("threat_confidence", p)
            self.assertIn("anomaly", p)
            self.assertIn("model_breakdown", p)

    # -------------------------------------------------------------------------
    # Test 3: Campaign transitive merging across overlapping/contiguous windows
    # -------------------------------------------------------------------------
    def test_03_campaign_transitive_merging(self):
        # Construct 3 alerting windows: k=0, 10, 20 with W=10
        # k=0: [0, 10), k=10: [10, 20), k=20: [20, 30) -> all should merge into one
        windows = [
            {
                "event_set_id": "ES0000001", "window_id": "W00000", "k": 0,
                "source_ip": "172.16.0.1", "destination_ip": "192.168.10.50",
                "window_start": "2017-07-04 09:00:00", "window_end": "2017-07-04 09:10:00",
                "verdict": "KNOWN_THREAT", "confidence": 0.85
            },
            {
                "event_set_id": "ES0000002", "window_id": "W00010", "k": 10,
                "source_ip": "172.16.0.1", "destination_ip": "192.168.10.50",
                "window_start": "2017-07-04 09:10:00", "window_end": "2017-07-04 09:20:00",
                "verdict": "KNOWN_THREAT", "confidence": 0.90
            },
            {
                "event_set_id": "ES0000003", "window_id": "W00020", "k": 20,
                "source_ip": "172.16.0.1", "destination_ip": "192.168.10.50",
                "window_start": "2017-07-04 09:20:00", "window_end": "2017-07-04 09:30:00",
                "verdict": "KNOWN_THREAT", "confidence": 0.75
            }
        ]
        attributions = {"ES0000001": [1, 2], "ES0000002": [3, 4], "ES0000003": [5, 6]}

        res = coalesce_campaigns(windows, attributions, session_id="SESS-TEST1")
        campaigns = res["campaigns"]
        self.assertEqual(len(campaigns), 1)
        c = campaigns[0]
        self.assertEqual(c["start_k"], 0)
        self.assertEqual(c["end_k"], 30)
        self.assertEqual(c["window_count"], 3)
        self.assertEqual(c["max_confidence"], 0.90)
        self.assertEqual(c["attributed_flow_count"], 6)

    # -------------------------------------------------------------------------
    # Test 4: Contiguous window merging
    # -------------------------------------------------------------------------
    def test_04_contiguous_window_merging(self):
        # k=0 [0, 10) and k=10 [10, 20) are contiguous (next_start_bin <= current_end_bin)
        windows = [
            {
                "event_set_id": "ES0000001", "window_id": "W00000", "k": 0,
                "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
                "window_start": "2017-07-04 09:00:00", "window_end": "2017-07-04 09:10:00",
                "verdict": "KNOWN_THREAT", "confidence": 0.80
            },
            {
                "event_set_id": "ES0000002", "window_id": "W00010", "k": 10,
                "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
                "window_start": "2017-07-04 09:10:00", "window_end": "2017-07-04 09:20:00",
                "verdict": "KNOWN_THREAT", "confidence": 0.85
            }
        ]
        attributions = {"ES0000001": [1], "ES0000002": [2]}
        res = coalesce_campaigns(windows, attributions, session_id="SESS-CONTIG")
        self.assertEqual(len(res["campaigns"]), 1)
        self.assertEqual(res["campaigns"][0]["end_k"], 20)

    # -------------------------------------------------------------------------
    # Test 5: Non-contiguous windows remaining separate
    # -------------------------------------------------------------------------
    def test_05_non_contiguous_windows_separate(self):
        # k=0 [0, 10) and k=11 [11, 21): separated by 1 unalerted bin (k=10)
        windows = [
            {
                "event_set_id": "ES0000001", "window_id": "W00000", "k": 0,
                "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
                "window_start": "2017-07-04 09:00:00", "window_end": "2017-07-04 09:10:00",
                "verdict": "KNOWN_THREAT", "confidence": 0.80
            },
            {
                "event_set_id": "ES0000002", "window_id": "W00011", "k": 11,
                "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
                "window_start": "2017-07-04 09:11:00", "window_end": "2017-07-04 09:21:00",
                "verdict": "KNOWN_THREAT", "confidence": 0.85
            }
        ]
        attributions = {"ES0000001": [1], "ES0000002": [2]}
        res = coalesce_campaigns(windows, attributions, session_id="SESS-NONCONTIG")
        self.assertEqual(len(res["campaigns"]), 2)
        self.assertEqual(res["campaigns"][0]["end_k"], 10)
        self.assertEqual(res["campaigns"][1]["start_k"], 11)

    # -------------------------------------------------------------------------
    # Test 6: Different directional pairs remaining separate
    # -------------------------------------------------------------------------
    def test_06_different_directional_pairs_separate(self):
        windows = [
            {
                "event_set_id": "ES0000001", "window_id": "W00000", "k": 0,
                "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
                "window_start": "2017-07-04 09:00:00", "window_end": "2017-07-04 09:10:00",
                "verdict": "KNOWN_THREAT", "confidence": 0.80
            },
            {
                "event_set_id": "ES0000002", "window_id": "W00000", "k": 0,
                "source_ip": "10.0.0.3", "destination_ip": "10.0.0.4",
                "window_start": "2017-07-04 09:00:00", "window_end": "2017-07-04 09:10:00",
                "verdict": "KNOWN_THREAT", "confidence": 0.85
            }
        ]
        attributions = {"ES0000001": [1], "ES0000002": [2]}
        res = coalesce_campaigns(windows, attributions, session_id="SESS-DIFFPAIRS")
        self.assertEqual(len(res["campaigns"]), 2)
        pairs = {(c["source_ip"], c["destination_ip"]) for c in res["campaigns"]}
        self.assertIn(("10.0.0.1", "10.0.0.2"), pairs)
        self.assertIn(("10.0.0.3", "10.0.0.4"), pairs)

    # -------------------------------------------------------------------------
    # Test 7: Multiple upload sessions produce collision-safe campaign IDs
    # -------------------------------------------------------------------------
    def test_07_multiple_upload_sessions_unique_ids(self):
        windows = [
            {
                "event_set_id": "ES0000001", "window_id": "W00000", "k": 0,
                "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
                "window_start": "2017-07-04 09:00:00", "window_end": "2017-07-04 09:10:00",
                "verdict": "KNOWN_THREAT", "confidence": 0.80
            }
        ]
        res1 = coalesce_campaigns(windows, {"ES0000001": [1]}, session_id="SESSION_AAAA_1111")
        res2 = coalesce_campaigns(windows, {"ES0000001": [1]}, session_id="SESSION_BBBB_2222")

        id1 = res1["campaigns"][0]["campaign_id"]
        id2 = res2["campaigns"][0]["campaign_id"]
        self.assertNotEqual(id1, id2)
        self.assertTrue(id1.startswith("CMP-SESSION_"))
        self.assertTrue(id2.startswith("CMP-SESSION_"))

    # -------------------------------------------------------------------------
    # Test 8: Preservation of all window predictions inside campaign
    # -------------------------------------------------------------------------
    def test_08_preservation_of_window_predictions(self):
        windows = [
            {
                "event_set_id": "ES0000001", "window_id": "W00000", "k": 0,
                "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
                "window_start": "2017-07-04 09:00:00", "window_end": "2017-07-04 09:10:00",
                "verdict": "KNOWN_THREAT", "confidence": 0.81, "custom_field": "preserved_1"
            },
            {
                "event_set_id": "ES0000002", "window_id": "W00001", "k": 1,
                "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
                "window_start": "2017-07-04 09:01:00", "window_end": "2017-07-04 09:11:00",
                "verdict": "KNOWN_THREAT", "confidence": 0.82, "custom_field": "preserved_2"
            }
        ]
        res = coalesce_campaigns(windows, {"ES0000001": [1], "ES0000002": [2]}, session_id="SESS-PRESERVE")
        c = res["campaigns"][0]
        self.assertEqual(len(c["window_predictions"]), 2)
        self.assertEqual(c["window_predictions"][0]["custom_field"], "preserved_1")
        self.assertEqual(c["window_predictions"][1]["custom_field"], "preserved_2")

    # -------------------------------------------------------------------------
    # Test 9: Unique flow attribution across overlapping windows (no double counting)
    # -------------------------------------------------------------------------
    def test_09_unique_flow_attribution_no_double_counting(self):
        # Window 1 contains flows [0, 1, 2, 3]
        # Window 2 contains flows [2, 3, 4, 5] (flows 2 and 3 overlap!)
        windows = [
            {
                "event_set_id": "ES0000001", "window_id": "W00000", "k": 0,
                "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
                "window_start": "2017-07-04 09:00:00", "window_end": "2017-07-04 09:10:00",
                "verdict": "KNOWN_THREAT", "confidence": 0.80
            },
            {
                "event_set_id": "ES0000002", "window_id": "W00001", "k": 1,
                "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
                "window_start": "2017-07-04 09:01:00", "window_end": "2017-07-04 09:11:00",
                "verdict": "KNOWN_THREAT", "confidence": 0.85
            }
        ]
        attributions = {
            "ES0000001": [0, 1, 2, 3],
            "ES0000002": [2, 3, 4, 5]
        }
        res = coalesce_campaigns(windows, attributions, session_id="SESS-DEDUP")
        c = res["campaigns"][0]
        # Should deduplicate to exactly 6 flows: [0, 1, 2, 3, 4, 5]
        self.assertEqual(c["attributed_flow_count"], 6)
        self.assertEqual(c["attributed_flow_indices"], [0, 1, 2, 3, 4, 5])
        self.assertEqual(res["flow_statistics"]["unique_flows_analysed"], 6)

    # -------------------------------------------------------------------------
    # Test 10: Campaign verdict priority (KNOWN_THREAT > UNKNOWN_ANOMALOUS)
    # -------------------------------------------------------------------------
    def test_10_campaign_verdict_priority(self):
        windows = [
            {
                "event_set_id": "ES0000001", "window_id": "W00000", "k": 0,
                "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
                "window_start": "2017-07-04 09:00:00", "window_end": "2017-07-04 09:10:00",
                "verdict": "UNKNOWN_ANOMALOUS", "confidence": 0.70
            },
            {
                "event_set_id": "ES0000002", "window_id": "W00001", "k": 1,
                "source_ip": "10.0.0.1", "destination_ip": "10.0.0.2",
                "window_start": "2017-07-04 09:01:00", "window_end": "2017-07-04 09:11:00",
                "verdict": "KNOWN_THREAT", "confidence": 0.88
            }
        ]
        attributions = {"ES0000001": [1], "ES0000002": [2]}
        res = coalesce_campaigns(windows, attributions, session_id="SESS-PRIORITY")
        c = res["campaigns"][0]
        self.assertEqual(c["verdict"], "KNOWN_THREAT")
        self.assertEqual(c["max_confidence"], 0.88)

    # -------------------------------------------------------------------------
    # Test 11: Rejection of empty and invalid uploads (no silent fallback)
    # -------------------------------------------------------------------------
    def test_11_empty_and_invalid_uploads(self):
        # 1. Empty CSV
        with self.assertRaises(ValueError):
            self.service.process_file_upload(b"", "empty.csv")

        # 2. Insufficient temporal span (< 10 bins)
        short_csv = _generate_synthetic_flow_csv(n_bins=5, flows_per_bin=5)
        with self.assertRaises(InsufficientTemporalSpanError):
            self.service.process_file_upload(short_csv, "short.csv")

        # 3. Missing required columns
        df_missing = pd.DataFrame({"source_ip": ["10.0.0.1"], "destination_ip": ["10.0.0.2"]})
        buf = io.StringIO()
        df_missing.to_csv(buf, index=False)
        with self.assertRaises((MissingFeatureColumnsError, ValueError)):
            self.service.process_file_upload(buf.getvalue().encode("utf-8"), "missing_cols.csv")

    # -------------------------------------------------------------------------
    # Test 12: Benchmark annotation validation
    # -------------------------------------------------------------------------
    def test_12_benchmark_annotation_validation(self):
        # Benchmark replay requires block_id or split matching 20-minute windows
        # Provide invalid block_id
        csv_bytes = _generate_synthetic_flow_csv(n_bins=12, flows_per_bin=10)
        df = pd.read_csv(io.BytesIO(csv_bytes))
        df["split"] = "invalid_split_name"

        with self.assertRaises(InvalidBenchmarkAnnotationError):
            self.service.aggregator.aggregate_flows(df, is_benchmark_replay=True)

    # -------------------------------------------------------------------------
    # Test 13: Preaggregated event-profile CSV compatibility
    # -------------------------------------------------------------------------
    def test_13_preaggregated_event_profile_csv_compatibility(self):
        # Generate 8D basepoint profile CSV
        records = []
        for i in range(5):
            records.append({
                "bp_01": 0.85, "bp_02": 0.12, "bp_03": 0.05, "bp_04": 0.02,
                "bp_05": 0.01, "bp_06": 0.01, "bp_07": 0.01, "bp_08": 0.01,
                "source_ip": f"192.168.10.{i+10}",
                "destination_ip": "192.168.10.50",
                "destination_port": 21
            })
        df = pd.DataFrame(records)
        buf = io.StringIO()
        df.to_csv(buf, index=False)
        csv_bytes = buf.getvalue().encode("utf-8")

        summary = self.service.process_file_upload(csv_bytes, "preaggregated_profiles.csv")
        self.assertTrue(summary["has_data"])
        self.assertEqual(summary["detected_type"], "profile")
        self.assertEqual(summary["event_set_statistics"]["total_event_sets"], 5)
        self.assertIn("campaigns", summary)

    # -------------------------------------------------------------------------
    # Test 14: Manual classification remaining independent of batch results
    # -------------------------------------------------------------------------
    def test_14_manual_vs_batch_independence(self):
        # First upload a batch
        csv_bytes = _generate_synthetic_flow_csv(n_bins=12, flows_per_bin=15)
        batch_summary = self.service.process_file_upload(csv_bytes, "batch.csv")
        saved_session_id = batch_summary["session_id"]
        saved_total = batch_summary["event_set_statistics"]["total_event_sets"]

        # Run manual single-flow classification
        manual_flow = {
            "source_ip": "172.16.0.1",
            "destination_ip": "192.168.10.50",
            "destination_port": 21,
            "flow_packets_s": 500000.0,
            "flow_bytes_s": 2000000.0,
            "syn_flag_count": 1,
            "flow_duration": 1000.0,
            "flow_count": 15
        }
        manual_pred = self.service.predict_single_flow(manual_flow)
        self.assertIn("verdict", manual_pred)

        # CRITICAL VERIFICATION: current_analysis_summary must remain the batch summary!
        curr = self.service.get_dashboard_summary()
        self.assertEqual(curr["session_id"], saved_session_id)
        self.assertEqual(curr["event_set_statistics"]["total_event_sets"], saved_total)

    # -------------------------------------------------------------------------
    # Test 15: SOC Overview updating only from uploaded batches
    # -------------------------------------------------------------------------
    def test_15_soc_overview_batch_reflection(self):
        # 1. Before upload, empty state
        self.service.clear_batch_summary()
        summary0 = self.service.get_dashboard_summary()
        self.assertFalse(summary0["has_data"])
        self.assertEqual(summary0["total_records"], 0)

        # 2. Upload Batch 1 (12 bins = 3 windows)
        csv1 = _generate_synthetic_flow_csv(n_bins=12, flows_per_bin=15)
        res1 = self.service.process_file_upload(csv1, "batch1.csv")
        summary1 = self.service.get_dashboard_summary()
        self.assertTrue(summary1["has_data"])
        self.assertEqual(summary1["session_id"], res1["session_id"])
        self.assertEqual(summary1["event_set_statistics"]["total_event_sets"], 3)

        # 3. Upload Batch 2 (15 bins = 6 windows)
        csv2 = _generate_synthetic_flow_csv(n_bins=15, flows_per_bin=15)
        res2 = self.service.process_file_upload(csv2, "batch2.csv")
        summary2 = self.service.get_dashboard_summary()
        self.assertTrue(summary2["has_data"])
        # Second batch completely replaces the first in SOC Overview
        self.assertEqual(summary2["session_id"], res2["session_id"])
        self.assertNotEqual(summary2["session_id"], res1["session_id"])
        self.assertEqual(summary2["event_set_statistics"]["total_event_sets"], 6)

    # -------------------------------------------------------------------------
    # Test 16: Detection-history persistence and retrieval
    # -------------------------------------------------------------------------
    def test_16_persistence_and_retrieval(self):
        csv_bytes = _generate_synthetic_flow_csv(n_bins=12, flows_per_bin=15)
        summary = self.service.process_file_upload(csv_bytes, "persist_test.csv")
        sess_id = summary["session_id"]

        # Retrieve campaigns from SQLite
        campaigns = get_campaigns(session_id=sess_id)
        self.assertGreaterEqual(len(campaigns), 1)
        c0 = campaigns[0]
        self.assertIn("campaign_id", c0)
        self.assertEqual(c0["session_id"], sess_id)
        self.assertIn("source_ip", c0)
        self.assertIn("destination_ip", c0)
        self.assertIn("verdict", c0)
        self.assertIn("max_confidence", c0)
        self.assertIn("window_count", c0)
        self.assertIn("attributed_flow_count", c0)

        # Retrieve detections from SQLite
        detections = get_detections(session_id=sess_id)
        self.assertEqual(len(detections), 3)  # 3 evaluated windows
        d0 = detections[0]
        self.assertEqual(d0["session_id"], sess_id)
        self.assertIn("id", d0)
        self.assertIn("verdict", d0)
        self.assertIn("confidence", d0)


if __name__ == "__main__":
    unittest.main()
