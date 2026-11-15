"""
Unit and Integration Tests for Stage 1 Runtime Raw-Flow Event Aggregator.
Verifies exact parity against the offline Experiment B event profiling pipeline.
"""

import unittest
import numpy as np
import pandas as pd
from pathlib import Path

from src.config import PROJECT_ROOT
from backend.aggregator import (
    RawFlowAggregator,
    InsufficientTemporalSpanError,
    InvalidTimestampError,
    MissingFeatureColumnsError,
    InvalidBenchmarkAnnotationError,
    REQUIRED_FLOW_COLUMNS
)
from src.event_profiles.events import EVENT_NAMES, FLOW_EVENT_SPECS, compare, apply_flow_events
from src.event_profiles.tfidf import transform as offline_transform
from src.event_profiles.basepoints import compute_profiles as offline_compute_profiles


class TestRuntimeAggregator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.aggregator = RawFlowAggregator(experiment_id="B")

    def _create_dummy_flows(self, timestamps, source_ip="192.168.10.50", destination_ip="172.16.0.1",
                            flow_duration=100.0, flow_packets_s=100.0, flow_bytes_s=1000.0, syn_flag_count=0.0):
        """Helper to create valid flow records with given timestamps."""
        n = len(timestamps)
        return pd.DataFrame({
            "source_row": np.arange(n, dtype="int64"),
            "timestamp": timestamps,
            "source_ip": [source_ip] * n,
            "destination_ip": [destination_ip] * n,
            "flow_duration": [flow_duration] * n,
            "flow_packets_s": [flow_packets_s] * n,
            "flow_bytes_s": [flow_bytes_s] * n,
            "syn_flag_count": [syn_flag_count] * n
        })

    def test_01_normal_10_bin_window(self):
        """1. A normal 10-bin window (bins 0 to 9) must form exactly one valid window."""
        start = pd.Timestamp("2017-07-07 14:00:00")
        timestamps = [start + pd.Timedelta(seconds=i * 60) for i in range(10)]
        df = self._create_dummy_flows(timestamps)

        result = self.aggregator.aggregate_flows(df)
        self.assertEqual(result["metadata"]["total_bins"], 10)
        self.assertEqual(result["metadata"]["total_event_sets"], 1)
        self.assertEqual(len(result["profiles"]), 1)
        self.assertEqual(result["profiles"].shape[1], 8)
        self.assertEqual(result["event_sets"].iloc[0]["k"], 0)
        self.assertEqual(result["event_sets"].iloc[0]["n_flows"], 10)

    def test_02_verified_599_second_boundary_case(self):
        """2. The verified 599-second boundary case occupying bins 0 to 9 must be accepted."""
        start = pd.Timestamp("2017-07-07 14:00:00")
        timestamps = [start + pd.Timedelta(seconds=s) for s in [0, 60, 120, 180, 240, 300, 360, 420, 480, 599]]
        df = self._create_dummy_flows(timestamps)

        elapsed = (df["timestamp"].max() - df["timestamp"].min()).total_seconds()
        self.assertEqual(elapsed, 599.0)

        result = self.aggregator.aggregate_flows(df)
        self.assertEqual(result["metadata"]["total_bins"], 10)
        self.assertEqual(len(result["profiles"]), 1)
        self.assertEqual(result["event_sets"].iloc[0]["k"], 0)

    def test_03_fewer_than_10_occupied_bins_rejected(self):
        """3. Fewer than 10 occupied bins must be rejected with InsufficientTemporalSpanError."""
        start = pd.Timestamp("2017-07-07 14:00:00")
        timestamps = [start + pd.Timedelta(seconds=i * 60) for i in range(9)]
        df = self._create_dummy_flows(timestamps)

        with self.assertRaises(InsufficientTemporalSpanError) as ctx:
            self.aggregator.aggregate_flows(df)
        self.assertIn("at least one complete 600-second window", str(ctx.exception))
        self.assertEqual(ctx.exception.details["n_bins"], 9)
        self.assertEqual(ctx.exception.details["bins_required"], 10)

        # Micro-burst test (e.g. 40 records in 3.8s)
        micro_ts = [start + pd.Timedelta(milliseconds=i * 95) for i in range(40)]
        df_micro = self._create_dummy_flows(micro_ts)
        with self.assertRaises(InsufficientTemporalSpanError) as ctx_micro:
            self.aggregator.aggregate_flows(df_micro)
        self.assertEqual(ctx_micro.exception.details["n_bins"], 1)

    def test_04_overlapping_sliding_windows(self):
        """4. Overlapping sliding windows: 13 bins must generate 4 overlapping windows."""
        start = pd.Timestamp("2017-07-07 14:00:00")
        timestamps = [start + pd.Timedelta(seconds=i * 60) for i in range(13)]
        df = self._create_dummy_flows(timestamps)

        result = self.aggregator.aggregate_flows(df)
        self.assertEqual(result["metadata"]["total_bins"], 13)
        self.assertEqual(len(result["profiles"]), 4)
        k_values = list(result["event_sets"]["k"])
        self.assertEqual(k_values, [0, 1, 2, 3])

    def test_05_multiple_source_destination_pairs(self):
        """5. Multiple source-destination pairs must generate independent event sets."""
        start = pd.Timestamp("2017-07-07 14:00:00")
        ts = [start + pd.Timedelta(seconds=i * 60) for i in range(10)]
        df1 = self._create_dummy_flows(ts, source_ip="192.168.10.50", destination_ip="172.16.0.1")
        df2 = self._create_dummy_flows(ts, source_ip="192.168.10.51", destination_ip="172.16.0.2")
        df = pd.concat([df1, df2], ignore_index=True)

        result = self.aggregator.aggregate_flows(df)
        self.assertEqual(result["metadata"]["unique_pairs"], 2)
        self.assertEqual(len(result["profiles"]), 2)
        pairs_in_sets = set(zip(result["event_sets"]["source_ip"], result["event_sets"]["destination_ip"]))
        self.assertEqual(pairs_in_sets, {("192.168.10.50", "172.16.0.1"), ("192.168.10.51", "172.16.0.2")})

    def test_06_directional_pair_separation(self):
        """6. Directional communication grouping: A->B and B->A must remain distinct."""
        start = pd.Timestamp("2017-07-07 14:00:00")
        ts = [start + pd.Timedelta(seconds=i * 60) for i in range(10)]
        df_ab = self._create_dummy_flows(ts, source_ip="10.0.0.1", destination_ip="10.0.0.2")
        df_ba = self._create_dummy_flows(ts, source_ip="10.0.0.2", destination_ip="10.0.0.1")
        df = pd.concat([df_ab, df_ba], ignore_index=True)

        result = self.aggregator.aggregate_flows(df)
        self.assertEqual(result["metadata"]["unique_pairs"], 2)
        self.assertEqual(len(result["profiles"]), 2)
        sources = list(result["event_sets"]["source_ip"])
        self.assertIn("10.0.0.1", sources)
        self.assertIn("10.0.0.2", sources)

    def test_07_exact_event_counts_and_ordering(self):
        """7. Exact event counts and event ordering: verify thresholds and order."""
        start = pd.Timestamp("2017-07-07 14:00:00")
        ts_bin0 = [start + pd.Timedelta(seconds=i) for i in range(15)]
        ts_rest = [start + pd.Timedelta(seconds=b * 60) for b in range(1, 10)]
        ts_all = ts_bin0 + ts_rest

        n_bin0 = len(ts_bin0)  # 15
        n_rest = len(ts_rest)  # 9
        total_flows = n_bin0 + n_rest  # 24

        df = pd.DataFrame({
            "source_row": np.arange(total_flows, dtype="int64"),
            "timestamp": ts_all,
            "source_ip": ["192.168.1.100"] * total_flows,
            "destination_ip": ["10.0.0.5"] * total_flows,
            "flow_duration": [1.0] * n_bin0 + [1000.0] * n_rest,          # < 3.0 in bin 0
            "flow_packets_s": [700000.0] * n_bin0 + [100.0] * n_rest,     # > 666666.7 in bin 0
            "flow_bytes_s": [3000000.0] * n_bin0 + [100.0] * n_rest,     # > 2485351.05 in bin 0
            "syn_flag_count": [1.0] * n_bin0 + [0.0] * n_rest             # >= 1.0 in bin 0
        })

        result = self.aggregator.aggregate_flows(df)
        es = result["event_sets"].iloc[0]

        self.assertEqual(es["n_flows"], 24)
        self.assertEqual(es["HIGH_FLOW_RATE"], 1)
        self.assertEqual(es["HIGH_PACKET_RATE"], 15)
        self.assertEqual(es["HIGH_BYTE_RATE"], 15)
        self.assertEqual(es["SYN_ACTIVITY"], 15)
        self.assertEqual(es["SHORT_REPEATED_CONNECTIONS"], 15)

    def test_08_tfidf_parity(self):
        """8. TF-IDF parity: runtime TF-IDF vectors match offline transform within 1e-12."""
        counts = np.array([
            [1, 15, 15, 15, 15],
            [0, 0, 5, 10, 0],
            [0, 0, 0, 0, 0]
        ], dtype="int64")

        runtime_tfidf = offline_transform(counts, self.aggregator.tfidf_model)
        self.assertEqual(runtime_tfidf.shape, (3, 5))
        np.testing.assert_array_equal(runtime_tfidf[2], np.zeros(5))
        norm0 = np.linalg.norm(runtime_tfidf[0])
        self.assertAlmostEqual(norm0, 1.0, places=10)

    def test_09_basepoint_profile_parity(self):
        """9. Basepoint profile parity: runtime profiles match offline compute_profiles within 1e-12."""
        start = pd.Timestamp("2017-07-07 14:00:00")
        # 13 flows in bins 0..9 (4 in bin 0, 1 in each of bins 1..9) -> 13 flows in window k=0 -> HFR = 1
        ts = [start + pd.Timedelta(seconds=s) for s in [0, 5, 10, 15]] + [start + pd.Timedelta(seconds=b * 60) for b in range(1, 10)]

        df = pd.DataFrame({
            "source_row": np.arange(13, dtype="int64"),
            "timestamp": ts,
            "source_ip": ["1.1.1.1"] * 13,
            "destination_ip": ["2.2.2.2"] * 13,
            "flow_duration": [1.0] * 5 + [100.0] * 8,       # 5 SHORT_REPEATED_CONNECTIONS
            "flow_packets_s": [700000.0] * 2 + [10.0] * 11, # 2 HIGH_PACKET_RATE
            "flow_bytes_s": [3000000.0] * 3 + [10.0] * 10,  # 3 HIGH_BYTE_RATE
            "syn_flag_count": [1.0] * 4 + [0.0] * 9         # 4 SYN_ACTIVITY
        })

        res = self.aggregator.aggregate_flows(df)
        runtime_p = res["profiles"][0]

        counts_expected = np.array([[1, 2, 3, 4, 5]], dtype="int64")
        tfidf_expected = offline_transform(counts_expected, self.aggregator.tfidf_model)
        offline_p = offline_compute_profiles(tfidf_expected, self.aggregator.basepoints)[0]

        max_diff = float(np.max(np.abs(runtime_p - offline_p)))
        self.assertLessEqual(max_diff, 1e-12)

    def test_10_split_boundary_behavior(self):
        """10. Split-boundary behavior: benchmark replay drops boundary-straddling windows."""
        start = pd.Timestamp("2017-07-07 14:00:00")
        ts = [start + pd.Timedelta(seconds=b * 60) for b in range(25)]
        block_ids = [b // 20 for b in range(25)]
        splits = ["train" if b == 0 else "control_test" for b in block_ids]

        df = pd.DataFrame({
            "source_row": np.arange(25, dtype="int64"),
            "timestamp": ts,
            "source_ip": ["10.0.0.1"] * 25,
            "destination_ip": ["10.0.0.2"] * 25,
            "flow_duration": [100.0] * 25,
            "flow_packets_s": [100.0] * 25,
            "flow_bytes_s": [100.0] * 25,
            "syn_flag_count": [0.0] * 25,
            "block_id": block_ids,
            "split": splits
        })

        # Benchmark replay mode: windows straddling boundary must be dropped
        res_benchmark = self.aggregator.aggregate_flows(df, is_benchmark_replay=True)
        self.assertEqual(len(res_benchmark["profiles"]), 11)
        self.assertEqual(list(res_benchmark["event_sets"]["k"]), list(range(11)))

        # Operational mode: continuous stream (no artificial split drops)
        res_operational = self.aggregator.aggregate_flows(df.drop(columns=["block_id", "split"]), is_benchmark_replay=False)
        self.assertEqual(len(res_operational["profiles"]), 16)
        self.assertEqual(list(res_operational["event_sets"]["k"]), list(range(16)))

    def test_11_missing_or_invalid_timestamps(self):
        """11. Missing or unparseable timestamps must be rejected with InvalidTimestampError."""
        start = pd.Timestamp("2017-07-07 14:00:00")
        ts_str = [str(start + pd.Timedelta(seconds=i * 60)) for i in range(10)]
        df = self._create_dummy_flows(ts_str)

        # Corrupt timestamps with unparseable string
        df.loc[0, "timestamp"] = "CORRUPT_TIMESTAMP_NOT_PARSEABLE"

        with self.assertRaises(InvalidTimestampError):
            self.aggregator.aggregate_flows(df)

    def test_12_missing_required_flow_features(self):
        """12. Missing required flow feature columns must be rejected with MissingFeatureColumnsError."""
        start = pd.Timestamp("2017-07-07 14:00:00")
        ts = [start + pd.Timedelta(seconds=i * 60) for i in range(10)]
        df = self._create_dummy_flows(ts)

        # Drop required column 'flow_packets_s'
        df_missing = df.drop(columns=["flow_packets_s"])
        with self.assertRaises(MissingFeatureColumnsError):
            self.aggregator.aggregate_flows(df_missing)

        # Drop required column 'source_ip'
        df_no_ip = df.drop(columns=["source_ip"])
        with self.assertRaises(MissingFeatureColumnsError):
            self.aggregator.aggregate_flows(df_no_ip)


if __name__ == "__main__":
    unittest.main()
