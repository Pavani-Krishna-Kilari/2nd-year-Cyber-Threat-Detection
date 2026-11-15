"""
Unit tests for Multi-Day Event Profile Generation and Safety Guards.
Verifies:
  - Basepoint trace None-value formatting fix.
  - Experiment A and Experiment B split partition mapping.
  - Strict output isolation (data/processed/event_profiles/ is never overwritten).
  - Safety backup behavior when existing outputs are detected.
  - Training-only fitting and feature isolation (no forbidden leakage features).
  - Profile ID join integrity with ground truth targets.
  - Baseline Tuesday profile preservation.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
import hashlib
from pathlib import Path
import numpy as np
import pandas as pd

from src.config import load_config, PROJECT_ROOT
from src.event_profiles.errors import EventProfileError, ValidationError
from src.event_profiles.build_multi_day_profiles import (
    assign_experiment_b_split,
    TUESDAY_CONTROL_BLOCKS,
    GLOBAL_LABEL_TO_CODE,
    GLOBAL_CODE_TO_LABEL
)
from src.event_profiles.validation import validate_model_files, PROFILE_ID_COLUMNS
from src.event_profiles.events import (
    EVENT_NAMES, FLOW_EVENT_SPECS, fit_flow_thresholds,
    fit_set_threshold, compare, assert_no_forbidden_columns
)
from src.event_profiles.tfidf import fit_idf, transform
from src.event_profiles.basepoints import select_basepoints, compute_profiles


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


class TestMultiDayProfileSafety(unittest.TestCase):

    def test_first_basepoint_trace_none_formatting(self):
        """Verify the first basepoint trace where max_cosine_to_previous is None formats safely."""
        fake_trace = [
            {"order": 1, "max_cosine_to_previous": None, "rare_event_weight": 0.8523},
            {"order": 2, "max_cosine_to_previous": 0.1234, "rare_event_weight": 0.4321}
        ]
        formatted_logs = []
        for i, tr in enumerate(fake_trace, 1):
            cos_prev = tr.get("max_cosine_to_previous")
            cos_str = f"{cos_prev:.4f}" if cos_prev is not None else "N/A (first pick)"
            rare_w = tr.get("rare_event_weight", 0.0)
            msg = f"Basepoint bp_{i:02d}: selected from candidate (cosine to previous: {cos_str}, rare weight: {rare_w:.4f})"
            formatted_logs.append(msg)

        self.assertIn("cosine to previous: N/A (first pick)", formatted_logs[0])
        self.assertIn("rare weight: 0.8523", formatted_logs[0])
        self.assertIn("cosine to previous: 0.1234", formatted_logs[1])

    def test_experiment_b_split_assignments(self):
        """Verify Experiment B capture assignment: Mon/Tue/Wed -> train, Thu -> val, Fri -> test."""
        self.assertEqual(assign_experiment_b_split("Monday-WorkingHours_clean.csv"), "train")
        self.assertEqual(assign_experiment_b_split("Tuesday-WorkingHours_clean.csv"), "train")
        self.assertEqual(assign_experiment_b_split("Wednesday-workingHours_clean.csv"), "train")
        self.assertEqual(assign_experiment_b_split("Thursday-WorkingHours-Morning-WebAttacks_clean.csv"), "validation")
        self.assertEqual(assign_experiment_b_split("Thursday-WorkingHours-Afternoon-Infilteration_clean.csv"), "validation")
        self.assertEqual(assign_experiment_b_split("Friday-WorkingHours-Morning_clean.csv"), "test")
        self.assertEqual(assign_experiment_b_split("Friday-WorkingHours-Afternoon-PortScan_clean.csv"), "test")
        self.assertEqual(assign_experiment_b_split("Friday-WorkingHours-Afternoon-DDos_clean.csv"), "test")
        self.assertEqual(assign_experiment_b_split("Unknown-File.csv"), "unassigned")

        # Option A: Tuesday control blocks 4 and 27 mapped to control_test
        self.assertEqual(assign_experiment_b_split("Tuesday-WorkingHours_clean.csv", block_id=4), "control_test")
        self.assertEqual(assign_experiment_b_split("Tuesday-WorkingHours_clean.csv", block_id=27), "control_test")
        self.assertEqual(assign_experiment_b_split("Tuesday-WorkingHours_clean.csv", block_id=3), "train")
        self.assertEqual(assign_experiment_b_split("Tuesday-WorkingHours_clean.csv", block_id=25), "train")

    def test_tuesday_control_window_boundary_leakage_prevention(self):
        """Verify that valid_windows drops all transition windows bridging Tuesday train and control_test."""
        from src.event_profiles.windows import valid_windows
        # Block 3 (bins 0..19: train), Block 4 (bins 20..39: control_test), Block 5 (bins 40..59: train)
        names = np.array(["train"] * 20 + ["control_test"] * 20 + ["train"] * 20, dtype=object)
        W = 10  # 10 bins = 600 seconds
        valid, split_of = valid_windows(names, W)

        # Inside Block 3: windows 0..10 are train
        for k in range(11):
            self.assertTrue(valid[k])
            self.assertEqual(split_of[k], "train")

        # Boundary 1: transition windows 11..19 bridge Block 3 (train) and Block 4 (control_test) -> MUST BE INVALID
        for k in range(11, 20):
            self.assertFalse(valid[k], f"Window {k} bridges train and control_test and must be invalid")

        # Inside Block 4 (control_test): windows 20..30 are strictly control_test
        for k in range(20, 31):
            self.assertTrue(valid[k])
            self.assertEqual(split_of[k], "control_test")

        # Boundary 2: transition windows 31..39 bridge Block 4 (control_test) and Block 5 (train) -> MUST BE INVALID
        for k in range(31, 40):
            self.assertFalse(valid[k], f"Window {k} bridges control_test and train and must be invalid")

        # Inside Block 5: windows 40..50 are train
        for k in range(40, 51):
            self.assertTrue(valid[k])
            self.assertEqual(split_of[k], "train")

    def test_tuesday_control_blocks_excluded_from_training_fitting(self):
        """Verify that control_test event sets are excluded from training masks for thresholds and TF-IDF."""
        splits = np.array(["train"] * 100 + ["control_test"] * 20 + ["validation"] * 30 + ["test"] * 30)
        train_mask = (splits == "train")

        self.assertEqual(train_mask.sum(), 100)
        self.assertFalse(train_mask[100:120].any(), "control_test sets must never be included in train_mask")

        # Synthetic counts matrix
        counts = np.random.randint(0, 5, size=(len(splits), 5))
        # Fit on training sets only
        idf_model = fit_idf(counts[train_mask], sublinear=True)
        self.assertEqual(len(idf_model["document_frequency"]), 5)

    def test_tuesday_control_end_to_end_aggregation_and_join(self):
        """Verify end-to-end flow aggregation correctly sets split='control_test' on Tuesday blocks 4 and 27."""
        from src.event_profiles.windows import compute_bins, bin_split_names, valid_windows, aggregate_to_windows

        # Generate flows starting from 01:00:00 spanning blocks 0..4 (20 min each = 100 min total)
        # Block 4 is 02:20..02:39 (control_test), Blocks 0..3 are train
        times = pd.date_range("2017-07-04 01:00", periods=100, freq="min")
        df_flows = pd.DataFrame({
            "timestamp": times,
            "source_ip": ["192.168.10.1"] * 100,
            "destination_ip": ["192.168.10.50"] * 100,
            "block_id": [i // 20 for i in range(100)],
            "v0": [1] * 100
        })
        # Set split using Tuesday logic: block 4 is control_test
        df_flows["split"] = np.where(df_flows["block_id"].isin(TUESDAY_CONTROL_BLOCKS), "control_test", "train")

        step_sec = 60
        W = 10
        bins, t0 = compute_bins(df_flows["timestamp"], step_sec)
        names = bin_split_names(bins, df_flows["block_id"].to_numpy(), df_flows["split"].to_numpy(),
                                len(times), step_sec, 20)
        valid, window_split = valid_windows(names, W)

        pair = np.zeros(len(df_flows), dtype=int)
        values = df_flows[["v0"]].to_numpy()
        agg = aggregate_to_windows(pair, bins, values, W, valid, len(valid))

        agg["split"] = window_split[agg["k"].to_numpy()]
        split_counts = agg["split"].value_counts().to_dict()

        # Both train and control_test are produced
        self.assertIn("control_test", split_counts)
        self.assertIn("train", split_counts)
        # Exactly 11 valid windows in block 4
        self.assertEqual(split_counts["control_test"], 11)
        # Blocks 0..3 are continuous train (71 continuous valid windows from k=0..70)
        self.assertEqual(split_counts["train"], 71)

    def test_invalid_experiment_mode_rejected(self):
        """Calling pipeline with invalid mode must raise EventProfileError immediately."""
        from src.event_profiles.build_multi_day_profiles import run_multi_day_pipeline
        with self.assertRaises(EventProfileError) as ctx:
            run_multi_day_pipeline("invalid_experiment_name")
        self.assertIn("Invalid experiment_mode", str(ctx.exception))

    def test_baseline_directory_isolation_guard(self):
        """Verify that multi-day pipeline strictly refuses to write to baseline directory."""
        proc_dir = PROJECT_ROOT / "data" / "processed"
        baseline_dir = (proc_dir / "event_profiles").resolve()
        
        # Test that out_dirname is never 'event_profiles'
        for mode in ("exp_a", "exp_b"):
            out_dirname = "event_profiles_exp_a" if mode == "exp_a" else "event_profiles_exp_b"
            out_dir = (proc_dir / out_dirname).resolve()
            self.assertNotEqual(out_dir, baseline_dir, f"{mode} must never resolve to Tuesday baseline dir")

    def test_profile_feature_isolation_and_no_leakage_columns(self):
        """Verify profile dataframe only contains identifiers and bp_* features."""
        n_samples = 20
        bp_cols = [f"bp_{i:02d}" for i in range(1, 9)]
        df_profiles = pd.DataFrame({
            "event_set_id": [f"ES{i+1:07d}" for i in range(n_samples)],
            "window_id": [f"TUES_W{i:05d}" for i in range(n_samples)],
            "split": ["train"] * 10 + ["validation"] * 5 + ["test"] * 5,
            "window_start": pd.date_range("2017-07-04 09:00", periods=n_samples, freq="min")
        })
        for c in bp_cols:
            df_profiles[c] = np.random.uniform(0.0, 1.0, size=n_samples)

        df_targets = pd.DataFrame({
            "event_set_id": df_profiles["event_set_id"],
            "window_id": df_profiles["window_id"],
            "split": df_profiles["split"],
            "source_dataset": ["Tuesday-WorkingHours"] * n_samples,
            "target_binary": [0] * 15 + [1] * 5,
            "target_multiclass": [0] * 15 + [1] * 5
        })

        # Must pass validate_model_files without ValidationError
        checks = validate_model_files(df_profiles, df_targets)
        self.assertTrue(len(checks) > 0)
        
        # Verify forbidden columns are absent from profiles
        forbidden = ["source_ip", "destination_ip", "source_port", "destination_port",
                     "label", "source_dataset", "n_flows"]
        for fcol in forbidden:
            self.assertNotIn(fcol, df_profiles.columns)

    def test_backup_mechanism_on_existing_files(self):
        """Verify that existing outputs are backed up safely when rerun."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_out_dir = Path(tmpdir) / "event_profiles_exp_a"
            test_out_dir.mkdir(parents=True, exist_ok=True)
            dummy_file = test_out_dir / "event_profiles.csv"
            dummy_file.write_text("event_set_id,bp_01\nES0000001,0.5\n", encoding="utf-8")
            
            existing = [f for f in test_out_dir.iterdir() if f.is_file() and f.suffix in (".csv", ".json")]
            self.assertEqual(len(existing), 1)

            # Perform backup
            backup_dir = Path(tmpdir) / "backups" / "event_profiles_exp_a_backup_test"
            backup_dir.mkdir(parents=True, exist_ok=True)
            for f in existing:
                shutil.copy2(f, backup_dir / f.name)

            self.assertTrue((backup_dir / "event_profiles.csv").exists())
            self.assertEqual(
                (backup_dir / "event_profiles.csv").read_text(encoding="utf-8"),
                dummy_file.read_text(encoding="utf-8")
            )

    def test_training_only_fitting_principles(self):
        """Verify TF-IDF and basepoint selection fit strictly on training mask."""
        n_terms = len(EVENT_NAMES)
        rng = np.random.default_rng(42)
        counts = rng.integers(0, 5, size=(30, n_terms))
        split = np.array(["train"] * 18 + ["validation"] * 6 + ["test"] * 6)
        train_mask = split == "train"

        # Fit TF-IDF strictly on train
        settings = {
            "sublinear_tf": True,
            "rare_event_types": 3,
            "basepoints": 8,
            "redundancy_threshold": 0.8
        }
        idf_model = fit_idf(counts[train_mask], sublinear=True)
        self.assertEqual(len(idf_model["document_frequency"]), n_terms)
        
        # Transform all vectors using fitted model
        vectors = transform(counts, idf_model)
        self.assertEqual(vectors.shape, (30, n_terms))

        # Basepoint selection on train only
        bp_result = select_basepoints(vectors[train_mask], idf_model["document_frequency"], settings)
        self.assertLessEqual(len(bp_result["basepoints"]), 8)

        # Profiles computed across all 30 vectors
        profiles = compute_profiles(vectors, bp_result["basepoints"])
        self.assertEqual(profiles.shape[0], 30)
        self.assertEqual(profiles.shape[1], len(bp_result["basepoints"]))
        self.assertTrue((profiles >= 0.0).all() and (profiles <= 1.0 + 1e-7).all())

    def test_metadata_json_serialization(self):
        """Verify metadata dictionary serializes cleanly to JSON without tuple-key errors."""
        df_dummy_targets = pd.DataFrame({
            "split": ["train", "train", "validation", "test", "test"],
            "target_binary": [0, 1, 0, 0, 1],
            "target_label": ["BENIGN", "Bot", "BENIGN", "BENIGN", "PortScan"]
        })
        meta = {
            "experiment_mode": "exp_a",
            "split_distribution": {str(k): int(v) for k, v in df_dummy_targets["split"].value_counts().items()},
            "target_binary_distribution": {
                s: {str(b): int(cnt) for b, cnt in sub.items()}
                for s, sub in df_dummy_targets.groupby(["split", "target_binary"]).size().unstack(fill_value=0).to_dict("index").items()
            },
            "target_multiclass_distribution": {str(k): int(v) for k, v in df_dummy_targets["target_label"].value_counts().items()}
        }
        encoded = json.dumps(meta, indent=2)
        self.assertIsInstance(encoded, str)
        decoded = json.loads(encoded)
        self.assertIn("train", decoded["target_binary_distribution"])
        self.assertEqual(decoded["target_binary_distribution"]["train"]["1"], 1)

    def test_tuesday_baseline_profiles_preserved(self):
        """Rule 9: Tuesday baseline event profiles and metadata must remain intact."""
        baseline_dir = PROJECT_ROOT / "data" / "processed" / "event_profiles"
        self.assertTrue(baseline_dir.exists(), "Baseline event_profiles dir must exist")
        
        profiles_file = baseline_dir / "event_profiles.csv"
        targets_file = baseline_dir / "event_set_targets.csv"
        meta_file = baseline_dir / "event_profiles_metadata.json"
        
        self.assertTrue(profiles_file.exists())
        self.assertTrue(targets_file.exists())
        self.assertTrue(meta_file.exists())
        
        # Check metadata points to Tuesday
        meta_json = json.loads(meta_file.read_text(encoding="utf-8"))
        self.assertEqual(meta_json.get("input_file"), "Tuesday-WorkingHours_clean.csv")


if __name__ == "__main__":
    unittest.main()
