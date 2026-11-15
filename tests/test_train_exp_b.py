"""
Unit Tests for Experiment B Model Training Pipeline
===================================================
Tests safety guards, four-way partition loading, feature isolation,
threshold calibration isolation, output path protection, and baseline preservation.
"""

import os
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from src.config import PROJECT_ROOT
from src.event_profiles.validation import PROFILE_ID_COLUMNS
from src.models.train_exp_b import (
    PROFILE_COLS,
    SAVED_DIR_EXP_B,
    METRICS_DIR_EXP_B,
    BASELINE_SAVED_DIR,
    EXP_A_SAVED_DIR,
    BASELINE_PROCESSED_DIR,
    EXP_A_PROCESSED_DIR,
    load_exp_b_datasets,
    calculate_class_weights,
    calibrate_isolation_forest_threshold,
    find_optimal_threshold,
    compute_tri_state_verdicts,
    build_fcnn,
    build_cnn,
    build_lstm,
    sha256_of
)


class TestTrainExpBSafety(unittest.TestCase):
    """Verifies isolation safeguards and directory protection for Experiment B."""

    def test_output_path_isolation(self):
        """Rule 5: Experiment B outputs must strictly target models/saved_exp_b and metrics_exp_b."""
        self.assertEqual(SAVED_DIR_EXP_B.name, "saved_exp_b")
        self.assertEqual(METRICS_DIR_EXP_B.name, "metrics_exp_b")

        # Must never collide with baseline or Exp A paths
        self.assertNotEqual(SAVED_DIR_EXP_B.resolve(), BASELINE_SAVED_DIR.resolve())
        self.assertNotEqual(SAVED_DIR_EXP_B.resolve(), EXP_A_SAVED_DIR.resolve())
        self.assertNotEqual(METRICS_DIR_EXP_B.resolve(), (PROJECT_ROOT / "models" / "metrics_exp_a").resolve())

    def test_experiment_a_and_baseline_models_protected(self):
        """Rule 4: Baseline and Experiment A models must remain intact."""
        # Baseline check
        base_fcnn = BASELINE_SAVED_DIR / "fcnn_model.keras"
        self.assertTrue(base_fcnn.exists(), "Tuesday baseline fcnn_model.keras must exist")

        # Exp A check
        exp_a_fcnn = EXP_A_SAVED_DIR / "fcnn_model.keras"
        self.assertTrue(exp_a_fcnn.exists(), "Experiment A fcnn_model.keras must exist")

        exp_a_ens = EXP_A_SAVED_DIR / "ensemble_config.json"
        self.assertTrue(exp_a_ens.exists(), "Experiment A ensemble_config.json must exist")

        exp_a_iso = EXP_A_SAVED_DIR / "isolation_forest.joblib"
        self.assertTrue(exp_a_iso.exists(), "Experiment A isolation_forest.joblib must exist")

    def test_profile_feature_column_isolation(self):
        """Rule G: Model inputs must contain only bp_01 through bp_08 (no forbidden fields)."""
        self.assertEqual(len(PROFILE_COLS), 8)
        expected = [f"bp_{i:02d}" for i in range(1, 9)]
        self.assertEqual(PROFILE_COLS, expected)

        forbidden_names = [
            "source_ip", "destination_ip", "source_port", "destination_port",
            "label", "flow_duration", "n_flows", "split"
        ]
        for f in forbidden_names:
            self.assertNotIn(f, PROFILE_COLS)

    def test_class_weights_calculation_formula(self):
        """Rule C: Class weights must be calculated solely from training labels using w_j = N / (2 * N_j)."""
        # Synthetic binary vector: 1000 total, 10 attacks, 990 benign
        y_train = np.array([1] * 10 + [0] * 990, dtype=np.int8)
        weights = calculate_class_weights(y_train)

        expected_w0 = 1000.0 / (2.0 * 990.0)
        expected_w1 = 1000.0 / (2.0 * 10.0)

        self.assertAlmostEqual(weights[0], expected_w0, places=5)
        self.assertAlmostEqual(weights[1], expected_w1, places=5)
        self.assertGreater(weights[1], weights[0])
        self.assertEqual(weights[1], 50.0)


class TestTrainExpBPartitionLoading(unittest.TestCase):
    """Verifies four-way partition loading and leakage guards."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.in_dir = Path(self.tmpdir.name)

        # Create dummy 4-way partition dataset
        splits = ["train"] * 40 + ["validation"] * 20 + ["control_test"] * 10 + ["test"] * 10
        n_rows = len(splits)

        df_prof = pd.DataFrame({
            "event_set_id": [f"ES{i+1:07d}" for i in range(n_rows)],
            "window_id": [f"W{i:05d}" for i in range(n_rows)],
            "split": splits,
            "window_start": pd.date_range("2017-07-04", periods=n_rows, freq="min")
        })
        for c in PROFILE_COLS:
            df_prof[c] = np.random.uniform(0.0, 1.0, size=n_rows)

        df_tgt = pd.DataFrame({
            "event_set_id": df_prof["event_set_id"],
            "target_binary": [0] * 38 + [1] * 2 + [0] * 19 + [1] * 1 + [0] * 9 + [1] * 1 + [0] * 9 + [1] * 1,
            "target_multiclass": [0] * 38 + [7] * 2 + [0] * 19 + [9] * 1 + [0] * 9 + [11] * 1 + [0] * 9 + [1] * 1,
            "target_label": ["BENIGN"] * 38 + ["FTP-Patator"] * 2 + ["BENIGN"] * 19 + ["Infiltration"] * 1 +
                            ["BENIGN"] * 9 + ["SSH-Patator"] * 1 + ["BENIGN"] * 9 + ["Bot"] * 1
        })

        df_prof.to_csv(self.in_dir / "event_profiles.csv", index=False)
        df_tgt.to_csv(self.in_dir / "event_set_targets.csv", index=False)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_four_way_partition_loading_success(self):
        """Rule A: Loader must correctly partition into train, validation, control_test, and test."""
        X_dict, y_dict, y_mc_dict, labels_dict = load_exp_b_datasets(self.in_dir)

        # Verify all four partitions exist
        for s in ["train", "validation", "control_test", "test"]:
            self.assertIn(s, X_dict)
            self.assertIn(s, y_dict)
            self.assertIn(s, y_mc_dict)
            self.assertIn(s, labels_dict)

        # Verify shape & features
        self.assertEqual(X_dict["train"].shape, (40, 8))
        self.assertEqual(X_dict["validation"].shape, (20, 8))
        self.assertEqual(X_dict["control_test"].shape, (10, 8))
        self.assertEqual(X_dict["test"].shape, (10, 8))

        # Verify target distributions
        self.assertEqual(int(y_dict["train"].sum()), 2)
        self.assertEqual(int(y_dict["validation"].sum()), 1)
        self.assertEqual(int(y_dict["control_test"].sum()), 1)
        self.assertEqual(int(y_dict["test"].sum()), 1)

    def test_forbidden_columns_in_profiles_raises_error(self):
        """Rule G: If event_profiles.csv contains forbidden columns (e.g. IP, port), loader must raise ValueError."""
        prof_path = self.in_dir / "event_profiles.csv"
        df_bad = pd.read_csv(prof_path)
        df_bad["source_ip"] = "192.168.10.1"
        df_bad.to_csv(prof_path, index=False)

        with self.assertRaises(ValueError) as ctx:
            load_exp_b_datasets(self.in_dir)
        self.assertIn("Forbidden columns detected", str(ctx.exception))

    def test_missing_partition_raises_error(self):
        """If any of the 4 partitions is missing from data, loader must fail immediately."""
        prof_path = self.in_dir / "event_profiles.csv"
        df = pd.read_csv(prof_path)
        # Drop control_test partition
        df_missing = df[df["split"] != "control_test"]
        df_missing.to_csv(prof_path, index=False)

        with self.assertRaises(ValueError) as ctx:
            load_exp_b_datasets(self.in_dir)
        self.assertIn("Partition 'control_test' contains 0 event profiles", str(ctx.exception))


class TestTrainExpBModelLogic(unittest.TestCase):
    """Verifies threshold calibration, anomaly detector isolation, and tri-state logic."""

    def test_isolation_forest_calibration_strictly_on_benign_validation(self):
        """Rule E: Isolation Forest threshold must be calibrated on benign validation profiles only."""
        rng = np.random.default_rng(42)
        # 100 benign training vectors (centered at 0.2)
        X_train_benign = rng.normal(0.2, 0.05, size=(100, 8))
        iso = IsolationForest(n_estimators=50, random_state=42)
        iso.fit(X_train_benign)

        # 50 benign validation vectors (centered at 0.2)
        X_val_benign = rng.normal(0.2, 0.05, size=(50, 8))

        # Calibrate at 99th percentile
        thresh_99 = calibrate_isolation_forest_threshold(iso, X_val_benign, percentile=99.0)
        self.assertIsInstance(thresh_99, float)

        # Inverted score on benign validation
        scores = -iso.decision_function(X_val_benign)
        # Exactly 99th percentile of scores
        expected_p99 = float(np.percentile(scores, 99.0))
        self.assertEqual(thresh_99, expected_p99)

        # Anomalous test vector (centered at 0.8) should score higher than threshold
        X_test_outlier = rng.normal(0.8, 0.05, size=(5, 8))
        test_scores = -iso.decision_function(X_test_outlier)
        self.assertTrue((test_scores > thresh_99).all())

    def test_tri_state_verdicts_computation(self):
        """Verifies tri-state triage: KNOWN_THREAT, UNKNOWN_ANOMALOUS, and NORMAL."""
        # 5 test samples:
        # Sample 0: High ANN prob (0.9), Low Iso score (-0.1)  -> KNOWN_THREAT
        # Sample 1: Low ANN prob (0.1), High Iso score (0.2)   -> UNKNOWN_ANOMALOUS
        # Sample 2: Low ANN prob (0.1), Low Iso score (-0.1)   -> NORMAL
        # Sample 3: High ANN prob (0.8), High Iso score (0.2)  -> KNOWN_THREAT (ANN takes precedence)
        # Sample 4: Low ANN prob (0.05), Low Iso score (-0.2)  -> NORMAL
        ann_proba = np.array([0.90, 0.10, 0.10, 0.80, 0.05])
        iso_score = np.array([-0.10, 0.20, -0.10, 0.20, -0.20])
        y_true = np.array([1, 1, 0, 1, 0], dtype=np.int8)
        labels = np.array(["Bot", "Bot", "BENIGN", "PortScan", "BENIGN"])

        ann_th = 0.50
        iso_th = 0.05

        result = compute_tri_state_verdicts(ann_proba, ann_th, iso_score, iso_th, y_true, labels)

        self.assertEqual(result["triage_distribution"]["KNOWN_THREAT"], 2)
        self.assertEqual(result["triage_distribution"]["UNKNOWN_ANOMALOUS"], 1)
        self.assertEqual(result["triage_distribution"]["NORMAL"], 2)

        # Attacks: Sample 0 & 3 detected by ANN, Sample 1 captured by Isolation Forest, Sample 2 & 4 are benign
        self.assertEqual(result["attack_capture_breakdown"]["detected_by_ann"], 2)
        self.assertEqual(result["attack_capture_breakdown"]["captured_by_isolation"], 1)
        self.assertEqual(result["attack_capture_breakdown"]["missed_as_normal"], 0)
        self.assertEqual(result["combined_threat_detection_rate"], 1.0)


class TestActualExpBDatasetPartitionIntegrity(unittest.TestCase):
    """Verifies partition counts and target alignment against generated data on disk."""

    def test_actual_exp_b_targets_counts_match_specification(self):
        """Verifies actual generated target counts in data/processed/event_profiles_exp_b/."""
        tgt_csv = PROJECT_ROOT / "data" / "processed" / "event_profiles_exp_b" / "event_set_targets.csv"
        if not tgt_csv.exists():
            self.skipTest("event_set_targets.csv not found in event_profiles_exp_b")

        df = pd.read_csv(tgt_csv, usecols=["split", "target_binary", "target_label"])

        # Check total count
        self.assertEqual(len(df), 3234182)

        # Partition counts
        split_counts = df["split"].value_counts().to_dict()
        self.assertEqual(split_counts["train"], 1997495)
        self.assertEqual(split_counts["validation"], 625399)
        self.assertEqual(split_counts["control_test"], 42189)
        self.assertEqual(split_counts["test"], 569099)

        # Attack counts per partition
        attacks_per_split = df.groupby("split")["target_binary"].sum().to_dict()
        self.assertEqual(attacks_per_split["train"], 249)
        self.assertEqual(attacks_per_split["validation"], 176)
        self.assertEqual(attacks_per_split["control_test"], 22)
        self.assertEqual(attacks_per_split["test"], 1196)

        # Specific control attack classes
        ctrl_df = df[df["split"] == "control_test"]
        ctrl_attacks = ctrl_df[ctrl_df["target_binary"] == 1]["target_label"].value_counts().to_dict()
        self.assertEqual(ctrl_attacks.get("SSH-Patator"), 11)
        self.assertEqual(ctrl_attacks.get("FTP-Patator"), 11)

        # Specific Friday test attack classes (unseen)
        test_df = df[df["split"] == "test"]
        test_attacks = test_df[test_df["target_binary"] == 1]["target_label"].value_counts().to_dict()
        self.assertEqual(test_attacks.get("Bot"), 1080)
        self.assertEqual(test_attacks.get("PortScan"), 76)
        self.assertEqual(test_attacks.get("DDoS"), 40)


if __name__ == "__main__":
    unittest.main()
