"""
Unit tests for Experiment A Model Training, Architecture Safeguards, and Evaluation.
Verifies:
  - Input column restrictions (strictly bp_01 through bp_08).
  - Class weighting calculation for extreme imbalance.
  - Split isolation and zero-leakage threshold calibration.
  - Output directory isolation (models/saved_exp_a/ and models/metrics_exp_a/).
  - Proper handling of zero-support attack classes.
"""

import os
import json
import shutil
import tempfile
import unittest
import numpy as np
import pandas as pd

from src.config import PROJECT_ROOT
from src.models.train_exp_a import (
    calculate_class_weights,
    find_optimal_threshold,
    compute_comprehensive_metrics,
    PROFILE_COLS,
    SAVED_DIR_EXP_A,
    METRICS_DIR_EXP_A
)


class TestExperimentAModelSafeguards(unittest.TestCase):

    def test_feature_input_column_restrictions(self):
        """Verify model feature inputs contain strictly bp_01 to bp_08."""
        self.assertEqual(len(PROFILE_COLS), 8)
        self.assertEqual(PROFILE_COLS, [f"bp_{i:02d}" for i in range(1, 9)])
        
        forbidden = ["source_ip", "destination_ip", "source_port", "destination_port",
                     "timestamp", "flow_id", "label", "target_binary", "target_multiclass"]
        for col in forbidden:
            self.assertNotIn(col, PROFILE_COLS)

    def test_class_weighting_calculation(self):
        """Verify balanced inverse frequency class weighting formula."""
        # 1000 total samples: 999 normal (0), 1 attack (1)
        y = np.array([0] * 999 + [1], dtype=np.int8)
        weights = calculate_class_weights(y)
        
        # w0 = 1000 / (2 * 999) = 0.5005005
        # w1 = 1000 / (2 * 1) = 500.0
        self.assertAlmostEqual(weights[0], 1000.0 / (2.0 * 999.0), places=5)
        self.assertAlmostEqual(weights[1], 500.0, places=5)
        self.assertGreater(weights[1], weights[0] * 900)

    def test_optimal_threshold_tuning_on_validation_only(self):
        """Verify threshold tuning optimizes F1 on validation probabilities."""
        y_val = np.array([0, 0, 0, 0, 1, 1], dtype=np.int8)
        val_proba = np.array([0.1, 0.2, 0.3, 0.4, 0.7, 0.8], dtype=np.float32)
        
        best_thresh, best_f1 = find_optimal_threshold(y_val, val_proba)
        self.assertGreaterEqual(best_f1, 0.99)
        self.assertTrue(0.4 <= best_thresh <= 0.7)

    def test_output_directory_isolation(self):
        """Verify Experiment A model paths do not point to baseline models/saved/."""
        baseline_saved = (PROJECT_ROOT / "models" / "saved").resolve()
        baseline_metrics = (PROJECT_ROOT / "models" / "metrics").resolve()
        
        exp_a_saved = SAVED_DIR_EXP_A.resolve()
        exp_a_metrics = METRICS_DIR_EXP_A.resolve()
        
        self.assertNotEqual(exp_a_saved, baseline_saved)
        self.assertNotEqual(exp_a_metrics, baseline_metrics)
        self.assertIn("exp_a", str(exp_a_saved))
        self.assertIn("exp_a", str(exp_a_metrics))

    def test_per_class_support_handling_for_zero_classes(self):
        """Verify classes with zero support are marked UNTESTED_IN_SPLIT and N/A."""
        y_true = np.array([0, 0, 0, 1, 1], dtype=np.int8)
        y_proba = np.array([0.1, 0.2, 0.3, 0.8, 0.9], dtype=np.float32)
        labels = np.array(["BENIGN", "BENIGN", "BENIGN", "Bot", "SSH-Patator"])
        
        metrics = compute_comprehensive_metrics(y_true, y_proba, threshold=0.5, labels_true=labels)
        support = metrics["per_class_support"]
        
        # Evaluated classes
        self.assertEqual(support["BENIGN"]["status"], "EVALUATED")
        self.assertEqual(support["BENIGN"]["support"], 3)
        self.assertEqual(support["Bot"]["status"], "EVALUATED")
        self.assertEqual(support["Bot"]["support"], 1)
        self.assertEqual(support["SSH-Patator"]["status"], "EVALUATED")
        self.assertEqual(support["SSH-Patator"]["support"], 1)
        
        # Zero-support classes (e.g. DDoS, Heartbleed)
        self.assertEqual(support["DDoS"]["status"], "UNTESTED_IN_SPLIT")
        self.assertEqual(support["DDoS"]["support"], 0)
        self.assertEqual(support["DDoS"]["recall"], "N/A (0 test support)")
        self.assertEqual(support["Heartbleed"]["status"], "UNTESTED_IN_SPLIT")
        self.assertEqual(support["Heartbleed"]["support"], 0)


if __name__ == "__main__":
    unittest.main()
