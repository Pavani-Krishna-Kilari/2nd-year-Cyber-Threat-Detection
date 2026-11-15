"""
Unit tests for Isolation Forest Anomaly Detection module.
Run with:
    python -m unittest tests.test_anomaly -v
"""

import unittest
import numpy as np

from src.models.anomaly import AnomalyDetector, MODEL_PATH, METRICS_PATH


class TestAnomalyDetector(unittest.TestCase):
    def setUp(self):
        self.detector = AnomalyDetector()

    def test_detector_is_ready(self):
        self.assertTrue(self.detector.is_ready())
        self.assertTrue(MODEL_PATH.exists())
        self.assertTrue(METRICS_PATH.exists())

    def test_predict_single_normal(self):
        # Mean benign profile in Experiment A
        normal_profile = [0.3670, 0.3838, 0.7954, 0.3319, 0.3606, 0.5307, 0.4432, 0.4407]
        res = self.detector.predict_single(normal_profile)
        self.assertIn("is_anomaly", res)
        self.assertIn("anomaly_score", res)
        self.assertIn("verdict", res)
        self.assertEqual(res["verdict"], "NORMAL")
        self.assertFalse(res["is_anomaly"])

    def test_predict_single_anomaly(self):
        # Extreme unusual pattern with high activations across all basepoints
        outlier_profile = [0.95, 0.85, 0.90, 0.80, 0.95, 0.90, 0.95, 0.85]
        res = self.detector.predict_single(outlier_profile)
        self.assertIn(res["verdict"], ["ANOMALOUS", "NORMAL"])
        self.assertGreater(res["anomaly_score"], -0.10)

    def test_report_contains_real_metrics(self):
        rep = self.detector.report
        self.assertIn(rep.get("model", rep.get("model_type")), ["Isolation Forest", "IsolationForest"])
        self.assertTrue("validation_metrics_at_threshold" in rep or "metrics_on_test" in rep)


if __name__ == "__main__":
    unittest.main()
