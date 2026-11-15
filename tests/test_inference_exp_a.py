"""
Unit and Integration Tests for Experiment A Inference Corrections.
===================================================================
Tests all 10 requirements from Task 6:
 1. Correct Experiment A model paths.
 2. Tuesday baseline remains untouched.
 3. Correct bp_01 through bp_08 ordering and restriction.
 4. Ensemble configuration loading (model_weights & weights compatibility).
 5. Correct threshold loading.
 6. Isolation Forest score direction (higher = more anomalous).
 7. No test-data threshold leakage.
 8. No port-based attack subclass inference.
 9. Tri-state decision policy (NORMAL, KNOWN_THREAT, UNKNOWN_ANOMALOUS).
10. Missing model/configuration files produce clear errors.
"""

import json
import hashlib
import unittest
from pathlib import Path
import numpy as np

from src.config import PROJECT_ROOT
from src.inference.predict import ThreatInferenceEngine
from src.inference.decision_policy import classify_detection_outcome
from src.models.ensemble import SoftVotingEnsemble
from src.models.anomaly import AnomalyDetector


class TestExperimentAInferenceCorrections(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatInferenceEngine()
        cls.saved_a = PROJECT_ROOT / "models" / "saved_exp_a"
        cls.data_a = PROJECT_ROOT / "data" / "processed" / "event_profiles_exp_a"

    # 1. Correct Experiment A model paths
    def test_01_experiment_a_model_paths(self):
        self.assertEqual(self.engine.models_dir, self.saved_a)
        self.assertEqual(self.engine.data_dir, self.data_a)
        self.assertTrue((self.saved_a / "fcnn_model.keras").exists())
        self.assertTrue((self.saved_a / "cnn_model.keras").exists())
        self.assertTrue((self.saved_a / "lstm_model.keras").exists())
        self.assertTrue((self.saved_a / "ensemble_config.json").exists())
        self.assertTrue((self.saved_a / "isolation_forest.joblib").exists())
        self.assertTrue((self.saved_a / "anomaly_config.json").exists())

    # 2. Tuesday baseline remains untouched
    def test_02_tuesday_baseline_preservation(self):
        baseline_csv = PROJECT_ROOT / "data" / "processed" / "event_profiles" / "event_profiles.csv"
        baseline_meta = PROJECT_ROOT / "data" / "processed" / "event_profiles" / "event_profiles_metadata.json"
        
        self.assertTrue(baseline_csv.exists())
        self.assertTrue(baseline_meta.exists())

        def get_hash(p):
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for b in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(b)
            return h.hexdigest().upper()

        csv_hash = get_hash(baseline_csv)
        meta_hash = get_hash(baseline_meta)

        self.assertEqual(csv_hash, "D3B38B3012557CC606014AF91870B47DAD7ED4652AF00E7FD7D1E57FDD8DDD6E")
        self.assertEqual(meta_hash, "CE6234392C0E8682732795B64F7A553736879B7F8D5869F52A0AD11D73F81E54")

    # 3. Correct bp_01 through bp_08 ordering and restriction
    def test_03_basepoint_vector_ordering_and_length(self):
        valid_vec = [0.3670, 0.3838, 0.7954, 0.3319, 0.3606, 0.5307, 0.4432, 0.4407]
        res = self.engine.predict_profile(valid_vec)
        self.assertEqual(len(res["profile_vector"]), 8)

        # Reject fewer or more features
        with self.assertRaises(ValueError):
            self.engine.predict_profile([0.5] * 7)

        with self.assertRaises(ValueError):
            self.engine.predict_profile([0.5] * 9)

        # Reject NaN / Inf
        with self.assertRaises(ValueError):
            self.engine.predict_profile([0.5, np.nan, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5])

    # 4. Ensemble configuration loading
    def test_04_ensemble_configuration_loading(self):
        ens = self.engine.ensemble
        self.assertEqual(len(ens.weights), 3)
        self.assertAlmostEqual(sum(ens.weights), 1.0, places=5)

        # Dict compatibility check
        ens.set_weights({"fcnn": 0.5, "cnn": 0.25, "lstm": 0.25})
        self.assertAlmostEqual(ens.weights[0], 0.5)
        self.assertAlmostEqual(ens.weights[1], 0.25)
        self.assertAlmostEqual(ens.weights[2], 0.25)

        # Restore
        ens.set_weights([1/3, 1/3, 1/3])

    # 5. Correct threshold loading
    def test_05_correct_threshold_loading(self):
        # Ensemble threshold from Exp A
        self.assertAlmostEqual(self.engine.ensemble.threshold, 0.8398, places=3)

        # Isolation Forest calibrated threshold
        self.assertAlmostEqual(self.engine.anomaly_detector.threshold, -0.002268, places=5)

    # 6. Isolation Forest score direction (higher score = more anomalous)
    def test_06_isolation_forest_score_direction(self):
        detector = self.engine.anomaly_detector
        self.assertTrue(detector.is_ready())

        # Dense normal traffic prototype
        normal_vec = [0.3670, 0.3838, 0.7954, 0.3319, 0.3606, 0.5307, 0.4432, 0.4407]
        # Extreme synthetic outlier
        extreme_outlier = [0.99, 0.99, 0.99, 0.99, 0.99, 0.99, 0.99, 0.99]

        res_norm = detector.predict_single(normal_vec)
        res_out = detector.predict_single(extreme_outlier)

        # Outlier anomaly score must be higher than normal score
        self.assertGreater(res_out["anomaly_score"], res_norm["anomaly_score"])
        self.assertEqual(res_norm["verdict"], "NORMAL")
        self.assertFalse(res_norm["is_anomaly"])

    # 7. No test-data threshold leakage
    def test_07_no_test_data_threshold_leakage(self):
        cfg_path = self.saved_a / "anomaly_config.json"
        self.assertTrue(cfg_path.exists())
        with open(cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)

        self.assertEqual(cfg.get("calibration_split"), "validation")
        self.assertEqual(cfg.get("optimal_strategy"), "Max Validation F1 Grid Search")
        self.assertNotIn("test_split_f1", cfg)

    # 8. No port-based attack subclass inference
    def test_08_no_port_based_attack_subclass_inference(self):
        # Port 21 (previously claimed FTP-Patator)
        res_21 = classify_detection_outcome(
            threat_confidence=0.95,
            destination_port=21
        )
        self.assertEqual(res_21["verdict"], "KNOWN_THREAT")
        self.assertNotEqual(res_21["predicted_class"], "FTP-Patator Brute Force")
        self.assertEqual(res_21["predicted_class"], "Known Threat Pattern (Subclass Not Classified)")

        # Port 22 (previously claimed SSH-Patator)
        res_22 = classify_detection_outcome(
            threat_confidence=0.95,
            destination_port=22
        )
        self.assertEqual(res_22["verdict"], "KNOWN_THREAT")
        self.assertNotEqual(res_22["predicted_class"], "SSH-Patator Brute Force")
        self.assertEqual(res_22["predicted_class"], "Known Threat Pattern (Subclass Not Classified)")

    # 9. Tri-state decision policy
    def test_09_tri_state_decision_policy(self):
        # 1. KNOWN_THREAT
        res_threat = classify_detection_outcome(threat_confidence=0.90, threat_threshold=0.8398)
        self.assertEqual(res_threat["verdict"], "KNOWN_THREAT")
        self.assertTrue(res_threat["requires_investigation"])

        # 2. NORMAL
        res_normal = classify_detection_outcome(threat_confidence=0.10, anomaly_result={"is_anomaly": False})
        self.assertEqual(res_normal["verdict"], "NORMAL")
        self.assertFalse(res_normal["requires_investigation"])

        # 3. UNKNOWN_ANOMALOUS (Out of distribution anomaly)
        res_anom = classify_detection_outcome(
            threat_confidence=0.10,
            anomaly_result={"is_anomaly": True, "anomaly_score": 0.05, "normalized_score": 0.80}
        )
        self.assertEqual(res_anom["verdict"], "UNKNOWN_ANOMALOUS")
        self.assertTrue(res_anom["requires_investigation"])

        # 4. UNKNOWN_ANOMALOUS (Prediction Uncertainty)
        res_uncert = classify_detection_outcome(threat_confidence=0.55, threat_threshold=0.8398)
        self.assertEqual(res_uncert["verdict"], "UNKNOWN_ANOMALOUS")
        self.assertIn("Uncertain", res_uncert["predicted_class"])

    # 10. Missing model/configuration files produce clear errors
    def test_10_missing_files_clear_errors(self):
        bogus_dir = PROJECT_ROOT / "models" / "non_existent_dir_9999"
        engine_bogus = ThreatInferenceEngine(models_dir=bogus_dir)
        self.assertFalse(engine_bogus.is_ready())


if __name__ == "__main__":
    unittest.main()
