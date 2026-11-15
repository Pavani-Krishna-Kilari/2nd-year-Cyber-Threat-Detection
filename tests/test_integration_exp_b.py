"""
Integration Tests for Experiment B Backend Production Configuration.
Verifies Experiment B active state, directory resolution, calibrated thresholds,
strict tri-state decision hierarchy, metric separation (Friday unseen vs Tuesday control),
and database isolation.

Run with:
    python -m unittest tests.test_integration_exp_b -v
"""

import unittest
from pathlib import Path
from fastapi.testclient import TestClient

import backend.database
from backend.main import app
from backend.service import siem_service
from src.inference.decision_policy import (
    classify_detection_outcome,
    ANN_ALERT_THRESHOLD_EXP_B,
    DEFAULT_ANOMALY_THRESHOLD_EXP_B,
    FCNN_THRESHOLD_EXP_B,
    CNN_THRESHOLD_EXP_B,
    LSTM_THRESHOLD_EXP_B
)


class TestExperimentBIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Isolate database during testing to protect production detection history
        cls._orig_db_path = backend.database.DB_PATH
        cls._test_db_path = Path("data/test_detection_history_exp_b.db")
        backend.database.DB_PATH = cls._test_db_path
        backend.database.init_db()
        # Ensure Experiment B is active
        siem_service.set_experiment("B")
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        backend.database.DB_PATH = cls._orig_db_path
        if cls._test_db_path.exists():
            try:
                cls._test_db_path.unlink()
            except Exception:
                pass

    def test_01_exp_b_production_selection(self):
        """Verify active production experiment is strictly Experiment B."""
        self.assertEqual(siem_service.experiment_id, "B")
        status = siem_service.get_system_status()
        self.assertEqual(status["experiment_id"], "B")
        self.assertIn("Experiment B", status["active_experiment"])
        self.assertEqual(status["status"], "OPERATIONAL")

    def test_02_exp_b_model_and_profile_directories(self):
        """Verify models, profiles, and metrics directories resolve strictly to Exp B paths."""
        self.assertTrue(str(siem_service.models_dir).endswith("models\\saved_exp_b") or str(siem_service.models_dir).endswith("models/saved_exp_b"))
        self.assertTrue(str(siem_service.data_dir).endswith("event_profiles_exp_b"))
        self.assertTrue(str(siem_service.metrics_dir).endswith("metrics_exp_b"))

        status = siem_service.get_system_status()
        self.assertTrue(status["models_loaded"]["fcnn"])
        self.assertTrue(status["models_loaded"]["cnn"])
        self.assertTrue(status["models_loaded"]["lstm"])
        self.assertTrue(status["models_loaded"]["ensemble"])
        self.assertTrue(status["models_loaded"]["isolation_forest"])
        self.assertTrue(status["artifacts_loaded"]["basepoints"])
        self.assertTrue(status["artifacts_loaded"]["tfidf_model"])
        self.assertTrue(status["artifacts_loaded"]["thresholds"])

    def test_03_exp_b_calibrated_thresholds(self):
        """Verify calibrated ensemble, anomaly, and submodel thresholds match Experiment B."""
        status = siem_service.get_system_status()
        self.assertAlmostEqual(status["ensemble_config"]["threshold"], ANN_ALERT_THRESHOLD_EXP_B, places=5)
        self.assertAlmostEqual(status["ensemble_config"]["threshold"], 0.656122, places=4)

        sub_th = status["submodel_thresholds"]
        self.assertAlmostEqual(sub_th["fcnn"], FCNN_THRESHOLD_EXP_B, places=4)
        self.assertAlmostEqual(sub_th["cnn"], CNN_THRESHOLD_EXP_B, places=4)
        self.assertAlmostEqual(sub_th["lstm"], LSTM_THRESHOLD_EXP_B, places=4)

        self.assertAlmostEqual(siem_service.anomaly_detector.threshold, DEFAULT_ANOMALY_THRESHOLD_EXP_B, places=5)

    def test_04_ann_alert_priority_over_anomaly(self):
        """Priority 1: When ensemble threat prob >= 0.6561, verdict must be KNOWN_THREAT regardless of anomaly."""
        res = classify_detection_outcome(
            threat_confidence=0.75,
            anomaly_result={"is_anomaly": True, "anomaly_score": 0.05, "normalized_score": 0.90},
            dominant_basepoint="bp_03",
            threat_threshold=0.656122,
            anomaly_threshold=-0.012676,
            experiment_id="B"
        )
        self.assertEqual(res["verdict"], "KNOWN_THREAT")
        self.assertEqual(res["prediction_status"], "KNOWN_THREAT")
        self.assertIn("ANN Threat Alert", res["predicted_class"])
        self.assertTrue(res["requires_investigation"])

    def test_05_unknown_anomalous_when_ann_below_threshold(self):
        """Priority 2: When ensemble threat prob < 0.6561 but Isolation Forest detects anomaly, verdict is UNKNOWN_ANOMALOUS."""
        res = classify_detection_outcome(
            threat_confidence=0.25,
            anomaly_result={"is_anomaly": True, "anomaly_score": 0.02, "normalized_score": 0.75},
            dominant_basepoint="bp_01",
            threat_threshold=0.656122,
            anomaly_threshold=-0.012676,
            experiment_id="B"
        )
        self.assertEqual(res["verdict"], "UNKNOWN_ANOMALOUS")
        self.assertEqual(res["prediction_status"], "UNKNOWN_ANOMALOUS")
        self.assertIn("Unknown / Out-of-Distribution Anomaly", res["predicted_class"])
        self.assertTrue(res["requires_investigation"])

    def test_06_normal_when_neither_detects_issue(self):
        """Priority 3: When ensemble threat prob < 0.6561 and anomaly score < -0.012676, verdict is NORMAL."""
        res = classify_detection_outcome(
            threat_confidence=0.10,
            anomaly_result={"is_anomaly": False, "anomaly_score": -0.03, "normalized_score": 0.20},
            dominant_basepoint="bp_01",
            threat_threshold=0.656122,
            anomaly_threshold=-0.012676,
            experiment_id="B"
        )
        self.assertEqual(res["verdict"], "NORMAL")
        self.assertEqual(res["prediction_status"], "NORMAL")
        self.assertEqual(res["predicted_class"], "Benign Network Traffic")
        self.assertFalse(res["requires_investigation"])

    def test_07_separate_friday_unseen_and_tuesday_control_metrics(self):
        """Verify get_model_benchmarks() returns separate Friday unseen and Tuesday control evaluations."""
        benchmarks = siem_service.get_model_benchmarks()
        self.assertEqual(benchmarks["experiment_id"], "B")
        self.assertIn("evaluation_a_unseen", benchmarks)
        self.assertIn("evaluation_b_control", benchmarks)

        unseen = benchmarks["evaluation_a_unseen"]
        control = benchmarks["evaluation_b_control"]

        self.assertEqual(unseen.get("total_samples"), 569099)
        self.assertEqual(unseen.get("attack_types_tested"), ["Bot", "PortScan", "DDoS"])

        self.assertEqual(control.get("total_samples"), 42189)
        self.assertEqual(set(control.get("attack_types_tested", [])), {"FTP-Patator", "SSH-Patator"})

    def test_08_anomaly_overview_exp_b_no_exp_a_fallback(self):
        """Verify get_anomaly_overview() returns real Exp B metrics without Exp A fallback values."""
        overview = siem_service.get_anomaly_overview()
        self.assertEqual(overview["experiment_id"], "B")
        self.assertTrue(overview["is_ready"])
        self.assertEqual(overview["training_samples"], 1997246)
        self.assertEqual(overview["validation_samples"], 625223)
        self.assertEqual(overview["control_test_samples"], 42189)
        self.assertEqual(overview["test_samples"], 569099)
        self.assertAlmostEqual(overview["optimal_threshold"], -0.012676391259280995, places=5)
        self.assertEqual(overview["nominal_fpr_budget"], 0.01)

        # Confirm Friday unseen and Tuesday control metrics are both present
        self.assertIn("metrics_on_test", overview)
        self.assertIn("metrics_on_control", overview)
        self.assertEqual(overview["metrics_on_test"]["confusion_matrix"]["tp"], 74)
        self.assertEqual(overview["metrics_on_control"]["confusion_matrix"]["tp"], 10)

    def test_09_api_endpoints_operation_under_exp_b(self):
        """Verify REST API endpoints function cleanly with Exp B active."""
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["experiment_id"], "B")

        resp_anom = self.client.get("/api/anomaly/overview")
        self.assertEqual(resp_anom.status_code, 200)
        anom_data = resp_anom.json()
        self.assertEqual(anom_data["experiment_id"], "B")
        self.assertEqual(anom_data["test_samples"], 569099)

        resp_bm = self.client.get("/api/models/benchmarks")
        self.assertEqual(resp_bm.status_code, 200)
        bm_data = resp_bm.json()
        self.assertEqual(bm_data["experiment_id"], "B")
        self.assertEqual(bm_data["evaluation_a_unseen"]["total_samples"], 569099)


if __name__ == "__main__":
    unittest.main()
