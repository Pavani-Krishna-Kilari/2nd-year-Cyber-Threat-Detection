"""
Unit tests for the SIEM Tri-State Decision Policy Module.
Tests NORMAL, KNOWN THREAT, and UNKNOWN / ANOMALOUS outcomes, edge cases,
and end-to-end inference integration.
Run with:
    python -m unittest tests.test_decision_policy -v
"""

import unittest
import numpy as np

from src.inference.decision_policy import (
    classify_detection_outcome,
    KNOWN_THREAT_THRESHOLD,
    NORMAL_CONFIDENCE_THRESHOLD,
    DEFAULT_ANOMALY_THRESHOLD
)
from src.inference.predict import ThreatInferenceEngine


class TestDecisionPolicyUnit(unittest.TestCase):
    """Unit tests for classify_detection_outcome with isolated inputs."""

    def test_normal_outcome(self):
        """Benign traffic with low threat confidence and normal isolation score."""
        anomaly_res = {
            "is_anomaly": False,
            "anomaly_score": -0.0850,
            "normalized_score": 0.20,
            "verdict": "NORMAL",
            "threshold": DEFAULT_ANOMALY_THRESHOLD
        }
        res = classify_detection_outcome(
            threat_confidence=0.15,
            anomaly_result=anomaly_res,
            dominant_basepoint="bp_01"
        )
        self.assertEqual(res["verdict"], "NORMAL")
        self.assertEqual(res["prediction_status"], "NORMAL")
        self.assertEqual(res["predicted_class"], "Benign Network Traffic")
        self.assertEqual(res["anomaly_status"], "NORMAL")
        self.assertFalse(res["requires_investigation"])
        self.assertAlmostEqual(res["confidence"], 0.85, places=4)
        self.assertIn("benign", res["detection_reason"].lower())

    def test_known_threat_ftp_patator(self):
        """High-confidence threat targeting destination port 21."""
        anomaly_res = {
            "is_anomaly": True,
            "anomaly_score": 0.0500,
            "normalized_score": 0.95,
            "verdict": "ANOMALOUS",
            "threshold": DEFAULT_ANOMALY_THRESHOLD
        }
        res = classify_detection_outcome(
            threat_confidence=0.98,
            anomaly_result=anomaly_res,
            dominant_basepoint="bp_01",
            destination_port=21
        )
        self.assertEqual(res["verdict"], "KNOWN_THREAT")
        self.assertEqual(res["prediction_status"], "KNOWN_THREAT")
        self.assertEqual(res["predicted_class"], "Known Threat Pattern (Subclass Not Classified)")
        self.assertTrue(res["requires_investigation"])
        self.assertEqual(res["confidence"], 0.98)
        self.assertIn("known threat threshold", res["detection_reason"].lower())

    def test_known_threat_ssh_patator(self):
        """High-confidence threat targeting destination port 22."""
        res = classify_detection_outcome(
            threat_confidence=0.96,
            dominant_basepoint="bp_01",
            destination_port=22
        )
        self.assertEqual(res["verdict"], "KNOWN_THREAT")
        self.assertEqual(res["predicted_class"], "Known Threat Pattern (Subclass Not Classified)")
        self.assertTrue(res["requires_investigation"])

    def test_known_threat_syn_scan(self):
        """High-confidence threat with dominant SYN basepoint (bp_03)."""
        res = classify_detection_outcome(
            threat_confidence=0.97,
            dominant_basepoint="bp_03",
            destination_port=80
        )
        self.assertEqual(res["verdict"], "KNOWN_THREAT")
        self.assertEqual(res["predicted_class"], "Known Threat Pattern (Subclass Not Classified)")
        self.assertTrue(res["requires_investigation"])

    def test_known_threat_generic_patator(self):
        """High-confidence threat not matching specific port rules."""
        res = classify_detection_outcome(
            threat_confidence=0.955,
            dominant_basepoint="bp_02",
            destination_port=8080
        )
        self.assertEqual(res["verdict"], "KNOWN_THREAT")
        self.assertEqual(res["predicted_class"], "Known Threat Pattern (Subclass Not Classified)")
        self.assertTrue(res["requires_investigation"])

    def test_unknown_anomalous_out_of_distribution(self):
        """Anomaly detected by Isolation Forest despite low ensemble threat probability."""
        anomaly_res = {
            "is_anomaly": True,
            "anomaly_score": 0.0820,
            "normalized_score": 0.88,
            "verdict": "ANOMALOUS",
            "threshold": DEFAULT_ANOMALY_THRESHOLD
        }
        res = classify_detection_outcome(
            threat_confidence=0.10,
            anomaly_result=anomaly_res,
            dominant_basepoint="bp_05"
        )
        self.assertEqual(res["verdict"], "UNKNOWN_ANOMALOUS")
        self.assertEqual(res["prediction_status"], "UNKNOWN_ANOMALOUS")
        self.assertIn("Unknown / Anomalous Activity", res["predicted_class"])
        self.assertEqual(res["anomaly_status"], "ANOMALOUS")
        self.assertTrue(res["requires_investigation"])
        self.assertEqual(res["confidence"], 0.88)
        self.assertIn("out-of-distribution anomaly", res["detection_reason"].lower())

    def test_unknown_anomalous_compound_threat(self):
        """Compound alert: ambiguous ensemble + out-of-distribution anomaly."""
        anomaly_res = {
            "is_anomaly": True,
            "anomaly_score": 0.0350,
            "normalized_score": 0.75,
            "verdict": "ANOMALOUS",
            "threshold": DEFAULT_ANOMALY_THRESHOLD
        }
        res = classify_detection_outcome(
            threat_confidence=0.65,
            anomaly_result=anomaly_res,
            dominant_basepoint="bp_06"
        )
        self.assertEqual(res["verdict"], "UNKNOWN_ANOMALOUS")
        self.assertEqual(res["predicted_class"], "Compound Anomalous Threat")
        self.assertTrue(res["requires_investigation"])
        self.assertEqual(res["confidence"], 0.75)
        self.assertIn("compound alert", res["detection_reason"].lower())

    def test_unknown_anomalous_prediction_uncertainty(self):
        """Prediction uncertainty: ensemble in margin (0.30, 0.95) and non-anomalous."""
        anomaly_res = {
            "is_anomaly": False,
            "anomaly_score": -0.0500,
            "normalized_score": 0.35,
            "verdict": "NORMAL",
            "threshold": DEFAULT_ANOMALY_THRESHOLD
        }
        res = classify_detection_outcome(
            threat_confidence=0.55,
            anomaly_result=anomaly_res,
            dominant_basepoint="bp_04"
        )
        self.assertEqual(res["verdict"], "UNKNOWN_ANOMALOUS")
        self.assertIn("Uncertain", res["predicted_class"])
        self.assertTrue(res["requires_investigation"])
        self.assertIn("prediction uncertainty", res["detection_reason"].lower())

    def test_robustness_none_anomaly_result(self):
        """Robustness when anomaly detector is unavailable or returns None."""
        res = classify_detection_outcome(
            threat_confidence=0.10,
            anomaly_result=None
        )
        self.assertEqual(res["verdict"], "NORMAL")
        self.assertEqual(res["anomaly_status"], "NOT_EVALUATED")

    def test_robustness_nan_and_inf_inputs(self):
        """Robustness against NaN, inf, or out-of-bounds inputs."""
        res_nan = classify_detection_outcome(threat_confidence=float("nan"))
        self.assertEqual(res_nan["verdict"], "UNKNOWN_ANOMALOUS")

        res_inf = classify_detection_outcome(threat_confidence=float("inf"))
        self.assertEqual(res_inf["verdict"], "UNKNOWN_ANOMALOUS")

        res_neg = classify_detection_outcome(threat_confidence=-0.50)
        self.assertEqual(res_neg["verdict"], "NORMAL")

    def test_exact_threshold_boundaries(self):
        """Verifies exact calibrated boundaries: tau_threat=0.8398 and tau_normal=0.30."""
        # Exact threat threshold: >= KNOWN_THREAT_THRESHOLD is KNOWN_THREAT
        res_at_threat = classify_detection_outcome(threat_confidence=KNOWN_THREAT_THRESHOLD)
        self.assertEqual(res_at_threat["verdict"], "KNOWN_THREAT")

        # Just below threat threshold without anomaly: UNKNOWN_ANOMALOUS
        res_below_threat = classify_detection_outcome(threat_confidence=round(KNOWN_THREAT_THRESHOLD - 0.001, 4))
        self.assertEqual(res_below_threat["verdict"], "UNKNOWN_ANOMALOUS")

        # Exact normal threshold: <= 0.30 with no anomaly is NORMAL
        res_at_normal = classify_detection_outcome(threat_confidence=0.30)
        self.assertEqual(res_at_normal["verdict"], "NORMAL")

        # Just above normal threshold: > 0.30 is UNKNOWN_ANOMALOUS
        res_above_normal = classify_detection_outcome(threat_confidence=0.301)
        self.assertEqual(res_above_normal["verdict"], "UNKNOWN_ANOMALOUS")


class TestEngineDecisionIntegration(unittest.TestCase):
    """Integration tests verifying ThreatInferenceEngine produces tri-state outcomes."""

    @classmethod
    def setUpClass(cls):
        cls.engine = ThreatInferenceEngine()

    def test_engine_is_ready(self):
        self.assertTrue(self.engine.is_ready())

    def test_engine_predict_profile_normal(self):
        """Baseline normal profile in Experiment A must yield NORMAL."""
        normal_vec = [0.0925, 0.9765, 0.3905, 0.6040, 0.5797, 0.5831, 0.6330, 0.6870]
        pred = self.engine.predict_profile(normal_vec)
        self.assertEqual(pred["verdict"], "NORMAL")
        self.assertEqual(pred["prediction_status"], "NORMAL")
        self.assertEqual(pred["severity"], "LOW")
        self.assertFalse(pred["requires_investigation"])

    def test_engine_predict_profile_known_threat(self):
        """Known attack profile vector must yield KNOWN_THREAT without port-based subclass fabrication."""
        attack_vec = [0.5630, 0.3430, 0.9424, 0.2136, 0.2260, 0.7550, 0.5797, 0.5215]
        pred = self.engine.predict_profile(attack_vec, destination_port=22)
        self.assertEqual(pred["verdict"], "KNOWN_THREAT")
        self.assertEqual(pred["prediction_status"], "KNOWN_THREAT")
        self.assertEqual(pred["predicted_class"], "Known Threat Pattern (Subclass Not Classified)")
        self.assertTrue(pred["requires_investigation"])
        self.assertIn(pred["severity"], ["HIGH", "CRITICAL"])

    def test_engine_predict_profile_unknown_anomalous(self):
        """Event profile falling into the uncertain margin must yield UNKNOWN_ANOMALOUS."""
        uncertain_vec = [0.85, 0.20, 0.10, 0.05, 0.70, 0.80, 0.75, 0.05]
        pred = self.engine.predict_profile(uncertain_vec)
        self.assertEqual(pred["verdict"], "UNKNOWN_ANOMALOUS")
        self.assertEqual(pred["prediction_status"], "UNKNOWN_ANOMALOUS")
        self.assertTrue(pred["requires_investigation"])

    def test_engine_predict_flow_end_to_end(self):
        """End-to-end network flow inference produces complete tri-state telemetry."""
        flow = {
            "source_ip": "172.16.0.1",
            "destination_ip": "192.168.10.50",
            "source_port": 50123,
            "destination_port": 21,
            "protocol": 6,
            "flow_duration": 3000.0,
            "flow_packets_s": 700000.0,
            "flow_bytes_s": 2500000.0,
            "syn_flag_count": 2,
            "flow_count": 20
        }
        pred = self.engine.predict_flow(flow)
        self.assertIn(pred["verdict"], ["KNOWN_THREAT", "UNKNOWN_ANOMALOUS", "NORMAL"])
        self.assertIn("prediction_status", pred)
        self.assertIn("predicted_class", pred)
        self.assertIn("confidence", pred)
        self.assertIn("anomaly_status", pred)
        self.assertIn("detection_reason", pred)
        self.assertIn("flow_metadata", pred)
        self.assertEqual(pred["flow_metadata"]["destination_port"], 21)


if __name__ == "__main__":
    unittest.main()
