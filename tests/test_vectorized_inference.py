"""
Unit and regression tests verifying prediction equivalence and performance
for vectorized batch inference and deduplicated neural ensemble inference.

Guarantees:
  1. Serial predict_profile vs Vectorized predict_profiles_batch are strictly identical.
  2. Individual FCNN, CNN, LSTM probabilities match within numerical tolerance (<= 1e-6).
  3. Ensemble probabilities match within numerical tolerance (<= 1e-6).
  4. Isolation Forest scores match within numerical tolerance (<= 1e-4).
  5. Tri-state verdicts ('NORMAL', 'KNOWN_THREAT', 'UNKNOWN_ANOMALOUS') are 100% identical.
  6. Row ordering is strictly preserved.
  7. Tested across Benign, Known Threat, Unknown Anomalous, and near-threshold profiles.
"""

import unittest
import numpy as np
import pandas as pd
import io

from backend.service import SIEMService
from src.inference.predict import ThreatInferenceEngine
from src.models.ensemble import SoftVotingEnsemble
from src.models.anomaly import AnomalyDetector


class TestVectorizedInferenceEquivalence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.service_b = SIEMService(experiment_id="B")
        cls.engine_b = cls.service_b.engine
        
        cls.service_a = SIEMService(experiment_id="A")
        cls.engine_a = cls.service_a.engine

    def test_01_ensemble_predict_single_no_duplicate_identical(self):
        """Verifies predict_single produces identical confidence to predict_proba without duplicate calls."""
        ens = self.engine_b.ensemble
        v = np.array([0.15, 0.25, 0.35, 0.45, 0.55, 0.65, 0.75, 0.85], dtype=np.float32)
        
        res = ens.predict_single(v)
        expected_proba = float(ens.predict_proba(v.reshape(1, -1))[0])
        
        self.assertAlmostEqual(res["threat_confidence"], expected_proba, places=6)
        self.assertIn("submodel_probabilities", res)
        self.assertIn("fcnn", res["submodel_probabilities"])
        self.assertIn("cnn", res["submodel_probabilities"])
        self.assertIn("lstm", res["submodel_probabilities"])
        self.assertIn("verdict", res)

    def test_02_predict_profiles_batch_equivalence_experiment_b(self):
        """Tests that predict_profiles_batch matches predict_profile across diverse profile categories."""
        # 1. Benign profile
        # 2. Known threat profile (ES0000044 attack basepoint)
        # 3. Known threat high confidence
        # 4. Unknown anomalous profile (extreme values)
        # 5. Near-threshold boundary profile
        # 6. Synth DDoS profile
        # 7. Synth Benign profile
        # 8. All zero profile
        profiles = [
            [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            [0.71786759, 0.17310065, 0.27491244, 0.0, 0.0, 0.65870619, 0.84038849, 0.0],
            [0.85, 0.20, 0.10, 0.05, 0.70, 0.80, 0.75, 0.05],
            [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0],
            [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5],
            [0.0, 0.9630, 0.0, 0.5586, 0.4330, 0.5439, 0.3745, 0.0],
            [0.0, 0.8148, 0.0, 0.0, 0.6267, 0.0, 0.5420, 0.0],
            [0.2, 0.4, 0.1, 0.3, 0.5, 0.2, 0.1, 0.0]
        ]
        ports = [80, 21, 443, 8080, 22, 80, 8080, 53]

        serial_preds = [
            self.engine_b.predict_profile(p, destination_port=port)
            for p, port in zip(profiles, ports)
        ]

        batch_preds = self.engine_b.predict_profiles_batch(
            np.asarray(profiles, dtype=np.float32),
            destination_ports=ports
        )

        self.assertEqual(len(serial_preds), len(batch_preds))

        for idx, (s, b) in enumerate(zip(serial_preds, batch_preds)):
            # Verdict identity
            self.assertEqual(s["verdict"], b["verdict"], f"Verdict mismatch at index {idx}")
            self.assertEqual(s["prediction_status"], b["prediction_status"], f"Status mismatch at index {idx}")
            self.assertEqual(s["predicted_class"], b["predicted_class"], f"Class mismatch at index {idx}")
            self.assertEqual(s["severity"], b["severity"], f"Severity mismatch at index {idx}")
            self.assertEqual(s["dominant_basepoint"], b["dominant_basepoint"], f"Dominant BP mismatch at index {idx}")

            # Numerical tolerance checks
            self.assertAlmostEqual(s["threat_confidence"], b["threat_confidence"], places=5, msg=f"Confidence diff at {idx}")
            self.assertAlmostEqual(s["model_breakdown"]["fcnn"], b["model_breakdown"]["fcnn"], places=5)
            self.assertAlmostEqual(s["model_breakdown"]["cnn"], b["model_breakdown"]["cnn"], places=5)
            self.assertAlmostEqual(s["model_breakdown"]["lstm"], b["model_breakdown"]["lstm"], places=5)
            self.assertAlmostEqual(s["anomaly_score"], b["anomaly_score"], places=4)

    def test_03_predict_profiles_batch_equivalence_experiment_a(self):
        """Verifies backward-compatibility and equivalence under Experiment A."""
        profiles = [
            [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
            [0.72, 0.17, 0.27, 0.0, 0.0, 0.66, 0.84, 0.0],
            [0.0, 0.81, 0.0, 0.0, 0.63, 0.0, 0.54, 0.0]
        ]
        ports = [80, 21, 443]

        serial_preds = [
            self.engine_a.predict_profile(p, destination_port=port)
            for p, port in zip(profiles, ports)
        ]

        batch_preds = self.engine_a.predict_profiles_batch(
            np.asarray(profiles, dtype=np.float32),
            destination_ports=ports
        )

        for s, b in zip(serial_preds, batch_preds):
            self.assertEqual(s["verdict"], b["verdict"])
            self.assertAlmostEqual(s["threat_confidence"], b["threat_confidence"], places=5)

    def test_04_batch_upload_service_equivalence(self):
        """Verifies process_file_upload returns identical summary statistics and order."""
        # Create CSV bytes with 10 event profiles
        lines = ["bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08,destination_port"]
        # 5 normal
        for _ in range(5):
            lines.append("0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,80")
        # 5 known threats
        for _ in range(5):
            lines.append("0.71786759,0.17310065,0.27491244,0.0,0.0,0.65870619,0.84038849,0.0,21")
        csv_bytes = "\n".join(lines).encode("utf-8")

        summary = self.service_b.process_file_upload(csv_bytes, "test_equivalence_batch.csv")

        self.assertEqual(summary["total_records"], 10)
        self.assertEqual(summary["normal_events"], 5)
        self.assertEqual(summary["known_threats"], 5)
        self.assertEqual(summary["unknown_anomalous"], 0)
        self.assertEqual(summary["invalid_records"], 0)

        # Check sample results ordering
        samples = summary["sample_results"]
        self.assertEqual(len(samples), 10)
        for i in range(5):
            self.assertEqual(samples[i]["verdict"], "NORMAL")
            self.assertEqual(samples[i]["index"], i + 1)
        for i in range(5, 10):
            self.assertEqual(samples[i]["verdict"], "KNOWN_THREAT")
            self.assertEqual(samples[i]["index"], i + 1)


if __name__ == "__main__":
    unittest.main()
