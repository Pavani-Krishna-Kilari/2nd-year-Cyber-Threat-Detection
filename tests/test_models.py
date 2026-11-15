"""
Unit tests for Phase 4: ANN Models, Ensemble Prediction, and Evaluation Metrics.
Run with:
    python -m unittest tests.test_models -v
"""

import unittest
import numpy as np

from src.models.ensemble import SoftVotingEnsemble
from src.models.evaluate import compute_metrics, find_optimal_threshold


class DummyModel:
    """Mock model producing deterministic probabilities for fast unit testing."""
    def __init__(self, fixed_proba: float):
        self.fixed_proba = fixed_proba

    def predict(self, X, verbose=0, **kwargs):
        X = np.asarray(X)
        n = len(X)
        return np.full((n, 1), self.fixed_proba, dtype=np.float32)


class TestSoftVotingEnsemble(unittest.TestCase):
    def test_ensemble_weight_normalization(self):
        ens = SoftVotingEnsemble(weights=[2.0, 1.0, 1.0])
        self.assertAlmostEqual(sum(ens.weights), 1.0)
        self.assertAlmostEqual(ens.weights[0], 0.5)
        self.assertAlmostEqual(ens.weights[1], 0.25)
        self.assertAlmostEqual(ens.weights[2], 0.25)

    def test_single_verdict_threat_or_normal(self):
        m1 = DummyModel(0.8)
        m2 = DummyModel(0.6)
        m3 = DummyModel(0.7)
        ens = SoftVotingEnsemble(m1, m2, m3, weights=[1, 1, 1], threshold=0.5)

        sample = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
        res = ens.predict_single(sample)

        # Must display ONE final prediction: THREAT or NORMAL
        self.assertIn(res["verdict"], ["THREAT", "NORMAL"])
        self.assertEqual(res["verdict"], "THREAT")
        self.assertAlmostEqual(res["threat_confidence"], 0.7, places=4)

        # Test NORMAL verdict
        ens.set_threshold(0.9)
        res_normal = ens.predict_single(sample)
        self.assertEqual(res_normal["verdict"], "NORMAL")

    def test_combined_probability_formula(self):
        m1 = DummyModel(0.2)
        m2 = DummyModel(0.4)
        m3 = DummyModel(0.6)
        ens = SoftVotingEnsemble(m1, m2, m3, weights=[0.5, 0.3, 0.2], threshold=0.5)

        X = np.zeros((5, 8))
        probs = ens.predict_proba(X)
        expected = 0.5 * 0.2 + 0.3 * 0.4 + 0.2 * 0.6  # 0.10 + 0.12 + 0.12 = 0.34
        np.testing.assert_allclose(probs, expected, atol=1e-5)


class TestEvaluationMetrics(unittest.TestCase):
    def test_compute_metrics_known_values(self):
        # 10 samples: 2 positive (1, 1), 8 negative (0)
        y_true = np.array([0, 0, 0, 0, 0, 0, 0, 0, 1, 1])
        # Predict probas: index 8 is detected, index 9 is missed, index 7 is false positive
        y_proba = np.array([0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.1, 0.8, 0.9, 0.2])

        m = compute_metrics(y_true, y_proba, threshold=0.5)
        # TN=7, FP=1, FN=1, TP=1
        self.assertEqual(m["confusion_matrix"]["tp"], 1)
        self.assertEqual(m["confusion_matrix"]["fp"], 1)
        self.assertEqual(m["confusion_matrix"]["tn"], 7)
        self.assertEqual(m["confusion_matrix"]["fn"], 1)

        # FPR = FP / (FP + TN) = 1 / 8 = 0.125
        self.assertAlmostEqual(m["false_positive_rate"], 0.125)
        # Precision = TP / (TP + FP) = 1 / 2 = 0.5
        self.assertAlmostEqual(m["precision"], 0.5)
        # Recall = TP / (TP + FN) = 1 / 2 = 0.5
        self.assertAlmostEqual(m["recall"], 0.5)
        self.assertAlmostEqual(m["f1_score"], 0.5)

    def test_find_optimal_threshold(self):
        y_true = np.array([0, 0, 0, 0, 1, 1])
        y_proba = np.array([0.1, 0.2, 0.3, 0.4, 0.7, 0.8])
        best_thresh, best_f1 = find_optimal_threshold(y_true, y_proba)
        # Any threshold between 0.41 and 0.69 gives perfect Precision and Recall (F1 = 1.0)
        self.assertGreaterEqual(best_f1, 0.99)
        self.assertTrue(0.4 <= best_thresh <= 0.7)


class TestKerasArchitectures(unittest.TestCase):
    def test_builders_when_keras_available(self):
        try:
            from src.models.fcnn import build_fcnn
            from src.models.cnn import build_cnn
            from src.models.lstm import build_lstm
        except ImportError:
            self.skipTest("Keras/TensorFlow not installed yet")

        # FCNN
        fcnn = build_fcnn(input_dim=8)
        self.assertEqual(fcnn.input_shape, (None, 8))
        self.assertEqual(fcnn.output_shape, (None, 1))

        # CNN
        cnn = build_cnn(input_dim=8)
        self.assertEqual(cnn.input_shape, (None, 8))
        self.assertEqual(cnn.output_shape, (None, 1))

        # LSTM (time_steps=1)
        lstm = build_lstm(input_dim=8, time_steps=1)
        self.assertEqual(lstm.input_shape, (None, 8))
        self.assertEqual(lstm.output_shape, (None, 1))

        # Test forward pass with dummy vector
        x = np.random.uniform(0, 1, (2, 8)).astype(np.float32)
        p_fcnn = fcnn.predict(x, verbose=0)
        p_cnn = cnn.predict(x, verbose=0)
        p_lstm = lstm.predict(x, verbose=0)

        self.assertTrue(np.all((p_fcnn >= 0.0) & (p_fcnn <= 1.0)))
        self.assertTrue(np.all((p_cnn >= 0.0) & (p_cnn <= 1.0)))
        self.assertTrue(np.all((p_lstm >= 0.0) & (p_lstm <= 1.0)))


if __name__ == "__main__":
    unittest.main()
