"""
Soft-Voting Ensemble Classifier combining FCNN, 1D-CNN, and LSTM.

Computes a probability-weighted consensus:
  P_ensemble = w_fcnn * P_fcnn + w_cnn * P_cnn + w_lstm * P_lstm

The system outputs ONE definitive SIEM verdict: 'THREAT' or 'NORMAL'
based on a calibrated decision threshold tau (tuned on validation data).
"""

from typing import Dict, List, Optional, Tuple, Union
import numpy as np


class SoftVotingEnsemble:
    """
    Unified Soft-Voting Ensemble for FCNN, 1D-CNN, and LSTM.
    """

    def __init__(
        self,
        fcnn_model=None,
        cnn_model=None,
        lstm_model=None,
        weights: Optional[Union[List[float], Dict[str, float]]] = None,
        threshold: float = 0.50,
    ):
        self.fcnn_model = fcnn_model
        self.cnn_model = cnn_model
        self.lstm_model = lstm_model
        self.threshold = float(threshold)
        self.weights = self._normalize_weights(weights or [1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0])

    @staticmethod
    def _normalize_weights(weights: Union[List[float], Dict[str, float]]) -> List[float]:
        if isinstance(weights, dict):
            # Extract standard fcnn, cnn, lstm order
            w_list = [
                float(weights.get("fcnn", 1.0)),
                float(weights.get("cnn", 1.0)),
                float(weights.get("lstm", 1.0))
            ]
        else:
            w_list = [float(x) for x in weights]
        w = np.array(w_list, dtype=np.float64)
        if w.sum() == 0:
            return [1.0 / len(w)] * len(w)
        w = w / w.sum()
        return [float(x) for x in w]

    def set_weights(self, weights: Union[List[float], Dict[str, float]]) -> None:
        self.weights = self._normalize_weights(weights)

    def set_threshold(self, threshold: float) -> None:
        self.threshold = float(np.clip(threshold, 0.01, 0.99))

    def predict_individual_proba(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Returns (p_fcnn, p_cnn, p_lstm) as 1D numpy float arrays."""
        X = np.asarray(X, dtype=np.float32)
        if X.ndim == 1:
            X = X.reshape(1, -1)
            
        p_fcnn = np.zeros(len(X), dtype=np.float32)
        p_cnn = np.zeros(len(X), dtype=np.float32)
        p_lstm = np.zeros(len(X), dtype=np.float32)

        if self.fcnn_model is not None:
            p_fcnn = np.asarray(self.fcnn_model.predict(X, verbose=0)).reshape(-1)
        if self.cnn_model is not None:
            p_cnn = np.asarray(self.cnn_model.predict(X, verbose=0)).reshape(-1)
        if self.lstm_model is not None:
            p_lstm = np.asarray(self.lstm_model.predict(X, verbose=0)).reshape(-1)

        return p_fcnn, p_cnn, p_lstm

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Computes combined soft-voted threat probability in [0.0, 1.0]."""
        p_fcnn, p_cnn, p_lstm = self.predict_individual_proba(X)
        w1, w2, w3 = self.weights
        p_ensemble = (w1 * p_fcnn) + (w2 * p_cnn) + (w3 * p_lstm)
        return np.clip(p_ensemble, 0.0, 1.0)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Returns binary predictions: 1 for THREAT, 0 for NORMAL."""
        probas = self.predict_proba(X)
        return (probas >= self.threshold).astype(np.int8)

    def predict_single(self, vector_8d: Union[List[float], np.ndarray]) -> Dict[str, Union[str, float, Dict[str, float]]]:
        """
        Analyzes a single 8-dimensional event profile vector.
        Outputs ONE final verdict: 'THREAT' or 'NORMAL', along with detailed
        transparency probabilities for SIEM analytics.
        """
        v = np.asarray(vector_8d, dtype=np.float32).reshape(1, -1)
        p_fcnn, p_cnn, p_lstm = self.predict_individual_proba(v)
        w1, w2, w3 = self.weights
        p_comb = float(np.clip((w1 * p_fcnn[0]) + (w2 * p_cnn[0]) + (w3 * p_lstm[0]), 0.0, 1.0))
        verdict = "THREAT" if p_comb >= self.threshold else "NORMAL"

        return {
            "verdict": verdict,
            "threat_confidence": p_comb,
            "threshold_applied": self.threshold,
            "model_weights": {
                "fcnn": self.weights[0],
                "cnn": self.weights[1],
                "lstm": self.weights[2]
            },
            "submodel_probabilities": {
                "fcnn": float(p_fcnn[0]),
                "cnn": float(p_cnn[0]),
                "lstm": float(p_lstm[0])
            }
        }
