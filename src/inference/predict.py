"""
End-to-End Threat Inference Pipeline.
Supports both Experiment B (Active Default) and Experiment A (Legacy).
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

import numpy as np
import pandas as pd

from src.config import PROJECT_ROOT
from src.event_profiles.tfidf import transform
from src.event_profiles.basepoints import compute_profiles
from src.models.ensemble import SoftVotingEnsemble
from src.models.anomaly import AnomalyDetector
from src.inference.decision_policy import (
    classify_detection_outcome,
    ANN_ALERT_THRESHOLD,
    DEFAULT_ANOMALY_THRESHOLD,
    KNOWN_THREAT_THRESHOLD,
    NORMAL_CONFIDENCE_THRESHOLD,
    FCNN_THRESHOLD_EXP_B,
    CNN_THRESHOLD_EXP_B,
    LSTM_THRESHOLD_EXP_B
)


class ThreatInferenceEngine:
    """
    Production-grade inference engine integrating:
      1. Derived event thresholding
      2. TF-IDF vectorization & Basepoint cosine similarity
      3. Deep Neural Ensemble (FCNN + CNN + LSTM)
      4. Isolation Forest Out-of-Distribution Anomaly Detection
      5. Strict Experiment B Tri-State Decision Policy (ANN_ALERT / UNKNOWN_ANOMALOUS / NORMAL)
    """

    def __init__(
        self,
        models_dir: Optional[Path] = None,
        data_dir: Optional[Path] = None,
        experiment_id: str = "A"
    ):
        self.experiment_id = experiment_id

        if models_dir is not None:
            self.models_dir = Path(models_dir)
        else:
            self.models_dir = (PROJECT_ROOT / "models" / "saved_exp_b") if experiment_id == "B" else (PROJECT_ROOT / "models" / "saved_exp_a")

        if data_dir is not None:
            self.data_dir = Path(data_dir)
        else:
            self.data_dir = (PROJECT_ROOT / "data" / "processed" / "event_profiles_exp_b") if experiment_id == "B" else (PROJECT_ROOT / "data" / "processed" / "event_profiles_exp_a")

        self.fcnn_model = None
        self.cnn_model = None
        self.lstm_model = None
        self.ensemble = None

        self.basepoints = None
        self.tfidf_model = None
        self.thresholds = None
        self.submodel_thresholds = {
            "fcnn": FCNN_THRESHOLD_EXP_B if experiment_id == "B" else 0.8398,
            "cnn": CNN_THRESHOLD_EXP_B if experiment_id == "B" else 0.8398,
            "lstm": LSTM_THRESHOLD_EXP_B if experiment_id == "B" else 0.8398
        }
        self.anomaly_detector = AnomalyDetector(models_dir=self.models_dir)

        self._load_artifacts()

    def _load_artifacts(self):
        if not self.models_dir.exists() or not self.data_dir.exists():
            return

        # 1. Load fitted event profiling artifacts
        bp_path = self.data_dir / "basepoints.csv"
        tfidf_path = self.data_dir / "tfidf_model.json"
        thresh_path = self.data_dir / "event_thresholds.json"

        if bp_path.exists():
            df_bp = pd.read_csv(bp_path)
            event_cols = ["HIGH_FLOW_RATE", "HIGH_PACKET_RATE", "HIGH_BYTE_RATE", "SYN_ACTIVITY", "SHORT_REPEATED_CONNECTIONS"]
            self.basepoints = df_bp[event_cols].to_numpy(dtype=np.float64)

        if tfidf_path.exists():
            self.tfidf_model = json.loads(tfidf_path.read_text(encoding="utf-8"))

        if thresh_path.exists():
            self.thresholds = json.loads(thresh_path.read_text(encoding="utf-8"))

        # 2. Load trained deep learning models
        try:
            from keras.models import load_model
            fcnn_path = self.models_dir / "fcnn_model.keras"
            cnn_path = self.models_dir / "cnn_model.keras"
            lstm_path = self.models_dir / "lstm_model.keras"

            if fcnn_path.exists():
                self.fcnn_model = load_model(fcnn_path, compile=False)
            if cnn_path.exists():
                self.cnn_model = load_model(cnn_path, compile=False)
            if lstm_path.exists():
                self.lstm_model = load_model(lstm_path, compile=False)
        except Exception as e:
            print(f"Warning: could not load Keras models: {e}")

        # 3. Load ensemble configuration
        weights = [1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0]
        threshold = ANN_ALERT_THRESHOLD if self.experiment_id == "B" else 0.8398
        ens_cfg_path = self.models_dir / "ensemble_config.json"
        if ens_cfg_path.exists():
            try:
                cfg = json.loads(ens_cfg_path.read_text(encoding="utf-8"))
                if "model_weights" in cfg:
                    mw = cfg["model_weights"]
                    weights = [
                        float(mw.get("fcnn", 1.0 / 3.0)),
                        float(mw.get("cnn", 1.0 / 3.0)),
                        float(mw.get("lstm", 1.0 / 3.0))
                    ]
                elif "weights" in cfg:
                    weights = cfg["weights"]

                if "optimal_threshold" in cfg:
                    threshold = float(cfg["optimal_threshold"])
                elif "threshold" in cfg:
                    threshold = float(cfg["threshold"])
            except Exception as e:
                print(f"Warning: error loading ensemble_config.json: {e}")

        self.ensemble = SoftVotingEnsemble(
            fcnn_model=self.fcnn_model,
            cnn_model=self.cnn_model,
            lstm_model=self.lstm_model,
            weights=weights,
            threshold=threshold
        )

    def is_ready(self) -> bool:
        return (
            self.fcnn_model is not None
            and self.cnn_model is not None
            and self.lstm_model is not None
            and self.ensemble is not None
            and self.basepoints is not None
            and self.anomaly_detector.is_ready()
        )

    def predict_profile(self, bp_vector: Union[List[float], np.ndarray], destination_port: Optional[int] = None) -> Dict[str, Any]:
        """
        Direct inference on an 8-dimensional event profile vector [bp_01..bp_08].
        Produces tri-state outcome: 'NORMAL', 'ANN_ALERT', or 'UNKNOWN_ANOMALOUS'.
        """
        v_flat = np.asarray(bp_vector, dtype=np.float32).reshape(-1)
        if len(v_flat) != 8:
            raise ValueError(f"Expected exactly 8 basepoint features (bp_01..bp_08), got {len(v_flat)}")
        if not np.all(np.isfinite(v_flat)):
            raise ValueError("Input features contain NaN, Inf, or invalid values.")

        v = v_flat.reshape(1, -1)
        res = self.ensemble.predict_single(v[0])

        top_bp_idx = int(np.argmax(v[0])) + 1
        top_bp_val = float(v[0, top_bp_idx - 1])
        dom_bp = f"bp_{top_bp_idx:02d}"

        anomaly_res = None
        if self.anomaly_detector and self.anomaly_detector.is_ready():
            anomaly_res = self.anomaly_detector.predict_single(v[0])

        # Evaluate tri-state decision policy with calibrated thresholds
        anomaly_th = self.anomaly_detector.threshold if self.anomaly_detector else DEFAULT_ANOMALY_THRESHOLD
        policy = classify_detection_outcome(
            threat_confidence=res["threat_confidence"],
            anomaly_result=anomaly_res,
            dominant_basepoint=dom_bp,
            destination_port=destination_port,
            threat_threshold=res["threshold_applied"],
            anomaly_threshold=anomaly_th,
            experiment_id=self.experiment_id
        )

        p_status = policy["prediction_status"]
        if p_status in ["ANN_ALERT", "KNOWN_THREAT"]:
            severity = "CRITICAL" if res["threat_confidence"] > 0.85 else "HIGH"
        elif p_status == "UNKNOWN_ANOMALOUS":
            severity = "HIGH" if (anomaly_res and anomaly_res.get("is_anomaly")) else "MEDIUM"
        else:
            severity = "LOW"

        return {
            "verdict": p_status,
            "prediction_status": p_status,
            "predicted_class": policy["predicted_class"],
            "confidence": policy["confidence"],
            "anomaly_status": policy["anomaly_status"],
            "anomaly_score": policy["anomaly_score"],
            "detection_reason": policy["detection_reason"],
            "requires_investigation": policy["requires_investigation"],
            "threat_confidence": res["threat_confidence"],
            "threshold": res["threshold_applied"],
            "severity": severity,
            "dominant_basepoint": dom_bp,
            "dominant_basepoint_similarity": top_bp_val,
            "profile_vector": [float(x) for x in v[0]],
            "model_breakdown": res["submodel_probabilities"],
            "submodel_thresholds": self.submodel_thresholds,
            "experiment_id": self.experiment_id,
            "anomaly": anomaly_res
        }

    def predict_profiles_batch(
        self,
        bp_vectors: Union[List[List[float]], np.ndarray],
        destination_ports: Optional[List[Optional[int]]] = None
    ) -> List[Dict[str, Any]]:
        """
        Vectorized batch inference on multiple 8-dimensional event profile vectors.
        Evaluates FCNN, CNN, LSTM, and Isolation Forest in single batched operations.
        Produces mathematically equivalent tri-state outcomes in the original order.
        """
        X = np.asarray(bp_vectors, dtype=np.float32)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        if X.shape[1] != 8:
            raise ValueError(f"Expected 8 basepoint features per profile, got shape {X.shape}")
        if not np.all(np.isfinite(X)):
            raise ValueError("Input profile matrix contains NaN, Inf, or invalid values.")

        n_samples = len(X)
        if n_samples == 0:
            return []

        if destination_ports is None:
            ports = [None] * n_samples
        else:
            ports = destination_ports

        # 1. Batched Neural Ensemble Inference
        p_fcnn, p_cnn, p_lstm = self.ensemble.predict_individual_proba(X)
        w1, w2, w3 = self.ensemble.weights
        ens_probs = np.clip((w1 * p_fcnn) + (w2 * p_cnn) + (w3 * p_lstm), 0.0, 1.0)

        # 2. Batched Isolation Forest Anomaly Detection
        anomaly_th = self.anomaly_detector.threshold if self.anomaly_detector else DEFAULT_ANOMALY_THRESHOLD
        if self.anomaly_detector and self.anomaly_detector.is_ready():
            raw_scores = self.anomaly_detector.model.decision_function(X)
            iso_scores = -raw_scores
            is_anom = iso_scores >= anomaly_th
            norm_scores = 1.0 / (1.0 + np.exp(-5.0 * (iso_scores - anomaly_th)))
        else:
            iso_scores = np.zeros(n_samples, dtype=np.float32)
            is_anom = np.zeros(n_samples, dtype=bool)
            norm_scores = np.full(n_samples, 0.5, dtype=np.float32)

        # 3. Decision Policy Evaluation per Sample
        results = []
        for i in range(n_samples):
            top_bp_idx = int(np.argmax(X[i])) + 1
            top_bp_val = float(X[i, top_bp_idx - 1])
            dom_bp = f"bp_{top_bp_idx:02d}"

            anom_res = {
                "is_anomaly": bool(is_anom[i]),
                "anomaly_score": round(float(iso_scores[i]), 4),
                "normalized_score": round(float(norm_scores[i]), 4),
                "verdict": "ANOMALOUS" if is_anom[i] else "NORMAL",
                "threshold": round(float(anomaly_th), 4)
            }

            policy = classify_detection_outcome(
                threat_confidence=float(ens_probs[i]),
                anomaly_result=anom_res,
                dominant_basepoint=dom_bp,
                destination_port=ports[i],
                threat_threshold=self.ensemble.threshold,
                anomaly_threshold=anomaly_th,
                experiment_id=self.experiment_id
            )

            p_status = policy["prediction_status"]
            if p_status in ["ANN_ALERT", "KNOWN_THREAT"]:
                severity = "CRITICAL" if ens_probs[i] > 0.85 else "HIGH"
            elif p_status == "UNKNOWN_ANOMALOUS":
                severity = "HIGH" if anom_res["is_anomaly"] else "MEDIUM"
            else:
                severity = "LOW"

            results.append({
                "verdict": p_status,
                "prediction_status": p_status,
                "predicted_class": policy["predicted_class"],
                "confidence": policy["confidence"],
                "anomaly_status": policy["anomaly_status"],
                "anomaly_score": policy["anomaly_score"],
                "detection_reason": policy["detection_reason"],
                "requires_investigation": policy["requires_investigation"],
                "threat_confidence": float(ens_probs[i]),
                "threshold": self.ensemble.threshold,
                "severity": severity,
                "dominant_basepoint": dom_bp,
                "dominant_basepoint_similarity": top_bp_val,
                "profile_vector": [float(x) for x in X[i]],
                "model_breakdown": {
                    "fcnn": float(p_fcnn[i]),
                    "cnn": float(p_cnn[i]),
                    "lstm": float(p_lstm[i])
                },
                "submodel_thresholds": self.submodel_thresholds,
                "experiment_id": self.experiment_id,
                "anomaly": anom_res
            })

        return results

    def flow_to_profile(self, flow: Dict[str, Any]) -> np.ndarray:
        """
        Converts flow parameters to an 8-dimensional basepoint cosine profile:
          1. Evaluate against fitted thresholds to obtain event counts
          2. Transform via fitted TF-IDF
          3. Compute cosine similarity with the 8 basepoints
        """
        if self.thresholds is None or self.tfidf_model is None or self.basepoints is None:
            raise RuntimeError(f"Event profiling artifacts not loaded from {self.data_dir}.")

        # Derived event rules
        hfr = 1 if float(flow.get("flow_count", 1)) > self.thresholds["HIGH_FLOW_RATE"]["threshold"] else 0
        hpr = 1 if float(flow.get("flow_packets_s", 0)) > self.thresholds["HIGH_PACKET_RATE"]["threshold"] else 0
        hbr = 1 if float(flow.get("flow_bytes_s", 0)) > self.thresholds["HIGH_BYTE_RATE"]["threshold"] else 0
        syn = 1 if float(flow.get("syn_flag_count", 0)) >= self.thresholds["SYN_ACTIVITY"]["threshold"] else 0
        src = 1 if float(flow.get("flow_duration", 1000000)) < self.thresholds["SHORT_REPEATED_CONNECTIONS"]["threshold"] else 0

        counts = np.array([[hfr, hpr, hbr, syn, src]], dtype=np.int64)
        vectors = transform(counts, self.tfidf_model)
        profiles = compute_profiles(vectors, self.basepoints)
        return profiles[0]

    def predict_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        End-to-end inference from a raw network flow dictionary.
        """
        port = int(flow.get("destination_port", 0)) if flow.get("destination_port") else 0
        profile = self.flow_to_profile(flow)
        result = self.predict_profile(profile, destination_port=port)
        result["flow_metadata"] = {
            "source_ip": str(flow.get("source_ip", "N/A")),
            "destination_ip": str(flow.get("destination_ip", "N/A")),
            "source_port": flow.get("source_port", 0),
            "destination_port": port,
            "protocol": flow.get("protocol", 6)
        }
        return result
