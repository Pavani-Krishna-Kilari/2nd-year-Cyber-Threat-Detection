"""
SIEM Decision Policy Module for Tri-State Threat Detection.

Defines a reliable, data-grounded decision mechanism combining:
  1. Deep Neural Ensemble (FCNN + 1D-CNN + LSTM) soft-voted probabilities
  2. Unsupervised Isolation Forest out-of-distribution anomaly scores
  3. Strict thresholds calibrated exclusively on the Thursday VALIDATION split

Experiment B Tri-State Detection Outcomes (Authoritative Priority Order):
  Priority 1. ANN_ALERT:
     Triggered when ensemble threat probability meets or exceeds the calibrated
     Experiment B ensemble threshold (p_threat >= tau_ensemble = 0.6561).
     Requires investigation: True.
     Note: The ANN is a binary classifier and does not identify attack families.

  Priority 2. UNKNOWN_ANOMALOUS:
     Triggered when ensemble threat probability is below alert threshold, but
     Isolation Forest flags an out-of-distribution anomaly:
     (anomaly_score = -decision_function(X) >= tau_anomaly = -0.012676).
     Identifies statistical behavioral deviations or novel vector outliers.
     Requires investigation: True (not automatically a confirmed cyberattack).

  Priority 3. NORMAL:
     Triggered when ensemble threat probability is below threshold (p_threat < 0.6561)
     AND Isolation Forest confirms normal baseline distribution (anomaly_score < -0.012676).
     Requires investigation: False.
"""

from typing import Dict, Any, Optional
import numpy as np

# Experiment B Calibrated Thresholds (Authoritative from Phase 4 & Evaluation Report)
ANN_ALERT_THRESHOLD_EXP_B = 0.6561224489795918   # ~0.6561 (Soft-voting Ensemble optimal F1 threshold)
DEFAULT_ANOMALY_THRESHOLD_EXP_B = -0.012676391259280995  # ~ -0.012676 (99th percentile benign validation)

# Submodel individual thresholds (Experiment B)
FCNN_THRESHOLD_EXP_B = 0.8581632653061224        # ~0.8582
CNN_THRESHOLD_EXP_B = 0.3438775510204081         # ~0.3439
LSTM_THRESHOLD_EXP_B = 0.7663265306122449        # ~0.7663

# Active Defaults (Experiment B)
ANN_ALERT_THRESHOLD = ANN_ALERT_THRESHOLD_EXP_B
DEFAULT_ANOMALY_THRESHOLD = DEFAULT_ANOMALY_THRESHOLD_EXP_B

# Experiment A Legacy References (Preserved for compatibility)
KNOWN_THREAT_THRESHOLD = 0.8398
NORMAL_CONFIDENCE_THRESHOLD = 0.30
DEFAULT_ANOMALY_THRESHOLD_EXP_A = -0.002268


def classify_detection_outcome(
    threat_confidence: float,
    anomaly_result: Optional[Dict[str, Any]] = None,
    dominant_basepoint: str = "bp_01",
    destination_port: Optional[int] = None,
    threat_threshold: Optional[float] = None,
    normal_confidence_threshold: float = NORMAL_CONFIDENCE_THRESHOLD,
    anomaly_threshold: Optional[float] = None,
    experiment_id: str = "A"
) -> Dict[str, Any]:
    """
    Evaluates the tri-state detection policy for an evaluated event profile.

    Experiment B Evaluation Order (Strict Hierarchical Priority):
      1. Priority 1 (ANN Alert): p_threat >= threat_threshold -> KNOWN_THREAT
      2. Priority 2 (Anomaly Detection): anomaly_score >= anomaly_threshold -> UNKNOWN_ANOMALOUS
      3. Priority 3 (Normal Traffic): otherwise -> NORMAL

    Returns:
        Dict with keys:
          - prediction_status: 'NORMAL' | 'KNOWN_THREAT' | 'UNKNOWN_ANOMALOUS'
          - verdict: 'NORMAL' | 'KNOWN_THREAT' | 'UNKNOWN_ANOMALOUS'
          - predicted_class: Descriptive classification string
          - confidence: Confidence score in [0.0, 1.0]
          - anomaly_status: 'NORMAL' | 'ANOMALOUS' | 'NOT_EVALUATED'
          - anomaly_score: float
          - detection_reason: Human-readable explanation of why the verdict was issued
          - requires_investigation: bool
    """
    # 1. Validate and sanitize threat confidence
    try:
        p_threat = float(threat_confidence)
        if np.isnan(p_threat) or not np.isfinite(p_threat):
            p_threat = 0.50
    except (TypeError, ValueError):
        p_threat = 0.50

    p_threat = float(np.clip(p_threat, 0.0, 1.0))

    # Determine thresholds based on experiment
    if experiment_id == "B":
        th_threat = threat_threshold if threat_threshold is not None else ANN_ALERT_THRESHOLD_EXP_B
        th_anomaly = anomaly_threshold if anomaly_threshold is not None else DEFAULT_ANOMALY_THRESHOLD_EXP_B
    else:
        th_threat = threat_threshold if threat_threshold is not None else KNOWN_THREAT_THRESHOLD
        th_anomaly = anomaly_threshold if anomaly_threshold is not None else DEFAULT_ANOMALY_THRESHOLD_EXP_A

    # 2. Extract Isolation Forest anomaly telemetry
    if anomaly_result and isinstance(anomaly_result, dict):
        if "threshold" in anomaly_result and anomaly_result["threshold"] is not None:
            try:
                th_anomaly = float(anomaly_result["threshold"])
            except (TypeError, ValueError):
                pass
        anomaly_score = float(anomaly_result.get("anomaly_score", 0.0))
        if "is_anomaly" in anomaly_result and anomaly_result["is_anomaly"] is not None:
            is_anomaly = bool(anomaly_result["is_anomaly"])
        else:
            is_anomaly = (anomaly_score >= th_anomaly)
        anomaly_status = "ANOMALOUS" if is_anomaly else "NORMAL"
        norm_anomaly_score = float(anomaly_result.get("normalized_score", 0.5))
    else:
        anomaly_score = 0.0
        is_anomaly = False
        anomaly_status = "NOT_EVALUATED"
        norm_anomaly_score = 0.5

    # 3. Decision Policy Evaluation
    if experiment_id == "B":
        # EXPERIMENT B STRICT PRIORITY HIERARCHY
        # PRIORITY 1: ANN Alert -> KNOWN_THREAT
        if p_threat >= th_threat:
            status = "KNOWN_THREAT"
            cls_name = "ANN Threat Alert (Binary Classifier - Subclass Not Identified)"
            reason = (
                f"Ensemble threat probability ({p_threat * 100:.2f}%) exceeds Experiment B alert threshold "
                f"(\u03c4 = {th_threat * 100:.2f}%), aligned with profile basepoint {dominant_basepoint}. "
                f"Note: ANN is a binary classifier and does not identify specific attack families (e.g. Bot, DDoS, PortScan)."
            )
            conf = p_threat
            requires_inv = True

        # PRIORITY 2: Anomaly Detection
        elif is_anomaly or (anomaly_score >= th_anomaly and anomaly_result is not None):
            status = "UNKNOWN_ANOMALOUS"
            cls_name = "Unknown / Out-of-Distribution Anomaly"
            reason = (
                f"Out-of-distribution anomaly detected by Isolation Forest (score: {anomaly_score:.4f} \u2265 "
                f"\u03c4 = {th_anomaly:.4f}) while ANN threat probability is below threshold "
                f"({p_threat * 100:.2f}% < {th_threat * 100:.2f}%). "
                f"Behavioral anomaly indicates statistical deviation from normal traffic, not a confirmed cyberattack. Requires SOC triage."
            )
            conf = norm_anomaly_score
            requires_inv = True

        # PRIORITY 3: Normal
        else:
            status = "NORMAL"
            cls_name = "Benign Network Traffic"
            normal_conf = round(1.0 - p_threat, 4)
            reason = (
                f"Normal traffic confirmed: Ensemble threat probability ({p_threat * 100:.2f}%) is below alert threshold "
                f"(\u03c4 = {th_threat * 100:.2f}%) and Isolation Forest confirms baseline distribution "
                f"(score: {anomaly_score:.4f} < \u03c4 = {th_anomaly:.4f})."
            )
            conf = normal_conf
            requires_inv = False

    else:
        # EXPERIMENT A LEGACY POLICY (Preserved for compatibility)
        if p_threat >= th_threat:
            status = "KNOWN_THREAT"
            cls_name = "Known Threat Pattern (Subclass Not Classified)"
            port_info = f" (Contextual Port: {destination_port})" if destination_port is not None else ""
            reason = (
                f"Ensemble threat confidence ({p_threat * 100:.1f}%) meets known threat threshold "
                f"(\u03c4 = {th_threat * 100:.1f}%), aligned with profile basepoint {dominant_basepoint}. "
                f"Specific attack subclass is not classified (binary ANN model). Contextual evidence{port_info}."
            )
            conf = p_threat
            requires_inv = True
        elif p_threat <= normal_confidence_threshold and not is_anomaly:
            status = "NORMAL"
            cls_name = "Benign Network Traffic"
            normal_conf = round(1.0 - p_threat, 4)
            reason = (
                f"Ensemble confidently predicts benign network traffic ({normal_conf * 100:.1f}% normal confidence, "
                f"p_threat \u2264 {normal_confidence_threshold * 100:.1f}%) and Isolation Forest confirms baseline distribution "
                f"(score: {anomaly_score:.4f} < \u03c4 = {th_anomaly:.4f})."
            )
            conf = normal_conf
            requires_inv = False
        else:
            status = "UNKNOWN_ANOMALOUS"
            requires_inv = True
            if is_anomaly and p_threat <= normal_confidence_threshold:
                cls_name = "Unknown / Anomalous Activity (Unconfirmed Attack)"
                reason = (
                    f"Out-of-distribution anomaly detected by Isolation Forest (score: {anomaly_score:.4f} \u2265 "
                    f"\u03c4 = {th_anomaly:.4f}) despite low ensemble threat probability ({p_threat * 100:.1f}%). "
                    f"Behavioral anomaly indicates statistical deviation from normal traffic, not a confirmed cyberattack. Requires SOC triage."
                )
                conf = norm_anomaly_score
            elif is_anomaly and (normal_confidence_threshold < p_threat < th_threat):
                cls_name = "Compound Anomalous Threat"
                reason = (
                    f"Compound alert: Ensemble threat prediction is uncertain ({p_threat * 100:.1f}%) and "
                    f"Isolation Forest detected significant out-of-distribution anomaly (score: {anomaly_score:.4f} \u2265 "
                    f"\u03c4 = {th_anomaly:.4f}). Unseen pattern requires SOC investigation."
                )
                conf = round(max(p_threat, norm_anomaly_score), 4)
            else:
                cls_name = "Prediction Uncertainty / Review Required"
                reason = (
                    f"Prediction uncertainty: Ensemble threat probability ({p_threat * 100:.1f}%) falls into ambiguous margin "
                    f"({normal_confidence_threshold * 100:.1f}% - {th_threat * 100:.1f}%), while Isolation Forest confirms normal distribution. "
                    f"Flagged for review due to model uncertainty, NOT a confirmed cyberattack."
                )
                conf = round(max(p_threat, 1.0 - p_threat), 4)

    return {
        "prediction_status": status,
        "verdict": status,
        "predicted_class": cls_name,
        "confidence": round(float(conf), 4),
        "anomaly_status": anomaly_status,
        "anomaly_score": round(float(anomaly_score), 4),
        "detection_reason": reason,
        "requires_investigation": bool(requires_inv)
    }
