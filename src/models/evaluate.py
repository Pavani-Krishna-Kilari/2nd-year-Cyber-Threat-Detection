"""
Evaluation and Metrics Calculation for Threat Detection Models.

Evaluates models with:
  - Precision, Recall, F1-score
  - PR-AUC (Precision-Recall Area Under Curve)
  - ROC-AUC
  - False Positive Rate (FPR = FP / (FP + TN))
  - Confusion Matrix [[TN, FP], [FN, TP]]
  - Threshold Calibration on Validation split to avoid data leakage
"""

from typing import Dict, Any, Tuple
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    precision_recall_curve,
    auc,
    confusion_matrix,
    average_precision_score
)


def compute_metrics(
    y_true: np.ndarray,
    y_pred_proba: np.ndarray,
    threshold: float = 0.50
) -> Dict[str, Any]:
    """
    Computes comprehensive SIEM threat detection metrics.
    """
    y_true = np.asarray(y_true, dtype=np.int8)
    y_pred_proba = np.asarray(y_pred_proba, dtype=np.float32)
    y_pred = (y_pred_proba >= threshold).astype(np.int8)

    acc = float(accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))

    try:
        roc_val = float(roc_auc_score(y_true, y_pred_proba))
    except Exception:
        roc_val = 0.5

    try:
        pr_auc_val = float(average_precision_score(y_true, y_pred_proba))
    except Exception:
        pr_auc_val = 0.0

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    return {
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "pr_auc": pr_auc_val,
        "roc_auc": roc_val,
        "false_positive_rate": fpr,
        "confusion_matrix": {
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "tp": tp,
            "matrix": [[tn, fp], [fn, tp]]
        },
        "threshold": float(threshold),
        "total_samples": int(len(y_true)),
        "attack_samples": int(y_true.sum()),
        "normal_samples": int(len(y_true) - y_true.sum())
    }


def find_optimal_threshold(
    y_val_true: np.ndarray,
    y_val_proba: np.ndarray,
    num_steps: int = 50
) -> Tuple[float, float]:
    """
    Finds the threshold tau in [0.05, 0.95] that maximizes F1-score on the VALIDATION split.
    Prevents leakage into test split.
    Returns (best_threshold, best_f1).
    """
    y_val_true = np.asarray(y_val_true, dtype=np.int8)
    y_val_proba = np.asarray(y_val_proba, dtype=np.float32)

    best_thresh = 0.50
    best_f1 = -1.0

    for thresh in np.linspace(0.05, 0.95, num_steps):
        preds = (y_val_proba >= thresh).astype(np.int8)
        f1 = f1_score(y_val_true, preds, zero_division=0)
        if f1 > best_f1:
            best_f1 = float(f1)
            best_thresh = float(thresh)

    return best_thresh, best_f1
