"""
Anomaly Detection Module using Isolation Forest for Event Profiles.

Trains an unsupervised Isolation Forest on normal/training event profiles (bp_01 to bp_08).
Enables zero-day and out-of-distribution threat detection without relying on supervised labels.
Adheres strictly to train/validation/test separation without data leakage.
"""

import json
import time
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score, precision_score, recall_score, f1_score, confusion_matrix

from src.config import PROJECT_ROOT, resolve_path

PROFILE_COLS = [f"bp_{i:02d}" for i in range(1, 9)]
SAVED_DIR = PROJECT_ROOT / "models" / "saved"
METRICS_DIR = PROJECT_ROOT / "models" / "metrics"
MODEL_PATH = SAVED_DIR / "isolation_forest.joblib"
METRICS_PATH = METRICS_DIR / "anomaly_report.json"

SAVED_DIR_EXP_A = PROJECT_ROOT / "models" / "saved_exp_a"
MODEL_PATH_EXP_A = SAVED_DIR_EXP_A / "isolation_forest.joblib"
CONFIG_PATH_EXP_A = SAVED_DIR_EXP_A / "anomaly_config.json"


def train_isolation_forest(
    n_estimators: int = 100,
    max_samples: int = 2048,
    contamination: float = 0.005,
    random_state: int = 42
) -> Dict[str, Any]:
    """
    Fits Isolation Forest strictly on TRAINING event profiles.
    Tunes threshold on VALIDATION split, and evaluates on unseen TEST split.
    """
    SAVED_DIR.mkdir(parents=True, exist_ok=True)
    METRICS_DIR.mkdir(parents=True, exist_ok=True)

    prof_path = resolve_path("data/processed/event_profiles/event_profiles.csv")
    tgt_path = resolve_path("data/processed/event_profiles/event_set_targets.csv")

    if not prof_path.exists() or not tgt_path.exists():
        raise FileNotFoundError("Event profiles or targets not found in data/processed/event_profiles/.")

    print("Loading event profiles for Anomaly Detection ...")
    df_prof = pd.read_csv(prof_path, usecols=["event_set_id", "split"] + PROFILE_COLS)
    df_tgt = pd.read_csv(tgt_path, usecols=["event_set_id", "target_binary"])
    merged = df_prof.merge(df_tgt, on="event_set_id", how="inner")

    # Strictly separate splits
    train_mask = merged["split"] == "train"
    val_mask = merged["split"] == "validation"
    test_mask = merged["split"] == "test"

    X_train = merged.loc[train_mask, PROFILE_COLS].to_numpy(dtype=np.float32)
    y_train = merged.loc[train_mask, "target_binary"].to_numpy(dtype=np.int8)

    X_val = merged.loc[val_mask, PROFILE_COLS].to_numpy(dtype=np.float32)
    y_val = merged.loc[val_mask, "target_binary"].to_numpy(dtype=np.int8)

    X_test = merged.loc[test_mask, PROFILE_COLS].to_numpy(dtype=np.float32)
    y_test = merged.loc[test_mask, "target_binary"].to_numpy(dtype=np.int8)

    print(f"Training Isolation Forest on {len(X_train):,} training event profiles ...")
    t0 = time.time()
    iso = IsolationForest(
        n_estimators=n_estimators,
        max_samples=min(max_samples, len(X_train)),
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1
    )
    # Fit strictly on training split
    iso.fit(X_train)
    t_train = time.time() - t0
    print(f"Isolation Forest fitted in {t_train:.2f} seconds.")

    # Save model
    joblib.dump(iso, MODEL_PATH)

    # Invert decision function so higher score = MORE anomalous
    val_raw_scores = iso.decision_function(X_val)
    val_anomaly_scores = -val_raw_scores

    test_raw_scores = iso.decision_function(X_test)
    test_anomaly_scores = -test_raw_scores

    # Tune threshold on validation split
    best_thresh = float(np.percentile(val_anomaly_scores, 99.0))
    best_f1 = -1.0
    for pct in np.linspace(95.0, 99.9, 50):
        thresh = float(np.percentile(val_anomaly_scores, pct))
        preds = (val_anomaly_scores >= thresh).astype(np.int8)
        f1 = f1_score(y_val, preds, zero_division=0)
        if f1 > best_f1:
            best_f1 = float(f1)
            best_thresh = thresh

    print(f"Optimal validation anomaly threshold: {best_thresh:.4f} (Val F1: {best_f1:.4f})")

    # Evaluate on UNSEEN TEST split
    test_preds = (test_anomaly_scores >= best_thresh).astype(np.int8)
    cm = confusion_matrix(y_test, test_preds, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    try:
        roc_auc = float(roc_auc_score(y_test, test_anomaly_scores))
    except Exception:
        roc_auc = 0.5

    report = {
        "model": "Isolation Forest",
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "training_samples": len(X_train),
        "validation_samples": len(X_val),
        "test_samples": len(X_test),
        "n_estimators": n_estimators,
        "max_samples": max_samples,
        "contamination": contamination,
        "optimal_threshold": float(best_thresh),
        "validation_f1": float(best_f1),
        "metrics_on_test": {
            "accuracy": float((tp + tn) / len(y_test)),
            "precision": float(precision_score(y_test, test_preds, zero_division=0)),
            "recall": float(recall_score(y_test, test_preds, zero_division=0)),
            "f1_score": float(f1_score(y_test, test_preds, zero_division=0)),
            "roc_auc": roc_auc,
            "false_positive_rate": fpr,
            "confusion_matrix": {
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "matrix": [[tn, fp], [fn, tp]]
            }
        }
    }

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"Test Set Anomaly Detection Metrics: Recall={report['metrics_on_test']['recall']:.4f}, Prec={report['metrics_on_test']['precision']:.4f}, FPR={fpr:.6f}, ROC-AUC={roc_auc:.4f}")
    return report


class AnomalyDetector:
    """Production runtime anomaly detector using fitted Isolation Forest."""

    def __init__(
        self,
        model_path: Optional[Path] = None,
        metrics_path: Optional[Path] = None,
        models_dir: Optional[Path] = None
    ):
        if models_dir is not None:
            self.model_path = models_dir / "isolation_forest.joblib"
            cfg_p = models_dir / "anomaly_config.json"
            self.metrics_path = cfg_p if cfg_p.exists() else (models_dir / "anomaly_report.json")
        else:
            if MODEL_PATH_EXP_A.exists():
                self.model_path = model_path or MODEL_PATH_EXP_A
                self.metrics_path = metrics_path or CONFIG_PATH_EXP_A
            else:
                self.model_path = model_path or MODEL_PATH
                self.metrics_path = metrics_path or METRICS_PATH

        self.model: Optional[IsolationForest] = None
        self.threshold: float = 0.0
        self.report: Dict[str, Any] = {}
        self._load()

    def _load(self):
        if self.model_path.exists():
            try:
                self.model = joblib.load(self.model_path)
            except Exception as e:
                print(f"Warning: could not load Isolation Forest: {e}")

        if self.metrics_path.exists():
            try:
                self.report = json.loads(self.metrics_path.read_text(encoding="utf-8"))
                self.threshold = float(self.report.get("optimal_threshold", 0.0))
            except Exception:
                pass

    def is_ready(self) -> bool:
        return self.model is not None

    def predict_single(self, vector_8d: Union[list, np.ndarray]) -> Dict[str, Any]:
        """
        Calculates anomaly score and verdict for an 8D event profile vector.
        """
        if not self.is_ready():
            return {
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "normalized_score": 0.0,
                "verdict": "NORMAL",
                "threshold": self.threshold
            }

        X = np.asarray(vector_8d, dtype=np.float32).reshape(1, -1)
        # raw decision function: negative means outlier
        raw = float(self.model.decision_function(X)[0])
        anomaly_score = -raw
        is_anomaly = anomaly_score >= self.threshold

        # Normalized confidence in [0, 1] for visual display
        normalized = float(1.0 / (1.0 + np.exp(-5.0 * (anomaly_score - self.threshold))))

        return {
            "is_anomaly": bool(is_anomaly),
            "anomaly_score": round(float(anomaly_score), 4),
            "normalized_score": round(normalized, 4),
            "verdict": "ANOMALOUS" if is_anomaly else "NORMAL",
            "threshold": round(float(self.threshold), 4)
        }
