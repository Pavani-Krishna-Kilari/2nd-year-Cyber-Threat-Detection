"""
Training Pipeline for Event-Profile-Based Threat Detection Models.

Strict Leakage-Free Design:
  - Fits model weights strictly on TRAINING split.
  - Applies cost-sensitive class weights to counter the severe imbalance (0.024% attacks).
  - Tunes decision thresholds on VALIDATION split.
  - Evaluates final performance on unseen TEST split.
  - Saves model artifacts and metrics to models/saved/ and models/metrics/.
"""

import os
import json
import time
from pathlib import Path
from typing import Dict, Any, Tuple

import numpy as np
import pandas as pd

from src.config import PROJECT_ROOT, resolve_path
from .fcnn import build_fcnn
from .cnn import build_cnn
from .lstm import build_lstm
from .ensemble import SoftVotingEnsemble
from .evaluate import compute_metrics, find_optimal_threshold

PROFILE_COLS = [f"bp_{i:02d}" for i in range(1, 9)]
MODELS_DIR = PROJECT_ROOT / "models"
SAVED_DIR = MODELS_DIR / "saved"
METRICS_DIR = MODELS_DIR / "metrics"


def load_datasets() -> Tuple[Dict[str, np.ndarray], Dict[str, np.ndarray]]:
    """
    Loads event profiles and targets, partitioned by train/val/test splits.
    """
    prof_path = resolve_path("data/processed/event_profiles/event_profiles.csv")
    tgt_path = resolve_path("data/processed/event_profiles/event_set_targets.csv")
    
    if not prof_path.exists() or not tgt_path.exists():
        raise FileNotFoundError(
            f"Required data files not found in data/processed/event_profiles/.\n"
            f"Profiles: {prof_path}\nTargets: {tgt_path}"
        )
        
    print(f"Loading event profiles from {prof_path.name} ...")
    df_prof = pd.read_csv(prof_path, usecols=["event_set_id", "split"] + PROFILE_COLS)
    
    print(f"Loading targets from {tgt_path.name} ...")
    df_tgt = pd.read_csv(tgt_path, usecols=["event_set_id", "target_binary", "target_multiclass"])
    
    merged = df_prof.merge(df_tgt, on="event_set_id", how="inner")
    
    X_dict = {}
    y_dict = {}
    
    for split_name in ["train", "validation", "test"]:
        sub = merged[merged["split"] == split_name]
        X_dict[split_name] = sub[PROFILE_COLS].to_numpy(dtype=np.float32)
        y_dict[split_name] = sub["target_binary"].to_numpy(dtype=np.int8)
        print(f"  Split '{split_name}': {len(sub):,} samples, {y_dict[split_name].sum():,} attacks")
        
    return X_dict, y_dict


def calculate_class_weights(y_train: np.ndarray) -> Dict[int, float]:
    """
    Computes balanced class weights for severe class imbalance:
      w_j = N / (2 * N_j)
    """
    total = len(y_train)
    n_pos = int(y_train.sum())
    n_neg = total - n_pos
    
    w0 = total / (2.0 * max(n_neg, 1))
    w1 = total / (2.0 * max(n_pos, 1))
    
    print(f"Calculated class weights: Class 0 (Normal): {w0:.4f}, Class 1 (Threat): {w1:.4f}")
    return {0: float(w0), 1: float(w1)}


def train_and_evaluate_all(epochs: int = 10, batch_size: int = 512) -> Dict[str, Any]:
    """
    Full training pipeline for FCNN, 1D-CNN, LSTM, and Soft-Voting Ensemble.
    """
    SAVED_DIR.mkdir(parents=True, exist_ok=True)
    METRICS_DIR.mkdir(parents=True, exist_ok=True)
    
    X_dict, y_dict = load_datasets()
    X_train, y_train = X_dict["train"], y_dict["train"]
    X_val, y_val = X_dict["validation"], y_dict["validation"]
    X_test, y_test = X_dict["test"], y_dict["test"]
    
    class_weights = calculate_class_weights(y_train)
    
    models = {
        "FCNN": build_fcnn(input_dim=8),
        "CNN": build_cnn(input_dim=8),
        "LSTM": build_lstm(input_dim=8, time_steps=1)
    }
    
    val_probas = {}
    test_probas = {}
    optimal_thresholds = {}
    training_histories = {}
    
    for name, model in models.items():
        print(f"\n==================== Training {name} ====================")
        t0 = time.time()
        history = model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            class_weight=class_weights,
            verbose=1
        )
        t_elapsed = time.time() - t0
        print(f"{name} trained in {t_elapsed:.2f} seconds.")
        
        # Save model
        model_save_path = SAVED_DIR / f"{name.lower()}_model.keras"
        model.save(model_save_path)
        print(f"Saved {name} model to {model_save_path}")
        
        # Predictions
        v_prob = model.predict(X_val, batch_size=batch_size, verbose=0).reshape(-1)
        t_prob = model.predict(X_test, batch_size=batch_size, verbose=0).reshape(-1)
        
        val_probas[name] = v_prob
        test_probas[name] = t_prob
        
        # Tune threshold on validation set
        thresh, val_f1 = find_optimal_threshold(y_val, v_prob)
        optimal_thresholds[name] = thresh
        print(f"Optimal validation threshold for {name}: {thresh:.3f} (Val F1: {val_f1:.4f})")
        
        training_histories[name] = {k: [float(v) for v in vals] for k, vals in history.history.items()}
        
    # Build Ensemble
    print("\n==================== Evaluating Ensemble ====================")
    ensemble = SoftVotingEnsemble(
        fcnn_model=models["FCNN"],
        cnn_model=models["CNN"],
        lstm_model=models["LSTM"],
        weights=[1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0]
    )
    
    val_ens_prob = ensemble.predict_proba(X_val)
    test_ens_prob = ensemble.predict_proba(X_test)
    
    ens_thresh, ens_val_f1 = find_optimal_threshold(y_val, val_ens_prob)
    ensemble.set_threshold(ens_thresh)
    optimal_thresholds["Ensemble"] = ens_thresh
    print(f"Optimal validation threshold for Ensemble: {ens_thresh:.3f} (Val F1: {ens_val_f1:.4f})")
    
    # Save ensemble configuration
    ens_config = {
        "weights": ensemble.weights,
        "threshold": ensemble.threshold,
        "val_f1": ens_val_f1
    }
    with open(SAVED_DIR / "ensemble_config.json", "w", encoding="utf-8") as f:
        json.dump(ens_config, f, indent=2)
        
    # Evaluate all models on TEST split
    results = {
        "evaluated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "test_samples": len(y_test),
        "test_attacks": int(y_test.sum()),
        "test_normal": int(len(y_test) - y_test.sum()),
        "models": {}
    }
    
    for name in ["FCNN", "CNN", "LSTM"]:
        metrics = compute_metrics(y_test, test_probas[name], threshold=optimal_thresholds[name])
        results["models"][name] = metrics
        
    ens_metrics = compute_metrics(y_test, test_ens_prob, threshold=ens_thresh)
    results["models"]["Ensemble"] = ens_metrics
    
    # Save benchmark report
    with open(METRICS_DIR / "evaluation_report.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
        
    with open(METRICS_DIR / "training_history.json", "w", encoding="utf-8") as f:
        json.dump(training_histories, f, indent=2)
        
    print("\n==================== TEST SET FINAL RESULTS ====================")
    for model_name, m in results["models"].items():
        print(f"Model: {model_name:10s} | Threshold: {m['threshold']:.3f} | Recall: {m['recall']:.4f} | Prec: {m['precision']:.4f} | F1: {m['f1_score']:.4f} | PR-AUC: {m['pr_auc']:.4f} | ROC-AUC: {m['roc_auc']:.4f} | FPR: {m['false_positive_rate']:.6f}")
        
    return results


if __name__ == "__main__":
    train_and_evaluate_all()
