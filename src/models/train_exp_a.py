"""
Controlled Model Training Pipeline for Experiment A
===================================================
Project: AI-Based SIEM System for Cyber Threat Detection Using Event Profiles
Input Directory: data/processed/event_profiles_exp_a/
Output Directory: models/saved_exp_a/ and models/metrics_exp_a/

Safety & Methodology Rules:
  - Preserves data/processed/event_profiles/ and models/saved/ completely untouched.
  - Model inputs strictly restricted to bp_01 through bp_08 (no IDs, IPs, ports, timestamps, or labels).
  - Training partition used for fitting only.
  - Validation partition used for early stopping, model selection, and threshold calibration.
  - Final evaluation performed strictly on held-out test split.
  - Loss-weighted classification to handle severe class imbalance without synthetic oversampling.
  - Isolation Forest fitted exclusively on benign training profiles.
"""

import os
import sys
import json
import time
import shutil
import hashlib
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional, Union

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix
)

# Set random seed for reproducibility
SEED = 42
np.random.seed(SEED)

try:
    import keras
    from keras import layers, models, regularizers, callbacks
    keras.utils.set_random_seed(SEED)
    HAS_KERAS = True
except ImportError:
    try:
        from tensorflow import keras
        from tensorflow.keras import layers, models, regularizers, callbacks
        keras.utils.set_random_seed(SEED)
        HAS_KERAS = True
    except ImportError:
        HAS_KERAS = False

from src.config import PROJECT_ROOT, resolve_path
from src.event_profiles.validation import PROFILE_ID_COLUMNS

PROFILE_COLS = [f"bp_{i:02d}" for i in range(1, 9)]
INPUT_DIR = PROJECT_ROOT / "data" / "processed" / "event_profiles_exp_a"
SAVED_DIR_EXP_A = PROJECT_ROOT / "models" / "saved_exp_a"
METRICS_DIR_EXP_A = PROJECT_ROOT / "models" / "metrics_exp_a"

# Frozen baseline paths for preservation checks
BASELINE_PROCESSED_DIR = PROJECT_ROOT / "data" / "processed" / "event_profiles"
BASELINE_SAVED_DIR = PROJECT_ROOT / "models" / "saved"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def load_exp_a_datasets():
    """
    Loads Experiment A profiles and targets, verifying 1-to-1 joins and feature isolation.
    """
    prof_path = INPUT_DIR / "event_profiles.csv"
    tgt_path = INPUT_DIR / "event_set_targets.csv"

    if not prof_path.exists() or not tgt_path.exists():
        raise FileNotFoundError(f"Experiment A profiles or targets missing in {INPUT_DIR}")

    print(f"Loading Experiment A profiles from {prof_path.name} ...")
    df_prof = pd.read_csv(prof_path)
    
    # Strict feature restriction check
    extra_cols = [c for c in df_prof.columns if c not in PROFILE_ID_COLUMNS and c not in PROFILE_COLS]
    if extra_cols:
        raise ValueError(f"CRITICAL ERROR: Forbidden columns detected in profile input: {extra_cols}")
    
    print(f"Loading Experiment A targets from {tgt_path.name} ...")
    df_tgt = pd.read_csv(tgt_path)

    merged = df_prof.merge(df_tgt[["event_set_id", "target_binary", "target_multiclass", "target_label"]],
                           on="event_set_id", how="inner", validate="one_to_one")

    X_dict = {}
    y_dict = {}
    y_mc_dict = {}
    labels_dict = {}

    for split in ["train", "validation", "test"]:
        sub = merged[merged["split"] == split]
        X_dict[split] = sub[PROFILE_COLS].to_numpy(dtype=np.float32)
        y_dict[split] = sub["target_binary"].to_numpy(dtype=np.int8)
        y_mc_dict[split] = sub["target_multiclass"].to_numpy(dtype=np.int64)
        labels_dict[split] = sub["target_label"].to_numpy()
        print(f"  Split '{split}': {len(sub):,} event sets | {int(y_dict[split].sum()):,} attack sets")

    return X_dict, y_dict, y_mc_dict, labels_dict


def calculate_class_weights(y_train: np.ndarray) -> Dict[int, float]:
    """
    Computes balanced class weights for severe binary class imbalance:
      w_j = N / (2 * N_j)
    """
    total = len(y_train)
    n_pos = int(y_train.sum())
    n_neg = total - n_pos

    w0 = total / (2.0 * max(n_neg, 1))
    w1 = total / (2.0 * max(n_pos, 1))

    print(f"Calculated Binary Class Weights: Class 0 (Benign)={w0:.6f}, Class 1 (Attack)={w1:.6f}")
    return {0: float(w0), 1: float(w1)}


def build_fcnn(input_dim: int = 8, lr: float = 0.001):
    inputs = layers.Input(shape=(input_dim,), name="profile_input")
    x = layers.Dense(64, activation="relu", kernel_regularizer=regularizers.l2(1e-4), name="dense_1")(inputs)
    x = layers.BatchNormalization(name="bn_1")(x)
    x = layers.Dropout(0.3, name="drop_1")(x)
    x = layers.Dense(32, activation="relu", kernel_regularizer=regularizers.l2(1e-4), name="dense_2")(x)
    x = layers.BatchNormalization(name="bn_2")(x)
    x = layers.Dropout(0.2, name="drop_2")(x)
    x = layers.Dense(16, activation="relu", name="dense_3")(x)
    outputs = layers.Dense(1, activation="sigmoid", name="threat_proba")(x)

    model = models.Model(inputs=inputs, outputs=outputs, name="FCNN_ExpA")
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=lr),
        loss="binary_crossentropy",
        metrics=["accuracy", keras.metrics.Precision(name="precision"), keras.metrics.Recall(name="recall"),
                 keras.metrics.AUC(name="pr_auc", curve="PR")]
    )
    return model


def build_cnn(input_dim: int = 8, lr: float = 0.001):
    inputs = layers.Input(shape=(input_dim,), name="profile_input")
    x = layers.Reshape((input_dim, 1), name="reshape_1d")(inputs)
    x = layers.Conv1D(32, kernel_size=3, padding="same", activation="relu",
                      kernel_regularizer=regularizers.l2(1e-4), name="conv_1")(x)
    x = layers.BatchNormalization(name="bn_1")(x)
    x = layers.Conv1D(64, kernel_size=3, padding="same", activation="relu",
                      kernel_regularizer=regularizers.l2(1e-4), name="conv_2")(x)
    x = layers.GlobalMaxPooling1D(name="maxpool")(x)
    x = layers.Dense(32, activation="relu", name="dense_proj")(x)
    x = layers.Dropout(0.2, name="drop")(x)
    outputs = layers.Dense(1, activation="sigmoid", name="threat_proba")(x)

    model = models.Model(inputs=inputs, outputs=outputs, name="1D_CNN_ExpA")
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=lr),
        loss="binary_crossentropy",
        metrics=["accuracy", keras.metrics.Precision(name="precision"), keras.metrics.Recall(name="recall"),
                 keras.metrics.AUC(name="pr_auc", curve="PR")]
    )
    return model


def build_lstm(input_dim: int = 8, lr: float = 0.001):
    inputs = layers.Input(shape=(input_dim,), name="profile_input")
    x = layers.Reshape((1, input_dim), name="reshape_seq")(inputs)
    x = layers.Bidirectional(
        layers.LSTM(32, return_sequences=False, kernel_regularizer=regularizers.l2(1e-4)),
        name="bi_lstm"
    )(x)
    x = layers.BatchNormalization(name="bn")(x)
    x = layers.Dense(16, activation="relu", name="dense_1")(x)
    x = layers.Dropout(0.2, name="drop")(x)
    outputs = layers.Dense(1, activation="sigmoid", name="threat_proba")(x)

    model = models.Model(inputs=inputs, outputs=outputs, name="LSTM_ExpA")
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=lr),
        loss="binary_crossentropy",
        metrics=["accuracy", keras.metrics.Precision(name="precision"), keras.metrics.Recall(name="recall"),
                 keras.metrics.AUC(name="pr_auc", curve="PR")]
    )
    return model


def find_optimal_threshold(y_true: np.ndarray, y_proba: np.ndarray, num_steps: int = 50) -> Tuple[float, float]:
    """Tunes optimal decision threshold tau in [0.05, 0.95] on VALIDATION data to maximize F1."""
    best_thresh = 0.50
    best_f1 = -1.0
    for thresh in np.linspace(0.05, 0.95, num_steps):
        preds = (y_proba >= thresh).astype(np.int8)
        f1 = f1_score(y_true, preds, zero_division=0)
        if f1 > best_f1:
            best_f1 = float(f1)
            best_thresh = float(thresh)
    return best_thresh, best_f1


def compute_comprehensive_metrics(y_true: np.ndarray, y_proba: np.ndarray, threshold: float,
                                  labels_true: np.ndarray) -> Dict[str, Any]:
    """Computes all required SIEM metrics and per-class test support."""
    y_true = np.asarray(y_true, dtype=np.int8)
    y_pred = (y_proba >= threshold).astype(np.int8)

    acc = float(accuracy_score(y_true, y_pred))
    bal_acc = float(balanced_accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    try:
        roc_val = float(roc_auc_score(y_true, y_proba))
    except Exception:
        roc_val = 0.5

    try:
        pr_auc_val = float(average_precision_score(y_true, y_proba))
    except Exception:
        pr_auc_val = 0.0

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    # Per-class attack support and detection recall
    all_known_classes = [
        "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest",
        "DoS slowloris", "FTP-Patator", "Heartbleed", "Infiltration", "PortScan",
        "SSH-Patator", "Web Attack - Brute Force", "Web Attack - Sql Injection", "Web Attack - XSS"
    ]
    
    per_class_support = {}
    observed_class_f1s = []
    
    df_eval = pd.DataFrame({"label": labels_true, "pred": y_pred, "true_bin": y_true})
    for cls_name in all_known_classes:
        sub_cls = df_eval[df_eval["label"] == cls_name]
        support = len(sub_cls)
        if support == 0:
            per_class_support[cls_name] = {
                "support": 0,
                "detected": 0,
                "recall": "N/A (0 test support)",
                "status": "UNTESTED_IN_SPLIT"
            }
        else:
            if cls_name == "BENIGN":
                detected = int((sub_cls["pred"] == 0).sum())
                cls_rec = float(detected / support)
            else:
                detected = int((sub_cls["pred"] == 1).sum())
                cls_rec = float(detected / support)
            per_class_support[cls_name] = {
                "support": support,
                "detected": detected,
                "recall": cls_rec,
                "status": "EVALUATED"
            }

    return {
        "accuracy": acc,
        "balanced_accuracy": bal_acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "pr_auc": pr_auc_val,
        "roc_auc": roc_val,
        "false_positive_rate": fpr,
        "confusion_matrix": {
            "tn": tn, "fp": fp, "fn": fn, "tp": tp,
            "matrix": [[tn, fp], [fn, tp]]
        },
        "threshold": float(threshold),
        "total_samples": int(len(y_true)),
        "attack_samples": int(y_true.sum()),
        "normal_samples": int(len(y_true) - y_true.sum()),
        "per_class_support": per_class_support
    }


def run_experiment_a_training(epochs: int = 15, batch_size: int = 2048):
    t_start = time.time()
    SAVED_DIR_EXP_A.mkdir(parents=True, exist_ok=True)
    METRICS_DIR_EXP_A.mkdir(parents=True, exist_ok=True)

    # 1. Baseline Preservation Fingerprinting
    print("=" * 70)
    print("CONTROLLED MODEL TRAINING FOR EXPERIMENT A")
    print(f"Inputs: {INPUT_DIR}")
    print(f"Saved Models: {SAVED_DIR_EXP_A}")
    print(f"Saved Metrics: {METRICS_DIR_EXP_A}")
    print("=" * 70)

    baseline_csv = BASELINE_PROCESSED_DIR / "event_profiles.csv"
    baseline_meta = BASELINE_PROCESSED_DIR / "event_profiles_metadata.json"
    h_csv_before = sha256_of(baseline_csv) if baseline_csv.exists() else None
    h_meta_before = sha256_of(baseline_meta) if baseline_meta.exists() else None

    # 2. Data Loading & Verification
    X_dict, y_dict, y_mc_dict, labels_dict = load_exp_a_datasets()
    X_train, y_train = X_dict["train"], y_dict["train"]
    X_val, y_val = X_dict["validation"], y_dict["validation"]
    X_test, y_test = X_dict["test"], y_dict["test"]
    labels_test = labels_dict["test"]

    class_weights = calculate_class_weights(y_train)

    # Model instances
    model_defs = {
        "FCNN": build_fcnn(input_dim=8),
        "CNN": build_cnn(input_dim=8),
        "LSTM": build_lstm(input_dim=8)
    }

    val_probas = {}
    test_probas = {}
    optimal_thresholds = {}
    training_histories = {}
    model_runtimes = {}
    best_epochs = {}

    # 3. Supervised Model Training (FCNN, CNN, LSTM)
    for name, model in model_defs.items():
        print(f"\n>>> Training {name} on {len(X_train):,} samples (Batch Size: {batch_size}) ...")
        t0 = time.time()
        
        es = callbacks.EarlyStopping(
            monitor="val_loss",
            patience=5,
            restore_best_weights=True,
            verbose=1
        )
        
        history = model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=epochs,
            batch_size=batch_size,
            class_weight=class_weights,
            callbacks=[es],
            verbose=1
        )
        t_model = time.time() - t0
        model_runtimes[name] = round(t_model, 2)
        
        # Best epoch determination
        best_epoch = int(np.argmin(history.history["val_loss"])) + 1
        best_epochs[name] = best_epoch
        print(f"  {name} finished in {t_model:.1f}s. Best Epoch: {best_epoch}/{len(history.history['val_loss'])}")

        # Save model inside models/saved_exp_a/
        save_file = SAVED_DIR_EXP_A / f"{name.lower()}_model.keras"
        model.save(save_file)
        print(f"  Saved {name} model to {save_file}")

        # Prediction probabilities
        v_prob = model.predict(X_val, batch_size=batch_size, verbose=0).reshape(-1)
        t_prob = model.predict(X_test, batch_size=batch_size, verbose=0).reshape(-1)
        
        val_probas[name] = v_prob
        test_probas[name] = t_prob

        # Calibrate optimal decision threshold on VALIDATION set
        thresh, val_f1 = find_optimal_threshold(y_val, v_prob)
        optimal_thresholds[name] = thresh
        print(f"  Validation Optimal Threshold: {thresh:.3f} | Validation F1: {val_f1:.4f}")
        
        training_histories[name] = {k: [float(v) for v in vals] for k, vals in history.history.items()}

    # 4. Soft-Voting Ensemble (Validation-Selected Consensus)
    print("\n>>> Building Soft-Voting Ensemble (FCNN + CNN + LSTM) ...")
    t0_ens = time.time()
    ens_weights = [1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0]
    val_ens_prob = (ens_weights[0] * val_probas["FCNN"] +
                    ens_weights[1] * val_probas["CNN"] +
                    ens_weights[2] * val_probas["LSTM"])
    test_ens_prob = (ens_weights[0] * test_probas["FCNN"] +
                     ens_weights[1] * test_probas["CNN"] +
                     ens_weights[2] * test_probas["LSTM"])

    ens_thresh, ens_val_f1 = find_optimal_threshold(y_val, val_ens_prob)
    optimal_thresholds["Ensemble"] = ens_thresh
    model_runtimes["Ensemble"] = round(time.time() - t0_ens, 2)
    best_epochs["Ensemble"] = "N/A (Composite)"
    print(f"  Ensemble Validation Optimal Threshold: {ens_thresh:.3f} | Validation F1: {ens_val_f1:.4f}")

    ens_config = {
        "model_weights": {"fcnn": ens_weights[0], "cnn": ens_weights[1], "lstm": ens_weights[2]},
        "optimal_threshold": ens_thresh,
        "validation_f1": ens_val_f1
    }
    with open(SAVED_DIR_EXP_A / "ensemble_config.json", "w", encoding="utf-8") as f:
        json.dump(ens_config, f, indent=2)

    # 5. Isolation Forest (Unsupervised Anomaly Detector on Benign Profiles Only)
    print("\n>>> Training Isolation Forest strictly on BENIGN training profiles ...")
    t0_iso = time.time()
    benign_mask_train = (y_train == 0)
    X_train_benign = X_train[benign_mask_train]
    print(f"  Fitting Isolation Forest on {len(X_train_benign):,} benign profiles ...")

    iso = IsolationForest(
        n_estimators=100,
        max_samples=min(2048, len(X_train_benign)),
        contamination=0.005,
        random_state=SEED,
        n_jobs=-1
    )
    iso.fit(X_train_benign)
    t_iso = time.time() - t0_iso
    model_runtimes["IsolationForest"] = round(t_iso, 2)
    best_epochs["IsolationForest"] = "N/A (Unsupervised)"
    print(f"  Isolation Forest fitted in {t_iso:.1f}s.")

    # Save Isolation Forest model
    joblib.dump(iso, SAVED_DIR_EXP_A / "isolation_forest.joblib")

    # Raw scores (inverted so higher score = more anomalous)
    val_iso_scores = -iso.decision_function(X_val)
    test_iso_scores = -iso.decision_function(X_test)

    # Calibrate anomaly threshold on validation split
    iso_thresh, iso_val_f1 = find_optimal_threshold(y_val, val_iso_scores)
    optimal_thresholds["IsolationForest"] = iso_thresh
    print(f"  Isolation Forest Validation Anomaly Threshold: {iso_thresh:.4f} | Val F1: {iso_val_f1:.4f}")

    # 6. Comprehensive Held-Out Test Evaluation
    print("\n" + "=" * 70)
    print("HELD-OUT TEST SET EVALUATION")
    print(f"Total Test Samples: {len(y_test):,} (Normal: {len(y_test)-y_test.sum():,}, Attack: {y_test.sum():,})")
    print("=" * 70)

    test_probas_all = {
        "FCNN": test_probas["FCNN"],
        "CNN": test_probas["CNN"],
        "LSTM": test_probas["LSTM"],
        "Ensemble": test_ens_prob,
        "IsolationForest": test_iso_scores
    }

    val_probas_all = {
        "FCNN": val_probas["FCNN"],
        "CNN": val_probas["CNN"],
        "LSTM": val_probas["LSTM"],
        "Ensemble": val_ens_prob,
        "IsolationForest": val_iso_scores
    }

    test_metrics = {}
    val_metrics = {}

    for name, p_test in test_probas_all.items():
        th = optimal_thresholds[name]
        m_test = compute_comprehensive_metrics(y_test, p_test, th, labels_test)
        m_val = compute_comprehensive_metrics(y_val, val_probas_all[name], th, labels_dict["validation"])
        
        test_metrics[name] = m_test
        val_metrics[name] = m_val
        
        print(f"\n[{name}]")
        print(f"  Threshold: {th:.4f} (Calibrated on Validation)")
        print(f"  Test Accuracy:        {m_test['accuracy']*100:.2f}% | Balanced Acc: {m_test['balanced_accuracy']*100:.2f}%")
        print(f"  Test Precision:       {m_test['precision']:.4f}")
        print(f"  Test Recall:          {m_test['recall']:.4f} ({m_test['confusion_matrix']['tp']}/{m_test['attack_samples']} attacks detected)")
        print(f"  Test F1-Score:        {m_test['f1_score']:.4f}")
        print(f"  Test PR-AUC:          {m_test['pr_auc']:.4f}")
        print(f"  Test ROC-AUC:         {m_test['roc_auc']:.4f}")
        print(f"  Test False Pos Rate:  {m_test['false_positive_rate']*100:.4f}% ({m_test['confusion_matrix']['fp']} false alarms)")
        print(f"  Confusion Matrix:     TN={m_test['confusion_matrix']['tn']:,}, FP={m_test['confusion_matrix']['fp']:,}, FN={m_test['confusion_matrix']['fn']:,}, TP={m_test['confusion_matrix']['tp']:,}")

    # 7. Baseline Preservation Post-Run Audit
    if h_csv_before is not None:
        h_csv_after = sha256_of(baseline_csv)
        if h_csv_before != h_csv_after:
            raise RuntimeError("CRITICAL ERROR: Baseline event_profiles.csv was modified!")
    if h_meta_before is not None:
        h_meta_after = sha256_of(baseline_meta)
        if h_meta_before != h_meta_after:
            raise RuntimeError("CRITICAL ERROR: Baseline event_profiles_metadata.json was modified!")

    print("\n[BASELINE CHECK] Tuesday baseline files in data/processed/event_profiles/ verified completely untouched.")

    # 8. Save Evaluation Reports
    final_report = {
        "experiment": "Experiment A (Multi-Day Time-Blocked Classification)",
        "completed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_elapsed_seconds": round(time.time() - t_start, 2),
        "dataset": {
            "source_directory": str(INPUT_DIR),
            "train_samples": len(y_train),
            "train_attacks": int(y_train.sum()),
            "validation_samples": len(y_val),
            "validation_attacks": int(y_val.sum()),
            "test_samples": len(y_test),
            "test_attacks": int(y_test.sum()),
            "imbalance_ratio": f"1 : {len(y_train)/max(y_train.sum(),1):.1f}"
        },
        "loss_weights": class_weights,
        "model_runtimes_seconds": model_runtimes,
        "best_epochs": best_epochs,
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics
    }

    eval_json_path = METRICS_DIR_EXP_A / "evaluation_report.json"
    with open(eval_json_path, "w", encoding="utf-8") as f:
        json.dump(final_report, f, indent=2)

    hist_json_path = METRICS_DIR_EXP_A / "training_history.json"
    with open(hist_json_path, "w", encoding="utf-8") as f:
        json.dump(training_histories, f, indent=2)

    print(f"\nSaved benchmark metrics to {eval_json_path}")
    print(f"Saved training histories to {hist_json_path}")
    print(f"SUCCESS: Completed Experiment A training and evaluation in {round(time.time() - t_start, 1)}s.")
    return final_report


if __name__ == "__main__":
    run_experiment_a_training()
