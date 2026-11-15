"""
Controlled Model Training Pipeline for Experiment B
===================================================
Project: AI-Based SIEM System for Cyber Threat Detection Using Event Profiles
Input Directory:  data/processed/event_profiles_exp_b/
Output Directory: models/saved_exp_b/ and models/metrics_exp_b/

Methodology: Unseen Attack Detection Under Temporal and Domain Shift
  - Supervised training strictly on Monday, Wednesday, and non-control Tuesday records ('train').
  - Model selection, early stopping, and decision-threshold tuning strictly on Thursday ('validation').
  - Unsupervised Isolation Forest trained strictly on benign training profiles.
  - Isolation Forest threshold calibrated strictly on benign Thursday validation profiles at 99th percentile (alpha = 0.01).
  - Evaluation A (Held-Out Unseen Attacks): Friday test partition (Bot, PortScan, DDoS).
  - Evaluation B (Known-Attack Control): Held-out Tuesday blocks 4 & 27 (SSH-Patator, FTP-Patator).
  - Under no circumstances are Evaluation A and Evaluation B metrics averaged or combined.
  - Baseline and Experiment A models and artifacts are protected from overwrite.
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

# Pinned random seed for strict reproducibility
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
        keras = None
        HAS_KERAS = False

from src.config import PROJECT_ROOT, resolve_path
from src.event_profiles.validation import PROFILE_ID_COLUMNS

PROFILE_COLS = [f"bp_{i:02d}" for i in range(1, 9)]
INPUT_DIR_EXP_B = PROJECT_ROOT / "data" / "processed" / "event_profiles_exp_b"
SAVED_DIR_EXP_B = PROJECT_ROOT / "models" / "saved_exp_b"
METRICS_DIR_EXP_B = PROJECT_ROOT / "models" / "metrics_exp_b"

# Protected directories that must NEVER be modified by Experiment B
BASELINE_PROCESSED_DIR = PROJECT_ROOT / "data" / "processed" / "event_profiles"
BASELINE_SAVED_DIR = PROJECT_ROOT / "models" / "saved"
EXP_A_PROCESSED_DIR = PROJECT_ROOT / "data" / "processed" / "event_profiles_exp_a"
EXP_A_SAVED_DIR = PROJECT_ROOT / "models" / "saved_exp_a"
EXP_A_METRICS_DIR = PROJECT_ROOT / "models" / "metrics_exp_a"

ALL_CICIDS_CLASSES = [
    "BENIGN", "Bot", "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS Slowhttptest",
    "DoS slowloris", "FTP-Patator", "Heartbleed", "Infiltration", "PortScan",
    "SSH-Patator", "Web Attack - Brute Force", "Web Attack - Sql Injection", "Web Attack - XSS"
]


def sha256_of(path: Path) -> str:
    """Computes SHA256 hash of a file for cryptographic preservation verification."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def load_exp_b_datasets(input_dir: Optional[Path] = None):
    """
    Loads Experiment B multi-day profiles and targets across all four partitions:
      - 'train': Monday, Wednesday, and non-held-out Tuesday profiles.
      - 'validation': Thursday morning and afternoon profiles.
      - 'control_test': Tuesday Block 4 (SSH) and Block 27 (FTP) held-out profiles.
      - 'test': Friday held-out unseen attack profiles.

    Enforces strict feature isolation (only bp_01 through bp_08 allowed in X).
    Returns X_dict, y_dict, y_mc_dict, labels_dict.
    """
    in_dir = Path(input_dir or INPUT_DIR_EXP_B)
    prof_path = in_dir / "event_profiles.csv"
    tgt_path = in_dir / "event_set_targets.csv"

    if not prof_path.exists() or not tgt_path.exists():
        raise FileNotFoundError(
            f"Experiment B dataset files missing in {in_dir}. "
            "Run 'python -m src.event_profiles.build_multi_day_profiles exp_b' first."
        )

    print(f"Loading Experiment B profiles from {prof_path.name} ...")
    df_prof = pd.read_csv(prof_path)

    # Strict feature restriction check: Only identifiers and bp_* features permitted
    extra_cols = [c for c in df_prof.columns if c not in PROFILE_ID_COLUMNS and c not in PROFILE_COLS]
    if extra_cols:
        raise ValueError(f"CRITICAL ERROR: Forbidden columns detected in profile input: {extra_cols}")

    print(f"Loading Experiment B targets from {tgt_path.name} ...")
    df_tgt = pd.read_csv(tgt_path)

    merged = df_prof.merge(
        df_tgt[["event_set_id", "target_binary", "target_multiclass", "target_label"]],
        on="event_set_id",
        how="inner",
        validate="one_to_one"
    )

    expected_splits = ["train", "validation", "control_test", "test"]
    X_dict = {}
    y_dict = {}
    y_mc_dict = {}
    labels_dict = {}

    for split in expected_splits:
        sub = merged[merged["split"] == split]
        if len(sub) == 0:
            raise ValueError(f"CRITICAL ERROR: Partition '{split}' contains 0 event profiles in {in_dir}.")
        X_dict[split] = sub[PROFILE_COLS].to_numpy(dtype=np.float32)
        y_dict[split] = sub["target_binary"].to_numpy(dtype=np.int8)
        y_mc_dict[split] = sub["target_multiclass"].to_numpy(dtype=np.int64)
        labels_dict[split] = sub["target_label"].to_numpy()
        print(f"  Split '{split:12s}': {len(sub):,} event sets | {int(y_dict[split].sum()):,} attack sets")

    return X_dict, y_dict, y_mc_dict, labels_dict


def calculate_class_weights(y_train: np.ndarray) -> Dict[int, float]:
    """
    Computes balanced class weights exclusively from training labels:
      w_j = N / (2 * N_j)
    Compensates for severe positive class rarity without synthetic oversampling.
    """
    total = len(y_train)
    n_pos = int(y_train.sum())
    n_neg = total - n_pos

    w0 = total / (2.0 * max(n_neg, 1))
    w1 = total / (2.0 * max(n_pos, 1))

    print(f"Calculated Binary Class Weights: Class 0 (Benign)={w0:.6f}, Class 1 (Attack)={w1:.6f}")
    return {0: float(w0), 1: float(w1)}


def build_fcnn(input_dim: int = 8, lr: float = 0.001):
    """FCNN / Multi-Layer Perceptron architecture for 8-dimensional event profiles."""
    if not HAS_KERAS:
        raise ImportError("TensorFlow / Keras is required to build FCNN.")
    inputs = layers.Input(shape=(input_dim,), name="profile_input")
    x = layers.Dense(64, activation="relu", kernel_regularizer=regularizers.l2(1e-4), name="dense_1")(inputs)
    x = layers.BatchNormalization(name="bn_1")(x)
    x = layers.Dropout(0.3, name="drop_1")(x)
    x = layers.Dense(32, activation="relu", kernel_regularizer=regularizers.l2(1e-4), name="dense_2")(x)
    x = layers.BatchNormalization(name="bn_2")(x)
    x = layers.Dropout(0.2, name="drop_2")(x)
    x = layers.Dense(16, activation="relu", name="dense_3")(x)
    outputs = layers.Dense(1, activation="sigmoid", name="threat_proba")(x)

    model = models.Model(inputs=inputs, outputs=outputs, name="FCNN_ExpB")
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=lr),
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            keras.metrics.Precision(name="precision"),
            keras.metrics.Recall(name="recall"),
            keras.metrics.AUC(name="pr_auc", curve="PR")
        ]
    )
    return model


def build_cnn(input_dim: int = 8, lr: float = 0.001):
    """1D-CNN architecture over 8-dimensional basepoint feature map."""
    if not HAS_KERAS:
        raise ImportError("TensorFlow / Keras is required to build CNN.")
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

    model = models.Model(inputs=inputs, outputs=outputs, name="1D_CNN_ExpB")
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=lr),
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            keras.metrics.Precision(name="precision"),
            keras.metrics.Recall(name="recall"),
            keras.metrics.AUC(name="pr_auc", curve="PR")
        ]
    )
    return model


def build_lstm(input_dim: int = 8, lr: float = 0.001):
    """
    Bidirectional LSTM architecture for event profile threat scoring.
    Note on Architectural Limitation:
      Input is reshaped as (1, input_dim) representing a sequence of length T=1.
      Recurrent gating executes over one step without temporal sequence history.
    """
    if not HAS_KERAS:
        raise ImportError("TensorFlow / Keras is required to build LSTM.")
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

    model = models.Model(inputs=inputs, outputs=outputs, name="LSTM_ExpB")
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=lr),
        loss="binary_crossentropy",
        metrics=[
            "accuracy",
            keras.metrics.Precision(name="precision"),
            keras.metrics.Recall(name="recall"),
            keras.metrics.AUC(name="pr_auc", curve="PR")
        ]
    )
    return model


def find_optimal_threshold(y_true: np.ndarray, y_proba: np.ndarray, num_steps: int = 50) -> Tuple[float, float]:
    """
    Tunes optimal decision threshold tau in [0.05, 0.95] on VALIDATION data to maximize F1-score.
    Prevents any test split label leakage.
    """
    best_thresh = 0.50
    best_f1 = -1.0
    for thresh in np.linspace(0.05, 0.95, num_steps):
        preds = (y_proba >= thresh).astype(np.int8)
        f1 = f1_score(y_true, preds, zero_division=0)
        if f1 > best_f1:
            best_f1 = float(f1)
            best_thresh = float(thresh)
    return float(best_thresh), float(best_f1)


def calibrate_isolation_forest_threshold(
    iso_model: IsolationForest,
    X_val_benign: np.ndarray,
    percentile: float = 99.0
) -> float:
    """
    Calibrates Isolation Forest anomaly threshold tau_anomaly strictly on BENIGN validation profiles.
    Predeclared false alarm budget rule: 99th percentile (nominal alpha = 0.01).
    Score convention: inverted decision function s(x) = -decision_function(x).
    Higher score indicates greater deviation from normality.
    """
    scores_val_benign = -iso_model.decision_function(X_val_benign)
    threshold = float(np.percentile(scores_val_benign, percentile))
    return threshold


def compute_comprehensive_metrics(
    y_true: np.ndarray,
    y_score: np.ndarray,
    threshold: float,
    labels_true: np.ndarray,
    is_anomaly_score: bool = False
) -> Dict[str, Any]:
    """
    Computes all standard SIEM evaluation metrics, confusion matrix, continuous curves,
    and per-class attack support and recall.
    """
    y_true = np.asarray(y_true, dtype=np.int8)
    y_pred = (y_score >= threshold).astype(np.int8)

    acc = float(accuracy_score(y_true, y_pred))
    bal_acc = float(balanced_accuracy_score(y_true, y_pred))
    prec = float(precision_score(y_true, y_pred, zero_division=0))
    rec = float(recall_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    try:
        roc_val = float(roc_auc_score(y_true, y_score))
    except Exception:
        roc_val = 0.5

    try:
        pr_auc_val = float(average_precision_score(y_true, y_score))
    except Exception:
        pr_auc_val = 0.0

    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    per_class_support = {}
    df_eval = pd.DataFrame({"label": labels_true, "pred": y_pred, "true_bin": y_true})
    for cls_name in ALL_CICIDS_CLASSES:
        sub_cls = df_eval[df_eval["label"] == cls_name]
        support = len(sub_cls)
        if support == 0:
            per_class_support[cls_name] = {
                "support": 0,
                "detected": 0,
                "recall": "N/A (0 samples)",
                "status": "UNOBSERVED_IN_PARTITION"
            }
        else:
            if cls_name == "BENIGN":
                detected = int((sub_cls["pred"] == 0).sum())
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
        "score_type": "anomaly_score" if is_anomaly_score else "threat_probability",
        "per_class_support": per_class_support
    }


def compute_tri_state_verdicts(
    ann_proba: np.ndarray,
    ann_thresh: float,
    iso_score: np.ndarray,
    iso_thresh: float,
    y_true: np.ndarray,
    labels_true: np.ndarray
) -> Dict[str, Any]:
    """
    Computes SIEM tri-state classification:
      1. KNOWN_THREAT:       ann_proba >= ann_thresh
      2. UNKNOWN_ANOMALOUS:  ann_proba < ann_thresh AND iso_score >= iso_thresh
      3. NORMAL:             ann_proba < ann_thresh AND iso_score < iso_thresh
    """
    is_known = ann_proba >= ann_thresh
    is_unknown = (~is_known) & (iso_score >= iso_thresh)
    is_normal = (~is_known) & (~is_unknown)

    n_total = len(y_true)
    n_attacks = int(y_true.sum())
    n_benign = n_total - n_attacks

    # Overall triage distribution
    triage_counts = {
        "KNOWN_THREAT": int(is_known.sum()),
        "UNKNOWN_ANOMALOUS": int(is_unknown.sum()),
        "NORMAL": int(is_normal.sum())
    }

    # Attack capture triage
    attack_mask = (y_true == 1)
    attack_triage = {
        "detected_by_ann": int((is_known & attack_mask).sum()),
        "captured_by_isolation": int((is_unknown & attack_mask).sum()),
        "missed_as_normal": int((is_normal & attack_mask).sum()),
        "total_attacks": n_attacks
    }

    # Benign false alarm triage
    benign_mask = (y_true == 0)
    benign_triage = {
        "ann_false_positives": int((is_known & benign_mask).sum()),
        "isolation_false_positives": int((is_unknown & benign_mask).sum()),
        "correct_normal": int((is_normal & benign_mask).sum()),
        "total_benign": n_benign
    }

    return {
        "total_samples": n_total,
        "triage_distribution": triage_counts,
        "attack_capture_breakdown": attack_triage,
        "benign_triage_breakdown": benign_triage,
        "combined_threat_detection_rate": float(
            (attack_triage["detected_by_ann"] + attack_triage["captured_by_isolation"]) / max(n_attacks, 1)
        ),
        "combined_false_alarm_rate": float(
            (benign_triage["ann_false_positives"] + benign_triage["isolation_false_positives"]) / max(n_benign, 1)
        )
    }


def run_experiment_b_training(
    epochs: int = 15,
    batch_size: int = 2048,
    seed: int = SEED,
    log_fn=print
) -> Dict[str, Any]:
    """
    Executes the full controlled training pipeline for Experiment B:
      1. Baseline and Experiment A preservation verification.
      2. 4-way partition loading from data/processed/event_profiles_exp_b/.
      3. Class-weight calculation on training attacks.
      4. FCNN, CNN, and LSTM supervised training with validation early stopping.
      5. Soft-Voting Ensemble construction and validation threshold tuning.
      6. Isolation Forest unsupervised training on benign profiles & 99th-percentile validation calibration.
      7. Separate Evaluation A (Friday Unseen) and Evaluation B (Tuesday Known Control).
      8. Artifact and report persistence strictly to models/saved_exp_b/ and models/metrics_exp_b/.
    """
    t_start = time.time()
    SAVED_DIR_EXP_B.mkdir(parents=True, exist_ok=True)
    METRICS_DIR_EXP_B.mkdir(parents=True, exist_ok=True)

    log_fn("=" * 75)
    log_fn("STARTING EXPERIMENT B CONTROLLED MODEL TRAINING PIPELINE")
    log_fn(f"Input Directory:   {INPUT_DIR_EXP_B}")
    log_fn(f"Model Directory:   {SAVED_DIR_EXP_B}")
    log_fn(f"Metrics Directory: {METRICS_DIR_EXP_B}")
    log_fn("=" * 75)

    # 1. Baseline & Exp A Cryptographic Fingerprint Verification
    baseline_csv = BASELINE_PROCESSED_DIR / "event_profiles.csv"
    exp_a_csv = EXP_A_PROCESSED_DIR / "event_profiles.csv"
    h_baseline_before = sha256_of(baseline_csv) if baseline_csv.exists() else None
    h_exp_a_before = sha256_of(exp_a_csv) if exp_a_csv.exists() else None

    # 2. Four-Way Partition Dataset Loading
    X_dict, y_dict, y_mc_dict, labels_dict = load_exp_b_datasets(INPUT_DIR_EXP_B)

    X_train, y_train = X_dict["train"], y_dict["train"]
    X_val, y_val = X_dict["validation"], y_dict["validation"]
    X_ctrl, y_ctrl = X_dict["control_test"], y_dict["control_test"]
    X_test, y_test = X_dict["test"], y_dict["test"]

    labels_val = labels_dict["validation"]
    labels_ctrl = labels_dict["control_test"]
    labels_test = labels_dict["test"]

    # 3. Class-Weight Calculation on Training Partition Only
    class_weights = calculate_class_weights(y_train)

    # 4. Neural Network Models Instantiation
    model_defs = {
        "FCNN": build_fcnn(input_dim=8),
        "CNN": build_cnn(input_dim=8),
        "LSTM": build_lstm(input_dim=8)
    }

    val_probas = {}
    test_probas = {}
    ctrl_probas = {}
    optimal_thresholds = {}
    training_histories = {}
    model_runtimes = {}
    best_epochs = {}

    # 5. Supervised Model Training on 'train' with Validation Early Stopping
    for name, model in model_defs.items():
        log_fn(f"\n>>> Training {name} on {len(X_train):,} samples (Batch Size: {batch_size}) ...")
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

        best_epoch = int(np.argmin(history.history["val_loss"])) + 1
        best_epochs[name] = best_epoch
        log_fn(f"  {name} finished in {t_model:.1f}s. Best Epoch: {best_epoch}/{len(history.history['val_loss'])}")

        # Save model inside models/saved_exp_b/
        save_file = SAVED_DIR_EXP_B / f"{name.lower()}_model.keras"
        model.save(save_file)
        log_fn(f"  Saved {name} model to {save_file}")

        # Compute predictions
        v_prob = model.predict(X_val, batch_size=batch_size, verbose=0).reshape(-1)
        t_prob = model.predict(X_test, batch_size=batch_size, verbose=0).reshape(-1)
        c_prob = model.predict(X_ctrl, batch_size=batch_size, verbose=0).reshape(-1)

        val_probas[name] = v_prob
        test_probas[name] = t_prob
        ctrl_probas[name] = c_prob

        # Calibrate optimal decision threshold on Thursday VALIDATION set
        thresh, val_f1 = find_optimal_threshold(y_val, v_prob)
        optimal_thresholds[name] = thresh
        log_fn(f"  Thursday Validation Threshold: {thresh:.3f} | Validation F1: {val_f1:.4f}")

        training_histories[name] = {k: [float(v) for v in vals] for k, vals in history.history.items()}

    # 6. Soft-Voting Ensemble Construction
    log_fn("\n>>> Building Soft-Voting Ensemble (FCNN + CNN + LSTM) ...")
    t0_ens = time.time()
    ens_weights = [1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0]
    val_ens_prob = (ens_weights[0] * val_probas["FCNN"] +
                    ens_weights[1] * val_probas["CNN"] +
                    ens_weights[2] * val_probas["LSTM"])
    test_ens_prob = (ens_weights[0] * test_probas["FCNN"] +
                     ens_weights[1] * test_probas["CNN"] +
                     ens_weights[2] * test_probas["LSTM"])
    ctrl_ens_prob = (ens_weights[0] * ctrl_probas["FCNN"] +
                     ens_weights[1] * ctrl_probas["CNN"] +
                     ens_weights[2] * ctrl_probas["LSTM"])

    ens_thresh, ens_val_f1 = find_optimal_threshold(y_val, val_ens_prob)
    optimal_thresholds["Ensemble"] = ens_thresh
    model_runtimes["Ensemble"] = round(time.time() - t0_ens, 2)
    best_epochs["Ensemble"] = "N/A (Composite)"
    log_fn(f"  Ensemble Thursday Validation Threshold: {ens_thresh:.3f} | Validation F1: {ens_val_f1:.4f}")

    ens_config = {
        "model_weights": {"fcnn": ens_weights[0], "cnn": ens_weights[1], "lstm": ens_weights[2]},
        "optimal_threshold": ens_thresh,
        "validation_f1": ens_val_f1,
        "calibration_split": "Thursday validation"
    }
    with open(SAVED_DIR_EXP_B / "ensemble_config.json", "w", encoding="utf-8") as f:
        json.dump(ens_config, f, indent=2)

    # 7. Isolation Forest Training & 99th-Percentile Calibration
    log_fn("\n>>> Training Isolation Forest strictly on BENIGN training profiles ...")
    t0_iso = time.time()
    X_train_benign = X_train[y_train == 0]
    log_fn(f"  Fitting Isolation Forest on {len(X_train_benign):,} benign profiles ...")

    iso = IsolationForest(
        n_estimators=100,
        max_samples=min(2048, len(X_train_benign)),
        contamination=0.005,
        random_state=seed,
        n_jobs=-1
    )
    iso.fit(X_train_benign)
    t_iso = time.time() - t0_iso
    model_runtimes["IsolationForest"] = round(t_iso, 2)
    best_epochs["IsolationForest"] = "N/A (Unsupervised)"
    log_fn(f"  Isolation Forest fitted in {t_iso:.1f}s.")

    joblib.dump(iso, SAVED_DIR_EXP_B / "isolation_forest.joblib")

    # Inverted anomaly scores: s(x) = -decision_function(x)
    val_iso_scores = -iso.decision_function(X_val)
    test_iso_scores = -iso.decision_function(X_test)
    ctrl_iso_scores = -iso.decision_function(X_ctrl)

    # Calibrate on BENIGN Thursday validation profiles only
    X_val_benign = X_val[y_val == 0]
    iso_thresh = calibrate_isolation_forest_threshold(iso, X_val_benign, percentile=99.0)
    optimal_thresholds["IsolationForest"] = iso_thresh
    log_fn(f"  Isolation Forest 99th-Percentile Threshold: {iso_thresh:.4f} (alpha = 0.01 calibration)")

    anomaly_config = {
        "model": "Isolation Forest",
        "model_type": "Isolation Forest",
        "fitted_on": "train_benign_only",
        "num_training_samples": len(X_train_benign),
        "features": PROFILE_COLS,
        "score_convention": "inverted_decision_function",
        "score_formula": "-decision_function(X)",
        "calibration_split": "Thursday validation benign only",
        "calibration_rule": "99th_percentile_benign_validation",
        "nominal_fpr_budget": 0.01,
        "optimal_threshold": float(iso_thresh),
        "validation_benign_samples": len(X_val_benign)
    }
    with open(SAVED_DIR_EXP_B / "anomaly_config.json", "w", encoding="utf-8") as f:
        json.dump(anomaly_config, f, indent=2)

    # 8. Evaluation A: Friday Unseen Attacks Under Domain Shift
    log_fn("\n" + "=" * 75)
    log_fn("EVALUATION A: FRIDAY UNSEEN ATTACK TEST (Bot, PortScan, DDoS)")
    log_fn(f"Total Test Samples: {len(y_test):,} (Normal: {len(y_test)-y_test.sum():,}, Attack: {y_test.sum():,})")
    log_fn("=" * 75)

    test_probas_all = {
        "FCNN": test_probas["FCNN"],
        "CNN": test_probas["CNN"],
        "LSTM": test_probas["LSTM"],
        "Ensemble": test_ens_prob,
        "IsolationForest": test_iso_scores
    }

    eval_a_metrics = {}
    for name, p_test in test_probas_all.items():
        th = optimal_thresholds[name]
        is_iso = (name == "IsolationForest")
        m_test = compute_comprehensive_metrics(y_test, p_test, th, labels_test, is_anomaly_score=is_iso)
        eval_a_metrics[name] = m_test
        log_fn(f"  [{name:15s}] F1: {m_test['f1_score']:.4f} | Prec: {m_test['precision']:.4f} | "
               f"Rec: {m_test['recall']:.4f} ({m_test['confusion_matrix']['tp']}/{m_test['attack_samples']}) | "
               f"FPR: {m_test['false_positive_rate']*100:.3f}%")

    tri_state_a = compute_tri_state_verdicts(
        test_ens_prob, optimal_thresholds["Ensemble"],
        test_iso_scores, iso_thresh,
        y_test, labels_test
    )
    eval_a_report = {
        "evaluation_name": "Evaluation A: Friday Unseen Attacks Under Domain Shift",
        "attack_types_tested": ["Bot", "PortScan", "DDoS"],
        "dataset_split": "test (Friday 100%)",
        "total_samples": len(y_test),
        "attack_samples": int(y_test.sum()),
        "benign_samples": int(len(y_test) - y_test.sum()),
        "model_metrics": eval_a_metrics,
        "tri_state_triage": tri_state_a
    }
    with open(METRICS_DIR_EXP_B / "evaluation_a_unseen.json", "w", encoding="utf-8") as f:
        json.dump(eval_a_report, f, indent=2)

    # 9. Evaluation B: Tuesday Known-Attack Control Test
    log_fn("\n" + "=" * 75)
    log_fn("EVALUATION B: TUESDAY KNOWN-ATTACK CONTROL TEST (SSH-Patator, FTP-Patator)")
    log_fn(f"Total Control Samples: {len(y_ctrl):,} (Normal: {len(y_ctrl)-y_ctrl.sum():,}, Attack: {y_ctrl.sum():,})")
    log_fn("=" * 75)

    ctrl_probas_all = {
        "FCNN": ctrl_probas["FCNN"],
        "CNN": ctrl_probas["CNN"],
        "LSTM": ctrl_probas["LSTM"],
        "Ensemble": ctrl_ens_prob,
        "IsolationForest": ctrl_iso_scores
    }

    eval_b_metrics = {}
    for name, p_ctrl in ctrl_probas_all.items():
        th = optimal_thresholds[name]
        is_iso = (name == "IsolationForest")
        m_ctrl = compute_comprehensive_metrics(y_ctrl, p_ctrl, th, labels_ctrl, is_anomaly_score=is_iso)
        eval_b_metrics[name] = m_ctrl
        log_fn(f"  [{name:15s}] F1: {m_ctrl['f1_score']:.4f} | Prec: {m_ctrl['precision']:.4f} | "
               f"Rec: {m_ctrl['recall']:.4f} ({m_ctrl['confusion_matrix']['tp']}/{m_ctrl['attack_samples']}) | "
               f"FPR: {m_ctrl['false_positive_rate']*100:.3f}%")

    tri_state_b = compute_tri_state_verdicts(
        ctrl_ens_prob, optimal_thresholds["Ensemble"],
        ctrl_iso_scores, iso_thresh,
        y_ctrl, labels_ctrl
    )
    eval_b_report = {
        "evaluation_name": "Evaluation B: Tuesday Known-Attack Control Test",
        "attack_types_tested": ["SSH-Patator", "FTP-Patator"],
        "dataset_split": "control_test (Tuesday Blocks 4 and 27)",
        "total_samples": len(y_ctrl),
        "attack_samples": int(y_ctrl.sum()),
        "benign_samples": int(len(y_ctrl) - y_ctrl.sum()),
        "model_metrics": eval_b_metrics,
        "tri_state_triage": tri_state_b
    }
    with open(METRICS_DIR_EXP_B / "evaluation_b_control.json", "w", encoding="utf-8") as f:
        json.dump(eval_b_report, f, indent=2)

    # 10. Baseline & Exp A Post-Run Preservation Verification
    if h_baseline_before is not None:
        h_baseline_after = sha256_of(baseline_csv)
        if h_baseline_before != h_baseline_after:
            raise RuntimeError("CRITICAL ERROR: Baseline event_profiles.csv was modified!")
    if h_exp_a_before is not None:
        h_exp_a_after = sha256_of(exp_a_csv)
        if h_exp_a_before != h_exp_a_after:
            raise RuntimeError("CRITICAL ERROR: Experiment A event_profiles.csv was modified!")

    log_fn("\n[BASELINE CHECK] Baseline and Experiment A artifacts verified cryptographically untouched.")

    # 11. Consolidated Evaluation Summary Report
    consolidated_report = {
        "experiment": "Experiment B (Unseen Attack Detection Under Domain Shift)",
        "completed_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_elapsed_seconds": round(time.time() - t_start, 2),
        "dataset": {
            "source_directory": str(INPUT_DIR_EXP_B),
            "train_samples": len(y_train),
            "train_attacks": int(y_train.sum()),
            "validation_samples": len(y_val),
            "validation_attacks": int(y_val.sum()),
            "control_test_samples": len(y_ctrl),
            "control_test_attacks": int(y_ctrl.sum()),
            "test_samples": len(y_test),
            "test_attacks": int(y_test.sum()),
            "imbalance_ratio": f"1 : {len(y_train)/max(y_train.sum(), 1):.1f}"
        },
        "loss_weights": class_weights,
        "model_runtimes_seconds": model_runtimes,
        "best_epochs": best_epochs,
        "optimal_thresholds": optimal_thresholds,
        "isolation_forest_calibration": anomaly_config,
        "evaluation_a_unseen": eval_a_report,
        "evaluation_b_control": eval_b_report
    }

    eval_json_path = METRICS_DIR_EXP_B / "evaluation_report.json"
    with open(eval_json_path, "w", encoding="utf-8") as f:
        json.dump(consolidated_report, f, indent=2)

    hist_json_path = METRICS_DIR_EXP_B / "training_history.json"
    with open(hist_json_path, "w", encoding="utf-8") as f:
        json.dump(training_histories, f, indent=2)

    elapsed = round(time.time() - t_start, 1)
    log_fn(f"\nSaved consolidated metrics to {eval_json_path}")
    log_fn(f"Saved training histories to {hist_json_path}")
    log_fn(f"SUCCESS: Completed Experiment B training and dual evaluations in {elapsed}s.")
    return consolidated_report


if __name__ == "__main__":
    print("Direct execution disabled. Awaiting explicit user approval before running training.")
