"""
TF-IDF over event sets. Document = event set, term = event type (5 terms). Fitted on TRAINING sets only.

    tf     = 1 + ln(count) if count > 0 else 0          (sublinear; plain count if sublinear_tf is false)
    df     = number of training sets with count > 0
    idf    = ln((1 + N_train) / (1 + df)) + 1            (smoothed document-frequency IDF; N_train includes empty sets)
    vector = tf * idf, then L2-normalised (an all-zero row stays all-zero)
"""

import numpy as np

from .events import EVENT_NAMES

EPS = 1e-12


def l2_normalize_rows(matrix):
    """Safe row normalisation: rows with (near-)zero length stay zero instead of dividing by zero."""
    m = np.asarray(matrix, dtype="float64")
    norms = np.sqrt((m * m).sum(axis=1))
    out = np.zeros_like(m)
    ok = norms > EPS
    out[ok] = m[ok] / norms[ok][:, None]
    return out


def tf_weights(counts, sublinear):
    c = np.asarray(counts, dtype="float64")
    if not sublinear:
        return c
    return np.where(c > 0, 1.0 + np.log(np.where(c > 0, c, 1.0)), 0.0)


def fit_idf(train_counts, sublinear):
    train_counts = np.asarray(train_counts)
    n_docs = int(train_counts.shape[0])
    df = (train_counts > 0).sum(axis=0).astype("int64")
    idf = np.log((1.0 + n_docs) / (1.0 + df)) + 1.0
    return {"vocabulary": list(EVENT_NAMES), "n_training_documents": n_docs,
            "document_frequency": df.tolist(), "idf": idf.tolist(), "sublinear_tf": bool(sublinear),
            "formula": "tf = 1+ln(count) if sublinear else count; idf = ln((1+N)/(1+df))+1; "
                       "vector = L2_normalize(tf*idf)"}


def transform(counts, model):
    tf = tf_weights(counts, model["sublinear_tf"])
    return l2_normalize_rows(tf * np.asarray(model["idf"], dtype="float64"))
