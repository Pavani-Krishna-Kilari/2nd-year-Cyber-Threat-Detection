"""
Basepoint selection (TRAINING vectors only, no labels) and event-profile computation.

Paper idea: prepare a list of the rarest event types, take event sets containing a rare event as basepoint
candidates, and replace redundant basepoints iteratively.  Our deterministic version for 5 event types:

 1. rare list   = the `rare_event_types` event types with the lowest training document frequency (df > 0 only)
 2. candidates  = distinct non-empty training vectors that contain a rare event
 3. first pick  = candidate with the largest weight on the rare events (ties: first in sorted order)
 4. next picks  = among candidates whose cosine to EVERY chosen basepoint is < redundancy_threshold,
                  the one whose largest cosine to the chosen basepoints is smallest (most different)
 5. stop at `basepoints` picks, or earlier if no non-redundant candidate remains (reported, never padded)
"""

import numpy as np

from .errors import EventProfileError
from .events import EVENT_NAMES
from .tfidf import l2_normalize_rows


def cosine_similarity_matrix(a, b):
    """Cosine similarity of every row of `a` with every row of `b`. Zero vectors give similarity 0 (never NaN)."""
    sim = l2_normalize_rows(a) @ l2_normalize_rows(b).T
    return np.clip(sim, 0.0, 1.0)


def select_basepoints(train_vectors, document_frequency, settings):
    v = np.asarray(train_vectors, dtype="float64")
    df = np.asarray(document_frequency)
    nonempty = (v > 0).any(axis=1)
    if not nonempty.any():
        raise EventProfileError("All training event sets are empty - no basepoint can be selected.",
                                "Inspect the thresholds in the report; no event fired on the training data.")
    usable = [j for j in range(len(df)) if df[j] > 0]
    rare = sorted(usable, key=lambda j: (df[j], j))[: settings["rare_event_types"]]

    distinct = np.unique(np.round(v[nonempty], 9), axis=0)
    distinct = l2_normalize_rows(distinct)
    cand = distinct[(distinct[:, rare] > 0).any(axis=1)]
    if len(cand) == 0:
        raise EventProfileError("No training vector contains a rare event.")

    rare_mass = cand[:, rare].sum(axis=1)
    chosen = [int(np.argmax(rare_mass))]
    trace = [{"order": 1, "max_cosine_to_previous": None, "rare_event_weight": float(rare_mass[chosen[0]])}]
    stop_reason = "reached the requested number of basepoints"
    while len(chosen) < settings["basepoints"]:
        sims = cand @ cand[chosen].T
        max_sim = sims.max(axis=1)
        eligible = max_sim < settings["redundancy_threshold"]
        eligible[chosen] = False
        if not eligible.any():
            stop_reason = (f"no remaining candidate has cosine < {settings['redundancy_threshold']} to all chosen "
                           f"basepoints ({len(cand)} distinct candidates in a {len(EVENT_NAMES)}-dimensional space)")
            break
        idx = int(np.argmin(np.where(eligible, max_sim, np.inf)))
        chosen.append(idx)
        trace.append({"order": len(chosen), "max_cosine_to_previous": float(max_sim[idx]),
                      "rare_event_weight": float(rare_mass[idx])})
    return {"basepoints": cand[chosen], "rare_events": [EVENT_NAMES[j] for j in rare],
            "n_training_nonempty_sets": int(nonempty.sum()), "n_distinct_candidates": int(len(cand)),
            "trace": trace, "stop_reason": stop_reason}


def compute_profiles(vectors, basepoints):
    """Event profile = cosine similarity of each TF-IDF event vector to each basepoint (empty set -> all zeros)."""
    return cosine_similarity_matrix(vectors, basepoints)
