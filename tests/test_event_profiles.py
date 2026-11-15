"""
Phase 3 tests on SMALL SYNTHETIC data (no real dataset needed).

    python -m unittest tests.test_event_profiles -v
"""

import copy
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from src.config import DEFAULT_CONFIG
from src.event_profiles.basepoints import cosine_similarity_matrix, select_basepoints
from src.event_profiles.build_event_profiles import (compute_event_sets, fit_transform_profiles,
                                                     load_event_inputs, run_pipeline)
from src.event_profiles.errors import EventProfileError, ValidationError
from src.event_profiles.events import (EVENT_INPUT_COLUMNS, EVENT_NAMES, FORBIDDEN_EVENT_COLUMNS,
                                       assert_no_forbidden_columns, fit_flow_thresholds)
from src.event_profiles.settings import load_settings
from src.event_profiles.targets import assign_targets, mixed_statistics
from src.event_profiles.tfidf import fit_idf, l2_normalize_rows, transform
from src.event_profiles.validation import validate_directory, validate_model_files
from src.event_profiles.windows import aggregate_to_windows, valid_windows

BLOCK_SPLIT = ["train", "train", "validation", "train", "test", "train", "train", "validation", "test"]


def quiet(_):
    pass


def make_cfg():
    return copy.deepcopy(DEFAULT_CONFIG)


def make_cleaned(seed=0, minutes=180):
    """3 hours of fake cleaned flows in 20-minute blocks (columns as Phase 2 writes them)."""
    rng = np.random.default_rng(seed)
    t0 = pd.Timestamp("2017-07-04 09:00")
    rows = []

    def add(minute, src, dst, dur, pps, bps, syn, label, code):
        rows.append({"source_row": len(rows), "timestamp": t0 + pd.Timedelta(minutes=minute),
                     "split": BLOCK_SPLIT[minute // 20], "block_id": minute // 20,
                     "source_ip": src, "destination_ip": dst, "source_port": 40000 + len(rows) % 1000,
                     "destination_port": 80, "protocol": 6, "flow_duration": dur, "flow_packets_s": pps,
                     "flow_bytes_s": bps, "syn_flag_count": syn, "label": label, "label_original": label,
                     "target_binary": int(code != 0), "target_multiclass": code})

    for minute in range(minutes):
        for p in rng.choice(8, size=int(rng.integers(3, 7)), replace=False):
            for _ in range(int(rng.integers(1, 4))):
                add(minute, f"192.168.10.{10 + p}", f"10.0.0.{p % 3 + 1}", int(rng.integers(1000, 5_000_000)),
                    float(rng.uniform(1, 500)), float(rng.uniform(100, 5e4)), int(rng.integers(0, 2)), "BENIGN", 0)
        if minute == 24:
            add(minute, "172.16.0.1", "192.168.10.50", 3000, 20.0, 900.0, 0, "BENIGN", 0)   # benign flow of the attacker pair
        if 25 <= minute <= 34 or 45 <= minute <= 54 or 85 <= minute <= 94:
            lab, code = ("SSH-Patator", 2) if minute >= 85 else ("FTP-Patator", 1)
            for _ in range(8):
                add(minute, "172.16.0.1", "192.168.10.50", int(rng.integers(10, 500)), float(rng.uniform(2000, 9000)),
                    float(rng.uniform(1e5, 5e5)), int(rng.integers(1, 7)), lab, code)
    return pd.DataFrame(rows)


def event_inputs(df):
    return df[EVENT_INPUT_COLUMNS].copy()


def run_on(df, tmp, name="x", cfg=None):
    cfg = cfg or make_cfg()
    settings = load_settings(cfg)
    inp = Path(tmp) / f"{name}_clean.csv"
    df.to_csv(inp, index=False)
    out = Path(tmp) / f"{name}_out"
    info = run_pipeline(inp, out, Path(tmp) / f"{name}_reports", cfg, settings, log=quiet)
    return info, out


class TestWindows(unittest.TestCase):
    def test_aggregate_matches_bruteforce(self):
        rng = np.random.default_rng(3)
        n, W, n_bins = 400, 6, 40
        pair = rng.integers(0, 5, n)
        bins = rng.integers(0, n_bins, n)
        vals = rng.integers(0, 4, (n, 2))
        n_windows = n_bins - W + 1
        valid = rng.random(n_windows) > 0.3
        agg = aggregate_to_windows(pair, bins, vals, W, valid, n_windows)
        ref = {}
        for k in range(n_windows):
            if not valid[k]:
                continue
            for p in range(5):
                m = (pair == p) & (bins >= k) & (bins < k + W)
                if m.any():
                    ref[(p, k)] = tuple(vals[m].sum(axis=0))
        got = {(int(r.pair), int(r.k)): (int(r.v0), int(r.v1)) for r in agg.itertuples()}
        self.assertEqual(ref, got)

    def test_valid_windows_never_cross_splits(self):
        names = np.array(["train"] * 5 + ["test"] * 5 + ["train"] * 5, dtype=object)
        valid, split_of = valid_windows(names, 3)
        for k, ok in enumerate(valid):
            same = len(set(names[k:k + 3])) == 1
            self.assertEqual(ok, same)
        self.assertEqual(int(valid.sum()), 9)

    def test_unknown_blocks_make_windows_invalid(self):
        names = np.array(["train", "train", None, "train", "train", "train"], dtype=object)
        valid, _ = valid_windows(names, 2)
        self.assertEqual(valid.tolist(), [True, False, False, True, True])


class TestEvents(unittest.TestCase):
    def test_threshold_is_linear_quantile_and_strict(self):
        train = pd.DataFrame({"flow_packets_s": np.arange(1, 101, dtype=float), "flow_bytes_s": np.arange(1, 101, dtype=float),
                              "syn_flag_count": np.arange(1, 101, dtype=float), "flow_duration": np.arange(1, 101, dtype=float)})
        t = fit_flow_thresholds(train, load_settings(make_cfg()))
        self.assertAlmostEqual(t["HIGH_PACKET_RATE"]["threshold"], 95.05)         # x[94] + 0.05*(x[95]-x[94])
        self.assertAlmostEqual(t["SHORT_REPEATED_CONNECTIONS"]["threshold"], 5.95)
        self.assertEqual(t["HIGH_PACKET_RATE"]["comparison"], "gt")

    def test_forbidden_columns_are_refused(self):
        for col in sorted(FORBIDDEN_EVENT_COLUMNS):
            df = pd.DataFrame({col: [1]})
            with self.assertRaises(EventProfileError):
                assert_no_forbidden_columns(df)

    def test_loader_never_reads_labels_or_ports(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "a_clean.csv"
            make_cleaned(minutes=60).to_csv(p, index=False)
            cols = set(load_event_inputs(p).columns)
        self.assertEqual(cols, set(EVENT_INPUT_COLUMNS))
        self.assertFalse(cols & FORBIDDEN_EVENT_COLUMNS)

    def test_grouping_other_than_source_destination_rejected(self):
        cfg = make_cfg()
        cfg["event_profiles"] = {"grouping": "global"}
        with self.assertRaises(EventProfileError):
            load_settings(cfg)


class TestTfidfBasepointsCosine(unittest.TestCase):
    def test_tfidf_numbers(self):
        counts = np.array([[0, 2, 0, 0, 0], [1, 0, 0, 0, 0], [0, 0, 0, 0, 0]])
        m = fit_idf(counts, True)
        self.assertEqual(m["document_frequency"], [1, 1, 0, 0, 0])
        self.assertAlmostEqual(m["idf"][0], np.log(4 / 2) + 1)
        self.assertAlmostEqual(m["idf"][2], np.log(4 / 1) + 1)
        v = transform(counts, m)
        np.testing.assert_allclose(v[0], [0, 1, 0, 0, 0])
        np.testing.assert_allclose(v[2], np.zeros(5))                       # empty set stays a zero vector

    def test_zero_vectors_are_safe(self):
        a = np.array([[0.0, 0, 0, 0, 0], [1.0, 0, 0, 0, 0]])
        b = np.array([[0.0, 0, 0, 0, 0], [1.0, 1.0, 0, 0, 0]])
        sim = cosine_similarity_matrix(a, b)
        self.assertTrue(np.isfinite(sim).all())
        np.testing.assert_allclose(sim[0], [0, 0])
        self.assertAlmostEqual(sim[1, 1], 1 / np.sqrt(2))
        np.testing.assert_allclose(l2_normalize_rows(np.zeros((2, 5))), np.zeros((2, 5)))

    def _vectors(self):
        axes = np.eye(5)
        near = l2_normalize_rows(np.array([[1.0, 0.1, 0, 0, 0]]))
        rows = [axes[0]] * 20 + [axes[1]] * 15 + [axes[2]] * 10 + [axes[3]] * 3 + [axes[4]] * 2 + [near[0]] * 4 + [np.zeros(5)] * 7
        v = np.array(rows)
        df = (v > 0).sum(axis=0)
        return v, df

    def test_basepoints_deterministic_nonredundant_nonzero(self):
        v, df = self._vectors()
        s = load_settings(make_cfg())
        a, b = select_basepoints(v, df, s), select_basepoints(v, df, s)
        np.testing.assert_array_equal(a["basepoints"], b["basepoints"])
        bpts = a["basepoints"]
        self.assertTrue((np.linalg.norm(bpts, axis=1) > 0).all())
        sims = bpts @ bpts.T
        np.fill_diagonal(sims, 0)
        self.assertTrue((sims < s["redundancy_threshold"]).all())
        self.assertEqual(a["rare_events"], [EVENT_NAMES[4], EVENT_NAMES[3]])  # lowest training document frequency
        self.assertLessEqual(len(bpts), 8)

    def test_fewer_basepoints_than_requested_is_reported_not_padded(self):
        v, df = self._vectors()
        s = load_settings(make_cfg())
        s["basepoints"] = 50
        out = select_basepoints(v, df, s)
        self.assertLess(len(out["basepoints"]), 50)
        self.assertIn("no remaining candidate", out["stop_reason"])

    def test_all_empty_training_sets_raise(self):
        with self.assertRaises(EventProfileError):
            select_basepoints(np.zeros((5, 5)), np.zeros(5, dtype=int), load_settings(make_cfg()))


class TestTargets(unittest.TestCase):
    def test_assignment_pure_and_mixed(self):
        cc = np.array([[5, 0, 0], [0, 3, 0], [2, 1, 0], [1, 1, 2]])
        t = assign_targets(cc, 0, 1, 0.0)
        self.assertEqual(t["target_binary"].tolist(), [0, 1, 1, 1])
        self.assertEqual(t["target_multiclass"].tolist(), [0, 1, 1, 2])
        self.assertEqual(t["is_mixed"].tolist(), [False, False, True, True])
        self.assertEqual(t["is_multi_attack"].tolist(), [False, False, False, True])
        self.assertEqual(assign_targets(cc, 0, 2, 0.0)["target_binary"].tolist(), [0, 1, 0, 1])
        self.assertEqual(assign_targets(cc, 0, 1, 0.5)["target_binary"].tolist(), [0, 1, 0, 1])

    def test_mixed_statistics(self):
        cc = np.array([[5, 0, 0], [0, 3, 0], [2, 1, 0], [1, 1, 2]])
        t = assign_targets(cc, 0, 1, 0.0)
        t["split"] = ["train", "train", "test", "test"]
        s = mixed_statistics(t)
        self.assertEqual(s["overall"]["mixed_sets"], 2)
        self.assertAlmostEqual(s["overall"]["mixed_pct_of_all"], 50.0)
        self.assertAlmostEqual(s["overall"]["mixed_pct_of_positive"], 200 / 3)
        self.assertEqual(s["overall"]["positive_with_attack_fraction_below_half"], 1)   # the 1-of-3 set
        self.assertEqual(s["test"]["mixed_sets"], 2)


class TestLeakageAndFitting(unittest.TestCase):
    def _res(self, df):
        return compute_event_sets(event_inputs(df), 600, 60, 20, load_settings(make_cfg()), quiet)

    def test_nontraining_data_cannot_change_fitted_values(self):
        base = make_cleaned()
        altered = base.copy()
        nt = altered["split"] != "train"
        altered.loc[nt, "flow_packets_s"] *= 1000
        altered.loc[nt, "flow_duration"] = 1
        altered.loc[nt, "syn_flag_count"] += 5
        drop = altered.index[nt][::2]                      # also remove half of the non-training flows
        altered = altered.drop(index=drop)
        s = load_settings(make_cfg())
        r1, r2 = self._res(base), self._res(altered)
        self.assertEqual(r1["thresholds"], r2["thresholds"])
        m1, v1, b1, p1 = fit_transform_profiles(r1, s)
        m2, v2, b2, p2 = fit_transform_profiles(r2, s)
        self.assertEqual(m1["idf"], m2["idf"])
        np.testing.assert_array_equal(b1["basepoints"], b2["basepoints"])

    def test_no_window_crosses_a_split(self):
        res = self._res(make_cleaned())
        sets, W = res["sets"], res["W"]
        for k, sp in zip(sets["k"].to_numpy(), sets["split"].to_numpy()):
            blocks = {(minute // 20) for minute in range(k, k + W)}
            self.assertEqual({BLOCK_SPLIT[b] for b in blocks}, {sp})
        self.assertGreater(int((~res["valid"]).sum()), 0)

    def test_hfr_uses_event_set_flow_count_not_window_total(self):
        res = self._res(make_cleaned())
        t = res["thresholds"]["HIGH_FLOW_RATE"]
        self.assertEqual(t["level"], "event_set")
        sets = res["sets"]
        train = sets[sets["split"] == "train"]
        self.assertAlmostEqual(t["threshold"], float(np.quantile(train["n_flows"], 0.95)))
        np.testing.assert_array_equal(sets["HIGH_FLOW_RATE"].to_numpy(), (sets["n_flows"] > t["threshold"]).astype(int))
        # per-window totals are larger than per-set counts, proving the unit is the set
        self.assertGreater(sets.groupby("window_id")["n_flows"].sum().max(), sets["n_flows"].max())

    def test_events_are_counts_not_yes_no(self):
        res = self._res(make_cleaned())
        self.assertGreater(res["sets"]["HIGH_PACKET_RATE"].max(), 1)


class TestPipelineOutputs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.df = make_cleaned()
        cls.info, cls.out = run_on(cls.df, cls.tmp.name)
        cls.profiles = pd.read_csv(cls.out / "event_profiles.csv", dtype={"event_set_id": str, "window_id": str})
        cls.targets = pd.read_csv(cls.out / "event_set_targets.csv", dtype={"event_set_id": str, "window_id": str})

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_ids_unique_and_both_files_match_exactly(self):
        for df in (self.profiles, self.targets):
            self.assertFalse(df["event_set_id"].duplicated().any())
            self.assertFalse(df["event_set_id"].isna().any())
        self.assertEqual(set(self.profiles["event_set_id"]), set(self.targets["event_set_id"]))
        self.assertEqual(len(self.profiles), len(self.targets))
        self.assertTrue(self.profiles["window_id"].nunique() < len(self.profiles))   # several sets share a window
        self.assertTrue(validate_directory(self.out))

    def test_model_input_has_only_ids_and_numeric_profile_columns(self):
        cols = list(self.profiles.columns)
        self.assertEqual(cols[:4], ["event_set_id", "window_id", "split", "window_start"])
        self.assertTrue(all(c.startswith("bp_") for c in cols[4:]))
        for bad in ("source_ip", "destination_ip", "label", "target_binary", "target_multiclass", "n_flows"):
            self.assertNotIn(bad, cols)
        self.assertFalse(any(c.startswith("bp_") for c in self.targets.columns))
        meta = json.loads((self.out / "event_profiles_metadata.json").read_text())
        self.assertEqual(meta["model_input_columns"], cols[4:])
        self.assertEqual(meta["join_key"], "event_set_id")

    def test_all_expected_files_and_reports_exist(self):
        for name in ["event_profiles.csv", "event_set_targets.csv", "event_sets.csv", "event_set_keys.csv",
                     "tfidf_event_vectors.csv", "tfidf_model.json", "event_thresholds.json", "basepoints.csv",
                     "basepoints.json", "event_profiles_metadata.json"]:
            self.assertTrue((self.out / name).exists(), name)
        for p in self.info["reports"].values():
            self.assertTrue(Path(p).exists())

    def test_empty_sets_have_zero_profiles_and_flag(self):
        es = pd.read_csv(self.out / "event_sets.csv", dtype={"event_set_id": str})
        empty_ids = set(es.loc[es["is_empty"], "event_set_id"])
        self.assertGreater(len(empty_ids), 0)
        bp = [c for c in self.profiles.columns if c.startswith("bp_")]
        sub = self.profiles[self.profiles["event_set_id"].isin(empty_ids)]
        self.assertTrue((sub[bp].to_numpy() == 0).all())
        self.assertEqual(self.info["stats"]["n_empty_total"], len(empty_ids))

    def test_targets_and_mixed_sets(self):
        t = self.targets
        self.assertGreater(int(t["is_mixed"].sum()), 0)                    # the benign flow of the attacker pair at minute 24
        self.assertTrue(((t["target_binary"] == 1) == (t["n_attack_flows"] >= 1)).all())
        for sp in ("train", "validation", "test"):
            self.assertGreater(int(t.loc[t["split"] == sp, "target_binary"].sum()), 0, sp)
        self.assertEqual(self.info["mixed"]["overall"]["mixed_sets"], int(t["is_mixed"].sum()))
        self.assertEqual(set(t["target_label"]) - {"BENIGN"}, {"FTP-Patator", "SSH-Patator"})

    def test_cleaned_input_untouched(self):
        self.assertTrue(self.info["input_untouched"])
        self.assertEqual(self.info["sha_before"], self.info["sha_after"])

    def test_labels_do_not_influence_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            shuffled = self.df.copy()
            perm = np.random.default_rng(9).permutation(len(shuffled))
            for c in ("label", "label_original", "target_binary", "target_multiclass"):
                shuffled[c] = shuffled[c].to_numpy()[perm]
            _, out2 = run_on(shuffled, tmp, "shuf")
            for name in ("event_profiles.csv", "event_sets.csv", "event_thresholds.json", "tfidf_model.json", "basepoints.csv"):
                self.assertEqual((self.out / name).read_bytes(), (out2 / name).read_bytes(), name)
            t2 = pd.read_csv(out2 / "event_set_targets.csv")
            self.assertFalse(t2["target_binary"].equals(self.targets["target_binary"]))   # targets DO follow the labels

    def test_ip_addresses_are_not_features(self):
        with tempfile.TemporaryDirectory() as tmp:
            renamed = self.df.copy()
            order = pd.unique(pd.concat([renamed["source_ip"], renamed["destination_ip"]]))
            mapping = {ip: f"zz-{len(order) - i}.example" for i, ip in enumerate(order)}   # different sort order, new text
            renamed["source_ip"] = renamed["source_ip"].map(mapping)
            renamed["destination_ip"] = renamed["destination_ip"].map(mapping)
            _, out2 = run_on(renamed, tmp, "ren")
            self.assertEqual((self.out / "event_profiles.csv").read_bytes(), (out2 / "event_profiles.csv").read_bytes())
            self.assertNotEqual((self.out / "event_set_keys.csv").read_bytes(), (out2 / "event_set_keys.csv").read_bytes())


class TestJoinValidationCatchesProblems(unittest.TestCase):
    def setUp(self):
        ids = [f"ES{i:07d}" for i in range(1, 6)]
        self.p = pd.DataFrame({"event_set_id": ids, "window_id": ["W00001"] * 5, "split": ["train"] * 5,
                               "window_start": ["2017-07-04 09:00:00"] * 5, "bp_01": [0.1] * 5, "bp_02": [0.9] * 5})
        self.t = pd.DataFrame({"event_set_id": ids, "window_id": ["W00001"] * 5, "split": ["train"] * 5,
                               "target_binary": [0, 1, 0, 0, 1], "target_multiclass": [0, 1, 0, 0, 2]})

    def test_valid_files_pass(self):
        self.assertTrue(all(ok for _, ok, _ in validate_model_files(self.p, self.t)))

    def test_duplicate_id_detected(self):
        t = self.t.copy()
        t.loc[1, "event_set_id"] = t.loc[0, "event_set_id"]
        with self.assertRaises(ValidationError):
            validate_model_files(self.p, t)

    def test_missing_id_detected(self):
        with self.assertRaises(ValidationError):
            validate_model_files(self.p, self.t.iloc[:-1])

    def test_extra_or_different_id_detected(self):
        t = self.t.copy()
        t.loc[4, "event_set_id"] = "ES0000099"
        with self.assertRaises(ValidationError):
            validate_model_files(self.p, t)

    def test_forbidden_column_in_model_input_detected(self):
        p = self.p.copy()
        p["source_ip"] = "10.0.0.1"
        with self.assertRaises(ValidationError):
            validate_model_files(p, self.t)
        p2 = self.p.copy()
        p2["target_binary"] = 0
        with self.assertRaises(ValidationError):
            validate_model_files(p2, self.t)

    def test_nan_profile_detected(self):
        p = self.p.copy()
        p.loc[2, "bp_01"] = np.nan
        with self.assertRaises(ValidationError):
            validate_model_files(p, self.t)

    def test_split_disagreement_detected(self):
        t = self.t.copy()
        t.loc[0, "split"] = "test"
        with self.assertRaises(ValidationError):
            validate_model_files(self.p, t)


if __name__ == "__main__":
    unittest.main()
