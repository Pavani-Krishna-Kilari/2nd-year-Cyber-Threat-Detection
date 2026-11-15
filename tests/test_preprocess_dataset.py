"""
Tests for Phase 2 using SMALL SYNTHETIC data (the real 166 MB CSV is not needed).

Run from the project root:
    python -m unittest discover -s tests -v
"""

import copy
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from src.config import DEFAULT_CONFIG, ConfigError, validate_config
from src.preprocessing.preprocess_dataset import (PreprocessingError, find_invalid_network_rows,
                                                  map_labels, normalize_columns, preprocess_dataframe,
                                                  process_file, read_processed_dataset, sha256_of)

FILE_NAME = "Tuesday-WorkingHours.pcap_ISCX.csv"


def make_raw(with_problems=True) -> pd.DataFrame:
    """Fake Tuesday capture, written the way CICIDS2017 writes it:
    padded column names, 12-hour clock (8-11 then 1-4), 4/7/2017 = 4 July."""
    rows = []
    rng = np.random.default_rng(1)
    times = [(h, m) for h in (8, 9, 10, 11) for m in range(60)] + [(h, m) for h in (1, 2, 3, 4) for m in range(60)]
    for h, m in times:
        ts = f"4/7/2017 {h}:{m:02d}"
        real_hour = h if h >= 8 else h + 12
        label, src, dport = "BENIGN", f"192.168.10.{rng.integers(2, 40)}", int(rng.choice([80, 443, 53]))
        rows.append([f"f{len(rows)}", src, int(rng.integers(1024, 60000)), "192.168.10.3", dport, 6, ts,
                     int(rng.integers(1, 5000)), float(rng.random() * 1000), float(rng.random() * 50),
                     0, int(rng.choice([-1, 8192, 29200])), label])
        if real_hour == 9 and m >= 20 or real_hour == 10 and m < 20:
            rows.append([f"f{len(rows)}", "172.16.0.1", int(rng.integers(1024, 60000)), "192.168.10.50", 21, 6, ts,
                         int(rng.integers(1, 5000)), float(rng.random() * 1000), float(rng.random() * 50),
                         0, 229, "FTP-Patator"])
        if real_hour == 14:
            rows.append([f"f{len(rows)}", "172.16.0.1", int(rng.integers(1024, 60000)), "192.168.10.50", 22, 6, ts,
                         int(rng.integers(1, 5000)), float(rng.random() * 1000), float(rng.random() * 50),
                         0, 229, " SSH-Patator "])          # extra spaces on purpose
    df = pd.DataFrame(rows, columns=[" Flow ID", " Source IP", " Source Port", " Destination IP",
                                     " Destination Port", " Protocol", " Timestamp", " Flow Duration",
                                     "Flow Bytes/s", " Flow Packets/s", " Const Flag", " Init_Win_bytes_forward",
                                     " Label"])
    if with_problems:
        df.loc[3, "Flow Bytes/s"] = np.inf
        df.loc[7, " Flow Packets/s"] = np.nan
        df = pd.concat([df, df.iloc[[10, 11, 12]]], ignore_index=True)   # 3 exact duplicates
    return df


def test_cfg():
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg["output"]["format"] = "csv"
    return cfg


def quiet(_):
    pass


class TestHelpers(unittest.TestCase):
    def test_normalize_columns(self):
        names = normalize_columns([" Flow Bytes/s", "Src IP", " Fwd Header Length.1", "Flow Bytes s"])
        self.assertEqual(names[0], "flow_bytes_s")
        self.assertEqual(names[1], "source_ip")
        self.assertEqual(names[2], "fwd_header_length_1")
        self.assertEqual(len(set(names)), 4)            # collision got a unique name

    def test_label_mapping(self):
        cfg = test_cfg()
        lab, b, m, code = map_labels(pd.Series(["BENIGN", " ssh-patator ", "FTP-Patator"]), cfg)
        self.assertEqual(list(b), [0, 1, 1])
        self.assertEqual(list(lab), ["BENIGN", "SSH-Patator", "FTP-Patator"])
        self.assertEqual(code["BENIGN"], 0)

    def test_unknown_label_raises(self):
        with self.assertRaises(PreprocessingError):
            map_labels(pd.Series(["BENIGN", "DDoS"]), test_cfg())

    def test_unknown_label_as_attack(self):
        cfg = test_cfg()
        cfg["labels"]["unknown_label_policy"] = "attack"
        _, b, _, _ = map_labels(pd.Series(["BENIGN", "DDoS"]), cfg)
        self.assertEqual(list(b), [0, 1])

    def test_invalid_network_rows(self):
        df = pd.DataFrame({"source_ip": ["1.2.3.4", "999.1.1.1"], "destination_ip": ["10.0.0.1", "10.0.0.2"],
                           "source_port": [80, 70000], "destination_port": [1, 2], "protocol": [6, 6]})
        bad, _ = find_invalid_network_rows(df)
        self.assertEqual(list(bad), [False, True])

    def test_config_validation(self):
        cfg = test_cfg()
        cfg["split"]["train_fraction"] = 0.9
        with self.assertRaises(ConfigError):
            validate_config(cfg)


class TestPipeline(unittest.TestCase):
    def setUp(self):
        self.cfg = test_cfg()
        self.raw = make_raw()
        self.df, self.info = preprocess_dataframe(self.raw.copy(), self.cfg, FILE_NAME, log=quiet)

    def test_no_missing_or_infinite_in_features(self):
        feats = self.df[self.info["feature_columns"]].to_numpy(dtype="float64")
        self.assertTrue(np.isfinite(feats).all())
        self.assertEqual(self.info["non_finite"]["rows"], 2)

    def test_duplicates_removed_and_configurable(self):
        self.assertEqual(self.info["duplicates"]["count"], 3)
        self.assertEqual(len(self.df), len(self.raw) - 3 - 2)
        cfg = test_cfg()
        cfg["cleaning"]["remove_duplicates"] = False
        df2, info2 = preprocess_dataframe(self.raw.copy(), cfg, FILE_NAME, log=quiet)
        self.assertEqual(len(df2), len(self.raw) - 2)

    def test_constant_column_removed_and_configurable(self):
        self.assertNotIn("const_flag", self.df.columns)
        cfg = test_cfg()
        cfg["cleaning"]["remove_constant_columns"] = False
        df2, _ = preprocess_dataframe(self.raw.copy(), cfg, FILE_NAME, log=quiet)
        self.assertIn("const_flag", df2.columns)

    def test_negative_values_preserved(self):
        self.assertTrue((self.df["init_win_bytes_forward"] == -1).any())

    def test_labels_and_targets(self):
        self.assertTrue(set(self.df["label_original"]).issuperset({" SSH-Patator "}))   # original kept
        self.assertEqual(set(self.df["label"].astype(str)), {"BENIGN", "FTP-Patator", "SSH-Patator"})
        self.assertTrue(((self.df["label"] == "BENIGN") == (self.df["target_binary"] == 0)).all())

    def test_timestamps_day_first_and_hour_fix(self):
        t = self.info["timestamp"]
        self.assertEqual(t["chosen_order"], "day_first")           # chosen via 'Tuesday' in file name
        self.assertTrue(t["hour_correction_applied"])
        self.assertEqual(self.df["timestamp"].min(), pd.Timestamp("2017-07-04 08:00"))
        self.assertEqual(self.df["timestamp"].max(), pd.Timestamp("2017-07-04 16:59"))
        self.assertTrue(self.df["timestamp"].is_monotonic_increasing)
        self.assertGreater(int(self.df["hour_shifted"].sum()), 0)
        self.assertFalse(t["uncertain"])

    def test_ambiguous_timestamp_is_flagged_without_weekday(self):
        _, info = preprocess_dataframe(make_raw(), self.cfg, "capture.csv", log=quiet)
        self.assertTrue(info["timestamp"]["uncertain"])             # cannot prove order -> documented

    def test_unambiguous_day_first_detected(self):
        raw = make_raw()
        raw[" Timestamp"] = raw[" Timestamp"].str.replace("4/7/2017", "25/7/2017")
        _, info = preprocess_dataframe(raw, self.cfg, "capture.csv", log=quiet)
        self.assertEqual(info["timestamp"]["chosen_order"], "day_first")
        self.assertFalse(info["timestamp"]["uncertain"])

    def test_hour_correction_can_be_disabled(self):
        cfg = test_cfg()
        cfg["timestamp"]["hour_correction"] = "never"
        df, info = preprocess_dataframe(make_raw(), cfg, FILE_NAME, log=quiet)
        self.assertFalse(info["timestamp"]["hour_correction_applied"])
        self.assertEqual(int(df["hour_shifted"].sum()), 0)

    def test_context_fields_not_features(self):
        for c in ("source_ip", "destination_ip", "flow_id", "source_port", "destination_port", "protocol", "timestamp"):
            self.assertNotIn(c, self.info["feature_columns"])
        for c in ("label", "target_binary", "split"):
            self.assertNotIn(c, self.info["feature_columns"])

    def test_leakage_table_flags_attacker_ip(self):
        row = [r for r in self.info["leakage"] if r[0] == "FTP-Patator" and r[1] == "source_ip"][0]
        self.assertEqual(row[2], "172.16.0.1")
        self.assertAlmostEqual(row[3], 1.0)
        self.assertEqual(row[4], 0.0)

    def test_split_blocks_whole_and_attacks_in_every_split(self):
        df = self.df
        self.assertTrue((df.groupby("block_id")["split"].nunique() == 1).all())   # a block never straddles splits
        tbl = self.info["split_table"]
        for lab in ("BENIGN", "FTP-Patator", "SSH-Patator"):
            for sp in ("train", "validation", "test"):
                self.assertGreater(tbl.loc[sp, lab], 0, f"{lab} missing from {sp}")
        df2, _ = preprocess_dataframe(make_raw(), test_cfg(), FILE_NAME, log=quiet)
        self.assertTrue((df2["split"].values == df["split"].values).all())        # reproducible

    def test_non_finite_keep_as_nan(self):
        cfg = test_cfg()
        cfg["cleaning"]["non_finite_strategy"] = "keep_as_nan"
        df, _ = preprocess_dataframe(make_raw(), cfg, FILE_NAME, log=quiet)
        self.assertFalse(np.isinf(df["flow_bytes_s"].to_numpy(dtype="float64")).any())
        self.assertTrue(df["flow_packets_s"].isna().any())

    def test_drop_fraction_safety_stop(self):
        cfg = test_cfg()
        cfg["cleaning"]["max_drop_fraction"] = 0.0001
        with self.assertRaises(PreprocessingError):
            preprocess_dataframe(make_raw(), cfg, FILE_NAME, log=quiet)

    def test_missing_required_column_gives_helpful_error(self):
        raw = make_raw().drop(columns=[" Source IP"])
        with self.assertRaises(PreprocessingError) as ctx:
            preprocess_dataframe(raw, self.cfg, FILE_NAME, log=quiet)
        self.assertIn("TrafficLabelling", ctx.exception.hint)


class TestEndToEnd(unittest.TestCase):
    def test_files_written_and_raw_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "raw").mkdir()
            raw_path = tmp / "raw" / FILE_NAME
            make_raw().to_csv(raw_path, index=False, encoding="latin-1")
            before = sha256_of(raw_path)

            cfg = test_cfg()
            cfg["paths"] = {"raw_dir": str(tmp / "raw"), "interim_dir": str(tmp / "interim"),
                            "processed_dir": str(tmp / "processed"), "reports_dir": str(tmp / "reports")}
            info = process_file(raw_path, cfg, log=quiet)

            self.assertEqual(sha256_of(raw_path), before)
            self.assertTrue(info["raw_untouched"])
            out = Path(info["outputs"]["processed data"])
            self.assertTrue(out.exists())
            back = read_processed_dataset(out)
            self.assertEqual(len(back), info["rows_final"])
            self.assertTrue(pd.api.types.is_datetime64_any_dtype(back["timestamp"]))
            meta = json.loads(Path(info["outputs"]["metadata"]).read_text(encoding="utf-8"))
            self.assertEqual(meta["raw_sha256"], before)

            from src.preprocessing.report_writer import write_preprocessing_report
            rp = tmp / "reports" / "preprocessing_report.md"
            write_preprocessing_report([info], cfg, "test", rp)
            text = rp.read_text(encoding="utf-8")
            self.assertIn("UNCHANGED", text)
            self.assertIn("Leakage-risk", text)


if __name__ == "__main__":
    unittest.main()
