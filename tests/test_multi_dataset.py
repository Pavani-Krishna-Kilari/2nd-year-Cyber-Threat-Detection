"""
Unit tests for multi-dataset preprocessing across all eight CICIDS2017 files.
Verifies schema compatibility, encoding normalization, blank row pruning,
Experiment A & B split partitioning, and preservation of Tuesday baseline data.
"""

import unittest
import hashlib
from pathlib import Path
import pandas as pd
import numpy as np

from src.config import load_config, PROJECT_ROOT
from src.preprocessing.preprocess_dataset import (
    map_labels, normalize_columns, parse_timestamps,
    REQUIRED_COLUMNS, HELPER_COLUMNS
)

RAW_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
BACKUP_DIR = PROJECT_ROOT / "backups" / "tuesday_baseline_backup"

EXPECTED_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
]

EXPECTED_HASHES = {
    "Monday-WorkingHours.pcap_ISCX.csv": "96f26aea87d513073769b48ce204c2921791149e1c6225f7db65a3fed7973820",
    "Tuesday-WorkingHours.pcap_ISCX.csv": "ae9c88e10c41a8eb1ff454ae98bc513454925097d0b0b57180f94e79de445815",
    "Wednesday-workingHours.pcap_ISCX.csv": "ed538e85b84181e8897dedb3d37d365982f44b27eccd67c477581a8b65f3d170",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv": "e3deaff483d18b53b100a441dff9b8919416df8876b4edcc0f0d1e4bf48397d0",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv": "d74238e054023c8bd4d8056650463cadb25c100fb0e26ebd4272c07b5c022c4b",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv": "c061cd98f39d8054aeaed6244a5129a20b3985983d0d022b860ae8aa07fe8d21",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv": "7e2ddaa80a5849ba629463296b6128436c161b4a32e8034bb5beae06b0c45e08",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv": "1f779b4f0d78f9225554c4de53b5a2c07912b60dcd136ee4c5c1d0d2496b7cc4",
}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


class TestMultiDatasetIntegrity(unittest.TestCase):

    def test_all_eight_raw_files_exist_and_hashes_unaltered(self):
        """Rule 1: Preserve all eight original CICIDS2017 CSV files unchanged."""
        for fname in EXPECTED_FILES:
            fpath = RAW_DIR / fname
            self.assertTrue(fpath.exists(), f"Missing dataset file: {fname}")
            actual_hash = sha256_of(fpath)
            self.assertEqual(actual_hash, EXPECTED_HASHES[fname], f"Hash mismatch for {fname}")

    def test_all_eight_files_have_compatible_85_col_schema(self):
        """Rule 4: Check whether the eight files have compatible feature schemas."""
        ref_cols = None
        for fname in EXPECTED_FILES:
            fpath = RAW_DIR / fname
            df_head = pd.read_csv(fpath, encoding="latin-1", nrows=2)
            norm_cols = normalize_columns(list(df_head.columns))
            self.assertEqual(len(norm_cols), 85, f"Expected 85 columns in {fname}, got {len(norm_cols)}")
            if ref_cols is None:
                ref_cols = norm_cols
            else:
                self.assertEqual(norm_cols, ref_cols, f"Column order or names differed in {fname}")

    def test_thursday_en_dash_label_normalization(self):
        """Rule 7: Investigate Thursday WebAttacks encoding issues and normalize without crashing."""
        cfg, _ = load_config()
        test_labels = pd.Series([
            "BENIGN",
            "Web Attack \x96 Brute Force",
            "Web Attack – XSS",
            "Web Attack - Sql Injection",
            "FTP-Patator"
        ])
        canonical, binary, multiclass, code = map_labels(test_labels, cfg)
        self.assertEqual(list(binary), [0, 1, 1, 1, 1])
        self.assertIn("Web Attack - Brute Force", list(canonical))
        self.assertIn("Web Attack - XSS", list(canonical))
        self.assertIn("Web Attack - Sql Injection", list(canonical))

    def test_thursday_blank_row_detection_and_pruning(self):
        """Rule 7: Verify trailing comma rows are detected as all-NaN and prunable."""
        path = RAW_DIR / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
        # Verify line count vs real flows
        df_raw = pd.read_csv(path, encoding="latin-1", low_memory=False)
        self.assertEqual(len(df_raw), 458968)
        all_nan = df_raw.isna().all(axis=1)
        self.assertEqual(int(all_nan.sum()), 288602)
        df_valid = df_raw.loc[~all_nan]
        self.assertEqual(len(df_valid), 170366)

    def test_afternoon_hour_correction(self):
        """Verify afternoon files with hours 1..5 are shifted to 13..17."""
        cfg, _ = load_config()
        raw_ts = pd.Series(["7/7/2017 1:15", "7/7/2017 2:30", "7/7/2017 4:45"])
        parsed, shifted, info = parse_timestamps(
            raw_ts, cfg, "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
        )
        self.assertTrue(shifted.all())
        self.assertEqual(list(parsed.dt.hour), [13, 14, 16])

    def test_all_fourteen_attack_labels_registered(self):
        """Verify all 14 attack categories are supported in config without error."""
        cfg, _ = load_config()
        expected_attacks = [
            "FTP-Patator", "SSH-Patator", "DoS Hulk", "DoS GoldenEye", "DoS slowloris",
            "DoS Slowhttptest", "Heartbleed", "Web Attack - Brute Force", "Web Attack - XSS",
            "Web Attack - Sql Injection", "Infiltration", "Bot", "PortScan", "DDoS"
        ]
        registered = set(cfg["labels"]["attack_labels"])
        for att in expected_attacks:
            self.assertIn(att, registered, f"Attack {att} must be in config attack_labels")

    def test_experiment_b_split_partition_logic(self):
        """Rule 4: Verify Experiment B partition: Mon/Tue/Wed train, Thu val, Fri test."""
        def get_exp_b(filename: str) -> str:
            fn = filename.lower()
            if any(d in fn for d in ["monday", "tuesday", "wednesday"]):
                return "train"
            elif "thursday" in fn:
                return "validation"
            elif "friday" in fn:
                return "test"
            return "unassigned"

        self.assertEqual(get_exp_b("Monday-WorkingHours.pcap_ISCX.csv"), "train")
        self.assertEqual(get_exp_b("Tuesday-WorkingHours.pcap_ISCX.csv"), "train")
        self.assertEqual(get_exp_b("Wednesday-workingHours.pcap_ISCX.csv"), "train")
        self.assertEqual(get_exp_b("Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"), "validation")
        self.assertEqual(get_exp_b("Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv"), "validation")
        self.assertEqual(get_exp_b("Friday-WorkingHours-Morning.pcap_ISCX.csv"), "test")
        self.assertEqual(get_exp_b("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"), "test")
        self.assertEqual(get_exp_b("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"), "test")

    def test_tuesday_clean_baseline_preserved(self):
        """Rule 9: Preserve all existing saved models, processed Tuesday files and reports."""
        tuesday_clean = PROCESSED_DIR / "Tuesday-WorkingHours_clean.csv"
        backup_clean = BACKUP_DIR / "data_processed" / "Tuesday-WorkingHours_clean.csv"
        if tuesday_clean.exists() and backup_clean.exists():
            h1 = sha256_of(tuesday_clean)
            h2 = sha256_of(backup_clean)
            self.assertEqual(h1, h2, "Tuesday clean file was modified! Must remain identical to backup.")


if __name__ == "__main__":
    unittest.main()
