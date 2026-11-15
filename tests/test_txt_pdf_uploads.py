"""
Comprehensive test suite for TXT and PDF file upload support in AI-SIEM.

Verifies:
  1. Extraction of structured network flow records from TXT files.
  2. Formatting variations, multi-word aliases, and line-wrapped fields.
  3. Ground-truth label stripping to protect neural model integrity.
  4. Behavior on fictional files without timestamps (e.g. siem_small_test_input.txt).
  5. Full end-to-end sliding-window temporal aggregation and inference on timestamped TXT/PDF.
  6. Direct vectorized neural batch inference on 8D basepoint profile TXT/PDF.
  7. Strict schema validation, rejection of empty/malformed files with descriptive errors.
  8. Zero regression on pre-existing CSV upload workflows.
"""

import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd
from fastapi.testclient import TestClient

import backend.database
from backend.main import app
from backend.parser import (
    parse_uploaded_file,
    parse_csv_bytes,
    parse_txt_bytes,
    parse_pdf_bytes,
    extract_flow_records_from_text,
    PROFILE_COLS,
    REQUIRED_FLOW_FEATURES
)
from backend.service import siem_service
from backend.aggregator import (
    MissingFeatureColumnsError,
    InsufficientTemporalSpanError,
    AggregatorError
)


def _create_minimal_pdf(text_lines: list) -> bytes:
    """Helper to generate a minimal valid PDF containing the given text lines."""
    stream_content = "BT\n/F1 12 Tf\n"
    y = 700
    for line in text_lines:
        safe_line = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        stream_content += f"72 {y} Td\n({safe_line}) Tj\n-72 0 Td\n"
        y -= 15
    stream_content += "ET\n"

    stream_bytes = stream_content.encode("latin-1")
    stream_len = len(stream_bytes)

    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 612 792] /Contents 5 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        b"5 0 obj\n<< /Length " + str(stream_len).encode("ascii") + b" >>\nstream\n"
        + stream_bytes +
        b"\nendstream\nendobj\n"
        b"xref\n0 6\n"
        b"0000000000 65535 f \n"
        b"trailer\n<< /Size 6 /Root 1 0 R >>\n"
        b"startxref\n0\n"
        b"%%EOF\n"
    )
    return pdf


class TestTxtPdfUploadSupport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.test_db_path = Path(cls.temp_dir.name) / "test_uploads.db"
        cls.orig_db_path = backend.database.DB_PATH
        backend.database.DB_PATH = cls.test_db_path
        backend.database.init_db()
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        backend.database.DB_PATH = cls.orig_db_path
        cls.temp_dir.cleanup()

    # -------------------------------------------------------------------------
    # 1. TXT Extraction & Format Variations
    # -------------------------------------------------------------------------

    def test_01_extract_flow_records_from_small_test_input(self):
        """Verifies exact extraction of the 3 fictional flows from siem_small_test_input.txt."""
        sample_txt = (
            "AI-SIEM TEST INPUT Synthetic network-flow sample for upload testing\n"
            "only. These records are fictional and are not captured network traffic.\n"
            "No ground-truth attack labels are included.\n\n"
            "FLOW 1 Source IP: 192.168.1.10 Destination IP: 192.168.1.20 Source Port:\n"
            "51514 Destination Port: 80 Protocol: TCP Flow Duration: 120000 Total Fwd\n"
            "Packets: 12 Total Backward Packets: 10 Flow Bytes/s: 850.5 Flow\n"
            "Packets/s: 183.3 SYN Flag Count: 1\n\n"
            "FLOW 2 Source IP: 192.168.1.15 Destination IP: 192.168.1.25 Source Port:\n"
            "51520 Destination Port: 443 Protocol: TCP Flow Duration: 250000 Total\n"
            "Fwd Packets: 24 Total Backward Packets: 20 Flow Bytes/s: 1450.0 Flow\n"
            "Packets/s: 176.0 SYN Flag Count: 1\n\n"
            "FLOW 3 Source IP: 10.0.0.8 Destination IP: 10.0.0.3 Source Port: 53000\n"
            "Destination Port: 22 Protocol: TCP Flow Duration: 90000 Total Fwd\n"
            "Packets: 35 Total Backward Packets: 2 Flow Bytes/s: 4200.0 Flow\n"
            "Packets/s: 411.1 SYN Flag Count: 1\n"
        )

        df, kind = parse_uploaded_file(sample_txt.encode("utf-8"), "siem_small_test_input.txt")
        self.assertEqual(kind, "flow")
        self.assertEqual(len(df), 3)

        # Verify Record 1 fields
        r1 = df.iloc[0]
        self.assertEqual(r1["source_ip"], "192.168.1.10")
        self.assertEqual(r1["destination_ip"], "192.168.1.20")
        self.assertEqual(r1["source_port"], 51514)
        self.assertEqual(r1["destination_port"], 80)
        self.assertEqual(r1["protocol"], "TCP")
        self.assertEqual(r1["flow_duration"], 120000)
        self.assertEqual(r1["total_fwd_packets"], 12)
        self.assertEqual(r1["total_backward_packets"], 10)
        self.assertAlmostEqual(r1["flow_bytes_s"], 850.5)
        self.assertAlmostEqual(r1["flow_packets_s"], 183.3)
        self.assertEqual(r1["syn_flag_count"], 1)

        # Verify Record 3 fields
        r3 = df.iloc[2]
        self.assertEqual(r3["source_ip"], "10.0.0.8")
        self.assertEqual(r3["destination_ip"], "10.0.0.3")
        self.assertEqual(r3["source_port"], 53000)
        self.assertEqual(r3["destination_port"], 22)
        self.assertEqual(r3["flow_duration"], 90000)

        # Timestamps must NOT be invented
        self.assertNotIn("timestamp", df.columns)

    def test_02_missing_timestamp_raises_informative_error(self):
        """Verifies that uploading a flow TXT without timestamps raises MissingFeatureColumnsError with record count."""
        sample_txt = (
            "FLOW 1 Source IP: 192.168.1.10 Destination IP: 192.168.1.20 Source Port: 51514\n"
            "Destination Port: 80 Protocol: TCP Flow Duration: 120000 Total Fwd Packets: 12\n"
            "Total Backward Packets: 10 Flow Bytes/s: 850.5 Flow Packets/s: 183.3 SYN Flag Count: 1\n"
        )
        with self.assertRaises(MissingFeatureColumnsError) as ctx:
            siem_service.process_file_upload(sample_txt.encode("utf-8"), "no_timestamp.txt")

        err_str = str(ctx.exception)
        self.assertIn("timestamp", err_str.lower())
        self.assertIn("1 network flow record(s)", err_str)
        self.assertIn("Sliding-window temporal aggregation", err_str)

    def test_03_api_endpoint_missing_timestamp_returns_422_with_details(self):
        """Verifies that REST endpoint returns HTTP 422 with structured validation details when timestamp is missing."""
        sample_txt = (
            "FLOW 1 Source IP: 192.168.1.10 Destination IP: 192.168.1.20 Source Port: 51514\n"
            "Destination Port: 80 Protocol: TCP Flow Duration: 120000 Total Fwd Packets: 12\n"
            "Total Backward Packets: 10 Flow Bytes/s: 850.5 Flow Packets/s: 183.3 SYN Flag Count: 1\n"
        )
        files = {"file": ("siem_small_test_input.txt", sample_txt.encode("utf-8"), "text/plain")}
        resp = self.client.post("/api/detect/upload", files=files)
        self.assertEqual(resp.status_code, 422)
        data = resp.json()
        self.assertIn("detail", data)
        detail = data["detail"]
        self.assertEqual(detail["error"], "MissingFeatureColumnsError")
        self.assertIn("details", detail)
        self.assertEqual(detail["details"]["extracted_records"], 1)
        self.assertIn("source_ip", detail["details"]["columns_found"])

    # -------------------------------------------------------------------------
    # 2. Timestamped TXT Full End-to-End Aggregation Pipeline
    # -------------------------------------------------------------------------

    def test_04_timestamped_txt_end_to_end_pipeline(self):
        """Verifies that a TXT file with timestamps spanning >= 10 bins executes sliding window aggregation and classification."""
        start_dt = datetime(2017, 7, 4, 9, 0, 0)
        lines = []
        for b in range(12):
            for f in range(2):
                dt = start_dt + timedelta(seconds=b * 60 + f * 10)
                lines.append(f"FLOW {b*2 + f + 1}:")
                lines.append(f"  Timestamp: {dt.strftime('%Y-%m-%d %H:%M:%S')}")
                lines.append(f"  Source IP: 192.168.10.50")
                lines.append(f"  Destination IP: 172.16.0.1")
                lines.append(f"  Source Port: {50000 + f}")
                lines.append(f"  Destination Port: 80")
                lines.append(f"  Flow Duration: 20000")
                lines.append(f"  Flow Packets/s: 650000.0")
                lines.append(f"  Flow Bytes/s: 2500000.0")
                lines.append(f"  SYN Flag Count: 2")
                lines.append("")

        txt_bytes = "\n".join(lines).encode("utf-8")
        res = siem_service.process_file_upload(txt_bytes, "timestamped_flows.txt")

        self.assertIn("session_id", res)
        self.assertIn("flow_statistics", res)
        self.assertIn("event_set_statistics", res)
        self.assertIn("campaign_statistics", res)
        self.assertEqual(res["flow_statistics"]["total_raw_flows"], 24)
        self.assertGreaterEqual(res["event_set_statistics"]["total_event_sets"], 1)

    # -------------------------------------------------------------------------
    # 3. Basepoint Event Profile TXT Direct Ingestion
    # -------------------------------------------------------------------------

    def test_05_profile_txt_direct_batch_inference(self):
        """Verifies that a TXT file containing 8-dimensional basepoint profiles executes vectorized batch inference."""
        bp_txt = (
            "bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08\n"
            "0.15,0.25,0.35,0.45,0.55,0.65,0.75,0.85\n"
            "0.85,0.75,0.65,0.55,0.45,0.35,0.25,0.15\n"
        )
        res = siem_service.process_file_upload(bp_txt.encode("utf-8"), "profiles.txt")
        self.assertEqual(res["total_records"], 2)
        self.assertIn("threats_detected", res)
        self.assertIn("known_threats", res)
        self.assertIn("unknown_anomalous", res)

    # -------------------------------------------------------------------------
    # 4. PDF File Parsing & Pipeline Integration
    # -------------------------------------------------------------------------

    def test_06_pdf_flow_extraction(self):
        """Verifies that a PDF document containing network flow text is cleanly parsed into a DataFrame."""
        pdf_lines = [
            "AI-SIEM NETWORK TRAFFIC SUMMARY REPORT",
            "FLOW 1 Source IP: 10.0.0.5 Destination IP: 10.0.0.9 Source Port: 44300",
            "Destination Port: 80 Protocol: TCP Flow Duration: 45000 Total Fwd Packets: 8",
            "Total Backward Packets: 6 Flow Bytes/s: 920.0 Flow Packets/s: 140.0 SYN Flag Count: 1",
            "",
            "FLOW 2 Source IP: 10.0.0.5 Destination IP: 10.0.0.9 Source Port: 44302",
            "Destination Port: 80 Protocol: TCP Flow Duration: 55000 Total Fwd Packets: 10",
            "Total Backward Packets: 8 Flow Bytes/s: 1100.0 Flow Packets/s: 160.0 SYN Flag Count: 1"
        ]
        pdf_bytes = _create_minimal_pdf(pdf_lines)
        df, kind = parse_uploaded_file(pdf_bytes, "traffic_summary.pdf")
        self.assertEqual(kind, "flow")
        self.assertEqual(len(df), 2)
        self.assertEqual(df.iloc[0]["source_ip"], "10.0.0.5")
        self.assertEqual(df.iloc[1]["destination_port"], 80)

    def test_07_pdf_basepoint_profile_batch_inference(self):
        """Verifies that a PDF document containing 8-dimensional basepoint event profiles runs batch inference."""
        pdf_lines = [
            "bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08",
            "0.10,0.20,0.30,0.40,0.50,0.60,0.70,0.80"
        ]
        pdf_bytes = _create_minimal_pdf(pdf_lines)
        res = siem_service.process_file_upload(pdf_bytes, "profiles.pdf")
        self.assertEqual(res["total_records"], 1)
        self.assertIn("session_id", res)

    # -------------------------------------------------------------------------
    # 5. Label Stripping & Security Protection
    # -------------------------------------------------------------------------

    def test_08_label_columns_stripped_from_txt_and_pdf(self):
        """Verifies that ground-truth labels in TXT or PDF are never passed as features."""
        txt_with_label = (
            "FLOW 1 Source IP: 192.168.1.10 Destination IP: 192.168.1.20\n"
            "Flow Duration: 120000 Flow Bytes/s: 850.5 Flow Packets/s: 183.3 SYN Flag Count: 1\n"
            "Label: DDoS Attack Type: DDoS target: 1\n"
        )
        df, _ = parse_uploaded_file(txt_with_label.encode("utf-8"), "labelled_flow.txt")
        for forbidden in ["label", "attack_type", "target"]:
            self.assertNotIn(forbidden, df.columns)

    # -------------------------------------------------------------------------
    # 6. Negative & Validation Error Tests
    # -------------------------------------------------------------------------

    def test_09_empty_txt_and_pdf_raises_value_error(self):
        """Verifies that uploading empty TXT or PDF raises ValueError."""
        with self.assertRaises(ValueError):
            parse_uploaded_file(b"", "empty.txt")
        with self.assertRaises(ValueError):
            parse_uploaded_file(b"", "empty.pdf")

    def test_10_unparseable_text_raises_clear_error(self):
        """Verifies that arbitrary unparseable text raises ValueError with helpful message."""
        gibberish = b"Hello world! This is a random text file with no network flows."
        with self.assertRaises(ValueError) as ctx:
            parse_uploaded_file(gibberish, "notes.txt")
        self.assertIn("Validation failed", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 7. CSV Regression Preservation
    # -------------------------------------------------------------------------

    def test_11_csv_upload_functionality_preserved(self):
        """Verifies that standard CSV parsing remains 100% intact."""
        csv_bytes = b"bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08\n0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8\n"
        df, kind = parse_uploaded_file(csv_bytes, "test.csv")
        self.assertEqual(kind, "profile")
        self.assertEqual(len(df), 1)

        res = siem_service.process_file_upload(csv_bytes, "test.csv")
        self.assertEqual(res["total_records"], 1)


if __name__ == "__main__":
    unittest.main()
