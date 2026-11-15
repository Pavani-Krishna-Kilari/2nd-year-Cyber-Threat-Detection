"""
Tests for Real-Time Sliding Window Threat Stream Verification & Isolation.

Verifies:
1. Stream reflects ONLY the latest successfully completed upload.
2. Subsequent upload replaces previous upload's stream completely (no mixing).
3. Previous upload sessions remain preserved in SQLite Detection History.
4. Failed uploads do not overwrite or corrupt the active stream.
5. Batch clear resets the stream without deleting SQLite detection history.
6. Server restart / cold start retrieves the latest completed session.
7. Zero synthetic data generation / zero SQLite pollution from stream polling.
8. Correct chronological ordering (rowid ASC) and accurate window/flow metadata.
9. Backwards compatibility for single-event consumers.

Run with:
    python -m unittest tests.test_latest_upload_threat_stream -v
"""

import io
import json
import sqlite3
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

import backend.database
from backend.main import app
from backend.service import siem_service


class TestLatestUploadThreatStream(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._orig_db_path = backend.database.DB_PATH
        cls._orig_exp_id = siem_service.experiment_id
        cls._test_db_path = Path("data/test_threat_stream.db")
        backend.database.DB_PATH = cls._test_db_path
        backend.database.init_db()
        siem_service.set_experiment("B")
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        siem_service.set_experiment(cls._orig_exp_id)
        backend.database.DB_PATH = cls._orig_db_path
        if cls._test_db_path.exists():
            try:
                cls._test_db_path.unlink()
            except Exception:
                pass

    def setUp(self):
        # Reset database tables and service state before each test
        conn = backend.database.get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM detections;")
                conn.execute("DELETE FROM campaigns;")
                conn.execute("DELETE FROM analysis_sessions;")
        finally:
            conn.close()
        siem_service.clear_batch_summary()

    def _create_profile_csv(self, rows_count=5, prefix="A", is_threat=False):
        """Generates a valid 8-dimensional event-profile CSV with distinct values."""
        csv_lines = [
            "event_set_id,window_id,k,source_ip,destination_ip,destination_port,protocol,n_flows,bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08"
        ]
        for i in range(rows_count):
            es_id = f"ES_{prefix}_{i + 1:04d}"
            w_id = f"W_{prefix}_{i + 1:04d}"
            src_ip = f"10.0.{prefix.encode()[0]}.{i + 1}"
            dst_ip = "192.168.1.100"
            port = 21 if is_threat else 80
            proto = "TCP"
            n_flows = 10 + i * 5
            if is_threat:
                # Strong threat vector
                bp_vals = [0.90, 0.20, 0.05, 0.05, 0.80, 0.90, 0.85, 0.05]
            else:
                # Pure benign vector
                bp_vals = [0.0] * 8
            bp_str = ",".join(str(v) for v in bp_vals)
            csv_lines.append(f"{es_id},{w_id},{i},{src_ip},{dst_ip},{port},{proto},{n_flows},{bp_str}")
        return "\n".join(csv_lines).encode("utf-8")

    def test_empty_stream_initial_state(self):
        """Verifies initial empty state before any CSV uploads."""
        resp = self.client.get("/api/detect/stream")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["has_data"])
        self.assertIsNone(data["session_id"])
        self.assertEqual(data["total_windows"], 0)
        self.assertEqual(len(data["records"]), 0)
        # Backwards compatible top-level fields
        self.assertIn("verdict", data)
        self.assertIn("source_ip", data)

    def test_upload_a_stream_population(self):
        """Upload A populates the threat stream with Upload A's genuine window records."""
        csv_a = self._create_profile_csv(rows_count=6, prefix="ALPHA", is_threat=True)
        resp_up = self.client.post(
            "/api/detect/upload",
            files={"file": ("upload_alpha.csv", io.BytesIO(csv_a), "text/csv")}
        )
        self.assertEqual(resp_up.status_code, 200)
        session_a = resp_up.json()["session_id"]

        # Stream query without parameters
        resp_stream = self.client.get("/api/detect/stream")
        self.assertEqual(resp_stream.status_code, 200)
        stream_data = resp_stream.json()

        self.assertTrue(stream_data["has_data"])
        self.assertEqual(stream_data["session_id"], session_a)
        self.assertEqual(stream_data["total_windows"], 6)
        self.assertEqual(len(stream_data["records"]), 6)

        # Check records details
        for i, rec in enumerate(stream_data["records"]):
            self.assertEqual(rec["session_id"], session_a)
            self.assertEqual(rec["window_id"], f"W_ALPHA_{i + 1:04d}")
            self.assertEqual(rec["event_set_id"], f"ES_ALPHA_{i + 1:04d}")
            self.assertEqual(rec["source_ip"], f"10.0.{ord('A')}.{i + 1}")
            self.assertEqual(rec["n_flows"], 10 + i * 5)
            self.assertIn("verdict", rec)
            self.assertIn("confidence", rec)
            self.assertIn("severity", rec)

    def test_upload_b_replaces_stream_strictly(self):
        """Upload B must strictly replace Upload A's stream without mixing records."""
        # Step 1: Upload A (4 threat windows)
        csv_a = self._create_profile_csv(rows_count=4, prefix="ALPHA", is_threat=True)
        resp_a = self.client.post(
            "/api/detect/upload",
            files={"file": ("upload_alpha.csv", io.BytesIO(csv_a), "text/csv")}
        )
        self.assertEqual(resp_a.status_code, 200)
        session_a = resp_a.json()["session_id"]

        # Step 2: Upload B (3 benign windows)
        csv_b = self._create_profile_csv(rows_count=3, prefix="BETA", is_threat=False)
        resp_b = self.client.post(
            "/api/detect/upload",
            files={"file": ("upload_beta.csv", io.BytesIO(csv_b), "text/csv")}
        )
        self.assertEqual(resp_b.status_code, 200)
        session_b = resp_b.json()["session_id"]
        self.assertNotEqual(session_a, session_b)

        # Step 3: Stream must now return ONLY Upload B
        resp_stream = self.client.get("/api/detect/stream")
        self.assertEqual(resp_stream.status_code, 200)
        stream_data = resp_stream.json()

        self.assertTrue(stream_data["has_data"])
        self.assertEqual(stream_data["session_id"], session_b)
        self.assertEqual(stream_data["total_windows"], 3)
        self.assertEqual(len(stream_data["records"]), 3)

        # Verify NO records from Upload A are in the stream
        for rec in stream_data["records"]:
            self.assertEqual(rec["session_id"], session_b)
            self.assertTrue(rec["window_id"].startswith("W_BETA"))
            self.assertFalse(rec["window_id"].startswith("W_ALPHA"))
            self.assertEqual(rec["verdict"], "NORMAL")

    def test_upload_a_preserved_in_history_and_queryable_by_id(self):
        """Upload A remains preserved in SQLite and can be viewed specifically via ?session_id=."""
        csv_a = self._create_profile_csv(rows_count=5, prefix="A", is_threat=True)
        resp_a = self.client.post(
            "/api/detect/upload",
            files={"file": ("file_a.csv", io.BytesIO(csv_a), "text/csv")}
        )
        session_a = resp_a.json()["session_id"]

        csv_b = self._create_profile_csv(rows_count=4, prefix="B", is_threat=False)
        resp_b = self.client.post(
            "/api/detect/upload",
            files={"file": ("file_b.csv", io.BytesIO(csv_b), "text/csv")}
        )
        session_b = resp_b.json()["session_id"]

        # Default stream is session B
        resp_stream = self.client.get("/api/detect/stream")
        self.assertEqual(resp_stream.json()["session_id"], session_b)

        # Query specifically for session A
        resp_stream_a = self.client.get(f"/api/detect/stream?session_id={session_a}")
        self.assertEqual(resp_stream_a.status_code, 200)
        data_a = resp_stream_a.json()
        self.assertEqual(data_a["session_id"], session_a)
        self.assertEqual(data_a["total_windows"], 5)
        for r in data_a["records"]:
            self.assertEqual(r["session_id"], session_a)

        # Verify Session A is also in /api/sessions
        resp_sessions = self.client.get("/api/sessions")
        self.assertEqual(resp_sessions.status_code, 200)
        session_ids = [s["session_id"] for s in resp_sessions.json()]
        self.assertIn(session_a, session_ids)
        self.assertIn(session_b, session_ids)

    def test_failed_upload_does_not_overwrite_stream(self):
        """A failed upload attempt must not overwrite or corrupt the latest valid stream."""
        # Successful upload
        csv_valid = self._create_profile_csv(rows_count=4, prefix="VALID", is_threat=False)
        resp_valid = self.client.post(
            "/api/detect/upload",
            files={"file": ("valid.csv", io.BytesIO(csv_valid), "text/csv")}
        )
        self.assertEqual(resp_valid.status_code, 200)
        valid_sess = resp_valid.json()["session_id"]

        # Malformed upload (invalid headers / no valid rows)
        corrupt_csv = b"random_gibberish,invalid_col\n123,456\n"
        resp_corrupt = self.client.post(
            "/api/detect/upload",
            files={"file": ("corrupt.csv", io.BytesIO(corrupt_csv), "text/csv")}
        )
        self.assertEqual(resp_corrupt.status_code, 400)

        # Stream must still be intact and point to the valid session
        resp_stream = self.client.get("/api/detect/stream")
        self.assertEqual(resp_stream.status_code, 200)
        data = resp_stream.json()
        self.assertTrue(data["has_data"])
        self.assertEqual(data["session_id"], valid_sess)
        self.assertEqual(data["total_windows"], 4)

    def test_batch_clear_resets_stream_without_dropping_sqlite_history(self):
        """POST /api/batch/clear resets active stream state but retains SQLite history."""
        csv_data = self._create_profile_csv(rows_count=3, prefix="CLR", is_threat=False)
        resp_up = self.client.post(
            "/api/detect/upload",
            files={"file": ("test_clear.csv", io.BytesIO(csv_data), "text/csv")}
        )
        sess_id = resp_up.json()["session_id"]

        # Verify stream is active
        stream_pre = self.client.get("/api/detect/stream").json()
        self.assertTrue(stream_pre["has_data"])

        # Call batch clear
        resp_clear = self.client.post("/api/batch/clear")
        self.assertEqual(resp_clear.status_code, 200)

        # Stream should now reflect empty state
        stream_post = self.client.get("/api/detect/stream").json()
        self.assertFalse(stream_post["has_data"])
        self.assertEqual(stream_post["total_windows"], 0)
        self.assertEqual(len(stream_post["records"]), 0)

        # SQLite session and detections must still exist in history
        history_resp = self.client.get(f"/api/detect/history?session_id={sess_id}")
        self.assertEqual(history_resp.status_code, 200)
        self.assertEqual(len(history_resp.json()), 3)

    def test_no_synthetic_data_or_db_pollution(self):
        """Repeatedly calling GET /api/detect/stream must NEVER insert records into SQLite."""
        csv_data = self._create_profile_csv(rows_count=4, prefix="POLLUTE_TEST", is_threat=True)
        resp_up = self.client.post(
            "/api/detect/upload",
            files={"file": ("pollute.csv", io.BytesIO(csv_data), "text/csv")}
        )
        self.assertEqual(resp_up.status_code, 200)

        conn = backend.database.get_connection()
        try:
            count_before = conn.execute("SELECT COUNT(*) FROM detections;").fetchone()[0]
        finally:
            conn.close()

        # Poll the stream 20 times (simulating 40 seconds of live polling)
        for _ in range(20):
            r = self.client.get("/api/detect/stream")
            self.assertEqual(r.status_code, 200)

        conn = backend.database.get_connection()
        try:
            count_after = conn.execute("SELECT COUNT(*) FROM detections;").fetchone()[0]
        finally:
            conn.close()

        # Verification: zero additional rows inserted
        self.assertEqual(count_before, count_after)
        self.assertEqual(count_after, 4)

    def test_server_restart_fallback_to_latest_session(self):
        """Simulates server restart: in-memory variables are None, falls back to latest SQLite session."""
        csv_data = self._create_profile_csv(rows_count=5, prefix="RESTART", is_threat=False)
        resp_up = self.client.post(
            "/api/detect/upload",
            files={"file": ("restart.csv", io.BytesIO(csv_data), "text/csv")}
        )
        sess_id = resp_up.json()["session_id"]

        # Simulate fresh process restart
        siem_service.latest_completed_session_id = None
        siem_service.current_analysis_summary = None
        siem_service._stream_explicitly_cleared = False

        # Cold query must retrieve latest session from SQLite
        stream_cold = self.client.get("/api/detect/stream").json()
        self.assertTrue(stream_cold["has_data"])
        self.assertEqual(stream_cold["session_id"], sess_id)
        self.assertEqual(stream_cold["total_windows"], 5)

    def test_chronological_ordering_of_stream_records(self):
        """Ensures stream records are ordered chronologically (rowid ASC)."""
        csv_data = self._create_profile_csv(rows_count=10, prefix="ORDER", is_threat=False)
        self.client.post(
            "/api/detect/upload",
            files={"file": ("order.csv", io.BytesIO(csv_data), "text/csv")}
        )

        stream = self.client.get("/api/detect/stream").json()
        records = stream["records"]
        self.assertEqual(len(records), 10)

        for i, r in enumerate(records):
            expected_window = f"W_ORDER_{i + 1:04d}"
            expected_es = f"ES_ORDER_{i + 1:04d}"
            self.assertEqual(r["window_id"], expected_window)
            self.assertEqual(r["event_set_id"], expected_es)


if __name__ == "__main__":
    unittest.main()
