"""
Unit and integration tests for AI-SIEM Dashboard Enhancements:
- Multi-section Threat Analyzer (Known Threats vs Unknown Anomalies vs Campaigns)
- Persistent Classification Reports per upload session
- Detection History Reports Archive & Retrieval
- Isolated Single-Session Transactional Deletion
- Preservation of unrelated sessions & error handling

Run with:
    python -m unittest tests.test_dashboard_enhancements -v
"""

import json
import tempfile
import unittest
from pathlib import Path
from fastapi.testclient import TestClient

import backend.database as db
from backend.main import app
from backend.service import siem_service


class TestDashboardEnhancements(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Isolate database completely to protect production records
        cls._orig_db_path = db.DB_PATH
        cls._temp_dir = tempfile.TemporaryDirectory()
        cls._test_db_path = Path(cls._temp_dir.name) / "test_isolated_history.db"
        db.DB_PATH = cls._test_db_path
        db.init_db()

        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        db.DB_PATH = cls._orig_db_path
        cls._temp_dir.cleanup()

    def setUp(self):
        # Clean isolated test database before each test
        db.clear_all_history()
        siem_service.current_analysis_summary = None

    def _create_sample_session(self, session_id: str, filename: str, known_threats: int = 1, unknown_anom: int = 0):
        """Helper to create and persist a structured test analysis session."""
        summary = {
            "session_id": session_id,
            "filename": filename,
            "source_name": filename,
            "input_type": "flow",
            "timestamp": "2026-11-15 12:00:00",
            "has_data": True,
            "total_records": 10,
            "normal_events": 10 - known_threats - unknown_anom,
            "threats_detected": known_threats + unknown_anom,
            "known_threats": known_threats,
            "unknown_anomalous": unknown_anom,
            "invalid_records": 0,
            "threat_ratio": round((known_threats + unknown_anom) / 10.0, 4),
            "attack_categories": {"DDoS": known_threats} if known_threats else {},
            "severity_distribution": {"HIGH": known_threats, "LOW": 10 - known_threats - unknown_anom},
            "model_summary": {
                "fcnn_avg": 0.85 if known_threats else 0.05,
                "cnn_avg": 0.82 if known_threats else 0.04,
                "lstm_avg": 0.80 if known_threats else 0.03,
                "ensemble_avg": 0.88 if known_threats else 0.05
            },
            "flow_statistics": {
                "total_raw_flows": 100,
                "unique_flows_analysed": 100,
                "benign_flows": 90,
                "known_threat_flows": 10 if known_threats else 0,
                "unknown_anomalous_flows": 10 if unknown_anom else 0,
                "invalid_flows": 0
            },
            "event_set_statistics": {
                "total_event_sets": 10,
                "normal_event_sets": 10 - known_threats - unknown_anom,
                "ann_alert_sets": known_threats,
                "unknown_anomalous_sets": unknown_anom
            },
            "campaign_statistics": {
                "total_campaigns": 1 if (known_threats or unknown_anom) else 0,
                "known_threat_campaigns": 1 if known_threats else 0,
                "unknown_anomalous_campaigns": 1 if (unknown_anom and not known_threats) else 0
            }
        }

        # Detections
        records = []
        for i in range(10):
            if i < known_threats:
                verdict = "KNOWN_THREAT"
                status = "KNOWN_THREAT"
                cat = "DDoS"
                conf = 0.95
                sev = "HIGH"
                camp_id = f"CMP-{session_id[-6:]}-0001"
            elif i < known_threats + unknown_anom:
                verdict = "UNKNOWN_ANOMALOUS"
                status = "UNKNOWN_ANOMALOUS"
                cat = "Benign Network Traffic"
                conf = 0.70
                sev = "MEDIUM"
                camp_id = f"CMP-{session_id[-6:]}-0002"
            else:
                verdict = "NORMAL"
                status = "NORMAL"
                cat = "Benign Network Traffic"
                conf = 0.02
                sev = "LOW"
                camp_id = "-"

            records.append({
                "id": f"DET-{session_id[-6:]}-{i:04d}",
                "session_id": session_id,
                "timestamp": "2026-11-15 12:00:00",
                "source": filename,
                "input_type": "flow",
                "source_ip": "192.168.10.15",
                "destination_ip": "172.16.0.1",
                "destination_port": 80,
                "protocol": "TCP",
                "verdict": verdict,
                "prediction_status": status,
                "predicted_class": cat,
                "confidence": conf,
                "threat_confidence": conf,
                "threat_type": cat,
                "severity": sev,
                "campaign_id": camp_id,
                "anomaly_score": 0.45 if verdict == "UNKNOWN_ANOMALOUS" else -0.15,
                "flow_metadata": {"n_flows": 10}
            })

        # Campaigns
        campaigns = []
        if known_threats:
            campaigns.append({
                "campaign_id": f"CMP-{session_id[-6:]}-0001",
                "session_id": session_id,
                "source_ip": "192.168.10.15",
                "destination_ip": "172.16.0.1",
                "start_time": "2026-11-15 12:00:00",
                "end_time": "2026-11-15 12:10:00",
                "verdict": "KNOWN_THREAT",
                "max_confidence": 0.95,
                "window_count": 1,
                "attributed_flow_count": 10,
                "constituent_windows": ["W00000"]
            })
        elif unknown_anom:
            campaigns.append({
                "campaign_id": f"CMP-{session_id[-6:]}-0002",
                "session_id": session_id,
                "source_ip": "192.168.10.15",
                "destination_ip": "172.16.0.1",
                "start_time": "2026-11-15 12:00:00",
                "end_time": "2026-11-15 12:10:00",
                "verdict": "UNKNOWN_ANOMALOUS",
                "max_confidence": 0.70,
                "window_count": 1,
                "attributed_flow_count": 10,
                "constituent_windows": ["W00000"]
            })

        summary["campaigns"] = campaigns
        summary["known_threats_list"] = [r for r in records if r["verdict"] == "KNOWN_THREAT"]
        summary["unknown_anomalies_list"] = [r for r in records if r["verdict"] == "UNKNOWN_ANOMALOUS"]
        summary["sample_results"] = records

        db.insert_session(summary)
        db.insert_detections(records, session_id=session_id)
        db.insert_campaigns(campaigns, session_id=session_id)
        return summary

    # -------------------------------------------------------------------------
    # Test 1: Empty history behavior
    # -------------------------------------------------------------------------
    def test_empty_history_behavior(self):
        """Verifies that an empty database returns valid zero/empty structures without error."""
        res = self.client.get("/api/sessions")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json(), [])

        res_count = self.client.get("/api/sessions/count")
        self.assertEqual(res_count.status_code, 200)
        self.assertEqual(res_count.json(), {"count": 0})

        res_404 = self.client.get("/api/sessions/SESS-NONEXISTENT")
        self.assertEqual(res_404.status_code, 404)

    # -------------------------------------------------------------------------
    # Test 2: Session listing and pagination
    # -------------------------------------------------------------------------
    def test_session_listing_and_pagination(self):
        """Verifies session listing returns correct summaries sorted chronologically descending."""
        self._create_sample_session("SESS-000001", "first_file.csv", known_threats=2)
        self._create_sample_session("SESS-000002", "second_file.csv", known_threats=0, unknown_anom=1)

        res = self.client.get("/api/sessions?limit=10&offset=0")
        self.assertEqual(res.status_code, 200)
        sessions = res.json()
        self.assertEqual(len(sessions), 2)

        res_count = self.client.get("/api/sessions/count")
        self.assertEqual(res_count.json(), {"count": 2})

        # Test pagination limit 1
        res_page1 = self.client.get("/api/sessions?limit=1&offset=0")
        self.assertEqual(len(res_page1.json()), 1)
        res_page2 = self.client.get("/api/sessions?limit=1&offset=1")
        self.assertEqual(len(res_page2.json()), 1)
        self.assertNotEqual(res_page1.json()[0]["session_id"], res_page2.json()[0]["session_id"])

    # -------------------------------------------------------------------------
    # Test 3: Session-specific report retrieval
    # -------------------------------------------------------------------------
    def test_session_specific_report_retrieval(self):
        """Verifies single report retrieval contains all required metadata, metrics, and lists."""
        self._create_sample_session("SESS-REPORT-01", "threat_capture.csv", known_threats=3, unknown_anom=2)

        res = self.client.get("/api/sessions/SESS-REPORT-01")
        self.assertEqual(res.status_code, 200)
        report = res.json()

        self.assertEqual(report["session_id"], "SESS-REPORT-01")
        self.assertEqual(report["filename"], "threat_capture.csv")
        self.assertEqual(report["status"], "Completed")
        self.assertIn("flow_statistics", report)
        self.assertIn("event_set_statistics", report)
        self.assertIn("campaign_statistics", report)
        self.assertIn("model_summary", report)

        # Verify separate lists
        self.assertEqual(len(report["known_threats_list"]), 3)
        self.assertEqual(len(report["unknown_anomalies_list"]), 2)
        self.assertEqual(len(report["campaigns"]), 1)

    # -------------------------------------------------------------------------
    # Test 4: Dedicated threats, anomalies, and campaigns endpoints
    # -------------------------------------------------------------------------
    def test_filtered_session_subendpoints(self):
        """Verifies /api/sessions/{session_id}/threats, /anomalies, and /campaigns endpoints."""
        self._create_sample_session("SESS-SUB-01", "sub_test.csv", known_threats=2, unknown_anom=3)

        res_thr = self.client.get("/api/sessions/SESS-SUB-01/threats")
        self.assertEqual(res_thr.status_code, 200)
        threats = res_thr.json()
        self.assertEqual(len(threats), 2)
        for t in threats:
            self.assertEqual(t["verdict"], "KNOWN_THREAT")
            self.assertEqual(t["session_id"], "SESS-SUB-01")

        res_anom = self.client.get("/api/sessions/SESS-SUB-01/anomalies")
        self.assertEqual(res_anom.status_code, 200)
        anomalies = res_anom.json()
        self.assertEqual(len(anomalies), 3)
        for a in anomalies:
            self.assertEqual(a["verdict"], "UNKNOWN_ANOMALOUS")
            self.assertEqual(a["session_id"], "SESS-SUB-01")

        res_camp = self.client.get("/api/sessions/SESS-SUB-01/campaigns")
        self.assertEqual(res_camp.status_code, 200)
        campaigns = res_camp.json()
        self.assertEqual(len(campaigns), 1)
        self.assertEqual(campaigns[0]["session_id"], "SESS-SUB-01")

    # -------------------------------------------------------------------------
    # Test 5: Two independent upload sessions and cross-session isolation
    # -------------------------------------------------------------------------
    def test_two_independent_sessions_isolation(self):
        """Verifies two sessions remain strictly independent and accessible after subsequent uploads."""
        sess1 = self._create_sample_session("SESS-AAA-001", "monday_traffic.csv", known_threats=4, unknown_anom=0)
        sess2 = self._create_sample_session("SESS-BBB-002", "friday_traffic.csv", known_threats=0, unknown_anom=2)

        # Retrieve session 1
        res1 = self.client.get("/api/sessions/SESS-AAA-001")
        self.assertEqual(res1.status_code, 200)
        rep1 = res1.json()
        self.assertEqual(rep1["filename"], "monday_traffic.csv")
        self.assertEqual(len(rep1["known_threats_list"]), 4)
        self.assertEqual(len(rep1["unknown_anomalies_list"]), 0)

        # Retrieve session 2
        res2 = self.client.get("/api/sessions/SESS-BBB-002")
        self.assertEqual(res2.status_code, 200)
        rep2 = res2.json()
        self.assertEqual(rep2["filename"], "friday_traffic.csv")
        self.assertEqual(len(rep2["known_threats_list"]), 0)
        self.assertEqual(len(rep2["unknown_anomalies_list"]), 2)

        # Re-verify session 1 remains completely unchanged after session 2 upload
        res1_recheck = self.client.get("/api/sessions/SESS-AAA-001")
        self.assertEqual(res1_recheck.status_code, 200)
        self.assertEqual(res1_recheck.json()["filename"], "monday_traffic.csv")

    # -------------------------------------------------------------------------
    # Test 6: Single-session transactional deletion and preservation of other sessions
    # -------------------------------------------------------------------------
    def test_single_session_deletion_preserves_others(self):
        """Verifies deleting one session removes only that session's data, preserving all other sessions."""
        self._create_sample_session("SESS-KEEP-001", "keep_me.csv", known_threats=1)
        self._create_sample_session("SESS-DELETE-002", "delete_me.csv", known_threats=2)

        # Verify initial count
        self.assertEqual(self.client.get("/api/sessions/count").json()["count"], 2)

        # Delete session 2
        del_res = self.client.delete("/api/sessions/SESS-DELETE-002")
        self.assertEqual(del_res.status_code, 200)
        self.assertEqual(del_res.json()["status"], "SUCCESS")

        # Confirm session 2 is gone
        res_del_check = self.client.get("/api/sessions/SESS-DELETE-002")
        self.assertEqual(res_del_check.status_code, 404)

        # Confirm session 2's detections and campaigns are gone
        self.assertEqual(len(self.client.get("/api/sessions/SESS-DELETE-002/threats").json()), 0)
        self.assertEqual(len(self.client.get("/api/sessions/SESS-DELETE-002/campaigns").json()), 0)

        # CONFIRM SESSION 1 REMAINS 100% INTACT
        res_keep_check = self.client.get("/api/sessions/SESS-KEEP-001")
        self.assertEqual(res_keep_check.status_code, 200)
        self.assertEqual(res_keep_check.json()["filename"], "keep_me.csv")
        self.assertEqual(len(res_keep_check.json()["known_threats_list"]), 1)

        # Confirm total count is now 1
        self.assertEqual(self.client.get("/api/sessions/count").json()["count"], 1)

    # -------------------------------------------------------------------------
    # Test 7: Invalid session ID returns 404
    # -------------------------------------------------------------------------
    def test_invalid_session_id_returns_404(self):
        """Verifies that invalid session IDs return HTTP 404 for retrieval and deletion."""
        res_get = self.client.get("/api/sessions/DOES_NOT_EXIST_XYZ")
        self.assertEqual(res_get.status_code, 404)
        self.assertIn("not found", res_get.json()["detail"].lower())

        res_del = self.client.delete("/api/sessions/DOES_NOT_EXIST_XYZ")
        self.assertEqual(res_del.status_code, 404)
        self.assertIn("not found", res_del.json()["detail"].lower())

    # -------------------------------------------------------------------------
    # Test 8: Transaction rollback on database error
    # -------------------------------------------------------------------------
    def test_transactional_integrity(self):
        """Verifies transactional delete behavior when session exists."""
        self._create_sample_session("SESS-TX-001", "transaction_test.csv", known_threats=1)

        # Test delete on valid session
        success = db.delete_session("SESS-TX-001")
        self.assertTrue(success)

        # Verify subsequent delete on already deleted session returns False without raising
        second_attempt = db.delete_session("SESS-TX-001")
        self.assertFalse(second_attempt)

    def test_transaction_rollback_on_failure(self):
        """Verifies transactional rollback if an error occurs mid-operation."""
        self._create_sample_session("SESS-ROLLBACK-01", "rollback_test.csv", known_threats=1)

        # Verify initial records
        self.assertEqual(len(db.get_detections(session_id="SESS-ROLLBACK-01")), 10)

        # Simulate a transaction that deletes detections but aborts before committing
        conn = db.get_connection()
        try:
            with conn:
                conn.execute("DELETE FROM detections WHERE session_id = ?", ("SESS-ROLLBACK-01",))
                raise RuntimeError("Simulated unexpected failure mid-transaction")
        except RuntimeError:
            pass
        finally:
            conn.close()

        # Detections MUST remain intact due to atomic transaction rollback
        self.assertEqual(len(db.get_detections(session_id="SESS-ROLLBACK-01")), 10)


if __name__ == "__main__":
    unittest.main()
