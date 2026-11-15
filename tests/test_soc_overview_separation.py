"""
Unit and regression tests verifying strict separation of SOC Overview
from Manual Single-Flow Classification.

Requirements verified:
1. Manual classification never changes SOC Overview.
2. All three sample prototype buttons never change SOC Overview.
3. CSV batch classification updates SOC Overview with actual batch results.
4. A second CSV replaces the previous batch statistics.
5. Clearing batch results restores the SOC Overview empty state without modifying detection history.
6. Charts and KPI cards use only uploaded batch results.
7. No manual classification result is ever used as a fallback.
"""

import unittest
from fastapi.testclient import TestClient
from backend.main import app
from backend.service import siem_service


class TestSOCOverviewSeparation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def setUp(self):
        # Reset batch summary to clean empty state before each test
        siem_service.clear_batch_summary()

    def tearDown(self):
        # Restore empty batch state after test
        siem_service.clear_batch_summary()

    def test_01_initial_soc_overview_starts_in_empty_state(self):
        """Req 3: When no uploaded CSV batch result exists, all counters are 0 and has_data is False."""
        resp = self.client.get("/api/dashboard/summary")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["has_data"])
        self.assertEqual(data["total_records"], 0)
        self.assertEqual(data["normal_events"], 0)
        self.assertEqual(data["threats_detected"], 0)
        self.assertEqual(data["invalid_records"], 0)

    def test_02_manual_classification_never_changes_soc_overview(self):
        """Req 1 & 4: Manual single-flow classification must NEVER update or contribute to SOC Overview."""
        payload = {
            "source_ip": "172.16.0.1",
            "destination_ip": "192.168.10.50",
            "source_port": 45120,
            "destination_port": 21,
            "protocol": 6,
            "flow_duration": 1000.0,
            "flow_packets_s": 500000.0,
            "flow_bytes_s": 2000000.0,
            "syn_flag_count": 1,
            "flow_count": 15
        }
        pred_resp = self.client.post("/api/models/predict/flow", json=payload)
        self.assertEqual(pred_resp.status_code, 200)
        pred = pred_resp.json()
        self.assertIn("verdict", pred)

        # Query SOC Overview summary: Must remain in empty state (0 records)
        summary_resp = self.client.get("/api/dashboard/summary")
        self.assertEqual(summary_resp.status_code, 200)
        summary = summary_resp.json()
        self.assertFalse(summary["has_data"], "SOC Overview has_data must remain False after manual classification")
        self.assertEqual(summary["total_records"], 0, "SOC Overview total_records must remain 0 after manual classification")
        self.assertEqual(summary["normal_events"], 0)
        self.assertEqual(summary["threats_detected"], 0)

    def test_03_sample_buttons_and_manual_form_decoupled_in_frontend(self):
        """Req 4: Sample prototype buttons and manual submit listener never trigger SOC Overview updates in app.js."""
        resp = self.client.get("/static/js/app.js")
        self.assertEqual(resp.status_code, 200)
        js = resp.text

        # 1. Sample buttons must only pre-fill inputs and never call requestSubmit
        analyzer_start = js.find("function initAnalyzerEvents()")
        analyzer_end = js.find("function escapeHtml(")
        self.assertNotEqual(analyzer_start, -1)
        self.assertNotEqual(analyzer_end, -1)
        analyzer_js = js[analyzer_start:analyzer_end]

        self.assertIn("btnSampleBenign", analyzer_js)
        self.assertIn("btnSampleFtpPatator", analyzer_js)
        self.assertIn("btnSampleSshPatator", analyzer_js)
        self.assertNotIn("requestSubmit", analyzer_js)

        # 2. Manual form submission must NOT call updateDashboardSummaryUI or fetchDashboardSummary
        submit_idx = analyzer_js.find('form.addEventListener("submit"')
        self.assertNotEqual(submit_idx, -1)
        sample_btns_idx = analyzer_js.find('document.getElementById("btnSampleBenign")')
        submit_handler_js = analyzer_js[submit_idx:sample_btns_idx]
        self.assertNotIn("updateDashboardSummaryUI", submit_handler_js,
                         "flowAnalyzerForm submit listener must never call updateDashboardSummaryUI")
        self.assertNotIn("fetchDashboardSummary", submit_handler_js,
                         "flowAnalyzerForm submit listener must never call fetchDashboardSummary")

    def test_04_csv_batch_classification_updates_soc_overview(self):
        """Req 2: Uploading a valid CSV updates SOC Overview with actual batch results and source 'Uploaded CSV Batch'."""
        csv_content = (
            "bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08\n"
            "0.85,0.20,0.10,0.05,0.70,0.80,0.75,0.05\n"
            "0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00\n"
        ).encode("utf-8")
        files = {"file": ("batch_sample_test.csv", csv_content, "text/csv")}
        upload_resp = self.client.post("/api/detect/upload", files=files)
        self.assertEqual(upload_resp.status_code, 200)
        upload_data = upload_resp.json()
        self.assertEqual(upload_data["total_records"], 2)

        # Query SOC Overview
        summary_resp = self.client.get("/api/dashboard/summary")
        self.assertEqual(summary_resp.status_code, 200)
        summary = summary_resp.json()
        self.assertTrue(summary["has_data"])
        self.assertEqual(summary["total_records"], 2)
        self.assertEqual(summary["filename"], "batch_sample_test.csv")
        self.assertEqual(summary["source"], "Uploaded CSV Batch")

    def test_05_second_csv_replaces_previous_batch_statistics(self):
        """Req 4: Uploading another CSV replaces the previous batch summary with the latest batch results."""
        # Upload first batch: 2 records
        csv1 = (
            "bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08\n"
            "0.85,0.20,0.10,0.05,0.70,0.80,0.75,0.05\n"
            "0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00\n"
        ).encode("utf-8")
        self.client.post("/api/detect/upload", files={"file": ("first_batch.csv", csv1, "text/csv")})

        summary1 = self.client.get("/api/dashboard/summary").json()
        self.assertEqual(summary1["total_records"], 2)
        self.assertEqual(summary1["filename"], "first_batch.csv")

        # Upload second batch: 3 records
        csv2 = (
            "bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08\n"
            "0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00\n"
            "0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00\n"
            "0.85,0.20,0.10,0.05,0.70,0.80,0.75,0.05\n"
        ).encode("utf-8")
        self.client.post("/api/detect/upload", files={"file": ("second_batch.csv", csv2, "text/csv")})

        summary2 = self.client.get("/api/dashboard/summary").json()
        self.assertEqual(summary2["total_records"], 3, "Second CSV must replace previous count, not add (2 + 3 != 5)")
        self.assertEqual(summary2["filename"], "second_batch.csv")

    def test_06_clearing_batch_results_restores_empty_state_without_touching_history(self):
        """Req 4 & 5: Clearing batch results restores SOC Overview to empty state while preserving SQLite detection history."""
        # Query baseline history count
        hist_before = self.client.get("/api/history?limit=1000").json()
        baseline_hist_count = len(hist_before)

        # Upload batch
        csv_content = (
            "bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08\n"
            "0.85,0.20,0.10,0.05,0.70,0.80,0.75,0.05\n"
        ).encode("utf-8")
        self.client.post("/api/detect/upload", files={"file": ("temp_batch.csv", csv_content, "text/csv")})

        # Verify summary is populated
        summary_pop = self.client.get("/api/dashboard/summary").json()
        self.assertTrue(summary_pop["has_data"])

        # Clear batch summary
        clear_resp = self.client.post("/api/batch/clear")
        self.assertEqual(clear_resp.status_code, 200)

        # Verify SOC Overview restored to empty state
        summary_cleared = self.client.get("/api/dashboard/summary").json()
        self.assertFalse(summary_cleared["has_data"])
        self.assertEqual(summary_cleared["total_records"], 0)
        self.assertEqual(summary_cleared["normal_events"], 0)
        self.assertEqual(summary_cleared["threats_detected"], 0)

        # Verify detection history was NOT erased (records preserved)
        hist_after = self.client.get("/api/history?limit=1000").json()
        self.assertGreaterEqual(len(hist_after), baseline_hist_count, "Historical detection records must be preserved")

    def test_07_no_manual_fallback_after_batch_analysis(self):
        """Req 7: Running a manual classification after a batch upload must NEVER overwrite or corrupt SOC Overview."""
        # Upload batch
        csv_content = (
            "bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08\n"
            "0.85,0.20,0.10,0.05,0.70,0.80,0.75,0.05\n"
            "0.85,0.20,0.10,0.05,0.70,0.80,0.75,0.05\n"
        ).encode("utf-8")
        self.client.post("/api/detect/upload", files={"file": ("persistent_batch.csv", csv_content, "text/csv")})

        summary_pre_manual = self.client.get("/api/dashboard/summary").json()
        self.assertEqual(summary_pre_manual["total_records"], 2)
        self.assertEqual(summary_pre_manual["filename"], "persistent_batch.csv")

        # Now classify a single manual flow (Normal flow)
        normal_flow = {
            "source_ip": "192.168.10.15",
            "destination_ip": "192.168.10.3",
            "source_port": 45120,
            "destination_port": 443,
            "protocol": 6,
            "flow_duration": 850000.0,
            "flow_packets_s": 120.0,
            "flow_bytes_s": 45000.0,
            "syn_flag_count": 0,
            "flow_count": 3
        }
        pred_resp = self.client.post("/api/models/predict/flow", json=normal_flow)
        self.assertEqual(pred_resp.status_code, 200)

        # Query SOC Overview again: It MUST STILL retain the batch results from persistent_batch.csv!
        summary_post_manual = self.client.get("/api/dashboard/summary").json()
        self.assertEqual(summary_post_manual["total_records"], 2,
                         "SOC Overview total_records must remain 2 (batch) and NOT be replaced by manual flow (1)")
        self.assertEqual(summary_post_manual["filename"], "persistent_batch.csv",
                         "SOC Overview filename must remain persistent_batch.csv and NOT 'Manual Flow Input'")
        self.assertEqual(summary_post_manual["source"], "Uploaded CSV Batch")

    def test_08_siem_test_event_profiles_csv_classification(self):
        """Req 2: Evaluates a 10-profile batch (5 benign, 5 attack) verifying expected distribution (5 normal, 5 known threats)."""
        # 5 Benign profile prototypes (all 0 cosine similarities)
        benign_row = "0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00"
        # 5 Known Attack profile prototypes (actual verified Experiment B attack basepoint vector)
        attack_row = "0.71786759,0.17310065,0.27491244,0.0,0.0,0.65870619,0.84038849,0.0"

        rows = ["bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08"]
        for _ in range(5):
            rows.append(benign_row)
        for _ in range(5):
            rows.append(attack_row)

        csv_content = "\n".join(rows).encode("utf-8")
        files = {"file": ("siem_test_event_profiles.csv", csv_content, "text/csv")}
        resp = self.client.post("/api/detect/upload", files=files)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertEqual(data["total_records"], 10)
        self.assertEqual(data["normal_events"], 5)
        self.assertEqual(data["known_threats"], 5)
        self.assertEqual(data["unknown_anomalous"], 0)
        self.assertEqual(data["invalid_records"], 0)

        # Verify SOC Overview reflects this exact batch
        summary = self.client.get("/api/dashboard/summary").json()
        self.assertEqual(summary["total_records"], 10)
        self.assertEqual(summary["normal_events"], 5)
        self.assertEqual(summary["known_threats"], 5)
        self.assertEqual(summary["unknown_anomalous"], 0)
        self.assertEqual(summary["invalid_records"], 0)
        self.assertEqual(summary["filename"], "siem_test_event_profiles.csv")
        self.assertEqual(summary["source"], "Uploaded CSV Batch")

    def test_09_frontend_serves_batch_empty_notice_and_labels(self):
        """Req 3: Index HTML serves the dedicated batch empty notice banner and Awaiting Upload labels."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.text
        self.assertIn('id="socBatchNotice"', html)
        self.assertIn("No uploaded dataset has been analysed yet. Upload a CSV in Threat Analyzer to view batch classification statistics.", html)
        self.assertIn("Source: Awaiting Upload", html)


if __name__ == "__main__":
    unittest.main()
