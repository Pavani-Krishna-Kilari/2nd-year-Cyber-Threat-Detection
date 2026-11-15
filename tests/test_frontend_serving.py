"""
Unit tests verifying static frontend file serving by FastAPI.
Run with:
    python -m unittest tests.test_frontend_serving -v
"""

import unittest
from fastapi.testclient import TestClient
from backend.main import app


class TestFrontendServing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_root_serves_index_html(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("AI SIEM Cyber Threat Detection System", resp.text)
        self.assertIn("view-analyzer", resp.text)
        self.assertIn("verdictBox", resp.text)

    def test_all_eight_sidebar_views_present(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        expected_views = [
            "view-dashboard",
            "view-analyzer",
            "view-profiles",
            "view-models",
            "view-anomaly",
            "view-history",
            "view-assistant",
            "view-about"
        ]
        for v in expected_views:
            self.assertIn(f'id="{v}"', resp.text, f"Missing view section: {v}")
            self.assertIn(f'data-view="{v}"', resp.text, f"Missing nav item for: {v}")
        self.assertNotIn('id="view-incident"', resp.text)
        self.assertNotIn('data-view="view-incident"', resp.text)

    def test_css_serving(self):
        resp = self.client.get("/static/css/styles.css")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("--bg-base", resp.text)

    def test_js_modules_serving(self):
        for js_file in ["app.js", "api.js", "charts.js"]:
            resp = self.client.get(f"/static/js/{js_file}")
            self.assertEqual(resp.status_code, 200, f"Failed to serve /static/js/{js_file}")

    def test_experiment_b_identification_in_frontend(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Experiment B", resp.text)
        self.assertIn("Multi-Day Control &amp; Unseen Evaluation", resp.text)
        self.assertIn("activeExperimentLabel", resp.text)

    def test_experiment_b_thresholds_in_frontend(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("0.6561", resp.text)  # Ensemble threshold
        self.assertIn("-0.012676", resp.text)  # Isolation Forest threshold
        self.assertIn("0.8582", resp.text)  # FCNN threshold
        self.assertIn("0.3439", resp.text)  # CNN threshold
        self.assertIn("0.7663", resp.text)  # LSTM threshold

    def test_separate_evaluation_tables_present(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn('id="benchmarkTableUnseen"', resp.text)
        self.assertIn('id="benchmarkTableControl"', resp.text)
        self.assertIn("Evaluation A: Friday Unseen Attacks", resp.text)
        self.assertIn("Evaluation B: Tuesday Control", resp.text)

    def test_verdict_presentation_in_app_js(self):
        resp = self.client.get("/static/js/app.js")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("formatVerdictLabel", resp.text)
        self.assertIn("ANN Alert", resp.text)
        self.assertIn("Unknown Anomalous", resp.text)
        self.assertIn("badge-threat", resp.text)

    def test_no_stale_experiment_a_fallbacks(self):
        resp_html = self.client.get("/")
        resp_js = self.client.get("/static/js/app.js")
        self.assertNotIn("306,936", resp_html.text)
        self.assertNotIn("306936", resp_js.text)
        self.assertNotIn("-0.0148", resp_html.text)
        self.assertNotIn("-0.0148", resp_js.text)

    def test_threat_analyzer_independent_section_layout(self):
        """Verifies Threat Analyzer has distinct Manual and Batch sections with isolated verdict containers."""
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        # Explicit Card Headings and Subheadings
        self.assertIn("Manual Single-Flow Classification", html)
        self.assertIn("Uploaded Dataset Batch Classification", html)
        self.assertIn("Configure individual network flow parameters or select a sample attack prototype", html)
        self.assertIn("Upload multi-record network captures (CSV, TXT, LOG, PDF)", html)

        # Verdict Box is housed inside the Manual Single-Flow card
        manual_card_idx = html.find("Manual Single-Flow Classification")
        batch_card_idx = html.find("Uploaded Dataset Batch Classification")
        verdict_box_idx = html.find('id="verdictBox"')
        
        self.assertNotEqual(manual_card_idx, -1)
        self.assertNotEqual(batch_card_idx, -1)
        self.assertNotEqual(verdict_box_idx, -1)
        self.assertTrue(manual_card_idx < verdict_box_idx < batch_card_idx,
                        "verdictBox must be housed within the Manual Single-Flow card before the Batch card")

        # 6-column batch results table
        self.assertIn('id="batchResultsTable"', html)
        self.assertIn("Source Host", html)
        self.assertIn("Destination Host", html)
        self.assertIn("<th>Verdict</th>", html)
        self.assertIn("<th>Confidence</th>", html)
        self.assertIn("<th>Severity</th>", html)

    def test_threat_analyzer_decoupled_sample_buttons_and_batch_triage(self):
        """Verifies sample buttons do not auto-submit and batch clear/triage functions are defined in app.js."""
        resp = self.client.get("/static/js/app.js")
        self.assertEqual(resp.status_code, 200)
        js = resp.text

        # Extract initAnalyzerEvents block to check sample buttons
        analyzer_block_start = js.find("function initAnalyzerEvents()")
        analyzer_block_end = js.find("function escapeHtml(")
        self.assertNotEqual(analyzer_block_start, -1)
        self.assertNotEqual(analyzer_block_end, -1)
        analyzer_js = js[analyzer_block_start:analyzer_block_end]

        # Threat Analyzer sample buttons must populate inputs only and NEVER auto-submit
        self.assertIn("btnSampleBenign", analyzer_js)
        self.assertIn("btnSampleFtpPatator", analyzer_js)
        self.assertIn("btnSampleSshPatator", analyzer_js)
        self.assertNotIn("requestSubmit", analyzer_js)

        # Batch clear results functionality
        self.assertIn("clearBatchResults", js)
        self.assertIn("btnClearBatchResults", js)

        # Batch status panel and KPI pills
        self.assertIn("batch-status-panel", js)
        self.assertIn("kpi-mini-pill", js)
        self.assertIn("Total Analysed", js)


if __name__ == "__main__":
    unittest.main()
