import io
import unittest
from fastapi.testclient import TestClient
from backend.main import app

class TestIncidentResponseRemovalVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_html_navigation_and_views(self):
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.text

        expected_views = [
            "view-dashboard", "view-analyzer", "view-profiles", "view-models",
            "view-anomaly", "view-history", "view-assistant", "view-about"
        ]
        for v in expected_views:
            self.assertIn(f'data-view="{v}"', html, f"Missing nav item for {v}")
            self.assertIn(f'id="{v}"', html, f"Missing section for {v}")

        # Incident response UI components must be absent
        self.assertNotIn('data-view="view-incident"', html)
        self.assertNotIn('id="view-incident"', html)
        self.assertNotIn('INC-2017-0704', html)
        self.assertNotIn('Automated Perimeter Containment Rules', html)
        self.assertNotIn('btnApplyContainment', html)
        self.assertNotIn('containmentCodeBox', html)
        self.assertNotIn('chkStep2', html)
        self.assertNotIn('chkStep5', html)
        self.assertNotIn('SOC Incident Response Checklist', html)
        self.assertNotIn('Linux IPTables', html)
        self.assertNotIn('Cisco ASA ACL', html)
        self.assertNotIn('Windows Firewall', html)

    def test_02_css_serving_clean(self):
        resp = self.client.get("/static/css/styles.css")
        self.assertEqual(resp.status_code, 200)
        css = resp.text
        self.assertNotIn("incident-header-banner", css)
        self.assertNotIn("platform-tabs", css)
        self.assertNotIn("checklist-box", css)

    def test_03_js_serving_clean(self):
        for js_file in ["app.js", "api.js", "charts.js"]:
            resp = self.client.get(f"/static/js/{js_file}")
            self.assertEqual(resp.status_code, 200)
            self.assertNotIn("initIncidentControls", resp.text)
            self.assertNotIn("generateContainment", resp.text)
            self.assertNotIn("currentContainmentRules", resp.text)

    def test_04_removed_endpoint_returns_404(self):
        payload = {"platform": "iptables"}
        resp = self.client.post("/api/incident/contain", json=payload)
        self.assertEqual(resp.status_code, 404)

    def test_05_core_api_endpoints_operational(self):
        self.assertEqual(self.client.get("/api/status").status_code, 200)
        self.assertEqual(self.client.get("/api/models/benchmarks").status_code, 200)
        self.assertEqual(self.client.get("/api/profiles/overview").status_code, 200)
        self.assertEqual(self.client.get("/api/anomaly/overview").status_code, 200)
        self.assertEqual(self.client.get("/api/history").status_code, 200)

        chat_resp = self.client.post("/api/assistant/chat", json={"query": "What is the system architecture?"})
        self.assertEqual(chat_resp.status_code, 200)
        self.assertNotIn("Incident Response", chat_resp.json()["reply"])

    def test_06_flow_and_profile_predictions_work(self):
        flow_resp = self.client.post("/api/models/predict/flow", json={
            "source_ip": "172.16.0.1", "destination_ip": "192.168.10.50",
            "source_port": 50000, "destination_port": 21, "protocol": 6,
            "flow_packets_s": 500000.0, "flow_bytes_s": 2000000.0, "syn_flag_count": 1,
            "flow_duration": 1000.0, "flow_count": 15
        })
        self.assertEqual(flow_resp.status_code, 200)
        self.assertIn("verdict", flow_resp.json())

        csv_content = "bp_01,bp_02,bp_03,bp_04,bp_05,bp_06,bp_07,bp_08\n0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8\n"
        up_resp = self.client.post("/api/detect/upload", files={"file": ("test.csv", io.BytesIO(csv_content.encode()), "text/csv")})
        self.assertEqual(up_resp.status_code, 200)

if __name__ == "__main__":
    unittest.main()
