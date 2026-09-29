"""
Unit tests for web server, WSGI adapter, and report generation
"""

import unittest
import os
import json
from cybertech.core.analyzer import CyberTechAnalyzer
from cybertech.reporting.html_report_generator import generate_html_report
from cybertech.reporting.json_exporter import export_to_json

class TestWebServer(unittest.TestCase):
    def setUp(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        pcap_path = os.path.join(base_dir, "sample_pcaps", "enterprise_smtps_hardened.pcap")
        analyzer = CyberTechAnalyzer()
        self.report = analyzer.analyze_pcap(pcap_path)

    def test_generate_html_report(self):
        html = generate_html_report(self.report)
        self.assertIn("CYBER TECH", html)
        self.assertIn("NIST FIPS 180-4", html)
        self.assertIn("TLS 1.3", html)

    def test_export_to_json(self):
        tmp_json = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test_out.json")
        export_to_json(self.report, tmp_json)
        self.assertTrue(os.path.exists(tmp_json))
        with open(tmp_json, "r") as f:
            data = json.load(f)
            self.assertEqual(data["posture_score"]["overall_grade"], "A+")
        if os.path.exists(tmp_json):
            os.remove(tmp_json)

    def test_wsgi_routes(self):
        from app import app
        environ = {"PATH_INFO": "/api/samples", "REQUEST_METHOD": "GET"}
        status_rec = []
        def start_response(s, h): status_rec.append(s)
        res = app(environ, start_response)
        self.assertEqual(status_rec[0], "200 OK")
        data = json.loads(res[0].decode("utf-8"))
        self.assertTrue(len(data) > 0)

if __name__ == "__main__":
    unittest.main()
