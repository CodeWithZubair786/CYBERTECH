"""
Cyber Tech - Standalone Forensic Web Server & REST API
Theme: Blockchain & Cybersecurity (Smart India Hackathon)
Standard library http.server (Python 3.8 - Python 3.13+ compatible, zero 'cgi' dependency).
"""

import os
import json
import email.parser
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse
from typing import Dict, Any, Optional

from ..core.analyzer import CyberTechAnalyzer
from ..blockchain.ledger import ForensicLedger
from ..reporting.html_report_generator import generate_html_report

GLOBAL_LEDGER = ForensicLedger()
GLOBAL_ANALYZER = CyberTechAnalyzer(ledger=GLOBAL_LEDGER)
LATEST_REPORT: Dict[str, Any] = {}

class CyberTechHTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
        super().__init__(*args, directory=static_dir, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self._serve_static_file("index.html", "text/html")
        elif path == "/style.css":
            self._serve_static_file("style.css", "text/css")
        elif path == "/app.js":
            self._serve_static_file("app.js", "application/javascript")
        elif path == "/api/samples":
            self._api_list_samples()
        elif path == "/api/ledger":
            self._api_get_ledger()
        elif path == "/api/report/html":
            self._api_download_html()
        elif path == "/api/report/json":
            self._api_download_json()
        elif path == "/api/latest":
            self._send_json(LATEST_REPORT)
        else:
            super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/analyze-sample":
            self._api_analyze_sample()
        elif path == "/api/upload":
            self._api_upload_pcap()
        else:
            self.send_error(404, "Endpoint not found")

    def _serve_static_file(self, filename: str, content_type: str):
        static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
        file_path = os.path.join(static_dir, filename)
        if not os.path.exists(file_path):
            self.send_error(404, f"File {filename} not found")
            return
        with open(file_path, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_json(self, data: Any, status: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _api_list_samples(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        samples_dir = os.path.join(base_dir, "sample_pcaps")
        if not os.path.exists(samples_dir):
            self._send_json([])
            return
        
        sample_meta = {
            "enterprise_smtps_hardened.pcap": {
                "name": "Enterprise SMTPS Hardened (TLS 1.3)",
                "description": "TLS 1.3, AES-256-GCM, SHA-512 Certificate, Forward Secrecy. Expected Grade: A+",
                "severity": "SECURE"
            },
            "mitm_starttls_stripping_attack.pcap": {
                "name": "Active STARTTLS Stripping Downgrade & Credential Sniffing",
                "description": "Server offers STARTTLS; client downgrades to plaintext AUTH LOGIN credentials. Expected Grade: F",
                "severity": "CRITICAL"
            },
            "legacy_pop3_sweet32_vuln.pcap": {
                "name": "Legacy POP3 with 3DES Sweet32 & TLS 1.0",
                "description": "Deprecated TLS 1.0, 3DES-CBC Sweet32 vulnerability (CVE-2016-2183), SHA-1 signature. Expected Grade: D/F",
                "severity": "CRITICAL"
            },
            "imaps_expired_selfsigned_cert.pcap": {
                "name": "IMAPS with Expired Self-Signed Cert & No PFS",
                "description": "Static RSA key exchange (no Forward Secrecy), expired untrusted self-signed cert. Expected Grade: F",
                "severity": "HIGH"
            },
            "shadow_c2_email_anomaly.pcap": {
                "name": "Covert C2 Email Channel Anomaly (RC4 Disguise)",
                "description": "Single exotic cipher suite (RC4), zero SNI, elevated AI anomaly score. Expected Grade: F",
                "severity": "CRITICAL"
            },
        }

        samples = []
        for f in sorted(os.listdir(samples_dir)):
            if f.endswith(".pcap"):
                meta = sample_meta.get(f, {"name": f, "description": "Custom PCAP", "severity": "UNKNOWN"})
                samples.append({
                    "filename": f,
                    "name": meta["name"],
                    "description": meta["description"],
                    "severity": meta["severity"],
                    "size_bytes": os.path.getsize(os.path.join(samples_dir, f))
                })
        self._send_json(samples)

    def _api_analyze_sample(self):
        global LATEST_REPORT
        length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(length)
        req = json.loads(post_data.decode("utf-8"))
        filename = req.get("filename")

        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        pcap_path = os.path.join(base_dir, "sample_pcaps", filename)

        if not os.path.exists(pcap_path):
            self._send_json({"error": f"Sample {filename} not found"}, status=404)
            return

        report = GLOBAL_ANALYZER.analyze_pcap(pcap_path, investigator="Cyber-Tech-Analyst")
        LATEST_REPORT = report
        self._send_json(report)

    def _api_upload_pcap(self):
        global LATEST_REPORT
        content_type = self.headers.get("Content-Type", "")
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            content_length = 0

        if content_length <= 0:
            self._send_json({"error": "Empty request body"}, status=400)
            return

        body_bytes = self.rfile.read(content_length)
        file_bytes = None

        if "multipart/form-data" in content_type:
            # 1. Standard library email.parser (Python 3.8 - Python 3.13+ safe)
            try:
                msg = email.parser.BytesParser().parsebytes(
                    b"Content-Type: " + content_type.encode("utf-8") + b"\r\n\r\n" + body_bytes
                )
                for part in msg.walk():
                    if part.get_filename() or part.get_param("name", header="content-disposition") == "file":
                        file_bytes = part.get_payload(decode=True)
                        if file_bytes:
                            break
            except Exception:
                pass

            # 2. Resilient manual boundary splitter fallback
            if not file_bytes:
                boundary = None
                for param in content_type.split(";"):
                    param = param.strip()
                    if param.lower().startswith("boundary="):
                        boundary = param.split("=", 1)[1].strip('"\'')
                        break
                if boundary:
                    delimiter = f"--{boundary}".encode("latin-1")
                    for section in body_bytes.split(delimiter):
                        if b"filename=" in section or b'name="file"' in section:
                            header_idx = section.find(b"\r\n\r\n")
                            if header_idx != -1:
                                data = section[header_idx + 4:]
                                if data.endswith(b"\r\n--"):
                                    data = data[:-4]
                                elif data.endswith(b"\r\n"):
                                    data = data[:-2]
                                file_bytes = data
                                break
        else:
            file_bytes = body_bytes

        if not file_bytes:
            self._send_json({"error": "No file uploaded or file was empty"}, status=400)
            return

        temp_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "scratch")
        os.makedirs(temp_dir, exist_ok=True)
        uploaded_path = os.path.join(temp_dir, "uploaded_capture.pcap")
        
        with open(uploaded_path, "wb") as f:
            f.write(file_bytes)

        report = GLOBAL_ANALYZER.analyze_pcap(uploaded_path, investigator="Cyber-Tech-Upload")
        LATEST_REPORT = report
        self._send_json(report)

    def _api_get_ledger(self):
        integrity = GLOBAL_LEDGER.verify_integrity()
        data = {
            "blocks": GLOBAL_LEDGER.to_list(),
            "verification": integrity
        }
        self._send_json(data)

    def _api_download_html(self):
        if not LATEST_REPORT:
            self.send_error(400, "No analysis available to export. Run an analysis first.")
            return
        html_content = generate_html_report(LATEST_REPORT).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Disposition", 'attachment; filename="Cyber_Tech_Forensic_Report.html"')
        self.send_header("Content-Length", str(len(html_content)))
        self.end_headers()
        self.wfile.write(html_content)

    def _api_download_json(self):
        if not LATEST_REPORT:
            self.send_error(400, "No analysis available to export. Run an analysis first.")
            return
        json_content = json.dumps(LATEST_REPORT, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Disposition", 'attachment; filename="Cyber_Tech_Forensic_Report.json"')
        self.send_header("Content-Length", str(len(json_content)))
        self.end_headers()
        self.wfile.write(json_content)

def run_server(host: Optional[str] = None, port: Optional[int] = None):
    if host is None:
        host = os.environ.get("HOST", "0.0.0.0")
    if port is None:
        port = int(os.environ.get("PORT", 8080))

    server_address = (host, port)
    httpd = HTTPServer(server_address, CyberTechHTTPHandler)
    print(f"\033[92m[+] Cyber Tech Forensic Dashboard running at: http://{host}:{port}\033[0m")
    print(f"\033[90m[*] Cloud/Render Deployment Ready &bull; Press Ctrl+C to terminate.\033[0m")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\033[93m[!] Stopping web server...\033[0m")
        httpd.server_close()
