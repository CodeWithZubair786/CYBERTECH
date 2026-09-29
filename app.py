"""
Cyber Tech - Cloud & Render Deployment Entrypoint
Theme: Blockchain & Cybersecurity (Smart India Hackathon)
Supports:
- python app.py (Direct server binding to $HOST and $PORT)
- gunicorn app:app (WSGI cloud production runner)
"""

import os
import sys
import json
from cybertech.web.server import (
    run_server,
    GLOBAL_ANALYZER,
    GLOBAL_LEDGER,
    LATEST_REPORT,
    generate_html_report
)

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", 8080))

def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET")
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cybertech", "web", "static")

    if path in ("/", "/index.html"):
        filepath = os.path.join(static_dir, "index.html")
        with open(filepath, "rb") as f:
            data = f.read()
        start_response("200 OK", [("Content-Type", "text/html"), ("Content-Length", str(len(data)))])
        return [data]

    elif path in ("/style.css", "/app.js"):
        filename = path.lstrip("/")
        filepath = os.path.join(static_dir, filename)
        ctype = "text/css" if filename.endswith(".css") else "application/javascript"
        if os.path.exists(filepath):
            with open(filepath, "rb") as f:
                data = f.read()
            start_response("200 OK", [("Content-Type", ctype), ("Content-Length", str(len(data)))])
            return [data]

    elif path == "/api/samples" and method == "GET":
        samples_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_pcaps")
        samples = []
        if os.path.exists(samples_dir):
            sample_meta = {
                "enterprise_smtps_hardened.pcap": {"name": "Enterprise SMTPS Hardened (TLS 1.3)", "description": "TLS 1.3, AES-256-GCM, SHA-512 Cert", "severity": "SECURE"},
                "mitm_starttls_stripping_attack.pcap": {"name": "Active STARTTLS Stripping Downgrade & Credential Sniffing", "description": "Server offers STARTTLS; client downgrades to plaintext", "severity": "CRITICAL"},
                "legacy_pop3_sweet32_vuln.pcap": {"name": "Legacy POP3 with 3DES Sweet32 & TLS 1.0", "description": "Deprecated TLS 1.0, 3DES Sweet32 (CVE-2016-2183)", "severity": "CRITICAL"},
                "imaps_expired_selfsigned_cert.pcap": {"name": "IMAPS with Expired Self-Signed Cert & No PFS", "description": "Static RSA, expired untrusted cert", "severity": "HIGH"},
                "shadow_c2_email_anomaly.pcap": {"name": "Covert C2 Email Channel Anomaly (RC4 Disguise)", "description": "Single exotic cipher (RC4), no SNI", "severity": "CRITICAL"},
            }
            for f in sorted(os.listdir(samples_dir)):
                if f.endswith(".pcap"):
                    meta = sample_meta.get(f, {"name": f, "description": "PCAP", "severity": "UNKNOWN"})
                    samples.append({
                        "filename": f,
                        "name": meta["name"],
                        "description": meta["description"],
                        "severity": meta["severity"],
                        "size_bytes": os.path.getsize(os.path.join(samples_dir, f))
                    })
        body = json.dumps(samples).encode("utf-8")
        start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
        return [body]

    elif path == "/api/ledger" and method == "GET":
        data = {
            "blocks": GLOBAL_LEDGER.to_list(),
            "verification": GLOBAL_LEDGER.verify_integrity()
        }
        body = json.dumps(data).encode("utf-8")
        start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
        return [body]

    elif path == "/api/analyze-sample" and method == "POST":
        try:
            content_length = int(environ.get("CONTENT_LENGTH", 0))
            post_data = environ["wsgi.input"].read(content_length)
            req = json.loads(post_data.decode("utf-8"))
            filename = req.get("filename")
            pcap_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_pcaps", filename)
            
            report = GLOBAL_ANALYZER.analyze_pcap(pcap_path, investigator="Cyber-Tech-Analyst")
            import cybertech.web.server as srv
            srv.LATEST_REPORT = report
            body = json.dumps(report).encode("utf-8")
            start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
            return [body]
        except Exception as e:
            err = json.dumps({"error": str(e)}).encode("utf-8")
            start_response("500 Internal Server Error", [("Content-Type", "application/json")])
            return [err]

    elif path == "/api/upload" and method == "POST":
        try:
            content_type = environ.get("CONTENT_TYPE", "")
            content_length = int(environ.get("CONTENT_LENGTH", 0))
            body_bytes = environ["wsgi.input"].read(content_length)
            file_bytes = None
            if "multipart/form-data" in content_type:
                import email.parser
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
                err = json.dumps({"error": "No file uploaded"}).encode("utf-8")
                start_response("400 Bad Request", [("Content-Type", "application/json")])
                return [err]

            temp_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scratch")
            os.makedirs(temp_dir, exist_ok=True)
            uploaded_path = os.path.join(temp_dir, "uploaded_capture.pcap")
            with open(uploaded_path, "wb") as f:
                f.write(file_bytes)

            report = GLOBAL_ANALYZER.analyze_pcap(uploaded_path, investigator="Cyber-Tech-Upload")
            import cybertech.web.server as srv
            srv.LATEST_REPORT = report
            body = json.dumps(report).encode("utf-8")
            start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
            return [body]
        except Exception as e:
            err = json.dumps({"error": str(e)}).encode("utf-8")
            start_response("500 Internal Server Error", [("Content-Type", "application/json")])
            return [err]

    elif path == "/api/report/html" and method == "GET":
        import cybertech.web.server as srv
        rep = srv.LATEST_REPORT
        if not rep:
            pcap_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_pcaps", "enterprise_smtps_hardened.pcap")
            rep = GLOBAL_ANALYZER.analyze_pcap(pcap_path)
            srv.LATEST_REPORT = rep
        html_bytes = generate_html_report(rep).encode("utf-8")
        start_response("200 OK", [
            ("Content-Type", "text/html"),
            ("Content-Disposition", 'attachment; filename="Cyber_Tech_Forensic_Report.html"'),
            ("Content-Length", str(len(html_bytes)))
        ])
        return [html_bytes]

    elif path == "/api/report/json" and method == "GET":
        import cybertech.web.server as srv
        rep = srv.LATEST_REPORT
        if not rep:
            pcap_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_pcaps", "enterprise_smtps_hardened.pcap")
            rep = GLOBAL_ANALYZER.analyze_pcap(pcap_path)
            srv.LATEST_REPORT = rep
        json_bytes = json.dumps(rep, indent=2).encode("utf-8")
        start_response("200 OK", [
            ("Content-Type", "application/json"),
            ("Content-Disposition", 'attachment; filename="Cyber_Tech_Forensic_Report.json"'),
            ("Content-Length", str(len(json_bytes)))
        ])
        return [json_bytes]

    elif path == "/api/latest" and method == "GET":
        import cybertech.web.server as srv
        body = json.dumps(srv.LATEST_REPORT).encode("utf-8")
        start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
        return [body]

    start_response("404 Not Found", [("Content-Type", "text/plain")])
    return [b"Not Found"]

if __name__ == "__main__":
    print(f"[*] Starting Cyber Tech Forensic Platform on {HOST}:{PORT}...")
    run_server(host=HOST, port=PORT)
