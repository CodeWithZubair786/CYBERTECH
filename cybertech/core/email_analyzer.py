"""
Email Protocol Analyzer (SMTP, IMAP, POP3)
"""
from typing import Dict, Any

class EmailProtocolAnalyzer:
    def analyze_stream(self, c2s: bytes, s2c: bytes, server_port: int) -> Dict[str, Any]:
        proto = "SMTP" if server_port in (25, 465, 587, 2525) else ("IMAP" if server_port in (143, 993) else ("POP3" if server_port in (110, 995) else "SMTP"))
        c2s_str = c2s.decode("latin-1", errors="ignore")
        s2c_str = s2c.decode("latin-1", errors="ignore")

        starttls_offered = "STARTTLS" in s2c_str.upper() or "STLS" in s2c_str.upper()
        starttls_initiated = "STARTTLS" in c2s_str.upper() or "STLS" in c2s_str.upper()
        starttls_downgraded = False
        plaintext_auth = False
        creds = []

        if "AUTH LOGIN" in c2s_str.upper() or "USER " in c2s_str.upper() or "LOGIN " in c2s_str.upper():
            plaintext_auth = True
            if starttls_offered and not starttls_initiated:
                starttls_downgraded = True

        for line in c2s_str.splitlines():
            line_up = line.strip().upper()
            if line_up.startswith("AUTH LOGIN") or line_up.startswith("USER "):
                creds.append(line.strip())

        return {
            "protocol": proto,
            "starttls_offered": starttls_offered,
            "starttls_initiated": starttls_initiated,
            "starttls_downgraded": starttls_downgraded,
            "plaintext_auth_observed": plaintext_auth,
            "credentials_leaked": creds
        }
