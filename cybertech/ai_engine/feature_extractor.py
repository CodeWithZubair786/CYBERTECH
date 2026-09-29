"""
Feature Extraction Engine for AI/ML Risk & Anomaly Assessment
"""
from typing import Dict, Any

def extract_forensic_features(stream_data: Dict[str, Any]) -> Dict[str, Any]:
    email_meta = stream_data.get("email_analysis", {})
    client_tls = stream_data.get("client_tls", {})
    server_tls = stream_data.get("server_tls", {})
    cert = stream_data.get("certificate", {})

    starttls_offered = 1 if email_meta.get("starttls_offered") else 0
    starttls_initiated = 1 if email_meta.get("starttls_initiated") else 0
    starttls_downgraded = 1 if email_meta.get("starttls_downgraded") else 0
    plaintext_auth = 1 if email_meta.get("plaintext_auth_observed") else 0

    version_str = server_tls.get("server_hello", {}).get("version_str") or "NONE"
    ver_score = 1.0 if "TLS 1.3" in version_str else (0.8 if "TLS 1.2" in version_str else (0.2 if "TLS 1.0" in version_str else 0.0))

    cipher_meta = server_tls.get("server_hello", {}).get("cipher_meta", {})
    has_pfs = 1 if cipher_meta.get("pfs") else 0
    sec = cipher_meta.get("security", "UNKNOWN")
    cipher_score = 1.0 if sec == "SECURE" else (0.6 if sec == "ACCEPTABLE" else 0.0)
    vulns_count = len(cipher_meta.get("vulns", []))

    key_bits = cert.get("public_key_bits", 0) if cert else 0
    is_expired = 1 if cert and cert.get("is_expired") else 0
    is_self_signed = 1 if cert and cert.get("is_self_signed") else 0
    sig_alg = cert.get("signature_algorithm", "") if cert else ""
    weak_sig = 1 if "sha1" in sig_alg.lower() else 0

    return {
        "starttls_offered": starttls_offered,
        "starttls_initiated": starttls_initiated,
        "starttls_downgraded": starttls_downgraded,
        "plaintext_auth": plaintext_auth,
        "ver_score": ver_score,
        "has_pfs": has_pfs,
        "cipher_score": cipher_score,
        "vulns_count": vulns_count,
        "key_bits": key_bits,
        "is_expired": is_expired,
        "is_self_signed": is_self_signed,
        "weak_sig": weak_sig
    }
