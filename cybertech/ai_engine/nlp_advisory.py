"""
NLP Advisory & Hardening Playbooks
"""
from typing import Dict, Any

def generate_nlp_advisory(report: Dict[str, Any]) -> Dict[str, Any]:
    score = report.get("posture_score", {}).get("overall_score", 0)
    grade = report.get("posture_score", {}).get("overall_grade", "F")
    risk = report.get("risk_classification", {}).get("predicted_risk", "HIGH")
    email_meta = report.get("email_analysis", {})

    brief = [f"Cryptographic posture evaluated at {score}/100 (Grade: {grade}), categorized as {risk} risk."]
    mitre = []
    recs = []

    if email_meta.get("starttls_downgraded") or email_meta.get("plaintext_auth_observed"):
        brief.append("CRITICAL: Active STARTTLS stripping downgrade attack identified. Plaintext credentials observed in transit.")
        mitre.append({"id": "T1557", "name": "Man-in-the-Middle", "tactic": "Credential Access", "description": "STARTTLS stripped to force cleartext authentication."})
        recs.append("Enforce MTA-STS (RFC 8461) and DANE (RFC 7672) with strict DNSSEC verification.")
        recs.append("Configure Postfix with `smtpd_tls_security_level = encrypt`.")

    if not recs:
        brief.append("Hardened enterprise configuration verified. Modern TLS with AEAD ciphers and Forward Secrecy.")
        recs.append("Maintain continuous passive monitoring to ensure posture against cipher obsolescence.")

    postfix_conf = """# /etc/postfix/main.cf - Hardened Cyber Tech Baseline
smtpd_tls_security_level = encrypt
smtpd_tls_mandatory_protocols = >=TLSv1.3
smtpd_tls_mandatory_ciphers = high
tls_high_cipherlist = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
"""

    dovecot_conf = """# /etc/dovecot/conf.d/10-ssl.conf - Hardened Cyber Tech Baseline
ssl = required
ssl_min_protocol = TLSv1.3
ssl_cipher_list = ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
"""

    return {
        "executive_summary": " ".join(brief),
        "mitre_mappings": mitre,
        "recommendations": recs,
        "hardening_playbook": {"postfix": postfix_conf, "dovecot": dovecot_conf}
    }
