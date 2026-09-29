"""
Publication-Grade HTML/PDF Forensic Report Generator for Cyber Tech
Generates comprehensive cryptographic audits suitable for executive debriefs and legal evidence.
"""

from typing import Dict, Any

def generate_html_report(report: Dict[str, Any]) -> str:
    meta = report.get("metadata", {})
    score = report.get("posture_score", {})
    risk = report.get("risk_classification", {})
    advisory = report.get("nlp_advisory", {})
    bchain = report.get("blockchain_evidence", {})
    cert = report.get("certificate", {})
    email_meta = report.get("email_analysis", {})
    s_tls = report.get("server_tls", {})

    grade = score.get("overall_grade", "N/A")
    grade_color = "#00e676" if grade in ("A+", "A") else ("#ffab00" if grade in ("B", "C") else "#ff1744")

    mitre_rows = ""
    for m in advisory.get("mitre_mappings", []):
        mitre_rows += f"""<tr>
            <td style="font-family:monospace; color:#00ffff; font-weight:bold;">{m.get('id')}</td>
            <td><strong>{m.get('name')}</strong></td>
            <td>{m.get('tactic')}</td>
            <td>{m.get('description')}</td>
        </tr>"""

    recs_list = "".join(f"<li>{r}</li>" for r in advisory.get("recommendations", []))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Cyber Tech Forensic Audit Report - {meta.get('filename')}</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0f19; color: #e2e8f0; margin: 0; padding: 40px; }}
    .header {{ border-bottom: 2px solid #1e293b; padding-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }}
    .logo-title {{ font-size: 26px; font-weight: 800; color: #00ffc2; letter-spacing: 1px; }}
    .score-badge {{ font-size: 42px; font-weight: 900; color: {grade_color}; border: 3px solid {grade_color}; border-radius: 12px; padding: 5px 20px; text-align: center; }}
    .card {{ background: #131b2e; border: 1px solid #1e293b; border-radius: 8px; padding: 20px; margin-top: 25px; }}
    h2 {{ color: #38bdf8; font-size: 18px; margin-top: 0; border-bottom: 1px solid #243452; padding-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }}
    th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #1e293b; }}
    th {{ background: #0e1526; color: #94a3b8; font-weight: 600; }}
    .hash-box {{ font-family: monospace; font-size: 11px; background: #080c14; padding: 10px; border-radius: 4px; word-break: break-all; color: #a5f3fc; border: 1px solid #16263f; }}
    .status-pill {{ padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }}
</style>
</head>
<body>

<div class="header">
    <div>
        <div class="logo-title">CYBER TECH &bull; FORENSIC AUDIT REPORT</div>
        <div style="color: #64748b; font-size: 13px; margin-top: 4px;">Theme: Blockchain & Cybersecurity &bull; NIST FIPS 180-4 / Section 65B Audit</div>
        <div style="color: #94a3b8; font-size: 14px; margin-top: 8px;">Target Capture: <strong>{meta.get('filename')}</strong> | Packets: {meta.get('total_packets')} | Duration: {meta.get('duration_seconds')}s</div>
    </div>
    <div class="score-badge">
        {grade}
        <div style="font-size: 12px; color: #94a3b8; font-weight: normal;">Score: {score.get('overall_score')}/100</div>
    </div>
</div>

<div class="card">
    <h2>1. Executive Summary & AI Risk Classification</h2>
    <p style="line-height: 1.6; font-size: 15px;">{advisory.get('executive_summary')}</p>
    <div style="margin-top: 15px;">
        <strong>Predicted Risk Level:</strong> <span style="color: {grade_color}; font-weight: bold;">{risk.get('predicted_risk')}</span> (Confidence: {int(risk.get('confidence', 0)*100)}%)
    </div>
</div>

<div class="card">
    <h2>2. Protocol & TLS Cryptographic Dissection</h2>
    <table>
        <tr><th>Parameter</th><th>Observed Value</th><th>Status</th></tr>
        <tr><td>Negotiated Protocol</td><td>{email_meta.get('protocol')}</td><td>Active</td></tr>
        <tr><td>STARTTLS Offered / Initiated</td><td>{'YES' if email_meta.get('starttls_offered') else 'NO'} / {'YES' if email_meta.get('starttls_initiated') else 'NO'}</td><td>{'CRITICAL DOWNGRADE' if email_meta.get('starttls_downgraded') else 'NORMAL'}</td></tr>
        <tr><td>TLS Version</td><td>{s_tls.get('version', 'None')}</td><td>{s_tls.get('version', 'None')}</td></tr>
        <tr><td>Selected Cipher Suite</td><td>{s_tls.get('cipher_name', 'None')}</td><td>{s_tls.get('cipher_meta', {}).get('security', 'N/A')}</td></tr>
        <tr><td>Perfect Forward Secrecy (PFS)</td><td>{'ENABLED' if s_tls.get('cipher_meta', {}).get('pfs') else 'DISABLED'}</td><td>{'SECURE' if s_tls.get('cipher_meta', {}).get('pfs') else 'HIGH RISK'}</td></tr>
    </table>
</div>

<div class="card">
    <h2>3. X.509 Certificate Chain & Identity Verification</h2>
    {f'''<table>
        <tr><th>Attribute</th><th>Value</th></tr>
        <tr><td>Subject Common Name</td><td>{cert.get('subject', {}).get('CN', 'Unknown')}</td></tr>
        <tr><td>Issuer Common Name</td><td>{cert.get('issuer', {}).get('CN', 'Unknown')}</td></tr>
        <tr><td>Public Key Length</td><td>{cert.get('public_key_bits')} bits ({cert.get('public_key_algorithm')})</td></tr>
        <tr><td>Signature Algorithm</td><td>{cert.get('signature_algorithm')}</td></tr>
        <tr><td>Validity Period</td><td>{cert.get('not_before')} to {cert.get('not_after')} ({'EXPIRED' if cert.get('is_expired') else 'VALID'})</td></tr>
        <tr><td>SHA-512 Fingerprint</td><td class="hash-box">{cert.get('sha512_fingerprint')}</td></tr>
    </table>''' if cert else '<p style="color:#64748b;">No X.509 certificate exchange detected in this stream.</p>'}
</div>

<div class="card">
    <h2>4. MITRE ATT&CK Threat Mapping</h2>
    <table>
        <tr><th>Technique ID</th><th>Name</th><th>Tactic</th><th>Forensic Evidence</th></tr>
        {mitre_rows if mitre_rows else '<tr><td colspan="4" style="color:#64748b;">No active adversarial attack patterns detected.</td></tr>'}
    </table>
</div>

<div class="card">
    <h2>5. Remediation Playbook</h2>
    <ul style="line-height: 1.8; font-size: 14px;">
        {recs_list}
    </ul>
</div>

<div class="card">
    <h2>6. Immutable Blockchain Evidence Seal (Section 65B Admissibility)</h2>
    <table>
        <tr><th>Blockchain Block Index</th><td>#{bchain.get('block_index')}</td></tr>
        <tr><th>Hash Algorithm</th><td>{bchain.get('hash_algorithm')}</td></tr>
        <tr><th>Block 512-Bit SHA-512 Hash</th><td class="hash-box">{bchain.get('block_hash')}</td></tr>
        <tr><th>Previous Block Hash</th><td class="hash-box">{bchain.get('previous_hash')}</td></tr>
        <tr><th>Merkle Tree Root</th><td class="hash-box">{bchain.get('merkle_root')}</td></tr>
        <tr><th>Timestamp & Investigator</th><td>{bchain.get('timestamp')} | {bchain.get('investigator')}</td></tr>
    </table>
</div>

</body>
</html>
"""
    return html
