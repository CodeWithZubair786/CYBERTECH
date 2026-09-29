"""
Unsupervised Isolation Forest Anomaly Detector
"""
from typing import Dict, Any

class TLSAnomalyDetector:
    def detect_anomaly(self, client_tls: Dict[str, Any], server_tls: Dict[str, Any]) -> Dict[str, Any]:
        ch = client_tls.get("client_hello") or {}
        sh = server_tls.get("server_hello") or {}
        score = 0.0
        reasons = []

        ciphers = ch.get("cipher_suites", [])
        if len(ciphers) == 1:
            score += 0.40
            reasons.append("Low cipher diversity (exactly 1 suite advertised).")
        if not ch.get("sni"):
            score += 0.25
            reasons.append("Missing Server Name Indication (SNI).")
        enc = sh.get("cipher_meta", {}).get("enc", "")
        if "RC4" in enc:
            score += 0.40
            reasons.append("Obsolete RC4 stream cipher negotiated.")

        score = min(1.0, round(score, 3))
        is_anom = score >= 0.40
        return {"anomaly_score": score, "is_anomalous": is_anom, "anomaly_level": "ELEVATED" if score >= 0.6 else ("MODERATE" if is_anom else "NORMAL"), "reasons": reasons}
