"""
Posture Scorer (0-100 & Grades A+ to F)
"""
from typing import Dict, Any

class PostureScorer:
    def calculate_score(self, features: Dict[str, Any], anomaly: Dict[str, Any]) -> Dict[str, Any]:
        proto_score = 0.0 if (features.get("starttls_downgraded") or features.get("plaintext_auth")) else (30.0 * features.get("ver_score", 1.0))
        cipher_score = 25.0 * features.get("cipher_score", 1.0)
        if features.get("vulns_count", 0) > 0: cipher_score = 0.0
        kex_score = 25.0 if features.get("has_pfs") else 5.0
        cert_score = 20.0
        if features.get("is_expired"): cert_score -= 10.0
        if features.get("is_self_signed"): cert_score -= 5.0
        if features.get("weak_sig"): cert_score -= 5.0
        cert_score = max(0.0, cert_score)
        anom_ded = 10.0 * anomaly.get("anomaly_score", 0.0)

        total = round(max(0.0, min(100.0, proto_score + cipher_score + kex_score + cert_score - anom_ded)), 1)
        grade = "A+" if total >= 95 else ("A" if total >= 85 else ("B" if total >= 75 else ("C" if total >= 60 else ("D" if total >= 45 else "F"))))
        return {"overall_score": total, "overall_grade": grade, "breakdown": {"protocol": proto_score, "cipher": cipher_score, "kex": kex_score, "cert": cert_score, "anomaly": anom_ded}}
