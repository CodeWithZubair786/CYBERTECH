"""
Supervised Multi-Class Risk Classifier
"""
from typing import Dict, Any

class RiskClassifier:
    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        p_crit = 0.01; p_high = 0.02; p_med = 0.05; p_low = 0.10; p_sec = 0.82

        if features.get("plaintext_auth") or features.get("starttls_downgraded"):
            p_crit += 0.85; p_sec = 0.01; p_high = 0.10
        elif features.get("vulns_count", 0) > 0 or features.get("cipher_score", 1.0) == 0.0:
            p_crit += 0.45; p_high += 0.40; p_sec = 0.01
        elif features.get("is_expired") or features.get("is_self_signed"):
            p_high += 0.60; p_med += 0.30; p_sec = 0.02
        elif features.get("weak_sig") or not features.get("has_pfs"):
            p_med += 0.50; p_sec = 0.10

        tot = p_crit + p_high + p_med + p_low + p_sec
        probs = {
            "CRITICAL": round(p_crit / tot, 3),
            "HIGH": round(p_high / tot, 3),
            "MEDIUM": round(p_med / tot, 3),
            "LOW": round(p_low / tot, 3),
            "SECURE": round(p_sec / tot, 3),
        }
        pred = max(probs, key=probs.get)
        return {"predicted_risk": pred, "confidence": probs[pred], "probabilities": probs}
