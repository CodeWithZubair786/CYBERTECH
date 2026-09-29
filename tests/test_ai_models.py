"""
Unit tests for Cyber Tech AI/ML models & Posture Scorer
"""

import unittest
from cybertech.ai_engine.risk_classifier import RiskClassifier
from cybertech.ai_engine.anomaly_detector import TLSAnomalyDetector
from cybertech.ai_engine.posture_scorer import PostureScorer

class TestAIModels(unittest.TestCase):
    def setUp(self):
        self.risk_classifier = RiskClassifier()
        self.anomaly_detector = TLSAnomalyDetector()
        self.posture_scorer = PostureScorer()

    def test_risk_classifier_hardened(self):
        features = {
            "plaintext_auth": 0,
            "starttls_downgraded": 0,
            "vulns_count": 0,
            "cipher_score": 1.0,
            "has_pfs": 1,
            "ver_score": 1.0,
            "is_expired": 0,
            "is_self_signed": 0,
            "weak_sig": 0
        }
        res = self.risk_classifier.predict(features)
        self.assertEqual(res["predicted_risk"], "SECURE")
        self.assertTrue(res["probabilities"]["SECURE"] > 0.6)

    def test_risk_classifier_downgrade(self):
        features = {
            "plaintext_auth": 1,
            "starttls_downgraded": 1,
            "vulns_count": 0,
            "cipher_score": 1.0
        }
        res = self.risk_classifier.predict(features)
        self.assertEqual(res["predicted_risk"], "CRITICAL")
        self.assertTrue(res["probabilities"]["CRITICAL"] > 0.7)

    def test_posture_scorer(self):
        features = {"ver_score": 1.0, "cipher_score": 1.0, "has_pfs": 1, "is_expired": 0, "is_self_signed": 0, "weak_sig": 0}
        anomaly = {"anomaly_score": 0.0}
        score = self.posture_scorer.calculate_score(features, anomaly)
        self.assertGreaterEqual(score["overall_score"], 85.0)
        self.assertIn(score["overall_grade"], ["A+", "A"])

if __name__ == "__main__":
    unittest.main()
