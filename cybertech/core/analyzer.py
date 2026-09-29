"""
Master Forensic Orchestrator for Cyber Tech
Coordinates PCAP dissection, TCP stream reassembly, protocol state evaluation,
cryptographic verification, AI/ML risk & anomaly scoring, and blockchain ledger recording.
"""

import os
from typing import Dict, Any, Optional

from .pcap_parser import PcapParser
from .tcp_reassembler import TCPReassembler
from .email_analyzer import EmailProtocolAnalyzer
from .tls_dissector import TLSDissector
from .x509_parser import X509Parser
from ..ai_engine.feature_extractor import extract_forensic_features
from ..ai_engine.risk_classifier import RiskClassifier
from ..ai_engine.anomaly_detector import TLSAnomalyDetector
from ..ai_engine.posture_scorer import PostureScorer
from ..ai_engine.nlp_advisory import generate_nlp_advisory
from ..blockchain.ledger import ForensicLedger

class CyberTechAnalyzer:
    def __init__(self, ledger: Optional[ForensicLedger] = None):
        self.ledger = ledger if ledger else ForensicLedger()
        self.email_analyzer = EmailProtocolAnalyzer()
        self.tls_dissector = TLSDissector()
        self.x509_parser = X509Parser()
        self.risk_classifier = RiskClassifier()
        self.anomaly_detector = TLSAnomalyDetector()
        self.posture_scorer = PostureScorer()

    def analyze_pcap(self, pcap_path: str, investigator: str = "Cyber-Tech-Analyst") -> Dict[str, Any]:
        parser = PcapParser(pcap_path)
        reassembler = TCPReassembler()

        packet_count = 0
        for pkt in parser.parse_packets():
            packet_count += 1
            reassembler.process_packet(pkt)

        streams = reassembler.get_reassembled_streams()
        
        # Primary stream evaluation
        primary_stream = None
        if streams:
            primary_stream = list(streams.values())[0]

        if not primary_stream:
            # Fallback for empty or non-TCP capture
            return self._empty_report(pcap_path, packet_count)

        c2s_data = primary_stream["c2s_payload"]
        s2c_data = primary_stream["s2c_payload"]
        server_port = primary_stream["server_endpoint"][1]

        # 1. Protocol State Machine
        email_analysis = self.email_analyzer.analyze_stream(c2s_data, s2c_data, server_port)

        # 2. TLS Dissection
        client_tls = self.tls_dissector.dissect_client_traffic(c2s_data)
        server_tls = self.tls_dissector.dissect_server_traffic(s2c_data)

        # 3. Certificate Parsing
        parsed_cert = None
        if server_tls.get("raw_certificates"):
            raw_der = server_tls["raw_certificates"][0]
            parsed_cert = self.x509_parser.parse_der(raw_der)

        stream_data = {
            "email_analysis": email_analysis,
            "client_tls": client_tls,
            "server_tls": server_tls,
            "certificate": parsed_cert,
            "packets_count": primary_stream["packets_count"],
            "duration": round(primary_stream["duration"], 4)
        }

        # 4. Feature Extraction & AI Models
        features = extract_forensic_features(stream_data)
        risk_classification = self.risk_classifier.predict(features)
        anomaly_detection = self.anomaly_detector.detect_anomaly(client_tls, server_tls)
        posture_score = self.posture_scorer.calculate_score(features, anomaly_detection)

        report = {
            "metadata": {
                "filename": os.path.basename(pcap_path),
                "total_packets": packet_count,
                "streams_analyzed": len(streams),
                "client_endpoint": f"{primary_stream['client_endpoint'][0]}:{primary_stream['client_endpoint'][1]}",
                "server_endpoint": f"{primary_stream['server_endpoint'][0]}:{primary_stream['server_endpoint'][1]}",
                "duration_seconds": round(primary_stream["duration"], 4)
            },
            "email_analysis": email_analysis,
            "client_tls": {
                "is_tls": client_tls["is_tls"],
                "version": client_tls.get("client_hello", {}).get("version_str") if client_tls.get("client_hello") else None,
                "ja3_hash": client_tls.get("ja3_hash"),
                "ja3_512": client_tls.get("ja3_512"),
                "ja3_string": client_tls.get("ja3_string"),
                "sni": client_tls.get("client_hello", {}).get("sni") if client_tls.get("client_hello") else None,
                "ciphers_offered_count": len(client_tls.get("client_hello", {}).get("cipher_suites", [])) if client_tls.get("client_hello") else 0,
                "extensions_count": len(client_tls.get("client_hello", {}).get("extensions", [])) if client_tls.get("client_hello") else 0
            },
            "server_tls": {
                "is_tls": server_tls["is_tls"],
                "version": server_tls.get("server_hello", {}).get("version_str") if server_tls.get("server_hello") else None,
                "cipher_code": hex(server_tls.get("server_hello", {}).get("cipher_code", 0)) if server_tls.get("server_hello") else None,
                "cipher_name": server_tls.get("server_hello", {}).get("cipher_name") if server_tls.get("server_hello") else None,
                "cipher_meta": server_tls.get("server_hello", {}).get("cipher_meta") if server_tls.get("server_hello") else {}
            },
            "certificate": parsed_cert,
            "features": features,
            "risk_classification": risk_classification,
            "anomaly_detection": anomaly_detection,
            "posture_score": posture_score
        }

        # 5. NLP Advisory & Hardening Playbooks
        nlp_advisory = generate_nlp_advisory(report)
        report["nlp_advisory"] = nlp_advisory

        # 6. Immutable Blockchain Recording (NIST FIPS 180-4 SHA-512)
        block = self.ledger.append_finding({
            "filename": os.path.basename(pcap_path),
            "score": posture_score["overall_score"],
            "grade": posture_score["overall_grade"],
            "risk": risk_classification["predicted_risk"],
            "ja3_512": client_tls.get("ja3_512"),
            "sha512_cert": parsed_cert.get("sha512_fingerprint") if parsed_cert else None,
            "starttls_downgraded": email_analysis.get("starttls_downgraded")
        }, investigator=investigator)

        report["blockchain_evidence"] = {
            "block_index": block.index,
            "block_hash": block.block_hash,
            "previous_hash": block.previous_hash,
            "merkle_root": block.merkle_root,
            "timestamp": block.timestamp,
            "investigator": block.investigator,
            "hash_algorithm": "NIST FIPS 180-4 (512-bit SHA-512)"
        }

        return report

    def _empty_report(self, pcap_path: str, packet_count: int) -> Dict[str, Any]:
        return {
            "metadata": {
                "filename": os.path.basename(pcap_path),
                "total_packets": packet_count,
                "streams_analyzed": 0
            },
            "posture_score": {"overall_score": 0.0, "overall_grade": "F", "breakdown": {}},
            "risk_classification": {"predicted_risk": "UNKNOWN", "confidence": 0.0, "probabilities": {}},
            "anomaly_detection": {"anomaly_score": 1.0, "is_anomalous": True, "reasons": ["Empty or non-TCP capture"]},
            "nlp_advisory": {"executive_summary": "No active TCP email stream could be reconstructed.", "mitre_mappings": [], "recommendations": []},
            "blockchain_evidence": {}
        }
