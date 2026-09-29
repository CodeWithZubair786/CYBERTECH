"""
Unit tests for PCAP parser and TCP reassembly
"""

import unittest
import os
from cybertech.core.pcap_parser import PcapParser
from cybertech.core.analyzer import CyberTechAnalyzer

class TestPcapParser(unittest.TestCase):
    def test_parse_sample(self):
        sample_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_pcaps", "enterprise_smtps_hardened.pcap")
        parser = PcapParser(sample_path)
        pkts = list(parser.parse_packets())
        self.assertGreater(len(pkts), 0)
        self.assertEqual(pkts[0]["dst_port"], 465)

    def test_full_analysis(self):
        sample_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_pcaps", "enterprise_smtps_hardened.pcap")
        analyzer = CyberTechAnalyzer()
        report = analyzer.analyze_pcap(sample_path)
        self.assertEqual(report["posture_score"]["overall_grade"], "A+")
        self.assertEqual(report["server_tls"]["cipher_name"], "TLS_AES_256_GCM_SHA384")

if __name__ == "__main__":
    unittest.main()
