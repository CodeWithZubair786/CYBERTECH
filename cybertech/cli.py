"""
Cyber Tech - Interactive Terminal CLI
Theme: Blockchain & Cybersecurity (Smart India Hackathon)
"""

import sys
import os
import json
from .core.analyzer import CyberTechAnalyzer

def main():
    if len(sys.argv) < 2:
        print("\033[96m========================================================================\033[0m")
        print("\033[92m                  CYBER TECH FORENSIC CLI                               \033[0m")
        print("\033[93m  AI-Assisted Cryptographic Security Posture Assessment for Email       \033[0m")
        print("\033[96m========================================================================\033[0m")
        print("\nUsage: python -m cybertech.cli <path_to_pcap>")
        print("Example: python -m cybertech.cli sample_pcaps/enterprise_smtps_hardened.pcap\n")
        sys.exit(1)

    pcap_path = sys.argv[1]
    if not os.path.exists(pcap_path):
        print(f"\033[91m[-] Error: File not found: {pcap_path}\033[0m")
        sys.exit(1)

    print(f"\033[94m[*] Ingesting and dissecting PCAP: {pcap_path}...\033[0m")
    analyzer = CyberTechAnalyzer()
    report = analyzer.analyze_pcap(pcap_path, investigator="Terminal-CLI-Analyst")

    score = report["posture_score"]
    risk = report["risk_classification"]
    advisory = report["nlp_advisory"]
    bchain = report["blockchain_evidence"]
    meta = report["metadata"]

    grade = score["overall_grade"]
    color = "\033[92m" if grade in ("A+", "A") else ("\033[93m" if grade in ("B", "C") else "\033[91m")

    print("\n" + "=" * 70)
    print(f"{color}>>> POSTURE SCORE: {score['overall_score']}/100 | GRADE: {grade} | RISK: {risk['predicted_risk']}\033[0m")
    print("=" * 70)
    print(f"Packets Analyzed: {meta['total_packets']} | Duration: {meta['duration_seconds']}s")
    print(f"Negotiated Protocol: {report['email_analysis']['protocol']}")
    print(f"STARTTLS Downgraded: {report['email_analysis']['starttls_downgraded']}")
    print(f"Selected Cipher: {report['server_tls'].get('cipher_name')}")
    print(f"JA3-512 Hash: {report['client_tls'].get('ja3_512')}")
    print(f"Blockchain Block Index: #{bchain.get('block_index')} | Hash: {bchain.get('block_hash')}")
    print("\n\033[96m--- Executive Advisory ---\033[0m")
    print(advisory["executive_summary"])
    print("\n\033[92m[+] Forensic audit completed successfully.\033[0m\n")

if __name__ == "__main__":
    main()
