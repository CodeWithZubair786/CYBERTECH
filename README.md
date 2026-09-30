# Cyber Tech
### AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications

**Theme:** Blockchain & Cybersecurity  
**Problem Statement:** Passive Network Forensic Framework for SMTP, IMAP, and POP3 Cryptographic Assessment  
**Standards:** NIST FIPS 180-4 (SHA-512), RFC 8461 (MTA-STS), RFC 7672 (DANE), RFC 8446 (TLS 1.3), Section 65B Indian Evidence Act  

---

## 🛡️ Executive Summary & Prototype Significance

**Cyber Tech** is an autonomous passive network forensic intelligence platform that evaluates the cryptographic security posture of enterprise, government, and financial electronic mail infrastructures.

Traditional security monitoring tools decode packet flows, but fail to detect opportunistic TLS downgrades, weak cipher negotiations, or anomalous covert tunnels. When a Man-in-the-Middle (MITM) adversary strips `250-STARTTLS` announcements, mail servers silently drop back to unencrypted cleartext transmission.

Cyber Tech resolves this critical blind spot:
- **Zero-Touch Passive Ingestion:** Operates entirely out-of-band via PCAP/PCAPNG network taps with zero impact on production mail transfer agents (MTAs).
- **Zero Privacy Violation:** Inspects cryptographic metadata (handshake parameters, ciphers, X.509 chains) without requiring private keys or reading email contents.
- **Section 65B Admissible Chain of Custody:** Anchors every forensic finding into an immutable 512-bit SHA-512 Merkle blockchain ledger.
- **Actionable AI & NLP Remediation:** Translates packet-level findings into automated Postfix and Dovecot hardening rules.

---

## ⚡ Key Architectural Features

1. **Pure-Python Stream Engine:** Reassembles bidirectional TCP streams across SMTP, IMAP, and POP3 without external C-libraries (libpcap/dpkt/scapy).
2. **Protocol State Machine & Downgrade Detection:** Detects active STARTTLS stripping attacks, plaintext credential theft (`AUTH LOGIN`), and invalid state transitions.
3. **Deep TLS Dissection & JA3-512:** Inspects ClientHello and ServerHello records, matches 350+ IANA ciphers, tests for Perfect Forward Secrecy (PFS), and computes 512-bit SHA-512 JA3 hashes.
4. **ASN.1 DER X.509 Certificate Engine:** Evaluates public key bit length (RSA 2048/4096, ECC), certificate validity, and weak signature hashes (SHA-1/MD5).
5. **Multi-Factor Posture Scoring (0–100):** Calculates an objective score and assigns grades from **A+** down to **F**.
6. **Dual AI/ML Engine:** Houses a 5-class supervised ensemble risk classifier and an unsupervised Isolation Forest model for zero-day anomaly detection.
7. **Automated NLP Playbooks:** Generates executive briefs, MITRE ATT&CK enterprise threat mappings, and hardened server configurations.

---
## 🚀 Quick Start & Local Execution

