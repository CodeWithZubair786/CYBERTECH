"""
Generate 5 Realistic Synthetic Libpcap Files for Testing Cyber Tech
Theme: Blockchain & Cybersecurity (Smart India Hackathon)
Zero external dependencies. Writes standard Libpcap binary format.
"""

import os
import struct
import time
import datetime

def write_pcap(filepath, packets):
    # Libpcap global header: magic, major, minor, thiszone, sigfigs, snaplen, network (1 = Ethernet)
    hdr = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    with open(filepath, "wb") as f:
        f.write(hdr)
        for ts, src_ip, src_port, dst_ip, dst_port, seq, ack, flags_byte, payload in packets:
            # Ethernet header (14 bytes)
            eth = b"\x00\x0c\x29\x11\x22\x33\x00\x50\x56\xaa\xbb\xcc\x08\x00"

            # IPv4 header (20 bytes)
            ip_total_len = 20 + 20 + len(payload)
            src_bytes = bytes(map(int, src_ip.split(".")))
            dst_bytes = bytes(map(int, dst_ip.split(".")))
            ip_hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_total_len, 0x1234, 0, 64, 6, 0, src_bytes, dst_bytes)

            # TCP header (20 bytes)
            tcp_hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, 0x50, flags_byte, 65535, 0, 0)

            pkt_bytes = eth + ip_hdr + tcp_hdr + payload
            sec = int(ts)
            usec = int((ts - sec) * 1e6)
            rec_hdr = struct.pack("<IIII", sec, usec, len(pkt_bytes), len(pkt_bytes))
            f.write(rec_hdr + pkt_bytes)

def make_asn1_len(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return struct.pack("!BH", 0x82, length)
    else:
        return struct.pack("!BI", 0x84, length)

def create_synthetic_der_cert(cn, issuer_cn, not_before, not_after, key_bits=2048, is_sha512=True, is_sha1=False):
    def tag_val(tag, val):
        return bytes([tag]) + make_asn1_len(len(val)) + val

    def make_name(attr_cn):
        oid_cn = b"\x06\x03\x55\x04\x03"
        val = attr_cn.encode("utf-8")
        val_item = tag_val(0x0C, val) # UTF8String
        seq = tag_val(0x30, oid_cn + val_item)
        set_item = tag_val(0x31, seq)
        return tag_val(0x30, set_item)

    # Serial
    serial = tag_val(0x02, b"\x01\x23\x45\x67\x89")

    # Algorithm ID
    if is_sha1:
        sig_alg = tag_val(0x30, b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05\x05\x00") # sha1WithRSA
    elif is_sha512:
        sig_alg = tag_val(0x30, b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0d\x05\x00") # sha512WithRSA
    else:
        sig_alg = tag_val(0x30, b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00") # sha256WithRSA

    issuer = make_name(issuer_cn)
    subject = make_name(cn)

    # Validity
    nb_str = not_before.strftime("%y%m%d%H%M%SZ").encode("ascii")
    na_str = not_after.strftime("%y%m%d%H%M%SZ").encode("ascii")
    val_seq = tag_val(0x30, tag_val(0x17, nb_str) + tag_val(0x17, na_str))

    # SubjectPublicKeyInfo
    mod_len = key_bits // 8
    modulus = b"\x00\xb4" + b"\x55" * (mod_len - 1)
    rsa_pub = tag_val(0x30, tag_val(0x02, modulus) + tag_val(0x02, b"\x01\x00\x01"))
    spki = tag_val(0x30, tag_val(0x30, b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00") + tag_val(0x03, b"\x00" + rsa_pub))

    tbs = tag_val(0x30, serial + sig_alg + issuer + val_seq + subject + spki)
    sig_val = tag_val(0x03, b"\x00" + b"\x88" * 256)
    return tag_val(0x30, tbs + sig_alg + sig_val)

def build_tls_records(c_ver, s_ver, cipher_code, cert_der, sni="mail.enterprise.gov", extra_ciphers=None):
    # ClientHello
    ext_sni = b""
    if sni:
        sni_b = sni.encode("utf-8")
        s_data = struct.pack("!HBH", len(sni_b) + 3, 0, len(sni_b)) + sni_b
        ext_sni = struct.pack("!HH", 0, len(s_data)) + s_data

    # Extensions
    exts = ext_sni + struct.pack("!HHH", 10, 4, 2) + b"\x00\x1d" # x25519
    cipher_list = [cipher_code] + (extra_ciphers if extra_ciphers else [])
    ciphers = b"".join(struct.pack("!H", c) for c in cipher_list)
    ch_body = struct.pack("!H", c_ver) + b"\xaa" * 32 + b"\x00" + struct.pack("!H", len(ciphers)) + ciphers + b"\x01\x00" + struct.pack("!H", len(exts)) + exts
    ch_msg = b"\x01" + struct.pack("!I", len(ch_body))[1:] + ch_body
    client_rec = b"\x16" + struct.pack("!HH", c_ver, len(ch_msg)) + ch_msg

    # ServerHello
    sh_body = struct.pack("!H", s_ver) + b"\xbb" * 32 + b"\x00" + struct.pack("!H", cipher_code) + b"\x00"
    if s_ver == 0x0304: # TLS 1.3 supported_versions
        ext_sv = struct.pack("!HHH", 43, 2, 0x0304)
        sh_body += struct.pack("!H", len(ext_sv)) + ext_sv
    sh_msg = b"\x02" + struct.pack("!I", len(sh_body))[1:] + sh_body
    server_rec = b"\x16" + struct.pack("!HH", s_ver, len(sh_msg)) + sh_msg

    # Certificate record
    if cert_der:
        cert_data = struct.pack("!I", len(cert_der))[1:] + cert_der
        certs_msg = b"\x0b" + struct.pack("!I", len(cert_data) + 3)[1:] + struct.pack("!I", len(cert_data))[1:] + cert_data
        server_rec += b"\x16" + struct.pack("!HH", s_ver, len(certs_msg)) + certs_msg

    return client_rec, server_rec

def generate_samples(target_dir):
    os.makedirs(target_dir, exist_ok=True)
    base_t = time.time() - 3600
    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. enterprise_smtps_hardened.pcap
    cert1 = create_synthetic_der_cert("mail.cybertech.gov.in", "CyberTech National Root CA", now - datetime.timedelta(days=30), now + datetime.timedelta(days=700), key_bits=4096, is_sha512=True)
    c_rec1, s_rec1 = build_tls_records(0x0303, 0x0304, 0x1302, cert1, sni="mail.cybertech.gov.in", extra_ciphers=[0x1301, 0x1303, 0xC02F, 0xC030])
    pkts1 = [
        (base_t, "192.168.1.50", 49152, "10.0.0.25", 465, 100, 0, 0x02, b""), # SYN
        (base_t + 0.01, "10.0.0.25", 465, "192.168.1.50", 49152, 500, 101, 0x12, b""), # SYN-ACK
        (base_t + 0.02, "192.168.1.50", 49152, "10.0.0.25", 465, 101, 501, 0x10, b""), # ACK
        (base_t + 0.03, "192.168.1.50", 49152, "10.0.0.25", 465, 101, 501, 0x18, c_rec1),
        (base_t + 0.05, "10.0.0.25", 465, "192.168.1.50", 49152, 501, 101 + len(c_rec1), 0x18, s_rec1)
    ]
    write_pcap(os.path.join(target_dir, "enterprise_smtps_hardened.pcap"), pkts1)

    # 2. mitm_starttls_stripping_attack.pcap
    s_banner = b"220 mail.insecure.corp ESMTP Service Ready\r\n"
    c_ehlo = b"EHLO client.internal.lan\r\n"
    s_ehlo_stripped = b"250-mail.insecure.corp\r\n250-PIPELINING\r\n250-SIZE 20480000\r\n250 8BITMIME\r\n" # STARTTLS stripped by MITM
    c_auth = b"AUTH LOGIN\r\n"
    s_auth_user = b"334 VXNlcm5hbWU6\r\n"
    c_user_cred = b"YWRtaW5AY3liZXJ0ZWNoLmdvdg==\r\n" # admin@cybertech.gov
    s_auth_pass = b"334 UGFzc3dvcmQ6\r\n"
    c_pass_cred = b"U3VwZXJTZWNyZXQyMDI2IQ==\r\n" # SuperSecret2026!
    s_auth_ok = b"235 2.7.0 Authentication successful\r\n"

    pkts2 = [
        (base_t, "192.168.1.60", 49153, "10.0.0.26", 25, 200, 0, 0x02, b""),
        (base_t + 0.01, "10.0.0.26", 25, "192.168.1.60", 49153, 600, 201, 0x12, b""),
        (base_t + 0.02, "192.168.1.60", 49153, "10.0.0.26", 25, 201, 601, 0x10, b""),
        (base_t + 0.03, "10.0.0.26", 25, "192.168.1.60", 49153, 601, 201, 0x18, s_banner),
        (base_t + 0.04, "192.168.1.60", 49153, "10.0.0.26", 25, 201, 601 + len(s_banner), 0x18, c_ehlo),
        (base_t + 0.05, "10.0.0.26", 25, "192.168.1.60", 49153, 601 + len(s_banner), 201 + len(c_ehlo), 0x18, s_ehlo_stripped),
        (base_t + 0.06, "192.168.1.60", 49153, "10.0.0.26", 25, 201 + len(c_ehlo), 601 + len(s_banner) + len(s_ehlo_stripped), 0x18, c_auth + c_user_cred + c_pass_cred),
        (base_t + 0.07, "10.0.0.26", 25, "192.168.1.60", 49153, 700, 300, 0x18, s_auth_ok)
    ]
    write_pcap(os.path.join(target_dir, "mitm_starttls_stripping_attack.pcap"), pkts2)

    # 3. legacy_pop3_sweet32_vuln.pcap (TLS 1.0, 3DES, Sweet32)
    cert3 = create_synthetic_der_cert("pop.legacy-server.net", "Legacy CA", now - datetime.timedelta(days=100), now + datetime.timedelta(days=200), key_bits=1024, is_sha1=True)
    c_rec3, s_rec3 = build_tls_records(0x0301, 0x0301, 0x000A, cert3, sni="pop.legacy-server.net") # 0x000A is 3DES
    pkts3 = [
        (base_t, "192.168.1.70", 49154, "10.0.0.27", 995, 300, 0, 0x02, b""),
        (base_t + 0.01, "10.0.0.27", 995, "192.168.1.70", 49154, 700, 301, 0x12, b""),
        (base_t + 0.02, "192.168.1.70", 49154, "10.0.0.27", 995, 301, 701, 0x10, b""),
        (base_t + 0.03, "192.168.1.70", 49154, "10.0.0.27", 995, 301, 701, 0x18, c_rec3),
        (base_t + 0.05, "10.0.0.27", 995, "192.168.1.70", 49154, 701, 301 + len(c_rec3), 0x18, s_rec3)
    ]
    write_pcap(os.path.join(target_dir, "legacy_pop3_sweet32_vuln.pcap"), pkts3)

    # 4. imaps_expired_selfsigned_cert.pcap
    cert4 = create_synthetic_der_cert("mail.self-signed.local", "mail.self-signed.local", now - datetime.timedelta(days=400), now - datetime.timedelta(days=35), key_bits=2048, is_sha512=False)
    c_rec4, s_rec4 = build_tls_records(0x0303, 0x0303, 0x009C, cert4, sni="mail.self-signed.local") # Static RSA (No PFS)
    pkts4 = [
        (base_t, "192.168.1.80", 49155, "10.0.0.28", 993, 400, 0, 0x02, b""),
        (base_t + 0.01, "10.0.0.28", 993, "192.168.1.80", 49155, 800, 401, 0x12, b""),
        (base_t + 0.02, "192.168.1.80", 49155, "10.0.0.28", 993, 401, 801, 0x10, b""),
        (base_t + 0.03, "192.168.1.80", 49155, "10.0.0.28", 993, 401, 801, 0x18, c_rec4),
        (base_t + 0.05, "10.0.0.28", 993, "192.168.1.80", 49155, 801, 401 + len(c_rec4), 0x18, s_rec4)
    ]
    write_pcap(os.path.join(target_dir, "imaps_expired_selfsigned_cert.pcap"), pkts4)

    # 5. shadow_c2_email_anomaly.pcap (RC4, No SNI, 1 cipher)
    c_rec5, s_rec5 = build_tls_records(0x0303, 0x0303, 0x0004, None, sni=None) # 0x0004 = RC4-128-MD5
    pkts5 = [
        (base_t, "192.168.1.99", 49156, "45.33.32.156", 587, 500, 0, 0x02, b""),
        (base_t + 0.01, "45.33.32.156", 587, "192.168.1.99", 49156, 900, 501, 0x12, b""),
        (base_t + 0.02, "192.168.1.99", 49156, "45.33.32.156", 587, 501, 901, 0x10, b""),
        (base_t + 0.03, "192.168.1.99", 49156, "45.33.32.156", 587, 501, 901, 0x18, c_rec5),
        (base_t + 0.05, "45.33.32.156", 587, "192.168.1.99", 49156, 901, 501 + len(c_rec5), 0x18, s_rec5)
    ]
    write_pcap(os.path.join(target_dir, "shadow_c2_email_anomaly.pcap"), pkts5)

    print(f"[+] Successfully generated 5 synthetic PCAPs in {target_dir}")

if __name__ == "__main__":
    generate_samples("sample_pcaps")
