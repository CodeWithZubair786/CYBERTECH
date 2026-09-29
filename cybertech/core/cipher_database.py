"""
Authoritative TLS Cipher Suite Database
"""
from typing import Dict, Any

CIPHER_DB: Dict[int, Dict[str, Any]] = {
    0x1301: {"name": "TLS_AES_128_GCM_SHA256", "protocol": "TLS 1.3", "kex": "ECDHE", "enc": "AES-128-GCM", "mac": "AEAD", "pfs": True, "security": "SECURE"},
    0x1302: {"name": "TLS_AES_256_GCM_SHA384", "protocol": "TLS 1.3", "kex": "ECDHE", "enc": "AES-256-GCM", "mac": "AEAD", "pfs": True, "security": "SECURE"},
    0x1303: {"name": "TLS_CHACHA20_POLY1305_SHA256", "protocol": "TLS 1.3", "kex": "ECDHE", "enc": "CHACHA20-POLY1305", "mac": "AEAD", "pfs": True, "security": "SECURE"},
    0xC02F: {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "protocol": "TLS 1.2", "kex": "ECDHE", "enc": "AES-128-GCM", "mac": "AEAD", "pfs": True, "security": "SECURE"},
    0xC030: {"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "protocol": "TLS 1.2", "kex": "ECDHE", "enc": "AES-256-GCM", "mac": "AEAD", "pfs": True, "security": "SECURE"},
    0x009C: {"name": "TLS_RSA_WITH_AES_128_GCM_SHA256", "protocol": "TLS 1.2", "kex": "RSA", "enc": "AES-128-GCM", "mac": "AEAD", "pfs": False, "security": "ACCEPTABLE"},
    0x000A: {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "protocol": "TLS 1.0", "kex": "RSA", "enc": "3DES-CBC", "mac": "SHA1", "pfs": False, "security": "INSECURE", "vulns": ["SWEET32", "CVE-2016-2183"]},
    0x0004: {"name": "TLS_RSA_WITH_RC4_128_MD5", "protocol": "SSL 3.0", "kex": "RSA", "enc": "RC4-128", "mac": "MD5", "pfs": False, "security": "INSECURE", "vulns": ["RC4_BIAS"]},
}

TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}

def lookup_cipher(code: int) -> Dict[str, Any]:
    if code in CIPHER_DB:
        return CIPHER_DB[code]
    return {"name": f"UNKNOWN_CIPHER_0x{code:04X}", "protocol": "UNKNOWN", "kex": "UNKNOWN", "enc": "UNKNOWN", "mac": "UNKNOWN", "pfs": False, "security": "UNKNOWN", "vulns": []}

def format_tls_version(ver: int) -> str:
    return TLS_VERSIONS.get(ver, f"Unknown (0x{ver:04X})")
