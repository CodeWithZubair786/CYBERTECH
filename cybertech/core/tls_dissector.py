"""
Deep TLS Dissector & JA3-512 Fingerprinter
"""
import struct
import hashlib
from typing import Dict, Any, List
from .cipher_database import lookup_cipher, format_tls_version

class TLSDissector:
    def dissect_client_traffic(self, data: bytes) -> Dict[str, Any]:
        res = {"is_tls": False, "client_hello": None, "ja3_string": None, "ja3_hash": None, "ja3_512": None}
        idx = data.find(b"\x16\x03")
        if idx == -1 or len(data[idx:]) < 5: return res
        data = data[idx:]
        res["is_tls"] = True
        rec_ver, rec_len = struct.unpack("!xHH", data[:5])
        payload = data[5:5+rec_len]
        if len(payload) >= 4 and payload[0] == 1: # ClientHello
            ch = self._parse_client_hello(payload[4:])
            if ch:
                res["client_hello"] = ch
                ja3_str = f"{ch['version']},{'-'.join(map(str, ch['cipher_suites']))},{'-'.join(map(str, ch['extensions']))},{'-'.join(map(str, ch['supported_groups']))},{'-'.join(map(str, ch['ec_formats']))}"
                res["ja3_string"] = ja3_str
                res["ja3_hash"] = hashlib.md5(ja3_str.encode()).hexdigest()
                res["ja3_512"] = hashlib.sha512(ja3_str.encode()).hexdigest()
        return res

    def dissect_server_traffic(self, data: bytes) -> Dict[str, Any]:
        res = {"is_tls": False, "server_hello": None, "raw_certificates": []}
        idx = 0
        while idx + 5 <= len(data):
            rec_type = data[idx]
            rec_ver, rec_len = struct.unpack("!xHH", data[idx:idx+5])
            if rec_type != 22: # Handshake
                idx += 1; continue
            res["is_tls"] = True
            payload = data[idx+5:idx+5+rec_len]
            idx += 5 + rec_len
            p = 0
            while p + 4 <= len(payload):
                m_type = payload[p]
                m_len = (payload[p+1] << 16) | (payload[p+2] << 8) | payload[p+3]
                body = payload[p+4:p+4+m_len]
                p += 4 + m_len
                if m_type == 2: # ServerHello
                    res["server_hello"] = self._parse_server_hello(body)
                elif m_type == 11 and len(body) >= 3: # Certificate
                    total_c = (body[0] << 16) | (body[1] << 8) | body[2]
                    cp = 3
                    while cp + 3 <= min(len(body), 3 + total_c):
                        clen = (body[cp] << 16) | (body[cp+1] << 8) | body[cp+2]
                        cp += 3
                        if cp + clen <= len(body): res["raw_certificates"].append(body[cp:cp+clen])
                        cp += clen
        return res

    def _parse_client_hello(self, body: bytes):
        if len(body) < 34: return None
        c_ver = struct.unpack("!H", body[:2])[0]
        pos = 34 + 1 + body[34] # skip random and session_id
        if pos + 2 > len(body): return None
        cs_len = struct.unpack("!H", body[pos:pos+2])[0]
        pos += 2
        ciphers = [struct.unpack("!H", body[pos+i:pos+i+2])[0] for i in range(0, cs_len, 2) if pos+i+2 <= len(body)]
        pos += cs_len
        if pos >= len(body): return None
        pos += 1 + body[pos] # skip compression
        extensions, supported_groups, ec_formats, sni = [], [], [], None
        if pos + 2 <= len(body):
            ext_len = struct.unpack("!H", body[pos:pos+2])[0]
            pos += 2
            end = pos + ext_len
            while pos + 4 <= end and pos + 4 <= len(body):
                etype, elen = struct.unpack("!HH", body[pos:pos+4])
                pos += 4
                edata = body[pos:pos+elen]
                pos += elen
                extensions.append(etype)
                if etype == 0 and len(edata) >= 5: # SNI
                    slen = struct.unpack("!H", edata[3:5])[0]
                    sni = edata[5:5+slen].decode("utf-8", errors="ignore")
                elif etype == 10 and len(edata) >= 2:
                    glen = struct.unpack("!H", edata[:2])[0]
                    supported_groups = [struct.unpack("!H", edata[2+j:4+j])[0] for j in range(0, glen, 2) if 4+j <= len(edata)]
                elif etype == 11 and len(edata) >= 1:
                    ec_formats = list(edata[1:1+edata[0]])
        return {"version": c_ver, "version_str": format_tls_version(c_ver), "cipher_suites": ciphers, "extensions": extensions, "supported_groups": supported_groups, "ec_formats": ec_formats, "sni": sni}

    def _parse_server_hello(self, body: bytes):
        if len(body) < 38: return None
        s_ver = struct.unpack("!H", body[:2])[0]
        pos = 34 + 1 + body[34]
        if pos + 2 > len(body): return None
        cs = struct.unpack("!H", body[pos:pos+2])[0]
        sel_ver = s_ver
        pos += 3
        if pos + 2 <= len(body):
            ext_len = struct.unpack("!H", body[pos:pos+2])[0]
            pos += 2
            end = pos + ext_len
            while pos + 4 <= end and pos + 4 <= len(body):
                etype, elen = struct.unpack("!HH", body[pos:pos+4])
                pos += 4
                edata = body[pos:pos+elen]
                pos += elen
                if etype == 43 and len(edata) >= 2: sel_ver = struct.unpack("!H", edata[:2])[0]
        meta = lookup_cipher(cs)
        return {"version": sel_ver, "version_str": format_tls_version(sel_ver), "cipher_code": cs, "cipher_name": meta["name"], "cipher_meta": meta}
