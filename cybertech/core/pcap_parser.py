"""
Pure-Python PCAP & PCAPNG Parser
"""
import struct
from typing import Iterator, Dict, Any, Optional

LINKTYPE_ETHERNET = 1

class PcapParser:
    def __init__(self, filepath: str):
        self.filepath = filepath

    def parse_packets(self) -> Iterator[Dict[str, Any]]:
        with open(self.filepath, "rb") as f:
            magic = f.read(4)
            if not magic or len(magic) < 4:
                return
            if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
                endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
                hdr_data = f.read(20)
                if len(hdr_data) < 20: return
                packet_index = 0
                while True:
                    rec_hdr = f.read(16)
                    if len(rec_hdr) < 16: break
                    packet_index += 1
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", rec_hdr)
                    pkt_data = f.read(incl_len)
                    if len(pkt_data) < incl_len: break
                    timestamp = float(ts_sec) + float(ts_usec) / 1e6
                    parsed = self._dissect_packet(pkt_data, timestamp, packet_index)
                    if parsed: yield parsed

    def _dissect_packet(self, data: bytes, timestamp: float, index: int) -> Optional[Dict[str, Any]]:
        if len(data) < 14: return None
        eth_proto = struct.unpack("!H", data[12:14])[0]
        ip_data = data[14:] if eth_proto == 0x0800 else None
        if not ip_data or len(ip_data) < 20: return None
        
        ihl = (ip_data[0] & 0x0F) * 4
        protocol = ip_data[9]
        if protocol != 6: return None # TCP only
        total_len = struct.unpack("!H", ip_data[2:4])[0]
        src_ip = ".".join(map(str, ip_data[12:16]))
        dst_ip = ".".join(map(str, ip_data[16:20]))
        tcp_data = ip_data[ihl:total_len]
        if len(tcp_data) < 20: return None

        src_port, dst_port, seq, ack, offset_flags = struct.unpack("!HHIIH", tcp_data[:14])
        data_offset = (offset_flags >> 12) * 4
        payload = tcp_data[data_offset:]
        return {
            "index": index,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "seq": seq,
            "ack": ack,
            "payload": payload,
            "stream_key": tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))
        }
