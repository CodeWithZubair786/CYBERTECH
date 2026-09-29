"""
TCP Stream Reassembly Engine
"""
from typing import Dict, Tuple, List, Any

class DirectionalStream:
    def __init__(self, src, dst):
        self.src = src
        self.dst = dst
        self.chunks = []

    def add(self, seq, payload, ts):
        if payload: self.chunks.append((seq, payload, ts))

    def assemble(self):
        if not self.chunks: return bytes()
        self.chunks.sort(key=lambda x: x[0])
        buf = bytearray()
        last_seq = None
        for seq, payload, ts in self.chunks:
            if last_seq is None:
                buf.extend(payload)
                last_seq = seq + len(payload)
            else:
                if seq < last_seq:
                    overlap = last_seq - seq
                    if overlap < len(payload):
                        buf.extend(payload[overlap:])
                        last_seq = seq + len(payload)
                else:
                    buf.extend(payload)
                    last_seq = seq + len(payload)
        return bytes(buf)

class TCPReassembler:
    def __init__(self):
        self.streams = {}

    def process_packet(self, pkt):
        key = pkt["stream_key"]
        src = (pkt["src_ip"], pkt["src_port"])
        dst = (pkt["dst_ip"], pkt["dst_port"])
        if key not in self.streams:
            self.streams[key] = {
                "client_endpoint": src,
                "server_endpoint": dst,
                "c2s": DirectionalStream(src, dst),
                "s2c": DirectionalStream(dst, src),
                "packets_count": 0,
                "start_time": pkt["timestamp"],
                "end_time": pkt["timestamp"]
            }
        st = self.streams[key]
        st["packets_count"] += 1
        st["end_time"] = pkt["timestamp"]
        if src == st["client_endpoint"]:
            st["c2s"].add(pkt["seq"], pkt["payload"], pkt["timestamp"])
        else:
            st["s2c"].add(pkt["seq"], pkt["payload"], pkt["timestamp"])

    def get_reassembled_streams(self):
        for k, v in self.streams.items():
            v["c2s_payload"] = v["c2s"].assemble()
            v["s2c_payload"] = v["s2c"].assemble()
            v["duration"] = v["end_time"] - v["start_time"]
        return self.streams
