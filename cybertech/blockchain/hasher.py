"""
NIST FIPS 180-4 SHA-512 Cryptographic Hasher & Binary Merkle Tree Engine
"""
import hashlib
from typing import List, Union

def sha512_hex(data: Union[bytes, str]) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha512(data).hexdigest()

def sha512_digest(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()

class MerkleTree512:
    def __init__(self, leaves: List[str]):
        self.leaves = leaves if leaves else [sha512_hex(b"EMPTY_LEAF")]
        self.root = self._build_tree(self.leaves)

    def _build_tree(self, current_level: List[str]) -> str:
        if len(current_level) == 1:
            return current_level[0]
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i+1] if i + 1 < len(current_level) else left
            combined = bytes.fromhex(left) + bytes.fromhex(right)
            parent_hash = sha512_hex(combined)
            next_level.append(parent_hash)
        return self._build_tree(next_level)

    def get_merkle_root(self) -> str:
        return self.root
