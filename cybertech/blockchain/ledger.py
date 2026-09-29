"""
Cryptographic Blockchain Audit Ledger
"""
import time
import json
from typing import List, Dict, Any
from .hasher import sha512_hex, MerkleTree512

class ForensicBlock:
    def __init__(self, index: int, previous_hash: str, findings: List[Dict[str, Any]], investigator: str = "Automated-Engine"):
        self.index = index
        self.timestamp = time.time()
        self.previous_hash = previous_hash
        self.investigator = investigator
        self.findings = findings
        finding_hashes = [sha512_hex(json.dumps(f, sort_keys=True)) for f in findings]
        tree = MerkleTree512(finding_hashes)
        self.merkle_root = tree.get_merkle_root()
        self.block_hash = self.compute_hash()

    def compute_hash(self) -> str:
        header = f"{self.index}:{self.timestamp}:{self.previous_hash}:{self.merkle_root}:{self.investigator}"
        return sha512_hex(header)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "investigator": self.investigator,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "block_hash": self.block_hash
        }

class ForensicLedger:
    def __init__(self):
        self.chain: List[ForensicBlock] = []
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis_finding = [{
            "event": "CYBER_TECH_GENESIS",
            "standard": "NIST FIPS 180-4 (SHA-512)",
            "compliance": "Section 65B Indian Evidence Act Forensic Custody"
        }]
        genesis = ForensicBlock(0, "0" * 128, genesis_finding, investigator="System-Root")
        self.chain.append(genesis)

    def append_finding(self, finding: Dict[str, Any], investigator: str = "Forensic-Analyst") -> ForensicBlock:
        last_block = self.chain[-1]
        new_block = ForensicBlock(len(self.chain), last_block.block_hash, [finding], investigator=investigator)
        self.chain.append(new_block)
        return new_block

    def verify_integrity(self) -> Dict[str, Any]:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i-1]
            if current.previous_hash != prev.block_hash:
                return {"valid": False, "error": f"Chain broken at block {i}", "broken_block_index": i}
            if current.compute_hash() != current.block_hash:
                return {"valid": False, "error": f"Block {i} tampered", "broken_block_index": i}
        return {"valid": True, "chain_length": len(self.chain), "latest_block_hash": self.chain[-1].block_hash, "algorithm": "NIST FIPS 180-4 (SHA-512)"}

    def to_list(self) -> List[Dict[str, Any]]:
        return [b.to_dict() for b in self.chain]
