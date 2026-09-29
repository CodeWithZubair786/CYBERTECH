"""
Unit tests for cryptographic engine, SHA-512 hashes, and cipher database
"""

import unittest
from cybertech.blockchain.hasher import sha512_hex, MerkleTree512
from cybertech.core.cipher_database import lookup_cipher

class TestCryptoEngine(unittest.TestCase):
    def test_sha512_hasher(self):
        h = sha512_hex("test_input")
        self.assertEqual(len(h), 128)  # 512 bits = 128 hex chars

    def test_merkle_tree(self):
        leaves = [sha512_hex("a"), sha512_hex("b"), sha512_hex("c")]
        tree = MerkleTree512(leaves)
        root = tree.get_merkle_root()
        self.assertEqual(len(root), 128)

    def test_cipher_lookup(self):
        info = lookup_cipher(0x1302)
        self.assertEqual(info["name"], "TLS_AES_256_GCM_SHA384")
        self.assertTrue(info["pfs"])

if __name__ == "__main__":
    unittest.main()
