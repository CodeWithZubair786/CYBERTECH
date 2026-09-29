"""
Unit tests for cryptographic blockchain ledger
"""

import unittest
from cybertech.blockchain.ledger import ForensicLedger

class TestBlockchainLedger(unittest.TestCase):
    def test_ledger_creation_and_integrity(self):
        ledger = ForensicLedger()
        self.assertEqual(len(ledger.chain), 1)
        self.assertEqual(ledger.chain[0].index, 0)

        ledger.append_finding({"finding": "test_record_1"}, investigator="Analyst-1")
        ledger.append_finding({"finding": "test_record_2"}, investigator="Analyst-2")

        self.assertEqual(len(ledger.chain), 3)
        res = ledger.verify_integrity()
        self.assertTrue(res["valid"])
        self.assertEqual(res["chain_length"], 3)

if __name__ == "__main__":
    unittest.main()
