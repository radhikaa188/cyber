"""Unit tests for the ChainOfCustody module."""

import tempfile
import unittest
from pathlib import Path
from core.chain_of_custody import ChainOfCustody


class TestChainOfCustody(unittest.TestCase):
    """Test chain-of-custody event logging and formatting."""

    def test_add_and_retrieve_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "CASE_001"
            case_dir.mkdir()

            coc = ChainOfCustody(case_dir)
            ev1 = coc.add_event(
                event_type="MEMORY_ACQUIRED",
                evidence_id="EVD_001",
                description="Acquisition completed.",
                status="SUCCESS",
            )
            self.assertEqual(ev1["event_id"], "EVT-001")
            self.assertEqual(ev1["event"], "MEMORY_ACQUIRED")

            ev2 = coc.add_event(
                event_type="HASH_GENERATED",
                evidence_id="EVD_001",
                description="SHA-256 seal computed.",
                status="SUCCESS",
                details={"sha256": "abc123"},
            )
            self.assertEqual(ev2["event_id"], "EVT-002")

            # Reload from disk
            coc2 = ChainOfCustody(case_dir)
            events = coc2.get_events()
            self.assertEqual(len(events), 2)
            self.assertEqual(events[1]["event_id"], "EVT-002")

            summary = coc2.get_summary_text()
            self.assertIn("EVT-001", summary)
            self.assertIn("MEMORY_ACQUIRED", summary)


if __name__ == "__main__":
    unittest.main()
