"""Unit tests for the EvidenceManager module."""

import tempfile
import unittest
from pathlib import Path
from core.evidence_manager import CaseEvidence, EvidenceManager


class TestEvidenceManager(unittest.TestCase):
    """Test evidence directory creation, overwrite prevention, and discovery."""

    def test_generate_case_id(self):
        """Case ID should have the format prefix_YYYYMMDD_HHMMSS."""
        cid = EvidenceManager.generate_case_id("CASE")
        self.assertTrue(cid.startswith("CASE_"))
        self.assertIn("_", cid)

    def test_case_evidence_locate_dump(self):
        """Should find memory.raw or memory_dump.raw in the case directory."""
        with tempfile.TemporaryDirectory() as tmp:
            case_path = Path(tmp) / "CASE_20260930_120000"
            case_path.mkdir()
            dump_file = case_path / "memory.raw"
            dump_file.write_bytes(b"REAL_RAM_DATA")

            case_obj = CaseEvidence(case_path)
            self.assertIsNotNone(case_obj.dump_file)
            self.assertEqual(case_obj.dump_file.name, "memory.raw")

    def test_overwrite_prevention(self):
        """Creating an existing case folder name should safely create a disambiguated unique folder."""
        with tempfile.TemporaryDirectory() as tmp:
            test_id = "CASE_DUPLICATE_TEST"
            folder1 = EvidenceManager.create_case_folder(test_id)
            folder2 = EvidenceManager.create_case_folder(test_id)

            self.assertTrue(folder1.exists())
            self.assertTrue(folder2.exists())
            self.assertNotEqual(folder1.resolve(), folder2.resolve())
            self.assertTrue(folder2.name.startswith(test_id))


if __name__ == "__main__":
    unittest.main()
