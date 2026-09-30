"""Unit tests for Evidence Integrity and Protection."""

import os
import stat
import tempfile
import unittest
from pathlib import Path
from core.evidence_integrity import EvidenceIntegrity
from core.hasher import Hasher


class TestEvidenceIntegrity(unittest.TestCase):
    """Test manifest creation, working copy separation, and integrity verification."""

    def test_evidence_manifest_creation_and_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "CASE_100"
            case_dir.mkdir()

            manifest = EvidenceIntegrity.create_evidence_manifest(
                case_dir=case_dir,
                case_id="CASE_100",
                evidence_id="EVD_100",
                original_filename="memory.raw",
                acquisition_start="2026-09-30T22:00:00",
                acquisition_end="2026-09-30T22:01:00",
                file_size=1048576,
                sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                operating_system="Windows",
                architecture="x86_64",
                acquisition_method="WinPmem",
                acquisition_status="SUCCESS",
                acquisition_mode="REAL",
            )

            loaded = EvidenceIntegrity.load_manifest(case_dir)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["case_id"], "CASE_100")
            self.assertEqual(loaded["acquisition_mode"], "REAL")

    def test_working_copy_separation(self):
        with tempfile.TemporaryDirectory() as tmp:
            orig_dir = Path(tmp) / "orig"
            orig_dir.mkdir()
            dump_file = orig_dir / "memory.raw"
            dump_file.write_bytes(b"ORIGINAL_SACRED_EVIDENCE")

            ok, working_path, _ = EvidenceIntegrity.create_analysis_working_copy(dump_file, "CASE_TEST")
            self.assertTrue(ok)
            self.assertTrue(working_path.exists())
            self.assertNotEqual(dump_file.resolve(), working_path.resolve())

            # Verify original content unchanged
            self.assertEqual(dump_file.read_bytes(), b"ORIGINAL_SACRED_EVIDENCE")

    def test_verify_case_integrity_verified_vs_tampered(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "CASE_TAMPER_TEST"
            case_dir.mkdir()
            dump_file = case_dir / "memory.raw"
            dump_file.write_bytes(b"INITIAL_EVIDENCE_STREAM")
            initial_hash = Hasher.calculate_sha256(dump_file)

            EvidenceIntegrity.create_evidence_manifest(
                case_dir=case_dir,
                case_id="CASE_TAMPER_TEST",
                evidence_id="EVD_TAMPER_TEST",
                original_filename="memory.raw",
                acquisition_start="2026-09-30T22:00:00",
                acquisition_end="2026-09-30T22:00:10",
                file_size=len(b"INITIAL_EVIDENCE_STREAM"),
                sha256_hash=initial_hash,
                operating_system="Windows",
                architecture="x86_64",
                acquisition_method="Test",
                acquisition_status="SUCCESS",
            )

            # Check 1: Pristine state -> INTEGRITY VERIFIED
            status1, cur1, exp1, _ = EvidenceIntegrity.verify_case_integrity(case_dir)
            self.assertEqual(status1, "INTEGRITY VERIFIED")
            self.assertEqual(cur1, exp1)

            # Check 2: Tampered state -> TAMPERING DETECTED
            os.chmod(dump_file, stat.S_IWRITE | stat.S_IREAD)
            dump_file.write_bytes(b"CORRUPTED_TAMPERED_STREAM")

            status2, cur2, exp2, _ = EvidenceIntegrity.verify_case_integrity(case_dir)
            self.assertEqual(status2, "TAMPERING DETECTED")
            self.assertNotEqual(cur2, exp2)


if __name__ == "__main__":
    unittest.main()
