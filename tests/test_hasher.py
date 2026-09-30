"""Unit tests for the Hasher module."""

import tempfile
import unittest
from pathlib import Path
from core.hasher import Hasher


class TestHasher(unittest.TestCase):
    """Test cryptographic SHA-256 computation and integrity checks."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_same_file_same_sha256(self):
        """Identical content must always yield the exact same SHA-256 hash."""
        f1 = self.base_path / "test1.raw"
        f2 = self.base_path / "test2.raw"
        content = b"FORENSIC_RAM_EVIDENCE_SAMPLE_BYTES_12345"
        f1.write_bytes(content)
        f2.write_bytes(content)

        hash1 = Hasher.calculate_sha256(f1)
        hash2 = Hasher.calculate_sha256(f2)

        self.assertEqual(hash1, hash2)
        self.assertEqual(len(hash1), 64)

    def test_modified_file_different_sha256(self):
        """Modifying even a single byte must produce a completely different hash (avalanche effect)."""
        f = self.base_path / "evidence.raw"
        f.write_bytes(b"ORIGINAL_EVIDENCE_DATA")
        hash_orig = Hasher.calculate_sha256(f)

        f.write_bytes(b"TAMPERED_EVIDENCE_DATA")
        hash_mod = Hasher.calculate_sha256(f)

        self.assertNotEqual(hash_orig, hash_mod)

    def test_verify_integrity_valid(self):
        """Integrity check should return VALID when file is unchanged."""
        f = self.base_path / "case.raw"
        f.write_bytes(b"SECURE_MEMORY_RECORD")
        digest = Hasher.calculate_sha256(f)

        status, cur, exp = Hasher.verify_integrity(f, digest)
        self.assertEqual(status, "VALID")
        self.assertEqual(cur, exp)

    def test_verify_integrity_modified(self):
        """Integrity check should return MODIFIED when file has been tampered."""
        f = self.base_path / "case.raw"
        f.write_bytes(b"INITIAL_RECORD")
        digest = Hasher.calculate_sha256(f)

        # Alter file
        f.write_bytes(b"CORRUPTED_RECORD")
        status, cur, exp = Hasher.verify_integrity(f, digest)
        self.assertEqual(status, "MODIFIED")
        self.assertNotEqual(cur, exp)

    def test_save_and_read_stored_hash(self):
        """Saving and loading hash.txt should preserve accurate hash string."""
        f = self.base_path / "data.bin"
        h_file = self.base_path / "hash.txt"
        f.write_bytes(b"DUMP_CONTENT")

        calc_hash = Hasher.save_hash_file(f, h_file)
        read_hash = Hasher.read_stored_hash(h_file)

        self.assertEqual(calc_hash, read_hash)


if __name__ == "__main__":
    unittest.main()
