"""Unit tests for validation utilities."""

import tempfile
import unittest
from pathlib import Path
from utils.validators import (
    sanitize_filename,
    validate_directory_exists,
    validate_file_exists,
)


class TestValidators(unittest.TestCase):
    """Test file, directory, and sanitization validators."""

    def test_validate_file_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            valid_file = Path(tmp) / "valid.bin"
            valid_file.write_bytes(b"DATA")

            ok, _ = validate_file_exists(valid_file)
            self.assertTrue(ok)

            empty_file = Path(tmp) / "empty.bin"
            empty_file.write_bytes(b"")
            bad_empty, _ = validate_file_exists(empty_file)
            self.assertFalse(bad_empty)

            bad_missing, _ = validate_file_exists(Path(tmp) / "missing.bin")
            self.assertFalse(bad_missing)

    def test_sanitize_filename(self):
        dirty = "../../malicious/path;*&.raw"
        clean = sanitize_filename(dirty)
        self.assertNotIn("..", clean)
        self.assertNotIn("/", clean)
        self.assertNotIn(";", clean)


if __name__ == "__main__":
    unittest.main()
