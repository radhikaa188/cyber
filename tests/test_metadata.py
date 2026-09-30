"""Unit tests for the Metadata module."""

import tempfile
import unittest
from pathlib import Path
from core.metadata import CaseMetadata


class TestMetadata(unittest.TestCase):
    """Test metadata record creation, serialization, and deserialization."""

    def test_metadata_roundtrip(self):
        """Metadata serialized to JSON must deserialize accurately."""
        with tempfile.TemporaryDirectory() as tmp:
            meta_path = Path(tmp) / "metadata.json"
            
            record = CaseMetadata.create_metadata_record(
                case_id="case_20260930_193000",
                os_name="Windows",
                architecture="x86_64",
                python_version="3.14.0",
                dump_file_name="memory_dump.raw",
                dump_size_bytes=1048576,
                sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                acquisition_status="SUCCESS",
                acquisition_mode="DEMO",
                acquisition_start="2026-09-30T19:30:00",
                acquisition_end="2026-09-30T19:30:15",
                is_admin=True,
                tool_used="Educational Simulation Engine",
            )

            CaseMetadata.save_metadata(record, meta_path)
            loaded = CaseMetadata.load_metadata(meta_path)

            self.assertEqual(loaded["case_id"], "case_20260930_193000")
            self.assertEqual(loaded["acquisition_mode"], "DEMO")
            self.assertEqual(loaded["dump_size_bytes"], 1048576)
            self.assertEqual(loaded["os"], "Windows")


if __name__ == "__main__":
    unittest.main()
