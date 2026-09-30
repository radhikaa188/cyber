"""Unit tests for the SystemDetector module."""

import unittest
from core.system_detector import SystemDetector


class TestSystemDetector(unittest.TestCase):
    """Test OS detection, summary generation, and privilege detection."""

    def test_os_type_not_empty(self):
        os_type = SystemDetector.get_os_type()
        self.assertIn(os_type, ["Windows", "Linux", "macOS", "Unknown"])

    def test_system_summary_structure(self):
        summary = SystemDetector.get_system_summary()
        expected_keys = [
            "os_name",
            "os_release",
            "os_version",
            "architecture",
            "python_version",
            "hostname",
            "is_admin",
            "timestamp",
        ]
        for key in expected_keys:
            self.assertIn(key, summary)


if __name__ == "__main__":
    unittest.main()
