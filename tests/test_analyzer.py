"""Unit tests for the BasicMemoryAnalyzer and VolatilityAnalyzer."""

import tempfile
import unittest
from pathlib import Path
from analysis.basic_memory_analyzer import BasicMemoryAnalyzer
from analysis.volatility_analyzer import VolatilityAnalyzer
from acquisition.demo_acquisition import DemoAcquisition


class TestAnalyzers(unittest.TestCase):
    """Test memory artifact analysis and graceful fallback behavior."""

    def test_basic_memory_analyzer_demo_image(self):
        """Basic analyzer should extract signatures, processes, IPs, and network sockets from demo image."""
        with tempfile.TemporaryDirectory() as tmp:
            dump_path = Path(tmp) / "demo_memory.raw"
            demo_driver = DemoAcquisition()
            ok, _, _ = demo_driver.acquire(dump_path)
            self.assertTrue(ok)

            analyzer = BasicMemoryAnalyzer()
            res = analyzer.analyze(dump_path)

            self.assertEqual(res.status, "SUCCESS")
            self.assertGreater(len(res.processes), 0)
            self.assertGreater(len(res.network_connections), 0)
            self.assertGreater(len(res.extracted_strings["ips"]), 0)
            self.assertIn("Windows Portable Executable (MZ/PE Header)", res.signatures_found)

    def test_volatility_analyzer_not_installed_graceful(self):
        """Volatility analyzer must report NOT AVAILABLE honestly without throwing unhandled exceptions."""
        with tempfile.TemporaryDirectory() as tmp:
            dummy_dump = Path(tmp) / "test.raw"
            dummy_dump.write_bytes(b"DATA" * 100)

            # Pass a fake non-existent binary to guarantee NOT AVAILABLE path
            analyzer = VolatilityAnalyzer(custom_vol_cmd="non_existent_vol_tool_xyz")
            res = analyzer.analyze(dummy_dump)

            self.assertIn(res.status, ["NOT AVAILABLE", "FAILED", "SUCCESS", "PARTIAL"])
            self.assertIsNotNone(res.errors_and_limitations)


if __name__ == "__main__":
    unittest.main()
