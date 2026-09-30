"""Unit tests for the ReportGenerator module."""

import tempfile
import unittest
from pathlib import Path
from analysis.analyzer import ForensicAnalysisResult
from analysis.report_generator import ReportGenerator


class TestReportGenerator(unittest.TestCase):
    """Test HTML and JSON report compilation."""

    def test_report_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            html_out = tmp_path / "test_report.html"
            json_out = tmp_path / "test_report.json"

            sample_meta = {
                "case_id": "CASE_TEST_001",
                "os": "Windows",
                "architecture": "AMD64",
                "python_version": "3.14.0",
                "dump_file": "memory.raw",
                "dump_size_bytes": 102400,
                "sha256": "abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
                "acquisition_status": "SUCCESS",
                "acquisition_mode": "REAL",
                "acquisition_start": "2026-09-30T22:00:00",
                "acquisition_end": "2026-09-30T22:00:05",
                "is_admin": True,
                "tool_used": "WinPmem (Windows Memory Acquisition Engine)",
            }

            sample_manifest = {
                "case_id": "CASE_TEST_001",
                "evidence_id": "EVD_TEST_001",
                "original_filename": "memory.raw",
            }

            sample_custody = [
                {"event_id": "EVT-001", "timestamp": "2026-09-30T22:00:00", "event": "MEMORY_ACQUIRED", "description": "RAM dump complete", "status": "SUCCESS"},
                {"event_id": "EVT-002", "timestamp": "2026-09-30T22:00:01", "event": "HASH_GENERATED", "description": "SHA-256 seal computed", "status": "SUCCESS"},
            ]

            sample_analysis = ForensicAnalysisResult(
                analyzer_name="Test Engine",
                status="SUCCESS",
                os_detected="Windows",
                signatures_found=["MZ/PE Header"],
                processes=[{"pid": 4, "ppid": 0, "name": "System", "threads": 100, "state": "RUNNING"}],
                network_connections=[{"proto": "TCP", "local_address": "127.0.0.1:80", "remote_address": "0.0.0.0:0", "state": "LISTEN", "process_info": "System"}],
                extracted_strings={"ips": ["192.168.1.1"], "urls": ["https://example.com"], "commands": []},
            )

            gen_html = ReportGenerator.generate_html_report(
                case_metadata=sample_meta,
                manifest=sample_manifest,
                custody_events=sample_custody,
                analysis_result=sample_analysis,
                integrity_status="INTEGRITY VERIFIED",
                output_html_path=html_out,
            )

            gen_json = ReportGenerator.generate_json_report(
                case_metadata=sample_meta,
                manifest=sample_manifest,
                custody_events=sample_custody,
                analysis_result=sample_analysis,
                integrity_status="INTEGRITY VERIFIED",
                output_json_path=json_out,
            )

            self.assertTrue(gen_html.exists())
            self.assertTrue(gen_json.exists())

            html_text = gen_html.read_text(encoding="utf-8")
            self.assertIn("CASE_TEST_001", html_text)
            self.assertIn("INTEGRITY VERIFIED", html_text)
            self.assertIn("EVT-001", html_text)
            self.assertIn("System", html_text)


if __name__ == "__main__":
    unittest.main()
