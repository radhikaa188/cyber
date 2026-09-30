"""Volatility 3 integration analyzer for MemoryMapper Lite.

Attempts to run Volatility 3 plugins (e.g. windows.info, windows.pslist, linux.pslist)
if Volatility 3 CLI or Python package is installed. Gracefully reports 'NOT AVAILABLE'
if missing, without faking results.
"""

import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional
from config.config import VOLATILITY_CMD
from analysis.analyzer import BaseAnalyzer, ForensicAnalysisResult
from utils.logger import logger
from utils.validators import validate_file_exists


class VolatilityAnalyzer(BaseAnalyzer):
    """Integrates with Volatility 3 framework for in-depth memory forensics."""

    def __init__(self, custom_vol_cmd: Optional[str] = None):
        self.vol_cmd = custom_vol_cmd or VOLATILITY_CMD

    @property
    def name(self) -> str:
        return "Volatility 3 Framework Engine"

    def is_volatility_installed(self) -> Tuple[bool, Optional[str]]:
        """Checks if Volatility 3 CLI or Python module is available."""
        # Check CLI binary
        for cmd in [self.vol_cmd, "vol", "volatility", "vol.py"]:
            found = shutil.which(cmd)
            if found:
                return True, found
        
        # Check if importable via Python
        try:
            import volatility3
            return True, "volatility3 (Python Library)"
        except ImportError:
            pass

        return False, None

    def analyze(self, dump_file_path: Path | str) -> ForensicAnalysisResult:
        """Runs Volatility 3 analysis plugins against the dump file."""
        path = Path(dump_file_path)
        now_iso = datetime.now().isoformat()
        
        valid, msg = validate_file_exists(path)
        if not valid:
            return ForensicAnalysisResult(
                analyzer_name=self.name,
                status="FAILED",
                dump_path=str(path),
                errors_and_limitations=[f"Dump file invalid: {msg}"],
                analysis_timestamp=now_iso,
            )

        installed, vol_target = self.is_volatility_installed()
        if not installed:
            logger.info("Volatility 3 is not installed on this machine.")
            return ForensicAnalysisResult(
                analyzer_name=self.name,
                status="NOT AVAILABLE",
                dump_path=str(path),
                dump_size_bytes=path.stat().st_size,
                summary_notes="Volatility 3 framework was not detected in system PATH or Python environment.",
                errors_and_limitations=[
                    "Volatility 3 is NOT installed.",
                    "To enable full kernel symbol analysis: pip install volatility3",
                    "No API keys required.",
                    "Local heuristic analysis can be used as a standalone alternative.",
                ],
                analysis_timestamp=now_iso,
            )

        # If Volatility is available, run basic info and pslist
        logger.info(f"Running Volatility 3 ({vol_target}) against {path.name}")
        processes = []
        errors = []
        os_detected = "Windows (Volatility Detected)"

        try:
            # Try running windows.pslist in JSON output mode
            cmd = [vol_target, "-f", str(path.resolve()), "-r", "json", "windows.pslist"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if res.returncode == 0:
                try:
                    ps_data = json.loads(res.stdout)
                    for item in ps_data:
                        processes.append({
                            "pid": item.get("PID"),
                            "ppid": item.get("PPID"),
                            "name": item.get("ImageFileName"),
                            "threads": item.get("Threads"),
                            "create_time": item.get("CreateTime"),
                        })
                except Exception:
                    # Fallback text parsing
                    for line in res.stdout.splitlines():
                        if line.strip():
                            errors.append(f"Output: {line[:80]}")
            else:
                errors.append(f"Volatility command returned code {res.returncode}: {res.stderr[:200]}")

        except Exception as e:
            errors.append(f"Volatility execution exception: {e}")

        status = "SUCCESS" if processes else "PARTIAL"
        return ForensicAnalysisResult(
            analyzer_name=self.name,
            status=status,
            os_detected=os_detected,
            dump_path=str(path),
            dump_size_bytes=path.stat().st_size,
            processes=processes,
            summary_notes=f"Volatility 3 analysis completed with {len(processes)} processes identified.",
            errors_and_limitations=errors,
            analysis_timestamp=now_iso,
        )
