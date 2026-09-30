"""Windows memory acquisition driver for MemoryMapper Lite.

Supports WinPmem (velocidex/WinPmem) and compatible Windows memory acquisition CLI tools.
Requires Administrator privileges and legitimate signed driver support.
"""

import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from config.config import WINPMEM_PATH
from core.acquisition import BaseAcquisition
from core.system_detector import SystemDetector
from utils.logger import logger


class WindowsAcquisition(BaseAcquisition):
    """Handles real physical RAM capture on Windows operating systems."""

    def __init__(self, executable_path: Optional[str] = None):
        self.custom_path = executable_path
        self._resolved_executable: Optional[str] = None

    @property
    def tool_name(self) -> str:
        return "WinPmem (Windows Memory Acquisition Engine)"

    def find_executable(self) -> Optional[str]:
        """Locates WinPmem or configured binary in PATH or specified location."""
        candidates = []
        if self.custom_path:
            candidates.append(self.custom_path)
        candidates.extend([
            WINPMEM_PATH,
            "winpmem.exe",
            "winpmem_mini_x64.exe",
            "winpmem_mini_x86.exe",
            "DumpIt.exe",
        ])

        for c in candidates:
            # Check direct file or shutil.which
            p = Path(c)
            if p.is_file():
                return str(p.resolve())
            found = shutil.which(c)
            if found:
                return found
        return None

    def check_prerequisites(self) -> Tuple[bool, str]:
        """Verifies OS compatibility, Administrator rights, and acquisition binary existence."""
        if SystemDetector.get_os_type() != "Windows":
            return False, "WindowsAcquisition is only supported on Windows OS."

        if not SystemDetector.is_admin():
            return False, (
                "Administrator privileges required! Physical RAM acquisition requires "
                "kernel driver loading permissions. Please restart your terminal/IDE as Administrator."
            )

        exe = self.find_executable()
        if not exe:
            return False, (
                "WinPmem executable not found!\n"
                "To perform real RAM acquisition on Windows:\n"
                "1. Download legitimate signed WinPmem executable (e.g. winpmem_mini_x64.exe) "
                "from official GitHub (https://github.com/Velocidex/WinPmem/releases)\n"
                "2. Place winpmem.exe in the project folder or set WINPMEM_PATH environment variable.\n"
                "Tip: Alternatively, use Option 8 (Demo Mode) to safely test the entire forensics pipeline without external tools."
            )

        self._resolved_executable = exe
        return True, f"Prerequisites met. Using acquisition utility: {exe}"

    def acquire(self, target_dump_path: Path) -> Tuple[bool, str, Dict[str, Any]]:
        """Executes WinPmem to dump physical RAM to the target destination."""
        ready, msg = self.check_prerequisites()
        if not ready:
            return False, msg, {"error_type": "PrerequisitesNotMet"}

        exe = self._resolved_executable
        target_path_str = str(target_dump_path.resolve())
        logger.info(f"Initiating Windows physical RAM acquisition with {exe} -> {target_path_str}")

        cmd = [exe, "-o", target_path_str]

        try:
            # Execute real acquisition command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=300,  # 5 min timeout
            )

            if result.returncode == 0 and target_dump_path.exists() and target_dump_path.stat().st_size > 0:
                logger.info("Windows RAM dump successfully created.")
                return True, "RAM acquisition completed successfully.", {
                    "returncode": result.returncode,
                    "stdout": result.stdout.strip(),
                    "dump_size": target_dump_path.stat().st_size,
                }
            else:
                err_msg = (
                    f"Acquisition tool returned code {result.returncode}.\n"
                    f"STDOUT: {result.stdout}\nSTDERR: {result.stderr}"
                )
                logger.error(err_msg)
                return False, err_msg, {
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
        except subprocess.TimeoutExpired:
            return False, "RAM acquisition timed out (exceeded 300 seconds).", {"timeout": True}
        except Exception as e:
            return False, f"Unexpected error during acquisition: {e}", {"exception": str(e)}
