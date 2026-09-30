"""Linux memory acquisition driver for MemoryMapper Lite.

Supports LiME (Linux Memory Extractor) kernel module and LinPmem userland/kernel tools.
Requires root (sudo) privileges.
"""

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from config.config import LIME_MODULE_PATH, LINPMEM_PATH
from core.acquisition import BaseAcquisition
from core.system_detector import SystemDetector
from utils.logger import logger


class LinuxAcquisition(BaseAcquisition):
    """Handles real physical RAM capture on Linux systems via LiME or LinPmem."""

    def __init__(self, lime_path: Optional[str] = None, linpmem_path: Optional[str] = None):
        self.lime_path = lime_path or LIME_MODULE_PATH
        self.linpmem_path = linpmem_path or LINPMEM_PATH
        self._mode: Optional[str] = None  # 'lime' or 'linpmem'
        self._tool_path: Optional[str] = None

    @property
    def tool_name(self) -> str:
        if self._mode == "linpmem":
            return "LinPmem (Linux Memory Acquisition Utility)"
        return "LiME (Linux Memory Extractor Kernel Module)"

    def check_prerequisites(self) -> Tuple[bool, str]:
        """Verifies OS compatibility, root privileges, and tool availability."""
        if SystemDetector.get_os_type() != "Linux":
            return False, "LinuxAcquisition is only supported on Linux OS."

        if not SystemDetector.is_admin():
            return False, "Root privileges required! Please run the tool with sudo or as root."

        # Check for LinPmem
        linpmem_bin = shutil.which(self.linpmem_path) or (Path(self.linpmem_path).is_file() and self.linpmem_path)
        if linpmem_bin:
            self._mode = "linpmem"
            self._tool_path = str(linpmem_bin)
            return True, f"Prerequisites met using LinPmem ({linpmem_bin})."

        # Check for LiME module
        if Path(self.lime_path).is_file():
            self._mode = "lime"
            self._tool_path = str(self.lime_path)
            return True, f"Prerequisites met using LiME module ({self.lime_path})."

        return False, (
            "Neither LiME (lime.ko) nor LinPmem was found!\n"
            "To acquire RAM on Linux:\n"
            "1. Compile LiME (https://github.com/504ensicsLabs/LiME) for your running kernel, or\n"
            "2. Download linpmem binary (https://github.com/Velocidex/c-aff4/releases)\n"
            "3. Place in project directory or configure paths in config/config.py.\n"
            "Tip: You can use Option 8 (Demo Mode) to safely test without root/kernel modules."
        )

    def acquire(self, target_dump_path: Path) -> Tuple[bool, str, Dict[str, Any]]:
        """Executes Linux RAM dump via LinPmem or LiME."""
        ready, msg = self.check_prerequisites()
        if not ready:
            return False, msg, {"error_type": "PrerequisitesNotMet"}

        target_path_str = str(target_dump_path.resolve())

        if self._mode == "linpmem":
            cmd = [self._tool_path, "-o", target_path_str]
            logger.info(f"Running LinPmem: {' '.join(cmd)}")
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if res.returncode == 0 and target_dump_path.exists() and target_dump_path.stat().st_size > 0:
                    return True, "Linux RAM acquisition completed via LinPmem.", {
                        "mode": "linpmem",
                        "size": target_dump_path.stat().st_size,
                    }
                return False, f"LinPmem failed: {res.stderr or res.stdout}", {"mode": "linpmem"}
            except Exception as e:
                return False, f"LinPmem execution error: {e}", {"exception": str(e)}

        elif self._mode == "lime":
            # LiME kernel module: insmod lime.ko "path=<path> format=raw"
            # Followed by rmmod lime
            insmod_cmd = ["insmod", self._tool_path, f"path={target_path_str}", "format=raw"]
            logger.info(f"Inserting LiME kernel module: {' '.join(insmod_cmd)}")
            try:
                res = subprocess.run(insmod_cmd, capture_output=True, text=True, timeout=300)
                # Cleanup module
                subprocess.run(["rmmod", "lime"], capture_output=True, text=True)

                if res.returncode == 0 and target_dump_path.exists() and target_dump_path.stat().st_size > 0:
                    return True, "Linux RAM acquisition completed via LiME.", {
                        "mode": "lime",
                        "size": target_dump_path.stat().st_size,
                    }
                return False, f"LiME acquisition failed: {res.stderr or res.stdout}", {"mode": "lime"}
            except Exception as e:
                return False, f"LiME execution error: {e}", {"exception": str(e)}

        return False, "Unknown Linux acquisition mode.", {}
