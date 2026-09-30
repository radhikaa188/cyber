"""System detection module for MemoryMapper Lite.

Detects operating system, architecture, kernel/OS release, Python version,
RAM capacity, and administrator/root privileges without mandatory third-party dependencies.
"""

import ctypes
import os
import platform
import sys
from datetime import datetime
from typing import Any, Dict


class SystemDetector:
    """Detects system parameters, hardware specs, and execution privileges."""

    @staticmethod
    def get_os_type() -> str:
        """Returns normalized OS name: 'Windows', 'Linux', 'Darwin', or 'Unknown'."""
        system = platform.system()
        if system == "Windows":
            return "Windows"
        elif system == "Linux":
            return "Linux"
        elif system == "Darwin":
            return "macOS"
        return system or "Unknown"

    @staticmethod
    def is_admin() -> bool:
        """Checks if the script is currently running with Administrator/Root privileges."""
        try:
            if platform.system() == "Windows":
                return bool(ctypes.windll.shell32.IsUserAnAdmin() != 0)
            else:
                return os.geteuid() == 0
        except Exception:
            return False

    @staticmethod
    def get_memory_info() -> Dict[str, Any]:
        """Attempts to retrieve total and available physical RAM using standard libraries."""
        mem_info = {"total_gb": None, "available_gb": None, "raw_total_bytes": 0}
        
        try:
            # First try psutil if optionally installed
            import psutil
            vm = psutil.virtual_memory()
            mem_info["total_gb"] = round(vm.total / (1024 ** 3), 2)
            mem_info["available_gb"] = round(vm.available / (1024 ** 3), 2)
            mem_info["raw_total_bytes"] = vm.total
            return mem_info
        except ImportError:
            pass

        # Native Windows fallback using GlobalMemoryStatusEx via ctypes
        if platform.system() == "Windows":
            try:
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                    ]

                stat = MEMORYSTATUSEX()
                stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                    mem_info["total_gb"] = round(stat.ullTotalPhys / (1024 ** 3), 2)
                    mem_info["available_gb"] = round(stat.ullAvailPhys / (1024 ** 3), 2)
                    mem_info["raw_total_bytes"] = stat.ullTotalPhys
                    return mem_info
            except Exception:
                pass

        # Native Linux fallback reading /proc/meminfo
        elif platform.system() == "Linux" and os.path.exists("/proc/meminfo"):
            try:
                with open("/proc/meminfo", "r") as f:
                    lines = f.readlines()
                total_kb = 0
                avail_kb = 0
                for line in lines:
                    if line.startswith("MemTotal:"):
                        total_kb = int(line.split()[1])
                    elif line.startswith("MemAvailable:"):
                        avail_kb = int(line.split()[1])
                if total_kb:
                    mem_info["total_gb"] = round(total_kb / (1024 ** 2), 2)
                    mem_info["available_gb"] = round(avail_kb / (1024 ** 2), 2)
                    mem_info["raw_total_bytes"] = total_kb * 1024
                    return mem_info
            except Exception:
                pass

        return mem_info

    @classmethod
    def get_system_summary(cls) -> Dict[str, Any]:
        """Returns comprehensive system information dictionary."""
        mem_info = cls.get_memory_info()
        now_iso = datetime.now().isoformat()
        
        return {
            "os_name": cls.get_os_type(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine() or platform.architecture()[0],
            "python_version": platform.python_version(),
            "python_executable": sys.executable,
            "hostname": platform.node() or "localhost",
            "is_admin": cls.is_admin(),
            "total_ram_gb": mem_info["total_gb"],
            "available_ram_gb": mem_info["available_gb"],
            "raw_total_bytes": mem_info["raw_total_bytes"],
            "timestamp": now_iso,
        }

    @classmethod
    def print_system_info(cls) -> None:
        """Prints a human-readable CLI summary of system information."""
        info = cls.get_system_summary()
        admin_str = "[+] Elevated (Admin/Root)" if info["is_admin"] else "[-] Non-Elevated (Standard User)"
        ram_str = f"{info['total_ram_gb']} GB (Available: {info['available_ram_gb']} GB)" if info['total_ram_gb'] else "Unknown"

        print("\n" + "=" * 50)
        print("           SYSTEM INFORMATION & DIAGNOSTICS")
        print("=" * 50)
        print(f"OS Platform      : {info['os_name']} ({info['os_release']})")
        print(f"OS Version       : {info['os_version']}")
        print(f"Architecture     : {info['architecture']}")
        print(f"Hostname         : {info['hostname']}")
        print(f"Python Version   : {info['python_version']}")
        print(f"Privilege Level  : {admin_str}")
        print(f"Physical RAM     : {ram_str}")
        print(f"Current Time     : {info['timestamp']}")
        print("=" * 50 + "\n")
