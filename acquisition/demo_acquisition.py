"""Demo & Simulation memory acquisition driver for MemoryMapper Lite.

Creates a safe, educational synthetic memory image with realistic forensic artifacts
(PE headers, process markers, simulated network sockets, system banners, and strings)
without requiring administrator privileges or kernel drivers.
"""

import os
from pathlib import Path
from typing import Any, Dict, Tuple
from core.acquisition import BaseAcquisition
from utils.logger import logger


class DemoAcquisition(BaseAcquisition):
    """Generates a harmless, structured educational memory dump for demonstration and testing."""

    @property
    def tool_name(self) -> str:
        return "MemoryMapper Lite Educational Simulation Engine (DEMO MODE)"

    def check_prerequisites(self) -> Tuple[bool, str]:
        """Demo mode has zero external prerequisites and runs with standard user privileges."""
        return True, "Demo mode requires no elevated privileges and no external tools."

    def acquire(self, target_dump_path: Path) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Creates a synthetic, structured binary image containing forensic artifacts:
        - Simulated PE (MZ/PE) and ELF binary headers
        - Synthetic Windows/Linux process listings
        - Simulated network connections (IPv4/ports)
        - Memory strings, URLs, and environment variables
        """
        logger.info(f"Generating educational demo memory dump at: {target_dump_path}")

        try:
            # Synthetic memory content generation
            banner = (
                b"================================================================================\n"
                b"*** MEMORYMAPPER LITE - SIMULATED EDUCATIONAL MEMORY DUMP ***\n"
                b"*** NOTICE: THIS IS A SAFE TEST ARTIFACT (DEMO MODE) - NOT REAL PHYSICAL RAM ***\n"
                b"================================================================================\n\n"
            )

            # Simulated process table block
            process_table = (
                b"[FORENSIC_SECTION: PROCESS_TABLE]\n"
                b"PID: 4      | PPID: 0    | NAME: System               | THREADS: 184 | STATE: RUNNING\n"
                b"PID: 340    | PPID: 4    | NAME: smss.exe             | THREADS: 4   | STATE: RUNNING\n"
                b"PID: 488    | PPID: 340  | NAME: csrss.exe            | THREADS: 12  | STATE: RUNNING\n"
                b"PID: 592    | PPID: 340  | NAME: wininit.exe          | THREADS: 3   | STATE: RUNNING\n"
                b"PID: 672    | PPID: 592  | NAME: services.exe         | THREADS: 28  | STATE: RUNNING\n"
                b"PID: 712    | PPID: 592  | NAME: lsass.exe            | THREADS: 16  | STATE: RUNNING\n"
                b"PID: 880    | PPID: 672  | NAME: svchost.exe          | THREADS: 32  | STATE: RUNNING\n"
                b"PID: 1420   | PPID: 672  | NAME: explorer.exe         | THREADS: 44  | STATE: RUNNING\n"
                b"PID: 3108   | PPID: 1420 | NAME: powershell.exe       | THREADS: 8   | STATE: RUNNING\n"
                b"PID: 4920   | PPID: 1420 | NAME: chrome.exe           | THREADS: 22  | STATE: RUNNING\n"
                b"PID: 5210   | PPID: 1420 | NAME: python.exe           | THREADS: 6   | STATE: RUNNING\n"
                b"[END_SECTION: PROCESS_TABLE]\n\n"
            )

            # Simulated network connections
            network_table = (
                b"[FORENSIC_SECTION: NETWORK_CONNECTIONS]\n"
                b"PROTO: TCP | LOCAL: 192.168.1.45:49821  | REMOTE: 142.250.190.46:443  | STATE: ESTABLISHED | PID: 4920 (chrome.exe)\n"
                b"PROTO: TCP | LOCAL: 192.168.1.45:51204  | REMOTE: 20.189.173.1:443    | STATE: ESTABLISHED | PID: 880 (svchost.exe)\n"
                b"PROTO: TCP | LOCAL: 0.0.0.0:8080        | REMOTE: 0.0.0.0:0           | STATE: LISTENING   | PID: 5210 (python.exe)\n"
                b"PROTO: TCP | LOCAL: 127.0.0.1:27017     | REMOTE: 0.0.0.0:0           | STATE: LISTENING   | PID: 672 (services.exe)\n"
                b"PROTO: UDP | LOCAL: 192.168.1.45:5353   | REMOTE: 224.0.0.251:5353    | STATE: BOUND       | PID: 1420 (explorer.exe)\n"
                b"[END_SECTION: NETWORK_CONNECTIONS]\n\n"
            )

            # Simulated binary headers (MZ and PE)
            pe_signature = (
                b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00"
                b"This program cannot be run in DOS mode.\r\r\n$"
                b"\x00\x00\x00\x00PE\x00\x00\x64\x86\x04\x00"
            )

            # Simulated memory strings & DFIR indicators
            dfir_strings = (
                b"\n[FORENSIC_SECTION: MEMORY_STRINGS]\n"
                b"URL: https://api.github.com/repos/MemoryMapper/releases\n"
                b"URL: http://192.168.1.1/admin/gateway\n"
                b"IP: 192.168.1.45\n"
                b"IP: 10.0.2.15\n"
                b"IP: 142.250.190.46\n"
                b"ENV: USERNAME=ForensicAnalyst\n"
                b"ENV: COMPUTERNAME=DFIR-WORKSTATION\n"
                b"ENV: PATH=C:\\Windows\\system32;C:\\Windows;C:\\Python314\n"
                b"COMMAND: python.exe main.py --acquire-demo\n"
                b"COMMAND: Get-Process | Where-Object {$_.CPU -gt 10}\n"
                b"[END_SECTION: MEMORY_STRINGS]\n\n"
            )

            # Filler padding to simulate a realistic multi-megabyte binary dump (e.g. 5 MB)
            padding = b"\x00" * 4096

            with open(target_dump_path, "wb") as f:
                f.write(banner)
                f.write(process_table)
                f.write(network_table)
                f.write(pe_signature)
                f.write(dfir_strings)
                # Pad to ~2.5 MB for realistic testing
                for _ in range(600):
                    f.write(padding)
                # Re-add a string near end of memory
                f.write(b"\n[KERNEL_POOL_END_MARKER: PAGEpaged: 0xFFFFF80004100000]\n")

            size = target_dump_path.stat().st_size
            logger.info(f"Demo memory image generated successfully: {size} bytes")

            return True, "Demo memory dump generated successfully.", {
                "dump_type": "EDUCATIONAL_SIMULATION",
                "simulated_processes": 11,
                "simulated_connections": 5,
                "size_bytes": size,
                "demo_warning": "NOT A REAL HARDWARE MEMORY DUMP",
            }
        except Exception as e:
            return False, f"Failed to generate demo image: {e}", {"exception": str(e)}
