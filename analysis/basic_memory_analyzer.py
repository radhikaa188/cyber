"""Basic heuristic memory analyzer for MemoryMapper Lite.

Extracts memory signatures, process tables, network artifacts, IP addresses,
URLs, environment strings, and DOS/PE/ELF binary markers using pure Python standard library.
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from config.config import BASIC_SCAN_MAX_BYTES
from analysis.analyzer import BaseAnalyzer, ForensicAnalysisResult
from utils.logger import logger
from utils.validators import validate_file_exists


class BasicMemoryAnalyzer(BaseAnalyzer):
    """Zero-dependency local memory artifact extractor."""

    @property
    def name(self) -> str:
        return "MemoryMapper Lite Heuristic Artifact Engine"

    def analyze(self, dump_file_path: Path | str) -> ForensicAnalysisResult:
        """Parses the memory dump file for digital forensics artifacts."""
        path = Path(dump_file_path)
        now_iso = datetime.now().isoformat()

        valid, msg = validate_file_exists(path)
        if not valid:
            return ForensicAnalysisResult(
                analyzer_name=self.name,
                status="FAILED",
                dump_path=str(path),
                errors_and_limitations=[f"File validation error: {msg}"],
                analysis_timestamp=now_iso,
            )

        file_size = path.stat().st_size
        logger.info(f"Analyzing memory dump: {path.name} ({file_size} bytes)")

        # Read first N bytes to safely prevent memory exhaustion
        bytes_to_read = min(file_size, BASIC_SCAN_MAX_BYTES)
        try:
            with open(path, "rb") as f:
                raw_bytes = f.read(bytes_to_read)
        except Exception as e:
            return ForensicAnalysisResult(
                analyzer_name=self.name,
                status="FAILED",
                dump_path=str(path),
                dump_size_bytes=file_size,
                errors_and_limitations=[f"Could not read memory dump: {e}"],
                analysis_timestamp=now_iso,
            )

        # 1. Signatures Discovery
        signatures_found = []
        if b"MZ" in raw_bytes and b"PE\x00\x00" in raw_bytes:
            signatures_found.append("Windows Portable Executable (MZ/PE Header)")
        if b"\x7fELF" in raw_bytes:
            signatures_found.append("Linux Executable & Linkable Format (ELF Header)")
        if b"PAGEpaged" in raw_bytes or b"PAGE" in raw_bytes:
            signatures_found.append("Windows Kernel Memory Pool (PAGE tag)")
        if b"*** MEMORYMAPPER LITE - SIMULATED" in raw_bytes:
            signatures_found.append("MemoryMapper Simulated Educational Artifact Marker")

        # 2. Extract Structured Process Entries (Handles both tagged tables and binary regex strings)
        processes: List[Dict[str, Any]] = []
        
        # Check structured process section
        proc_pattern = re.compile(
            rb"PID:\s*(\d+)\s*\|\s*PPID:\s*(\d+)\s*\|\s*NAME:\s*([^\s|]+)\s*\|\s*THREADS:\s*(\d+)\s*\|\s*STATE:\s*([^\r\n]+)"
        )
        for match in proc_pattern.finditer(raw_bytes):
            try:
                processes.append({
                    "pid": int(match.group(1).decode("utf-8")),
                    "ppid": int(match.group(2).decode("utf-8")),
                    "name": match.group(3).decode("utf-8"),
                    "threads": int(match.group(4).decode("utf-8")),
                    "state": match.group(5).decode("utf-8").strip(),
                })
            except Exception:
                continue

        # If no structured table found, extract executable names with standard extensions (.exe, .dll, .sys)
        if not processes:
            name_pattern = re.compile(rb"([a-zA-Z0-9_\-\.]{3,32}\.(?:exe|dll|sys))", re.IGNORECASE)
            seen_names = set()
            sim_pid = 1000
            for match in name_pattern.finditer(raw_bytes):
                try:
                    name_str = match.group(1).decode("ascii", errors="ignore").lower()
                    if name_str not in seen_names and len(name_str) > 4:
                        seen_names.add(name_str)
                        processes.append({
                            "pid": sim_pid,
                            "ppid": 0,
                            "name": name_str,
                            "threads": 1,
                            "state": "EXTRACTED_IMAGE_STRING",
                        })
                        sim_pid += 4
                        if len(processes) >= 20:
                            break
                except Exception:
                    continue

        # 3. Extract Network Connections
        network_connections: List[Dict[str, Any]] = []
        net_pattern = re.compile(
            rb"PROTO:\s*(\w+)\s*\|\s*LOCAL:\s*([^\s|]+)\s*\|\s*REMOTE:\s*([^\s|]+)\s*\|\s*STATE:\s*([^\s|]+)(?:\s*\|\s*PID:\s*([^\r\n]+))?"
        )
        for match in net_pattern.finditer(raw_bytes):
            try:
                network_connections.append({
                    "proto": match.group(1).decode("utf-8"),
                    "local_address": match.group(2).decode("utf-8"),
                    "remote_address": match.group(3).decode("utf-8"),
                    "state": match.group(4).decode("utf-8"),
                    "process_info": match.group(5).decode("utf-8").strip() if match.group(5) else "N/A",
                })
            except Exception:
                continue

        # 4. Extract Strings: IPs, URLs, Commands, Environment
        extracted_strings: Dict[str, List[str]] = {
            "urls": [],
            "ips": [],
            "commands": [],
            "environment": [],
        }

        # URLs
        url_pattern = re.compile(rb"https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&'()*+,;=%]{4,100}")
        found_urls = set()
        for m in url_pattern.finditer(raw_bytes):
            u = m.group(0).decode("utf-8", errors="ignore")
            if u not in found_urls:
                found_urls.add(u)
                extracted_strings["urls"].append(u)
                if len(extracted_strings["urls"]) >= 15:
                    break

        # IPs
        ip_pattern = re.compile(rb"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
        found_ips = set()
        for m in ip_pattern.finditer(raw_bytes):
            ip_str = m.group(0).decode("utf-8", errors="ignore")
            if ip_str not in found_ips and not ip_str.startswith("0.0."):
                found_ips.add(ip_str)
                extracted_strings["ips"].append(ip_str)
                if len(extracted_strings["ips"]) >= 15:
                    break

        # Commands & Environment markers
        cmd_pattern = re.compile(rb"(?:COMMAND|ENV):\s*([^\r\n]{4,120})")
        for m in cmd_pattern.finditer(raw_bytes):
            s = m.group(1).decode("utf-8", errors="ignore").strip()
            if "COMMAND" in m.group(0).decode("utf-8", errors="ignore"):
                extracted_strings["commands"].append(s)
            else:
                extracted_strings["environment"].append(s)

        os_detected = "Windows" if ("Windows Portable Executable (MZ/PE Header)" in signatures_found or any("exe" in p["name"] for p in processes)) else "Generic / Unknown"

        limitations = []
        if bytes_to_read < file_size:
            limitations.append(f"Heuristic scan capped at first {round(bytes_to_read / (1024**2), 1)} MB to maintain responsiveness.")
        if not processes:
            limitations.append("No active process tables resolved via simple signature scan.")

        summary_notes = (
            f"Heuristic memory inspection discovered {len(signatures_found)} header signature(s), "
            f"{len(processes)} process candidate(s), {len(network_connections)} network socket(s), "
            f"and {len(extracted_strings['ips'])} IP reference(s)."
        )

        return ForensicAnalysisResult(
            analyzer_name=self.name,
            status="SUCCESS",
            os_detected=os_detected,
            dump_path=str(path),
            dump_size_bytes=file_size,
            signatures_found=signatures_found,
            processes=processes,
            network_connections=network_connections,
            extracted_strings=extracted_strings,
            summary_notes=summary_notes,
            errors_and_limitations=limitations,
            analysis_timestamp=now_iso,
        )
