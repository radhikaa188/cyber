"""Configuration settings for MemoryMapper Lite."""

import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = BASE_DIR / "evidence"
WORKSPACE_DIR = BASE_DIR / "analysis_workspace"
REPORTS_DIR = BASE_DIR / "reports"
LOGS_DIR = BASE_DIR / "logs"
DOCS_DIR = BASE_DIR / "docs"

# Ensure directories exist
for directory in [EVIDENCE_DIR, WORKSPACE_DIR, REPORTS_DIR, LOGS_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Application Metadata
APP_NAME = "MemoryMapper Lite"
APP_VERSION = "1.1.0"
APP_SUBTITLE = "Real RAM Acquisition & Memory Forensics Tool with Chain of Custody"
AUTHORS = "Cybersecurity DFIR Academic Project"

# Log File
LOG_FILE = LOGS_DIR / "memorymapper.log"

# Default External Tool Paths (Configurable by user or auto-detected in PATH)
# Windows: WinPmem (e.g. winpmem.exe, winpmem_mini_x64.exe) or DumpIt
WINPMEM_PATH = os.getenv("WINPMEM_PATH", "winpmem.exe")

# Linux: LiME or linpmem
LIME_MODULE_PATH = os.getenv("LIME_MODULE_PATH", "/lib/modules/lime.ko")
LINPMEM_PATH = os.getenv("LINPMEM_PATH", "linpmem")

# Volatility CLI or Python package
VOLATILITY_CMD = os.getenv("VOLATILITY_CMD", "vol")

# Hashing Chunk Size (64 KB for memory efficiency on large dumps)
HASH_CHUNK_SIZE = 65536

# Maximum bytes to scan for basic memory strings analysis (e.g. 50 MB to prevent hanging)
BASIC_SCAN_MAX_BYTES = 50 * 1024 * 1024
