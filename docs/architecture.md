# MemoryMapper Lite &mdash; System Architecture & Technical Design

## 1. High-Level Architecture Overview

**MemoryMapper Lite** is designed following clean modular architecture principles to provide a genuine, defensible, and reliable Digital Forensics and Incident Response (DFIR) memory acquisition and analysis workflow.

### Architecture Pipeline

```text
+-------------------------------------------------------------+
|                      User Interaction                       |
|           (CLI Menu / Automated Command Flags)             |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                  core/system_detector.py                    |
|   - OS Platform, Kernel Release, Architecture               |
|   - Physical RAM capacity & Admin/Root Privilege Check      |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                  core/acquisition.py                        |
|            (AcquisitionManager & Driver Dispatch)           |
+-------------------------------------------------------------+
           |                         |                      |
           v [Primary Workflow]      v [Primary Workflow]   v [Fallback Demo Only]
+-----------------------+ +--------------------+ +-------------------+
| windows_acquisition.py| |linux_acquisition.py| |demo_acquisition.py|
| (WinPmem / DumpIt)    | | (LiME / LinPmem)   | | (Synthetic Demo)  |
+-----------------------+ +--------------------+ +-------------------+
                              |
                              v [Raw Memory Image: memory.raw]
+-------------------------------------------------------------+
|                  core/evidence_manager.py                   |
|   - Creates evidence/CASE_YYYYMMDD_HHMMSS/                  |
|   - Overwrite & Collision Prevention                        |
+-------------------------------------------------------------+
                              |
                              +---> core/hasher.py (SHA-256 Baseline Sealing)
                              |
                              +---> core/evidence_integrity.py (Manifest & Read-Only Seal)
                              |
                              +---> core/chain_of_custody.py (Event Logging: chain_of_custody.json)
                              |
                              v
+-------------------------------------------------------------+
|                      Non-Destructive Workspace              |
|   - Replicates memory.raw -> analysis_workspace/CASE_ID/    |
|   - Original evidence remains untouched and sealed          |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                   analysis/analyzer.py                      |
|               (Forensic Examination Pipeline)               |
+-------------------------------------------------------------+
           |                                                |
           v                                                v
+----------------------------------+         +-------------------------------+
|     basic_memory_analyzer.py     |         |    volatility_analyzer.py     |
| (Basic Heuristic String Scanner) |         |  (Volatility 3 Symbol Parser) |
| - Magic Byte Check (MZ/PE, ELF)  |         | - Kernel Pool & Plugin Runner |
| - Regex Executable Name Strings  |         | - Real EPROCESS / Netscan     |
| - IOC String Regex (IPs, URLs)   |         | - Graceful 'NOT AVAILABLE' if |
| - Demo Tag Structured Parsing    |         |   volatility is not installed |
+----------------------------------+         +-------------------------------+
                              |
                              v
+-------------------------------------------------------------+
|                 analysis/report_generator.py                |
|  - Standalone HTML Forensic Report (reports/*.html)         |
|  - Standardized JSON Report (evidence/*/forensic_report.json|
+-------------------------------------------------------------+
```

---

## 2. Core Component Matrix

| Component | File Path | Architectural Responsibility |
|---|---|---|
| **Entry Point** | `main.py` | CLI menu system, parameter parsing (`--acquire-real`, `--demo`, `--info`, `--test`, `--verify`, `--custody`), workflow coordination. |
| **System Detector** | `core/system_detector.py` | Queries system architecture, OS version, RAM capacity via standard libraries (ctypes/sysconf), and checks admin/root elevation. |
| **Acquisition Base** | `core/acquisition.py` | Abstract Base Class `BaseAcquisition` and `AcquisitionManager` lifecycle coordinator. |
| **Windows Driver** | `acquisition/windows_acquisition.py` | Validates admin elevation and invokes signed WinPmem CLI drivers. |
| **Linux Driver** | `acquisition/linux_acquisition.py` | Validates root elevation and loads LiME kernel modules or linpmem binaries. |
| **Demo Driver** | `acquisition/demo_acquisition.py` | Generates non-privileged synthetic test memory images containing realistic DFIR structures (PE headers, process tables, sockets). Explicitly labeled as DEMO. |
| **Hasher** | `core/hasher.py` | Computes 64KB-chunked SHA-256 checksums to preserve chain of custody; performs verification against reference hashes. |
| **Evidence Integrity** | `core/evidence_integrity.py` | Generates `evidence_manifest.json`, applies read-only attributes, creates non-destructive replicas in `analysis_workspace/`, and verifies integrity. |
| **Chain of Custody** | `core/chain_of_custody.py` | Manages `chain_of_custody.json` recording chronological audit events (`EVT-001`, `EVT-002`, ...). |
| **Evidence Manager**| `core/evidence_manager.py` | Handles timestamped case folder provisioning (`evidence/CASE_YYYYMMDD_HHMMSS/`) and collision prevention. |
| **Metadata Record** | `core/metadata.py` | Serializes environment parameters, timestamps, status, and hashes into standardized `metadata.json`. |
| **Basic Heuristic Scanner** | `analysis/basic_memory_analyzer.py` | Zero-dependency byte-pattern and regex string scanner searching for MZ/ELF magic bytes, executable name strings, IPv4 regex patterns, and URLs. |
| **Volatility Analyzer**| `analysis/volatility_analyzer.py`| Wraps Volatility 3 framework for genuine kernel data structure inspection (EPROCESS lists, sockets); returns structured diagnostics or explicit `NOT AVAILABLE` message if absent. |
| **Report Generator** | `analysis/report_generator.py` | Compiles responsive HTML reports with integrity badges, manifest summary, chain-of-custody table, and JSON summaries. |
