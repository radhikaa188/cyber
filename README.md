# MemoryMapper Lite &mdash; Real RAM Acquisition & Memory Forensics Tool

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Zero Dependency Core](https://img.shields.io/badge/Dependencies-Zero%20Mandatory-brightgreen.svg)](requirements.txt)
[![DFIR Standard](https://img.shields.io/badge/Standard-ISO%2FIEC%2027037-orange.svg)](docs/architecture.md)

> **A real-first, educational Digital Forensics and Incident Response (DFIR) tool demonstrating real physical RAM acquisition, evidence preservation, SHA-256 integrity verification, chain-of-custody logging, and memory analysis.**

---

## 1. Core Educational Concepts (For DFIR Beginners)

### What is RAM?
**RAM (Random Access Memory)** is the high-speed physical working memory of a computer. When software runs, its code, dynamic data, active network connections, and unencrypted variables reside directly in RAM.

### What is Volatile Memory?
Volatile memory is memory that requires continuous electrical power to maintain its state. When a computer is powered down or rebooted, **all data stored in volatile memory is lost permanently**. In cyber incident response, volatile memory holds the most fleeting yet critical forensic evidence.

### What is Memory Acquisition?
Memory acquisition is the process of extracting and preserving the raw contents of volatile physical RAM into an immutable digital image on non-volatile disk storage without altering running system artifacts.

### What is a Memory Dump?
A **memory dump** (e.g. `memory.raw`, `memory.dmp`) is a bit-by-bit raw byte image representing the physical memory space of the target computer at the exact moment of acquisition.

### What is Evidence Management?
Evidence management is the disciplined practice of organizing, cataloging, timestamping, and securing forensic evidence files into structured cases (`evidence/CASE_YYYYMMDD_HHMMSS/`) to guarantee authenticity for legal and investigative review.

### What is SHA-256?
**SHA-256 (Secure Hash Algorithm 256-bit)** is a cryptographic hash function that transforms any file into a unique 64-character hexadecimal fingerprint. Even changing a single bit in a 16 GB file produces a completely different hash (the *Avalanche Effect*).

### What is Integrity Verification?
Integrity verification is the process of re-hashing evidence and comparing the result against the original baseline recorded at acquisition time. If the hashes match, the evidence is mathematically proven to be unmodified (`INTEGRITY VERIFIED`). If they differ, tampering or corruption is detected (`TAMPERING DETECTED`).

### What is Chain of Custody?
**Chain of Custody** is a chronological, tamper-evident audit log (`chain_of_custody.json`) documenting who, when, what tool, and what action was performed on an evidence item from the moment of seizure to final reporting (ISO/IEC 27037 standard).

### What is Forensic Analysis?
Forensic analysis is the examination of memory dumps to reconstruct past events: identifying active process trees, injected threads, open sockets, loaded kernel drivers, network artifacts, and attacker commands.

### What is Volatility?
**Volatility 3** is the industry-standard open-source framework for deep memory forensics, analyzing kernel data structures (EPROCESS pools, VAD trees) using operating system symbol tables.

---

## 2. Crucial Distinction: Hashing vs Protection vs Chain of Custody

```text
+-------------------------------------------------------------------------------+
| HASHING (SHA-256)                                                             |
| -> Mathematically DETECTS whether evidence has changed.                       |
| -> Does NOT physically prevent a user or process from editing the file.       |
+-------------------------------------------------------------------------------+
| EVIDENCE PROTECTION                                                           |
| -> Software-level read-only attributes (chmod / attrib +r).                   |
| -> Non-destructive analysis copies in analysis_workspace/.                   |
| -> Helps prevent accidental overwriting or modification by user applications. |
+-------------------------------------------------------------------------------+
| CHAIN OF CUSTODY                                                              |
| -> Chronological audit trail (chain_of_custody.json).                         |
| -> Records every acquisition, hash check, analysis run, and report event.     |
+-------------------------------------------------------------------------------+
```

---

## 3. What the Project Protects Against & Limitations

### What it Protects Against:
- **Accidental Overwriting**: Case folders use duplicate collision checks to ensure existing evidence cannot be overwritten.
- **Analysis Mutation**: Memory dumps are replicated into `analysis_workspace/` so forensic tools never mutate the primary evidence.
- **Silent Tampering**: Re-verification detects any post-acquisition bit modification immediately.
- **Untracked Access**: All verification and examination events are automatically committed to the audit trail.

### Software Limitations (Honest Transparency):
- **Local Immutability Limit**: Local software-level read-only flags protect against accidental modification. If an attacker or user possesses root or administrative privileges on the host storage system, they can remove read-only flags. Absolute write-blocking requires physical hardware write-blockers or write-once-read-many (WORM) storage.
- **HVCI & Kernel Protection**: On Windows 11 with Hypervisor-Protected Code Integrity (HVCI) enabled, unsigned kernel drivers cannot be loaded. WinPmem must be digitally signed.
- **Heuristic Scanning vs Deep Kernel Reconstruction**: The built-in `BasicMemoryAnalyzer` is a zero-dependency **byte-pattern and regex string scanner** (searching for magic bytes, executable name strings, IPv4 patterns, URLs, and demo tags). It does NOT parse Windows `EPROCESS` doubly linked lists or kernel socket structures. True deep kernel structure reconstruction requires **Volatility 3**.

---

## 4. System Workflow

```text
User Interaction
       ↓
OS & Privilege Detection
       ↓
[PRIMARY] Real Memory Acquisition (WinPmem / LiME)
       ↓
Real Memory Dump (evidence/CASE_YYYYMMDD_HHMMSS/memory.raw)
       ↓
Cryptographic Sealing & Evidence Manifest (evidence_manifest.json + hash.txt)
       ↓
Chain of Custody Initialization (chain_of_custody.json)
       ↓
Integrity Protection (Read-Only Attribute Applied)
       ↓
Non-Destructive Replica (analysis_workspace/CASE_ID/working_copy_memory.raw)
       ↓
Forensic Analysis (Basic Heuristic Scanner or Volatility 3)
       ↓
Comprehensive Forensic Report (HTML & JSON)
```

---

## 5. Requirements & Installation

```text
============================================================
           MEMORYMAPPER LITE REQUIREMENTS CHECKLIST
============================================================
- Operating System        : Windows (10/11/Server) or Linux
- Python Version          : Python 3.10, 3.11, 3.12, 3.13, 3.14+
- Mandatory Pip Packages  : ZERO (Pure Python Standard Library Core)
- Optional Pip Packages   : psutil, volatility3, pytest
- External Acquisition Tool: Required for Real RAM capture (WinPmem on Windows / LiME on Linux)
- Admin / Root Privileges : Required for Real RAM capture
- API Key Required        : NO (100% Offline & Local)
- Internet Required       : NO
============================================================
```

### Setup for Real RAM Acquisition:
1. **Windows**:
   - Download signed `winpmem_mini_x64.exe` from [Velocidex WinPmem Releases](https://github.com/Velocidex/WinPmem/releases).
   - Place in project directory as `winpmem.exe`.
   - Run terminal as **Administrator**.
2. **Linux**:
   - Compile LiME (`make`) or download `linpmem`.
   - Run with `sudo python main.py`.

---

## 6. Usage & CLI Menu

```bash
python main.py
```

```text
========================================
       MEMORYMAPPER LITE (v1.1.0)
   Real RAM Acquisition & Forensics
========================================

1. System Information
2. Acquire Real Memory
3. Verify Evidence Integrity
4. Analyze Memory Dump
5. Generate Forensic Report
6. View Chain of Custody
7. Demo/Test Mode
8. Run Automated Self-Tests
9. Exit
```

### CLI Command Flags:
```bash
# View system diagnostics
python main.py --info

# Execute Real RAM acquisition
python main.py --acquire-real

# Verify integrity of a case
python main.py --verify CASE_20260930_220000

# View chain of custody audit log
python main.py --custody CASE_20260930_220000

# Run fallback simulation mode (for lab testing without admin rights)
python main.py --demo

# Run automated unit test suite
python main.py --test
```

---

## 7. Folder Structure & Evidence Vault

```text
MemoryMapper-Lite/
├── main.py                             # Interactive CLI and argument dispatcher
├── config/config.py                    # Paths, buffer settings, and tool configuration
├── core/
│   ├── system_detector.py              # OS, hardware, and admin rights detection
│   ├── acquisition.py                  # Acquisition controller & driver dispatch
│   ├── evidence_manager.py             # Case provisioning with collision prevention
│   ├── evidence_integrity.py           # Manifest creation, read-only seal, working copies
│   ├── chain_of_custody.py             # Event audit logger (chain_of_custody.json)
│   ├── hasher.py                       # 64KB chunked SHA-256 calculation & verification
│   └── metadata.py                     # Standardized metadata.json generator
├── acquisition/
│   ├── windows_acquisition.py          # Windows WinPmem driver implementation
│   ├── linux_acquisition.py            # Linux LiME / LinPmem driver implementation
│   └── demo_acquisition.py             # Fallback educational simulation generator
├── analysis/
│   ├── analyzer.py                     # Forensic result dataclass & interface
│   ├── basic_memory_analyzer.py        # Basic heuristic string scanner (Magic Bytes, Executable Strings, IPs/URLs)
│   ├── volatility_analyzer.py          # Volatility 3 wrapper with honest fallback
│   └── report_generator.py             # Responsive HTML & JSON report builder
├── evidence/                           # Secure evidence vault
│   └── CASE_YYYYMMDD_HHMMSS/
│       ├── memory.raw                  # Primary sealed memory dump (Read-Only)
│       ├── evidence_manifest.json      # Official evidence manifest
│       ├── chain_of_custody.json       # Chronological audit log
│       ├── metadata.json               # Environment & acquisition metadata
│       └── hash.txt                    # SHA-256 cryptographic seal
├── analysis_workspace/                 # Non-destructive working copy storage
│   └── CASE_YYYYMMDD_HHMMSS/
│       └── working_copy_memory.raw     # Replica examined by forensic tools
├── reports/                            # Generated HTML forensic reports
├── logs/memorymapper.log               # Centralized log records
└── tests/                              # Automated unit tests (20 passing tests)
```

---

## 8. Ethical & Legal Notice
> **DEFENSIVE CYBERSECURITY & FORENSICS ONLY:**
> MemoryMapper Lite is developed strictly for authorized educational research, defensive digital forensics, and authorized incident response. Memory acquisition must only be conducted on systems you own or have explicit written authorization to examine.
