# MemoryMapper Lite &mdash; Usage & Demonstration Guide

## 1. Running the Interactive CLI

Launch the interactive console menu:
```bash
python main.py
```

### Main Menu Options:

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

---

## 2. Command-Line Automation Flags

| Command | Action |
|---|---|
| `python main.py --info` | Prints system specifications, architecture, and privilege level. |
| `python main.py --acquire-real` | Initiates the primary real physical RAM acquisition workflow. |
| `python main.py --verify <case_id>` | Verifies cryptographic SHA-256 integrity and records verification in chain of custody. |
| `python main.py --custody <case_id>` | Prints the full chronological chain of custody audit log for a case. |
| `python main.py --demo` | Executes fallback automated demo acquisition, hashing, analysis, and report generation. |
| `python main.py --test` | Executes automated unit test suite. |

---

## 3. Step-by-Step Live Demonstration Walkthrough

### Step 1: Check System Diagnostics & Elevation
1. Choose **Option 1** (`System Information`).
2. Show the OS detection, architecture, Python version, RAM detection, and whether the terminal is running as Administrator/Root.

### Step 2: Acquire Real RAM (or Run Fallback Demo)
1. Choose **Option 2** (`Acquire Real Memory`).
   - If `winpmem.exe` is configured and running as Administrator, it captures live hardware memory into `evidence/CASE_YYYYMMDD_HHMMSS/memory.raw`.
   - If not configured, it honestly reports: `Acquisition tool is not configured.`
2. (Or choose **Option 7** for Demo/Test mode walkthrough).

### Step 3: Verify Evidence Integrity & Chain of Custody
1. Choose **Option 3** (`Verify Evidence Integrity`).
2. Select the case.
3. Observe status: `INTEGRITY VERIFIED (Match confirmed - Evidence pristine)`.
4. Choose **Option 6** (`View Chain of Custody`) to inspect the audit log containing all events from creation to verification.

### Step 4: Non-Destructive Analysis & HTML Report
1. Choose **Option 4** (`Analyze Memory Dump`). A working replica is established in `analysis_workspace/` preserving the original evidence file untouched.
2. Choose **Option 5** (`Generate Forensic Report`).
3. Open the generated report in `reports/` with any web browser.
