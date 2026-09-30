# MemoryMapper Lite &mdash; Installation & Prerequisites Guide

## Quick Summary Checklist

| Question | Answer |
|---|---|
| **Is Python required?** | **YES** (Python 3.10, 3.11, 3.12, 3.13, or 3.14+) |
| **Are Python packages mandatory?** | **NO** (The core operates 100% on Python Standard Library) |
| **Is an external memory acquisition tool required?** | **YES for Real RAM Acquisition** (WinPmem on Windows / LiME or LinPmem on Linux). **Demo mode requires none.** |
| **Are administrator/root privileges required?** | **YES for Real RAM Acquisition** (required by kernel drivers). Standard user privileges suffice for Demo Mode, Verification, Analysis, and Reporting. |
| **Is Volatility 3 required?** | **OPTIONAL** (Built-in Heuristic Analyzer runs automatically without Volatility) |
| **Is Internet access required?** | **NO** (100% local and offline) |
| **Is an API key required?** | **NO** (Explicitly zero API keys needed) |

---

## 1. Environment Requirements

### Python
MemoryMapper Lite requires **Python 3.10 or newer**.
Check your version:
```bash
python --version
```

---

## 2. Real Physical RAM Acquisition Setup (Primary Workflow)

Physical RAM capture requires kernel-level access. Operating systems enforce strict kernel protection (Kernel Patch Protection / SMEP / KASLR), so authorized signed drivers/tools are required:

### Windows
1. **Tool**: [Velocidex WinPmem](https://github.com/Velocidex/WinPmem/releases) (e.g. `winpmem_mini_x64.exe`).
2. **Setup**:
   - Download the signed executable.
   - Rename to `winpmem.exe` and place it in the project root directory, or add it to your system `PATH`, or set the `WINPMEM_PATH` environment variable.
3. **Privileges**: Launch your terminal/IDE as **Administrator**.

### Linux
1. **Tool**: [LiME (Linux Memory Extractor)](https://github.com/504ensicsLabs/LiME) or [LinPmem](https://github.com/Velocidex/c-aff4/releases).
2. **Setup**:
   - For LiME: Compile against your kernel headers (`make`).
   - Place `lime.ko` in the project folder or configure `LIME_MODULE_PATH` in `config/config.py`.
3. **Privileges**: Execute MemoryMapper Lite with `sudo python main.py`.

---

## 3. Demo / Educational Simulation Mode (Fallback Only)

If you are evaluating the project in a restricted classroom lab, running automated test suites, or lack administrator permissions:
- **No drivers, kernel modules, or administrator rights are needed.**
- Select **Option 7** in the interactive menu or run `python main.py --demo`.
- Generates realistic, structured forensic test artifacts and demonstrates the entire DFIR lifecycle without faking hardware RAM capture.
