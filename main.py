"""MemoryMapper Lite - Entry point and interactive CLI menu.

A lightweight, real-first cross-platform RAM acquisition and memory forensics tool.
"""

import argparse
import sys
import unittest
from pathlib import Path
from typing import Optional

from config.config import APP_NAME, APP_SUBTITLE, APP_VERSION, EVIDENCE_DIR, REPORTS_DIR, WORKSPACE_DIR
from core.acquisition import AcquisitionManager
from core.chain_of_custody import ChainOfCustody
from core.evidence_integrity import EvidenceIntegrity
from core.evidence_manager import CaseEvidence, EvidenceManager
from core.hasher import Hasher
from core.metadata import CaseMetadata
from core.system_detector import SystemDetector
from acquisition.demo_acquisition import DemoAcquisition
from acquisition.linux_acquisition import LinuxAcquisition
from acquisition.windows_acquisition import WindowsAcquisition
from analysis.basic_memory_analyzer import BasicMemoryAnalyzer
from analysis.volatility_analyzer import VolatilityAnalyzer
from analysis.report_generator import ReportGenerator
from utils.logger import logger


def print_banner():
    """Prints the application header banner."""
    print("=" * 60)
    print(f"        {APP_NAME.upper()} (v{APP_VERSION})")
    print(f"   {APP_SUBTITLE}")
    print("=" * 60)


def print_menu():
    """Displays the main interactive menu options."""
    print("\n" + "-" * 40)
    print("           MAIN MENU")
    print("-" * 40)
    print("1. System Information")
    print("2. Acquire Real Memory")
    print("3. Verify Evidence Integrity")
    print("4. Analyze Memory Dump")
    print("5. Generate Forensic Report")
    print("6. View Chain of Custody")
    print("7. Demo/Test Mode")
    print("8. Run Automated Self-Tests")
    print("9. Exit")
    print("-" * 40)


def menu_system_info():
    """Menu Option 1: Display system environment."""
    SystemDetector.print_system_info()
    vol_analyzer = VolatilityAnalyzer()
    installed, vol_path = vol_analyzer.is_volatility_installed()
    print("Forensic Analysis Tool Check:")
    if installed:
        print(f"  [+] Volatility 3: INSTALLED ({vol_path})")
    else:
        print("  [-] Volatility 3: NOT INSTALLED (Optional - Basic heuristic analyzer will be used)")
    
    os_type = SystemDetector.get_os_type()
    if os_type == "Windows":
        win_acq = WindowsAcquisition()
        win_exe = win_acq.find_executable()
        if win_exe:
            print(f"  [+] WinPmem Acquisition Utility: CONFIGURED ({win_exe})")
        else:
            print("  [-] WinPmem Acquisition Utility: NOT CONFIGURED (Required for Real RAM capture)")
    elif os_type == "Linux":
        lin_acq = LinuxAcquisition()
        ready, msg = lin_acq.check_prerequisites()
        print(f"  [{'+' if ready else '-'}] LiME / LinPmem: {msg}")


def menu_acquire_real_memory():
    """Menu Option 2: Real RAM acquisition."""
    print("\n" + "=" * 55)
    print("        [PRIMARY WORKFLOW: REAL MEMORY ACQUISITION]")
    print("=" * 55)
    os_type = SystemDetector.get_os_type()
    is_admin = SystemDetector.is_admin()

    if not is_admin:
        print("\n[!] ELEVATION ERROR: Administrator/Root privileges are REQUIRED for real physical RAM capture.")
        print("    Current privilege level: Standard User (Non-elevated).")
        print("    Kernel-level memory acquisition drivers cannot be loaded without administrative rights.")
        print("\nTo fix this:")
        if os_type == "Windows":
            print("  -> Right-click your terminal or IDE and select 'Run as Administrator'.")
        else:
            print("  -> Run this application using 'sudo python main.py'.")
        print("\nTip: If you only want to test the rest of the application without admin rights,")
        print("     please use Option 7 (Demo/Test Mode).")
        return

    if os_type == "Windows":
        driver = WindowsAcquisition()
    elif os_type == "Linux":
        driver = LinuxAcquisition()
    else:
        print(f"[!] Unsupported OS platform for physical acquisition: {os_type}")
        return

    # Check tool configuration
    ready, prereq_msg = driver.check_prerequisites()
    if not ready:
        print(f"\n[-] Acquisition tool is not configured.")
        print(f"    Details: {prereq_msg}")
        return

    manager = AcquisitionManager(driver, mode="REAL")
    custom_id = input("Enter custom Case ID (leave blank for auto-generated CASE_YYYYMMDD_HHMMSS): ").strip()
    
    print("\n[*] Initializing real RAM acquisition pipeline...")
    success, msg, meta = manager.run_workflow(custom_case_id=custom_id or None)
    
    if success:
        case_id = meta.get("case_id")
        case_dir = EVIDENCE_DIR / case_id
        print(f"\n[+] SUCCESS! Real physical RAM dump acquired and cryptographically sealed.")
        print(f"    Case ID          : {case_id}")
        print(f"    Dump File        : {meta.get('dump_file')}")
        print(f"    Evidence Size    : {meta.get('dump_size_bytes'):,} bytes")
        print(f"    SHA-256 Hash     : {meta.get('sha256')}")
        print(f"    Evidence Vault   : {case_dir}")
        print(f"    Evidence Manifest: {case_dir / 'evidence_manifest.json'}")
        print(f"    Chain of Custody : {case_dir / 'chain_of_custody.json'}")
    else:
        print(f"\n[-] Real RAM Acquisition FAILED: {msg}")


def menu_verify_evidence():
    """Menu Option 3: SHA-256 evidence integrity verification."""
    print("\n--- [VERIFY EVIDENCE INTEGRITY & TAMPER DETECTION] ---")
    cases = EvidenceManager.list_all_cases()
    if not cases:
        print("[-] No evidence cases found in evidence directory.")
        return

    print("Available Evidence Cases:")
    for idx, c in enumerate(cases, 1):
        print(f"  {idx}. {c.case_id}")

    choice = input("\nSelect case number or enter Case ID: ").strip()
    selected_case: Optional[CaseEvidence] = None

    if choice.isdigit() and 1 <= int(choice) <= len(cases):
        selected_case = cases[int(choice) - 1]
    else:
        selected_case = EvidenceManager.get_case_by_id(choice)

    if not selected_case:
        print("[-] Case not found.")
        return

    print(f"\n[*] Reading evidence manifest and calculating current SHA-256 for: {selected_case.case_id}...")
    status, cur_hash, exp_hash, details = EvidenceIntegrity.verify_case_integrity(selected_case.case_dir)

    print("\n" + "=" * 55)
    print("         EVIDENCE INTEGRITY VERIFICATION REPORT")
    print("=" * 55)
    print(f"Case Directory   : {selected_case.case_dir}")
    print(f"Recorded Baseline: {exp_hash}")
    print(f"Current Checksum : {cur_hash}")
    print("-" * 55)
    if status == "INTEGRITY VERIFIED":
        print(f"Verification Status : [+] INTEGRITY VERIFIED (Match confirmed - Evidence pristine)")
    elif status == "TAMPERING DETECTED":
        print(f"Verification Status : [!] TAMPERING DETECTED (MISMATCH! File has been altered)")
    else:
        print(f"Verification Status : [-] ERROR: {details}")
    print("-" * 55)
    print("Note: SHA-256 mathematically detects changes in evidence; it does not physically prevent modification.")
    print("      Verification event has been logged to chain_of_custody.json.")
    print("=" * 55)


def menu_analyze_memory():
    """Menu Option 4: Non-destructive memory dump analysis via working copy."""
    print("\n--- [NON-DESTRUCTIVE FORENSIC MEMORY ANALYSIS] ---")
    cases = EvidenceManager.list_all_cases()
    if not cases:
        print("[-] No evidence cases found.")
        return

    for idx, c in enumerate(cases, 1):
        print(f"  {idx}. {c.case_id}")

    choice = input("\nSelect case number to analyze: ").strip()
    selected_case: Optional[CaseEvidence] = None
    if choice.isdigit() and 1 <= int(choice) <= len(cases):
        selected_case = cases[int(choice) - 1]
    else:
        selected_case = EvidenceManager.get_case_by_id(choice)

    if not selected_case or not selected_case.dump_file:
        print("[-] Target memory dump file not found for this case.")
        return

    # Step 1: Create non-destructive working copy in analysis_workspace/
    print(f"\n[*] Creating safe non-destructive analysis working copy...")
    ok_copy, working_dump, copy_msg = EvidenceIntegrity.create_analysis_working_copy(
        original_dump_path=selected_case.dump_file,
        case_id=selected_case.case_id,
    )
    if not ok_copy or not working_dump:
        print(f"[-] Failed to establish working copy: {copy_msg}")
        return

    coc = selected_case.get_custody()
    manifest = selected_case.get_manifest()
    ev_id = manifest.get("evidence_id", selected_case.case_id) if manifest else selected_case.case_id

    coc.add_event(
        event_type="WORKING_COPY_CREATED",
        evidence_id=ev_id,
        description=f"Non-destructive replica created in analysis_workspace/{selected_case.case_id}/ for analysis.",
        status="SUCCESS",
        details={"workspace_path": str(working_dump)},
    )

    print("\nSelect Analysis Engine:")
    print("1. Basic Heuristic Artifact Engine (Zero-Dependency Strings, Headers & Signatures)")
    print("2. Volatility 3 Framework (Kernel Symbol Analysis)")
    an_choice = input("Enter choice (default=1): ").strip()

    if an_choice == "2":
        analyzer = VolatilityAnalyzer()
    else:
        analyzer = BasicMemoryAnalyzer()

    print(f"\n[*] Running {analyzer.name} against working copy: {working_dump.name}...")
    res = analyzer.analyze(working_dump)

    coc.add_event(
        event_type="ANALYSIS_COMPLETED",
        evidence_id=ev_id,
        description=f"Forensic analysis completed via {analyzer.name}. Status: {res.status}",
        status=res.status,
    )

    print("\n" + "=" * 55)
    print(f"         FORENSIC ANALYSIS FINDINGS")
    print("=" * 55)
    print(f"Analysis Engine  : {analyzer.name}")
    print(f"Status           : {res.status}")
    if res.status == "NOT AVAILABLE":
        print(f"Notice           : Advanced forensic analysis unavailable.")
        for err in res.errors_and_limitations:
            print(f"  - {err}")
    else:
        print(f"Signatures Found : {', '.join(res.signatures_found) if res.signatures_found else 'None'}")
        print(f"Processes Found  : {len(res.processes)}")
        print(f"Sockets Found    : {len(res.network_connections)}")
        print(f"Summary Notes    : {res.summary_notes}")
        if res.errors_and_limitations:
            print("\nLimitations / Notes:")
            for err in res.errors_and_limitations:
                print(f"  - {err}")

        if res.processes:
            print("\nProcess Artifacts Discovered:")
            print(f"  {'PID':<6} {'PPID':<6} {'Process Name':<20} {'State':<15}")
            print("  " + "-" * 50)
            for p in res.processes[:8]:
                print(f"  {str(p.get('pid')):<6} {str(p.get('ppid')):<6} {str(p.get('name')):<20} {str(p.get('state')):<15}")

        if res.network_connections:
            print("\nNetwork Sockets Discovered:")
            for n in res.network_connections[:5]:
                print(f"  [{n.get('proto')}] {n.get('local_address')} -> {n.get('remote_address')} ({n.get('state')})")
    print("=" * 55)

    # Save to report JSON
    rep_path = selected_case.case_dir / "forensic_analysis.json"
    import json
    with open(rep_path, "w", encoding="utf-8") as f:
        json.dump(res.to_dict(), f, indent=4)
    print(f"\n[+] Analysis results saved to: {rep_path}")


def menu_generate_report():
    """Menu Option 5: Build HTML & JSON forensic report."""
    print("\n--- [GENERATE COMPREHENSIVE FORENSIC REPORT] ---")
    cases = EvidenceManager.list_all_cases()
    if not cases:
        print("[-] No cases available.")
        return

    for idx, c in enumerate(cases, 1):
        print(f"  {idx}. {c.case_id}")

    choice = input("\nSelect case number: ").strip()
    selected_case: Optional[CaseEvidence] = None
    if choice.isdigit() and 1 <= int(choice) <= len(cases):
        selected_case = cases[int(choice) - 1]
    else:
        selected_case = EvidenceManager.get_case_by_id(choice)

    if not selected_case:
        print("[-] Case not found.")
        return

    meta = selected_case.get_metadata() or {}
    manifest = selected_case.get_manifest()
    coc = selected_case.get_custody()
    
    # Run or load analysis
    analysis_res = None
    if selected_case.dump_file and selected_case.dump_file.exists():
        print("[*] Extracting forensic artifacts for report...")
        analyzer = BasicMemoryAnalyzer()
        analysis_res = analyzer.analyze(selected_case.dump_file)

    # Check integrity
    print("[*] Performing verification check for report summary...")
    st, _, _, _ = EvidenceIntegrity.verify_case_integrity(selected_case.case_dir)

    html_path = ReportGenerator.generate_html_report(
        case_metadata=meta,
        manifest=manifest,
        custody_events=coc.get_events(),
        analysis_result=analysis_res,
        integrity_status=st,
    )
    json_path = ReportGenerator.generate_json_report(
        case_metadata=meta,
        manifest=manifest,
        custody_events=coc.get_events(),
        analysis_result=analysis_res,
        integrity_status=st,
        output_json_path=selected_case.case_dir / "forensic_report.json",
    )

    ev_id = manifest.get("evidence_id", selected_case.case_id) if manifest else selected_case.case_id
    coc.add_event(
        event_type="REPORT_GENERATED",
        evidence_id=ev_id,
        description=f"Investigation reports generated (HTML: {html_path.name}, JSON: forensic_report.json).",
        status="SUCCESS",
    )

    print(f"\n[+] Forensic Reports generated successfully!")
    print(f"    HTML Report : {html_path.resolve()}")
    print(f"    JSON Report : {json_path.resolve()}")


def menu_view_chain_of_custody():
    """Menu Option 6: View chronological chain of custody."""
    print("\n--- [CHAIN OF CUSTODY AUDIT TRAIL] ---")
    cases = EvidenceManager.list_all_cases()
    if not cases:
        print("[-] No evidence cases found.")
        return

    print("Available Cases:")
    for idx, c in enumerate(cases, 1):
        print(f"  {idx}. {c.case_id}")

    choice = input("\nSelect case number: ").strip()
    selected_case: Optional[CaseEvidence] = None
    if choice.isdigit() and 1 <= int(choice) <= len(cases):
        selected_case = cases[int(choice) - 1]
    else:
        selected_case = EvidenceManager.get_case_by_id(choice)

    if not selected_case:
        print("[-] Case not found.")
        return

    coc = selected_case.get_custody()
    print("\n" + "=" * 75)
    print(f"       CHAIN OF CUSTODY LOG: {selected_case.case_id}")
    print("=" * 75)
    print(coc.get_summary_text())
    print("=" * 75)


def menu_run_demo():
    """Menu Option 7: Safe fallback demo mode."""
    print("\n" + "=" * 65)
    print("               DEMO / TEST MODE (SIMULATION FALLBACK)")
    print("       *** NOTICE: THIS IS A SAFE TEST ARTIFACT ***")
    print("       *** NOT A REAL PHYSICAL HARDWARE MEMORY DUMP ***")
    print("=" * 65)

    # 1. Acquisition
    print("\n[Step 1/5] Generating Simulated Memory Image...")
    demo_driver = DemoAcquisition()
    manager = AcquisitionManager(demo_driver, mode="DEMO")
    success, msg, meta = manager.run_workflow()
    
    if not success:
        print(f"[-] Demo acquisition failed: {msg}")
        return

    case_id = meta.get("case_id")
    case_evidence = EvidenceManager.get_case_by_id(case_id)
    print(f"[+] Demo memory dump generated: {meta.get('dump_file')}")
    print(f"    Evidence Directory: {case_evidence.case_dir}")

    # 2. Cryptographic sealing
    print("\n[Step 2/5] Cryptographic Sealing (SHA-256)...")
    print(f"[+] SHA-256 Calculated: {meta.get('sha256')}")

    # 3. Integrity Verification
    print("\n[Step 3/5] Verifying Evidence Chain of Custody...")
    status, cur, exp, _ = EvidenceIntegrity.verify_case_integrity(case_evidence.case_dir)
    print(f"[+] Integrity Status: {status}")

    # 4. Forensic Analysis
    print("\n[Step 4/5] Executing Heuristic Artifact & Process Analysis...")
    analyzer = BasicMemoryAnalyzer()
    res = analyzer.analyze(case_evidence.dump_file)
    print(f"[+] Discovered {len(res.processes)} process artifacts and {len(res.network_connections)} network sockets.")

    # 5. Report Generation
    print("\n[Step 5/5] Compiling Comprehensive HTML & JSON Forensic Reports...")
    html_path = ReportGenerator.generate_html_report(
        case_metadata=meta,
        manifest=case_evidence.get_manifest(),
        custody_events=case_evidence.get_custody().get_events(),
        analysis_result=res,
        integrity_status=status,
    )
    json_path = ReportGenerator.generate_json_report(
        case_metadata=meta,
        manifest=case_evidence.get_manifest(),
        custody_events=case_evidence.get_custody().get_events(),
        analysis_result=res,
        integrity_status=status,
        output_json_path=case_evidence.case_dir / "forensic_report.json",
    )
    print(f"[+] HTML Report generated: {html_path.resolve()}")
    print(f"[+] JSON Report generated: {json_path.resolve()}")

    print("\n" + "=" * 65)
    print("      DEMO WALKTHROUGH COMPLETED SUCCESSFULLY!")
    print("=" * 65)


def run_tests():
    """Runs automated unit test suite."""
    print("\n[*] Discovering and executing automated unit tests...")
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(Path(__file__).parent / "tests"), pattern="test_*.py")
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


def main():
    """Main program entry point with CLI argument support."""
    parser = argparse.ArgumentParser(description=f"{APP_NAME} - {APP_SUBTITLE}")
    parser.add_argument("--acquire-real", action="store_true", help="Execute real memory acquisition workflow")
    parser.add_argument("--demo", action="store_true", help="Execute fallback demo simulation workflow")
    parser.add_argument("--info", action="store_true", help="Print system information and exit")
    parser.add_argument("--test", action="store_true", help="Run automated test suite and exit")
    parser.add_argument("--verify", type=str, help="Verify integrity for a given Case ID")
    parser.add_argument("--custody", type=str, help="View chain of custody for a given Case ID")
    args = parser.parse_args()

    if args.info:
        menu_system_info()
        sys.exit(0)
    elif args.acquire_real:
        menu_acquire_real_memory()
        sys.exit(0)
    elif args.demo:
        menu_run_demo()
        sys.exit(0)
    elif args.test:
        success = run_tests()
        sys.exit(0 if success else 1)
    elif args.verify:
        case = EvidenceManager.get_case_by_id(args.verify)
        if not case:
            print(f"[-] Case not found: {args.verify}")
            sys.exit(1)
        st, cur, exp, desc = EvidenceIntegrity.verify_case_integrity(case.case_dir)
        print(f"Status: {st} | Current: {cur} | Expected: {exp}")
        print(f"Details: {desc}")
        sys.exit(0 if st == "INTEGRITY VERIFIED" else 1)
    elif args.custody:
        case = EvidenceManager.get_case_by_id(args.custody)
        if not case:
            print(f"[-] Case not found: {args.custody}")
            sys.exit(1)
        coc = case.get_custody()
        print(coc.get_summary_text())
        sys.exit(0)

    print_banner()

    while True:
        try:
            print_menu()
            choice = input("Enter your choice (1-9): ").strip()

            if choice == "1":
                menu_system_info()
            elif choice == "2":
                menu_acquire_real_memory()
            elif choice == "3":
                menu_verify_evidence()
            elif choice == "4":
                menu_analyze_memory()
            elif choice == "5":
                menu_generate_report()
            elif choice == "6":
                menu_view_chain_of_custody()
            elif choice == "7":
                menu_run_demo()
            elif choice == "8":
                run_tests()
            elif choice == "9":
                print("\n[*] Exiting MemoryMapper Lite. Goodbye!")
                break
            else:
                print("\n[!] Invalid selection. Please enter a number between 1 and 9.")
        except KeyboardInterrupt:
            print("\n\n[*] Session interrupted by user. Exiting.")
            break
        except Exception as e:
            logger.exception(f"Unexpected error in CLI loop: {e}")
            print(f"\n[!] An error occurred: {e}")


if __name__ == "__main__":
    main()
