"""Forensic report generation module for MemoryMapper Lite.

Generates comprehensive, presentation-ready HTML reports and JSON artifacts
documenting the complete digital forensics chain of custody, evidence integrity,
manifest metadata, and memory analysis findings.
"""

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from config.config import APP_NAME, APP_SUBTITLE, APP_VERSION, REPORTS_DIR
from analysis.analyzer import ForensicAnalysisResult
from utils.logger import logger


class ReportGenerator:
    """Creates standalone HTML and JSON forensic reports."""

    @staticmethod
    def generate_html_report(
        case_metadata: Dict[str, Any],
        manifest: Optional[Dict[str, Any]] = None,
        custody_events: Optional[List[Dict[str, Any]]] = None,
        analysis_result: Optional[ForensicAnalysisResult] = None,
        integrity_status: str = "NOT VERIFIED",
        output_html_path: Optional[Path | str] = None,
    ) -> Path:
        """Builds a responsive, modern HTML forensic report."""
        case_id = case_metadata.get("case_id", "CASE_UNKNOWN")
        if not output_html_path:
            output_html_path = REPORTS_DIR / f"{case_id}_report.html"
        
        out_path = Path(output_html_path)

        # Extraction and sanitization
        mode = case_metadata.get("acquisition_mode", "REAL")
        is_demo = (mode == "DEMO")
        acq_status = case_metadata.get("acquisition_status", "UNKNOWN")
        os_name = html.escape(str(case_metadata.get("os", "Unknown")))
        arch = html.escape(str(case_metadata.get("architecture", "Unknown")))
        py_ver = html.escape(str(case_metadata.get("python_version", "Unknown")))
        dump_file = html.escape(str(case_metadata.get("dump_file", "None")))
        dump_size = case_metadata.get("dump_size_bytes", 0)
        sha256 = html.escape(str(case_metadata.get("sha256", "N/A")))
        tool_used = html.escape(str(case_metadata.get("tool_used", "N/A")))
        start_t = html.escape(str(case_metadata.get("acquisition_start", "N/A")))
        end_t = html.escape(str(case_metadata.get("acquisition_end", "N/A")))
        gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        evidence_id = manifest.get("evidence_id", f"EVD_{case_id}") if manifest else f"EVD_{case_id}"

        # Format sizes
        size_str = f"{dump_size:,} bytes"
        if dump_size > 1024 * 1024:
            size_str += f" ({round(dump_size / (1024 * 1024), 2)} MB)"

        # Integrity badge styling
        if integrity_status in ["INTEGRITY VERIFIED", "VALID"]:
            integrity_badge = '<span class="badge badge-success">✓ INTEGRITY VERIFIED (MATCHED)</span>'
        elif integrity_status in ["TAMPERING DETECTED", "MODIFIED"]:
            integrity_badge = '<span class="badge badge-danger">⚠ TAMPERING DETECTED (HASH MISMATCH)</span>'
        else:
            integrity_badge = f'<span class="badge badge-warning">{html.escape(integrity_status)}</span>'

        # Mode banner
        if is_demo:
            mode_badge = '<span class="badge badge-demo">DEMO / SIMULATION MODE (TEST ARTIFACT)</span>'
            demo_disclaimer = (
                '<div class="alert alert-warning">'
                '<strong>DEMO MODE NOTICE:</strong> This report represents an educational simulation test artifact. '
                'It was generated in a safe, non-privileged test environment and does NOT constitute real physical RAM capture.'
                '</div>'
            )
        else:
            mode_badge = '<span class="badge badge-primary">REAL PHYSICAL RAM ACQUISITION</span>'
            demo_disclaimer = ""

        # Status badge
        if acq_status == "SUCCESS":
            status_badge = '<span class="badge badge-success">ACQUISITION SUCCESSFUL</span>'
        else:
            status_badge = '<span class="badge badge-danger">ACQUISITION FAILED</span>'

        # Chain of custody rows
        custody_rows = ""
        if custody_events:
            for ev in custody_events:
                status_cls = "badge-success" if ev.get("status") in ["SUCCESS", "VALID", "PROTECTED"] else "badge-subtle"
                if ev.get("status") in ["TAMPERED", "FAILED"]:
                    status_cls = "badge-danger"
                custody_rows += f"""
                <tr>
                    <td><code>{html.escape(str(ev.get('event_id', 'N/A')))}</code></td>
                    <td>{html.escape(str(ev.get('timestamp', 'N/A'))[:19])}</td>
                    <td><strong>{html.escape(str(ev.get('event', 'N/A')))}</strong></td>
                    <td>{html.escape(str(ev.get('description', '')))}</td>
                    <td><span class="badge {status_cls}">{html.escape(str(ev.get('status', 'N/A')))}</span></td>
                </tr>
                """
        else:
            custody_rows = "<tr><td colspan='5' class='text-center text-muted'>No custody events logged.</td></tr>"

        # Analysis section building
        analysis_html = ""
        if analysis_result:
            analyzer_name = html.escape(analysis_result.analyzer_name)
            an_status = html.escape(analysis_result.status)
            notes = html.escape(analysis_result.summary_notes or "No summary notes provided.")

            # Process table
            proc_rows = ""
            for p in analysis_result.processes:
                proc_rows += f"""
                <tr>
                    <td><code>{p.get('pid', 'N/A')}</code></td>
                    <td><code>{p.get('ppid', 'N/A')}</code></td>
                    <td><strong>{html.escape(str(p.get('name', 'N/A')))}</strong></td>
                    <td>{p.get('threads', 'N/A')}</td>
                    <td><span class="badge badge-subtle">{html.escape(str(p.get('state', 'UNKNOWN')))}</span></td>
                </tr>
                """
            if not proc_rows:
                proc_rows = "<tr><td colspan='5' class='text-center text-muted'>No active process table artifacts resolved.</td></tr>"

            # Network connections
            net_rows = ""
            for n in analysis_result.network_connections:
                net_rows += f"""
                <tr>
                    <td><code>{html.escape(str(n.get('proto', 'TCP')))}</code></td>
                    <td><code>{html.escape(str(n.get('local_address', 'N/A')))}</code></td>
                    <td><code>{html.escape(str(n.get('remote_address', 'N/A')))}</code></td>
                    <td><span class="badge badge-subtle">{html.escape(str(n.get('state', 'N/A')))}</span></td>
                    <td>{html.escape(str(n.get('process_info', 'N/A')))}</td>
                </tr>
                """
            if not net_rows:
                net_rows = "<tr><td colspan='5' class='text-center text-muted'>No active network socket artifacts found.</td></tr>"

            # Signatures
            sig_list = "".join(f"<li>{html.escape(s)}</li>" for s in analysis_result.signatures_found) or "<li>None identified</li>"

            # Extracted strings
            urls_html = "".join(f"<li><code>{html.escape(u)}</code></li>" for u in analysis_result.extracted_strings.get("urls", [])) or "<li>None</li>"
            ips_html = "".join(f"<li><code>{html.escape(ip)}</code></li>" for ip in analysis_result.extracted_strings.get("ips", [])) or "<li>None</li>"
            cmds_html = "".join(f"<li><code>{html.escape(c)}</code></li>" for c in analysis_result.extracted_strings.get("commands", [])) or "<li>None</li>"

            # Limitations
            limitations_html = "".join(f"<li>{html.escape(l)}</li>" for l in analysis_result.errors_and_limitations) or "<li>None reported.</li>"

            analysis_html = f"""
            <section class="card">
                <div class="card-header">
                    <h2>5. Memory Forensics Analysis</h2>
                    <span class="badge badge-subtle">{analyzer_name} | Status: {an_status}</span>
                </div>
                <div class="card-body">
                    <p class="summary-text">{notes}</p>
                    
                    <h3>Detected Signatures & Headers</h3>
                    <ul>{sig_list}</ul>

                    <h3>Extracted Process Artifacts ({len(analysis_result.processes)})</h3>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr><th>PID</th><th>PPID</th><th>Process Name</th><th>Threads</th><th>State</th></tr>
                            </thead>
                            <tbody>
                                {proc_rows}
                            </tbody>
                        </table>
                    </div>

                    <h3>Network Socket Artifacts ({len(analysis_result.network_connections)})</h3>
                    <div class="table-container">
                        <table>
                            <thead>
                                <tr><th>Proto</th><th>Local Address</th><th>Remote Address</th><th>State</th><th>Process</th></tr>
                            </thead>
                            <tbody>
                                {net_rows}
                            </tbody>
                        </table>
                    </div>

                    <h3>Extracted Strings & Network IOCs</h3>
                    <div class="grid grid-3">
                        <div class="sub-card">
                            <h4>IP Addresses ({len(analysis_result.extracted_strings.get("ips", []))})</h4>
                            <ul class="compact-list">{ips_html}</ul>
                        </div>
                        <div class="sub-card">
                            <h4>URLs ({len(analysis_result.extracted_strings.get("urls", []))})</h4>
                            <ul class="compact-list">{urls_html}</ul>
                        </div>
                        <div class="sub-card">
                            <h4>Commands & Environment</h4>
                            <ul class="compact-list">{cmds_html}</ul>
                        </div>
                    </div>

                    <h3>Limitations & Analysis Notes</h3>
                    <ul class="warning-list">{limitations_html}</ul>
                </div>
            </section>
            """
        else:
            analysis_html = """
            <section class="card">
                <div class="card-header">
                    <h2>5. Memory Forensics Analysis</h2>
                </div>
                <div class="card-body">
                    <p class="text-muted">Forensic analysis has not yet been executed for this evidence bundle. You can run Option 4 in the CLI to perform analysis.</p>
                </div>
            </section>
            """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DFIR Forensic Report - {case_id}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-card: #1f242d;
            --border-color: #30363d;
            --text-primary: #f0f6fc;
            --text-secondary: #8b949e;
            --accent: #58a6ff;
            --success: #3fb950;
            --warning: #d29922;
            --danger: #f85149;
            --demo: #a371f7;
            --font-main: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            --font-mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: var(--font-main);
            line-height: 1.6;
            padding: 2rem 1rem;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        header {{
            background: linear-gradient(135deg, #161b22 0%, #1c2333 100%);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 8px 24px rgba(0,0,0,0.4);
        }}
        .header-title-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
            margin-bottom: 0.5rem;
        }}
        h1 {{ font-size: 1.8rem; color: var(--accent); }}
        .subtitle {{ color: var(--text-secondary); font-size: 1rem; margin-bottom: 1rem; }}
        .badge-group {{ display: flex; gap: 0.5rem; flex-wrap: wrap; }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .badge-primary {{ background: rgba(88, 166, 255, 0.2); color: var(--accent); border: 1px solid var(--accent); }}
        .badge-success {{ background: rgba(63, 185, 80, 0.2); color: var(--success); border: 1px solid var(--success); }}
        .badge-danger {{ background: rgba(248, 81, 73, 0.2); color: var(--danger); border: 1px solid var(--danger); }}
        .badge-warning {{ background: rgba(210, 153, 34, 0.2); color: var(--warning); border: 1px solid var(--warning); }}
        .badge-demo {{ background: rgba(163, 113, 247, 0.2); color: var(--demo); border: 1px solid var(--demo); }}
        .badge-subtle {{ background: #21262d; color: var(--text-secondary); border: 1px solid var(--border-color); }}
        
        .alert {{
            padding: 1rem 1.25rem;
            border-radius: 8px;
            margin: 1.5rem 0;
            font-size: 0.9rem;
        }}
        .alert-warning {{
            background: rgba(210, 153, 34, 0.15);
            border: 1px solid var(--warning);
            color: #e3b341;
        }}
        
        .card {{
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            margin-bottom: 2rem;
            overflow: hidden;
        }}
        .card-header {{
            background-color: var(--bg-card);
            padding: 1rem 1.5rem;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .card-header h2 {{ font-size: 1.2rem; color: var(--text-primary); }}
        .card-body {{ padding: 1.5rem; }}

        .grid {{ display: grid; gap: 1.5rem; }}
        .grid-2 {{ grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); }}
        .grid-3 {{ grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }}

        .meta-list {{ list-style: none; }}
        .meta-list li {{
            display: flex;
            justify-content: space-between;
            padding: 0.6rem 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            font-size: 0.9rem;
        }}
        .meta-list li span.label {{ color: var(--text-secondary); }}
        .meta-list li span.val {{ color: var(--text-primary); font-weight: 500; text-align: right; }}

        .table-container {{
            overflow-x: auto;
            margin: 1rem 0 1.5rem 0;
            border: 1px solid var(--border-color);
            border-radius: 6px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.88rem;
            text-align: left;
        }}
        th, td {{
            padding: 0.75rem 1rem;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: var(--bg-card);
            color: var(--text-secondary);
            font-weight: 600;
        }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover {{ background-color: rgba(255,255,255,0.02); }}

        code {{
            font-family: var(--font-mono);
            background-color: rgba(110, 118, 129, 0.2);
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            font-size: 0.85em;
            word-break: break-all;
        }}
        .hash-code {{
            color: #58a6ff;
            font-weight: 600;
            letter-spacing: 0.5px;
        }}

        .sub-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1rem;
        }}
        .sub-card h4 {{ font-size: 0.95rem; margin-bottom: 0.5rem; color: var(--accent); }}
        .compact-list {{ list-style: none; font-size: 0.85rem; max-height: 200px; overflow-y: auto; }}
        .compact-list li {{ padding: 0.25rem 0; }}
        .warning-list {{ margin-left: 1.5rem; color: var(--text-secondary); font-size: 0.88rem; }}
        .summary-text {{ margin-bottom: 1rem; color: #c9d1d9; font-size: 0.95rem; }}

        footer {{
            text-align: center;
            padding: 2rem 0;
            color: var(--text-secondary);
            font-size: 0.85rem;
            border-top: 1px solid var(--border-color);
            margin-top: 2rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title-row">
                <h1>{APP_NAME} &bull; Forensic Investigation Report</h1>
                <div class="badge-group">
                    {mode_badge}
                    {status_badge}
                </div>
            </div>
            <div class="subtitle">{APP_SUBTITLE} &bull; v{APP_VERSION}</div>
            <p style="color: var(--text-secondary); font-size: 0.85rem;">Generated on: {gen_time} | Authorized DFIR Examination Record</p>
            {demo_disclaimer}
        </header>

        <!-- Case & System Metadata -->
        <div class="grid grid-2">
            <section class="card">
                <div class="card-header">
                    <h2>1. Case Information</h2>
                </div>
                <div class="card-body">
                    <ul class="meta-list">
                        <li><span class="label">Case ID</span><span class="val"><code>{case_id}</code></span></li>
                        <li><span class="label">Evidence ID</span><span class="val"><code>{evidence_id}</code></span></li>
                        <li><span class="label">Acquisition Mode</span><span class="val">{mode}</span></li>
                        <li><span class="label">Acquisition Tool</span><span class="val">{tool_used}</span></li>
                        <li><span class="label">Start Timestamp</span><span class="val">{start_t}</span></li>
                        <li><span class="label">End Timestamp</span><span class="val">{end_t}</span></li>
                        <li><span class="label">Status</span><span class="val">{acq_status}</span></li>
                    </ul>
                </div>
            </section>

            <section class="card">
                <div class="card-header">
                    <h2>2. Target System Environment</h2>
                </div>
                <div class="card-body">
                    <ul class="meta-list">
                        <li><span class="label">Operating System</span><span class="val">{os_name}</span></li>
                        <li><span class="label">Architecture</span><span class="val">{arch}</span></li>
                        <li><span class="label">Python Version</span><span class="val">{py_ver}</span></li>
                        <li><span class="label">Execution Privileges</span><span class="val">{"Administrator / Root" if case_metadata.get("is_admin") else "Standard User"}</span></li>
                        <li><span class="label">Report Timestamp</span><span class="val">{gen_time}</span></li>
                    </ul>
                </div>
            </section>
        </div>

        <!-- Evidence & Integrity -->
        <section class="card">
            <div class="card-header">
                <h2>3. Evidence Preservation &amp; Cryptographic Integrity</h2>
                {integrity_badge}
            </div>
            <div class="card-body">
                <ul class="meta-list">
                    <li><span class="label">Dump File Name</span><span class="val"><code>{dump_file}</code></span></li>
                    <li><span class="label">Evidence File Size</span><span class="val">{size_str}</span></li>
                    <li><span class="label">Cryptographic Hash (SHA-256)</span><span class="val"><code class="hash-code">{sha256}</code></span></li>
                    <li><span class="label">Verification Status</span><span class="val">{integrity_status}</span></li>
                    <li><span class="label">Evidence Storage Status</span><span class="val">Read-Only File Attribute Applied</span></li>
                </ul>
                <div style="margin-top: 1rem; font-size: 0.85rem; color: var(--text-secondary); line-height: 1.6;">
                    <p><strong>Chain of Custody &amp; Tamper Detection:</strong></p>
                    <ul style="margin-left: 1.2rem; margin-top: 0.3rem;">
                        <li><strong>SHA-256 Hashing:</strong> Detects whether the evidence has been modified or corrupted after acquisition. (Note: Hashing mathematically <em>detects</em> changes; it does not physically prevent modification).</li>
                        <li><strong>Read-Only Storage:</strong> Software-level protection prevents accidental overwriting by applications during examination.</li>
                        <li><strong>Working Copy Policy:</strong> Analysis is performed on replicated working copies in <code>analysis_workspace/</code> to preserve primary evidence untouched.</li>
                    </ul>
                </div>
            </div>
        </section>

        <!-- Chain of Custody Audit Trail -->
        <section class="card">
            <div class="card-header">
                <h2>4. Chain-of-Custody Audit Trail</h2>
                <span class="badge badge-subtle">{len(custody_events or [])} Recorded Events</span>
            </div>
            <div class="card-body">
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>Event ID</th>
                                <th>Timestamp</th>
                                <th>Event Type</th>
                                <th>Description</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {custody_rows}
                        </tbody>
                    </table>
                </div>
            </div>
        </section>

        <!-- Analysis Section -->
        {analysis_html}

        <!-- Conclusion & Disclaimer -->
        <section class="card">
            <div class="card-header">
                <h2>6. Forensic Conclusion &amp; Chain of Custody Declaration</h2>
            </div>
            <div class="card-body">
                <p class="summary-text">
                    This digital forensics report was automatically generated by <strong>{APP_NAME}</strong>. 
                    Evidence acquisition, SHA-256 cryptographic sealing, chain-of-custody logging, and preliminary artifact extraction have been performed in accordance with digital forensics standards (ISO/IEC 27037).
                </p>
                <p style="font-size: 0.85rem; color: var(--text-secondary);">
                    <strong>Ethics &amp; Legal Compliance:</strong> This software is intended strictly for authorized educational research, defensive security operations, and legitimate incident response. Unauthorized acquisition of digital memory from systems without explicit consent is illegal.
                </p>
            </div>
        </section>

        <footer>
            <p>{APP_NAME} &bull; College Digital Forensics & Incident Response (DFIR) Mini-Project</p>
            <p style="margin-top: 0.3rem;">Real RAM Acquisition &bull; Chain of Custody &bull; Standalone Offline Architecture</p>
        </footer>
    </div>
</body>
</html>
"""
        out_path.write_text(html_content, encoding="utf-8")
        logger.info(f"Generated HTML forensic report at: {out_path}")
        return out_path

    @staticmethod
    def generate_json_report(
        case_metadata: Dict[str, Any],
        manifest: Optional[Dict[str, Any]] = None,
        custody_events: Optional[List[Dict[str, Any]]] = None,
        analysis_result: Optional[ForensicAnalysisResult] = None,
        integrity_status: str = "NOT VERIFIED",
        output_json_path: Optional[Path | str] = None,
    ) -> Path:
        """Saves a structured JSON report artifact in the case folder."""
        case_id = case_metadata.get("case_id", "CASE_UNKNOWN")
        if not output_json_path:
            output_json_path = REPORTS_DIR / f"{case_id}_report.json"
        
        out_path = Path(output_json_path)

        data = {
            "app_name": APP_NAME,
            "version": APP_VERSION,
            "report_generated_at": datetime.now().isoformat(),
            "case_metadata": case_metadata,
            "evidence_manifest": manifest,
            "integrity_status": integrity_status,
            "chain_of_custody_events": custody_events or [],
            "analysis": analysis_result.to_dict() if analysis_result else None,
        }

        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)

        logger.info(f"Generated JSON forensic report at: {out_path}")
        return out_path
