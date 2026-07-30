#!/opt/pipeline/venv/bin/python
"""
generate-report.py — Render a pipeline analysis report as PDF.

Reads the merged JSON report from the pipeline and produces a formatted
PDF using WeasyPrint. Each finding is attributed to the pipeline stage
that surfaced it (Triage, Cape, Volatility, Ghidra, or AI Reverse Engineering).

Usage:
    generate-report.py <report.json> [output.pdf]

If output path is not given, writes to <report_dir>/report.pdf.

Author: Christopher Shaiman
License: Apache 2.0
"""

import json
import sys
from datetime import datetime
from pathlib import Path

import markdown as md
from weasyprint import CSS, HTML

# ---------------------------------------------------------------------------
# Source attribution badges — each finding tagged with originating stage
# ---------------------------------------------------------------------------

SOURCE_COLORS = {
    "Triage": "#2196f3",
    "Cape": "#ff9800",
    "Volatility": "#9c27b0",
    "Ghidra": "#4caf50",
    "AI Reverse Engineering": "#e91e63",
    "Summary": "#607d8b",
}


# ---------------------------------------------------------------------------
# CSS stylesheet
# ---------------------------------------------------------------------------

CSS_STYLES = """
@page {
    size: A4;
    margin: 1.5cm 2cm;
    @bottom-center {
        content: "Page " counter(page) " of " counter(pages);
        font-size: 9px;
        color: #666;
    }
}

body {
    font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    font-size: 11px;
    line-height: 1.5;
    color: #1a1a1a;
}

h1 {
    font-size: 22px;
    color: #b22222;
    border-bottom: 3px solid #b22222;
    padding-bottom: 6px;
    margin-top: 0;
}

h2 {
    font-size: 16px;
    color: #333;
    border-bottom: 1px solid #ccc;
    padding-bottom: 4px;
    margin-top: 24px;
}

h3 {
    font-size: 13px;
    color: #444;
    margin-top: 16px;
}

.header-meta {
    background: #f5f5f5;
    border: 1px solid #ddd;
    border-radius: 4px;
    padding: 10px 14px;
    margin-bottom: 16px;
    font-size: 10px;
}

.header-meta td {
    padding: 2px 12px 2px 0;
    vertical-align: top;
}

.header-meta .label {
    font-weight: bold;
    color: #555;
    white-space: nowrap;
}

.severity {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 3px;
    font-weight: bold;
    font-size: 11px;
    text-transform: uppercase;
}

.severity-critical { background: #b22222; color: white; }
.severity-high { background: #e65100; color: white; }
.severity-medium { background: #f9a825; color: #333; }
.severity-low { background: #4caf50; color: white; }

.source-badge {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 3px;
    font-size: 8px;
    font-weight: bold;
    color: white;
    margin-right: 4px;
    vertical-align: middle;
}

.executive-summary {
    background: #fafafa;
    border-left: 4px solid #b22222;
    padding: 12px 16px;
    margin: 12px 0;
    font-size: 10.5px;
}

.ioc-table {
    width: 100%;
    border-collapse: collapse;
    margin: 8px 0;
    font-size: 10px;
}

.ioc-table th {
    background: #333;
    color: white;
    padding: 6px 8px;
    text-align: left;
    font-size: 10px;
}

.ioc-table td {
    border-bottom: 1px solid #ddd;
    padding: 4px 8px;
    word-break: break-all;
}

.ioc-table tr:nth-child(even) { background: #f9f9f9; }

.mitre-table {
    width: 100%;
    border-collapse: collapse;
    margin: 8px 0;
    font-size: 10px;
}

.mitre-table th {
    background: #1a237e;
    color: white;
    padding: 6px 8px;
    text-align: left;
}

.mitre-table td {
    border-bottom: 1px solid #ddd;
    padding: 4px 8px;
}

.mitre-table tr:nth-child(even) { background: #f5f5ff; }

.capability-list {
    list-style: none;
    padding-left: 0;
}

.capability-list li {
    padding: 3px 0;
    font-size: 10px;
}

.findings-list li {
    margin-bottom: 6px;
    font-size: 10px;
}

.actions-list li {
    margin-bottom: 6px;
    font-size: 10px;
}

.code-block {
    background: #1e1e1e;
    color: #d4d4d4;
    padding: 10px;
    border-radius: 4px;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 8.5px;
    line-height: 1.4;
    white-space: pre-wrap;
    word-break: break-all;
    overflow: hidden;
    margin: 6px 0;
}

.stage-header {
    background: #e8e8e8;
    padding: 4px 10px;
    border-radius: 3px;
    font-size: 10px;
    margin: 6px 0;
}

.yara-tag {
    display: inline-block;
    background: #ffecb3;
    border: 1px solid #ffc107;
    border-radius: 3px;
    padding: 1px 6px;
    margin: 1px 2px;
    font-size: 9px;
}

.footer-note {
    margin-top: 30px;
    padding-top: 10px;
    border-top: 1px solid #ccc;
    font-size: 9px;
    color: #888;
    text-align: center;
}

.stage-section {
    border-left: 3px solid #ccc;
    padding-left: 12px;
    margin: 10px 0;
}
"""


# ---------------------------------------------------------------------------
# HTML generation helpers
# ---------------------------------------------------------------------------

def escape_html(s: str) -> str:
    """Escape HTML special characters."""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def source_badge(source: str) -> str:
    """Render a colored source attribution badge."""
    color = SOURCE_COLORS.get(source, "#999")
    return f'<span class="source-badge" style="background: {color};">{escape_html(source)}</span>'


def render_markdown(text: str) -> str:
    """Convert markdown text to HTML for PDF rendering.

    If the text contains a JSON blob (from a failed parse_final_response),
    try to extract the narrative field from it.
    """
    import re as _re
    if not text:
        return ""
    text = str(text)

    # Check if this looks like it contains a JSON blob with a narrative key
    narr_idx = text.find('"narrative"')
    if narr_idx != -1:
        # Try JSON parse of the whole blob first
        first_brace = text.find("{")
        last_brace = text.rfind("}")
        if first_brace != -1 and last_brace > first_brace:
            try:
                parsed = json.loads(text[first_brace:last_brace + 1])
                if isinstance(parsed, dict) and "narrative" in parsed:
                    text = parsed["narrative"]
                    return md.markdown(text, extensions=["nl2br", "fenced_code"])
            except (json.JSONDecodeError, TypeError):
                pass

        # JSON broken — extract everything after "narrative": "
        match = _re.search(r'"narrative"\s*:\s*"', text)
        if match:
            start = match.end()
            extracted = []
            i = start
            while i < len(text):
                ch = text[i]
                if ch == '\\' and i + 1 < len(text):
                    next_ch = text[i + 1]
                    if next_ch == 'n':
                        extracted.append('\n')
                    elif next_ch == '"':
                        extracted.append('"')
                    elif next_ch == '\\':
                        extracted.append('\\')
                    else:
                        extracted.append(ch + next_ch)
                    i += 2
                elif ch == '"':
                    break
                else:
                    extracted.append(ch)
                    i += 1
            text = ''.join(extracted)

    return md.markdown(text, extensions=["nl2br", "fenced_code"])


def severity_badge(severity: str) -> str:
    """Render a colored severity badge."""
    s = severity.lower() if severity else "unknown"
    css_class = f"severity-{s}" if s in ("critical", "high", "medium", "low") else ""
    return f'<span class="severity {css_class}">{escape_html(s)}</span>'


# ---------------------------------------------------------------------------
# Report sections
# ---------------------------------------------------------------------------

def render_header(report: dict) -> str:
    """Render report header with sample metadata."""
    sample_name = report.get("sample_name", "unknown")
    task_id = report.get("task_id", "unknown")
    started = report.get("started_at", "")

    severity = (report.get("severity")
                or report.get("executive_summary", {}).get("severity")
                or report.get("llm_interpretation", {}).get("analysis", {}).get("risk_assessment")
                or "unknown")

    family = (report.get("family")
              or report.get("llm_interpretation", {}).get("analysis", {}).get("malware_family_guess")
              or "unknown")

    sha256 = "unknown"
    ghidra_files = report.get("ghidra", {}).get("analyzed_files", [])
    if ghidra_files:
        sha256 = ghidra_files[0].get("sha256", "unknown")

    triage = report.get("triage", {})
    file_type = triage.get("file_type", "unknown")

    return f"""
    <h1>Malware Analysis Report</h1>
    <table class="header-meta"><tr>
        <td><span class="label">Sample:</span></td><td>{escape_html(sample_name)}</td>
        <td><span class="label">Severity:</span></td><td>{severity_badge(severity)}</td>
    </tr><tr>
        <td><span class="label">SHA256:</span></td>
        <td colspan="3" style="font-family: monospace; font-size: 9px;">{escape_html(sha256)}</td>
    </tr><tr>
        <td><span class="label">Family:</span></td><td>{source_badge("AI Reverse Engineering")} <strong>{escape_html(family)}</strong></td>
        <td><span class="label">File Type:</span></td><td>{source_badge("Triage")} {escape_html(file_type)}</td>
    </tr><tr>
        <td><span class="label">Task ID:</span></td><td>{escape_html(task_id)}</td>
        <td><span class="label">Analyzed:</span></td><td>{escape_html(started[:19] if started else 'n/a')}</td>
    </tr></table>
    """


def render_executive_summary(report: dict) -> str:
    """Render the executive summary section."""
    summary = report.get("executive_summary", {})
    if not summary or summary.get("error") or not summary.get("executive_summary"):
        return ""

    html = f'<h2>{source_badge("Summary")} Executive Summary</h2>\n'
    html += f'<div class="executive-summary">{render_markdown(summary["executive_summary"])}</div>\n'

    findings = summary.get("key_findings", [])
    if findings:
        html += '<h3>Key Findings</h3>\n<ol class="findings-list">\n'
        for f in findings:
            html += f'  <li>{escape_html(f)}</li>\n'
        html += '</ol>\n'

    actions = summary.get("recommended_actions", [])
    if actions:
        html += '<h3>Recommended Actions</h3>\n<ol class="actions-list">\n'
        for a in actions:
            html += f'  <li>{escape_html(a)}</li>\n'
        html += '</ol>\n'

    return html


def render_cross_correlations(report: dict) -> str:
    """Render cross-tool correlation findings."""
    correlations = report.get("cross_correlations", [])
    if not correlations:
        return ""

    html = '<h2>Cross-Tool Correlation Findings</h2>\n'
    html += '<p style="font-size:10px;color:#666;">Findings detected by comparing data across multiple analysis tools.</p>\n'
    html += '<table class="ioc-table">\n'
    html += '<tr><th>Severity</th><th>Finding</th><th>Sources</th><th>MITRE</th></tr>\n'

    for c in correlations:
        sev = c.get("severity", "info")
        sev_color = {"critical": "#b22222", "high": "#e65100", "medium": "#f9a825",
                     "low": "#4caf50"}.get(sev, "#999")
        sources = ", ".join(c.get("sources", []))
        html += f'<tr><td><span style="color:{sev_color};font-weight:bold;text-transform:uppercase;">{escape_html(sev)}</span></td>'
        html += f'<td><strong>{escape_html(c.get("title", ""))}</strong></td>'
        html += f'<td style="font-size:9px;">{escape_html(sources)}</td>'
        html += f'<td style="font-size:9px;">{escape_html(c.get("mitre", ""))}</td></tr>\n'

        # Detail row with before/after data
        detail = c.get("detail", "")
        before = c.get("before", "")
        after = c.get("after", "")
        if detail or before or after:
            extra = ""
            if before:
                extra += f'<strong>Before:</strong> <span style="font-family:monospace;">{escape_html(str(before)[:120])}</span><br/>'
            if after:
                extra += f'<strong>After:</strong> <span style="font-family:monospace;">{escape_html(str(after)[:120])}</span><br/>'
            if detail:
                extra += escape_html(str(detail)[:300])
            html += f'<tr><td colspan="4" style="padding-left:16px;font-size:9px;color:#666;">{extra}</td></tr>\n'

    html += '</table>\n'
    return html


def render_iocs(report: dict) -> str:
    """Render IOC table from the pipeline's extracted_iocs field.

    Uses the centralized IOC extraction (extract_iocs in run-pipeline.py)
    which pulls actionable indicators from all stages with STIX types.
    """
    ioc_entries = report.get("extracted_iocs", [])

    if not ioc_entries:
        return ""

    html = '<h2>Indicators of Compromise (IOCs)</h2>\n'
    html += f'<p style="font-size:10px;color:#666;">{len(ioc_entries)} indicators extracted from all pipeline stages. '
    html += 'Types follow STIX 2.1 Observable vocabulary.</p>\n'
    html += '<table class="ioc-table">\n'
    html += '<tr><th>Source</th><th>Type</th><th>Value</th><th>Context</th></tr>\n'
    for entry in ioc_entries:
        html += f'<tr><td>{source_badge(entry.get("source", "?"))}</td>'
        html += f'<td style="white-space:nowrap;">{escape_html(entry.get("type", "?"))}</td>'
        html += f'<td style="font-family:monospace;font-size:9px;word-break:break-all;">{escape_html(entry.get("value", ""))}</td>'
        html += f'<td style="font-size:8px;color:#666;">{escape_html(entry.get("context", ""))}</td></tr>\n'
    html += '</table>\n'
    return html


def render_mitre(report: dict) -> str:
    """Render MITRE ATT&CK techniques table consolidated from all sources."""
    all_techniques = []

    # From AI RE interpretation
    interp_techniques = (report.get("llm_interpretation", {})
                         .get("analysis", {})
                         .get("attack_techniques", []))
    for t in interp_techniques:
        all_techniques.append({
            "id": t.get("id", "?"),
            "name": t.get("name", "?"),
            "source": "AI Reverse Engineering",
        })

    # From Cape behavioral signatures (already mapped by Cape)
    cape_ttps = report.get("cape", {}).get("mitre_ttps", [])
    for t in cape_ttps:
        all_techniques.append({
            "id": t.get("id", "?"),
            "name": t.get("source_signature", "Cape behavioral signature"),
            "source": "Cape",
        })

    # From executive summary (new structured format)
    summary_techniques = report.get("executive_summary", {}).get("mitre_techniques", [])
    for t in summary_techniques:
        all_techniques.append({
            "id": t.get("id", "?"),
            "name": t.get("name", "?"),
            "source": t.get("source", "Summary"),
        })

    if not all_techniques:
        return ""

    # Deduplicate by technique ID, keep first source seen
    seen_ids = set()
    unique = []
    for t in all_techniques:
        if t["id"] not in seen_ids:
            seen_ids.add(t["id"])
            unique.append(t)

    html = '<h2>MITRE ATT&CK Mapping</h2>\n'
    html += '<table class="mitre-table">\n'
    html += '<tr><th>Source</th><th>Technique ID</th><th>Name</th></tr>\n'
    for t in unique:
        html += f'<tr><td>{source_badge(t["source"])}</td>'
        html += f'<td><strong>{escape_html(t["id"])}</strong></td>'
        html += f'<td>{escape_html(t["name"])}</td></tr>\n'
    html += '</table>\n'
    return html


def render_capabilities(report: dict) -> str:
    """Render capabilities list with source."""
    caps = (report.get("llm_interpretation", {})
            .get("analysis", {})
            .get("capabilities", []))
    if not caps:
        return ""

    html = '<h2>Identified Capabilities</h2>\n'
    html += '<ul class="capability-list">\n'
    for c in caps:
        html += f'  <li>{source_badge("AI Reverse Engineering")} {escape_html(c)}</li>\n'
    html += '</ul>\n'
    return html


def render_triage(report: dict) -> str:
    """Render triage results."""
    triage = report.get("triage", {})
    if not triage or triage.get("error"):
        return ""

    html = f'<h2>{source_badge("Triage")} Stage 1: Triage Analysis</h2>\n'
    html += '<div class="stage-section">\n'

    file_type = triage.get("file_type", "unknown")
    entropy = triage.get("entropy", "n/a")
    file_mime = triage.get("file_mime", "n/a")
    html += f'<div class="stage-header">File type: {escape_html(file_type)} | MIME: {escape_html(file_mime)} | Entropy: {escape_html(str(entropy))}</div>\n'

    yara = triage.get("yara_matches", [])
    if yara:
        html += f'<h3>YARA Matches ({len(yara)})</h3>\n<div>'
        for m in yara:
            rule = m.get("rule", "?")
            html += f'<span class="yara-tag">{escape_html(rule)}</span> '
        html += '</div>\n'

    # ssdeep
    ssdeep = triage.get("ssdeep", "")
    if ssdeep:
        html += f'<p><strong>ssdeep:</strong> <span style="font-family: monospace; font-size: 9px;">{escape_html(ssdeep)}</span></p>\n'

    html += '</div>\n'
    return html


def render_cape(report: dict) -> str:
    """Render Cape dynamic analysis summary."""
    cape = report.get("cape", {})
    if not cape:
        return ""

    html = f'<h2>{source_badge("Cape")} Stage 2: Dynamic Analysis (Cape)</h2>\n'
    html += '<div class="stage-section">\n'

    status = cape.get("status", "unknown")
    task_id = cape.get("task_id", "n/a")
    malscore = cape.get("malscore", "n/a")
    payloads = cape.get("payloads_extracted", 0)
    html += f'<div class="stage-header">Status: {escape_html(status)} | Task ID: {escape_html(str(task_id))} | Malscore: {escape_html(str(malscore))} | Payloads extracted: {payloads}</div>\n'

    # Behavioral signatures (top by severity)
    sigs = cape.get("signatures", [])
    if sigs:
        # Sort by severity descending
        sorted_sigs = sorted(sigs, key=lambda s: s.get("severity", 0), reverse=True)
        html += f'<h3>Behavioral Signatures ({len(sigs)})</h3>\n'
        html += '<table class="ioc-table">\n'
        html += '<tr><th>Severity</th><th>Signature</th><th>Description</th></tr>\n'
        for s in sorted_sigs[:25]:
            sev = s.get("severity", 0)
            sev_color = {3: "#b22222", 2: "#e65100", 1: "#f9a825"}.get(sev, "#999")
            html += f'<tr><td><span style="color:{sev_color};font-weight:bold;">{sev}</span></td>'
            html += f'<td>{escape_html(s.get("name", ""))}</td>'
            html += f'<td style="font-size:9px;">{escape_html(s.get("description", "")[:150])}</td></tr>\n'
        if len(sigs) > 25:
            html += f'<tr><td colspan="3"><em>...and {len(sigs) - 25} more signatures</em></td></tr>\n'
        html += '</table>\n'

    # Network IOCs
    network = cape.get("network", {})
    if network:
        html += '<h3>Network Activity</h3>\n'

        dns = network.get("dns_queries", [])
        if dns:
            html += f'<p><strong>DNS Queries ({len(dns)}):</strong></p>\n'
            html += '<div style="font-size: 9px; font-family: monospace;">'
            for d in dns[:15]:
                html += f'{escape_html(d.get("domain", ""))} ({d.get("type", "")})<br/>'
            if len(dns) > 15:
                html += f'<em>...and {len(dns) - 15} more</em>'
            html += '</div>\n'

        domains = network.get("domains", [])
        if domains:
            html += f'<p><strong>Contacted Domains ({len(domains)}):</strong></p>\n'
            html += '<div style="font-size: 9px; font-family: monospace;">'
            for d in domains[:15]:
                domain = d.get("domain", "")
                ip = d.get("ip", "")
                html += f'{escape_html(domain)}'
                if ip:
                    html += f' → {escape_html(ip)}'
                html += '<br/>'
            html += '</div>\n'

        tcp = network.get("tcp_connections", [])
        if tcp:
            html += f'<p><strong>TCP Connections ({len(tcp)}):</strong></p>\n'
            html += '<div style="font-size: 9px; font-family: monospace;">'
            for c in tcp[:10]:
                html += f'{escape_html(c.get("src", ""))} → {escape_html(c.get("dst", ""))}<br/>'
            html += '</div>\n'

        http = network.get("http_requests", [])
        if http:
            html += f'<p><strong>HTTP Requests ({len(http)}):</strong></p>\n'
            html += '<div style="font-size: 9px; font-family: monospace;">'
            for h in http[:10]:
                html += f'{escape_html(h.get("method", ""))} {escape_html(h.get("url", ""))}<br/>'
            html += '</div>\n'

    # CAPE extracted configs (C2, keys, etc.)
    configs = cape.get("extracted_configs", [])
    if configs:
        html += '<h3>Extracted Malware Configuration</h3>\n'
        for cfg in configs:
            html += f'<div class="code-block">{escape_html(json.dumps(cfg, indent=2))}</div>\n'

    html += '</div>\n'
    return html


def render_volatility(report: dict) -> str:
    """Render Volatility results summary."""
    vol = report.get("volatility", {})
    if not vol or not vol.get("triggered"):
        return ""

    html = f'<h2>{source_badge("Volatility")} Stage 3: Memory Forensics</h2>\n'
    html += '<div class="stage-section">\n'

    triggers = vol.get("trigger_signatures", [])
    if triggers:
        html += f'<div class="stage-header">Triggered by: {escape_html(", ".join(triggers))}</div>\n'

    summary = vol.get("summary", {})
    injected = summary.get("injected_processes", 0)
    connections = summary.get("suspicious_connections", 0)
    plugins_run = vol.get("plugins_run", [])

    html += f'<p>Injected processes (malfind): <strong>{injected}</strong> | '
    html += f'Suspicious connections (netscan): <strong>{connections}</strong></p>\n'
    html += f'<p>Plugins run: {escape_html(", ".join(plugins_run))}</p>\n'

    html += '</div>\n'
    return html


def render_ghidra(report: dict) -> str:
    """Render Ghidra analysis results."""
    ghidra = report.get("ghidra", {})
    if not ghidra or not ghidra.get("triggered"):
        return ""

    html = f'<h2>{source_badge("Ghidra")} Stage 4: Static Analysis</h2>\n'
    html += '<div class="stage-section">\n'

    for af in ghidra.get("analyzed_files", []):
        source = af.get("source", "pe_analysis")
        name = af.get("filename", af.get("program_name", "unknown"))
        funcs = af.get("functions_count", 0)
        imports = af.get("imports", [])
        success = af.get("analysis_success", False)

        if source == "malfind_injection":
            source_label = "Injected Shellcode"
            badge = source_badge("Volatility")
            pid = af.get("pid", "?")
            process = af.get("process", "?")
            addr = af.get("injection_address", "?")
            arch = af.get("architecture", "?")
            html += f'<h3>{badge} {escape_html(source_label)}: PID {pid} ({escape_html(process)})</h3>\n'
            html += f'<div class="stage-header">Address: {escape_html(str(addr))} | Architecture: {arch} | Functions: {funcs} | Score: {af.get("filter_score", "?")}</div>\n'

            # Shellcode artifacts — the most valuable data from injected memory
            sc_artifacts = af.get("shellcode_artifacts", {})
            if sc_artifacts:
                resolved = sc_artifacts.get("resolved_apis", [])
                if resolved:
                    html += f'<p><strong>Resolved APIs ({len(resolved)}):</strong></p>\n'
                    html += '<div style="font-size: 9px; font-family: monospace;">'
                    html += ", ".join(escape_html(a) for a in resolved)
                    html += '</div>\n'

                file_paths = sc_artifacts.get("file_paths", [])
                if file_paths:
                    html += '<p><strong>File Paths:</strong></p>\n'
                    html += '<div style="font-size: 9px; font-family: monospace;">'
                    for p in file_paths:
                        html += f'{escape_html(p)}<br/>'
                    html += '</div>\n'

                dll_names = sc_artifacts.get("dll_names", [])
                if dll_names:
                    html += f'<p><strong>DLL Names:</strong> {escape_html(", ".join(dll_names))}</p>\n'

                urls = sc_artifacts.get("urls", [])
                if urls:
                    html += '<p><strong>URLs:</strong></p>\n'
                    for u in urls:
                        html += f'<div class="mono" style="font-size:9px;">{escape_html(u)}</div>\n'

                ips = sc_artifacts.get("ip_addresses", [])
                if ips:
                    html += f'<p><strong>IP Addresses:</strong> {escape_html(", ".join(ips))}</p>\n'

                if sc_artifacts.get("embedded_pe"):
                    pe_offsets = sc_artifacts.get("pe_offsets", [])
                    html += f'<p><strong>Embedded PE detected</strong> at offsets: {escape_html(", ".join(pe_offsets))}</p>\n'
        else:
            html += f'<h3>{source_badge("Ghidra")} PE Binary: {escape_html(name)}</h3>\n'
            html += f'<div class="stage-header">Functions: {funcs} | Imports: {len(imports)} | Success: {"Yes" if success else "No"}</div>\n'

        if imports:
            html += '<p><strong>Key Imports:</strong></p>\n'
            html += '<div style="font-size: 9px; font-family: monospace; column-count: 2; column-gap: 20px;">'
            for imp in imports[:40]:
                html += f'{escape_html(imp)}<br/>'
            if len(imports) > 40:
                html += f'<em>...and {len(imports) - 40} more</em>'
            html += '</div>\n'

    html += '</div>\n'
    return html


def render_llm_narrative(report: dict) -> str:
    """Render the LLM interpretation narrative."""
    interp = report.get("llm_interpretation", {})
    analysis = interp.get("analysis", {})
    narrative = analysis.get("narrative", "")
    if not narrative:
        return ""

    model = interp.get("model_final", interp.get("model_initial", "unknown"))
    tool_calls = interp.get("tool_calls_used", 0)
    duration = interp.get("duration_seconds", 0)
    influenced = interp.get("possible_prompt_influence", False)

    html = f'<h2>{source_badge("AI Reverse Engineering")} AI Reverse Engineering</h2>\n'
    html += '<div class="stage-section">\n'
    html += f'<div class="stage-header">Model: {escape_html(model)} | Tool calls: {tool_calls} | Duration: {duration}s'
    if influenced:
        html += ' | <strong style="color: red;">POSSIBLE PROMPT INFLUENCE DETECTED</strong>'
    html += '</div>\n'
    html += f'<div class="executive-summary">{render_markdown(narrative)}</div>\n'

    notes = analysis.get("working_notes", "")
    if notes:
        html += '<h3>Investigation Notes</h3>\n'
        html += f'<div class="code-block">{escape_html(notes)}</div>\n'

    html += '</div>\n'
    return html


def render_footer() -> str:
    """Render report footer."""
    now = datetime.now(tz=__import__('datetime').timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""
    <div class="footer-note">
        Generated by Malware Analysis Pipeline | {now}<br/>
        Author: Christopher Shaiman | Apache 2.0
    </div>
    """


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def generate_html(report: dict) -> str:
    """Generate the full HTML report."""
    sections = [
        render_header(report),
        render_executive_summary(report),
        render_cross_correlations(report),
        render_iocs(report),
        render_mitre(report),
        render_capabilities(report),
        render_triage(report),
        render_cape(report),
        render_volatility(report),
        render_ghidra(report),
        render_llm_narrative(report),
        render_footer(),
    ]

    body = "\n".join(s for s in sections if s)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8"/>
    <title>Malware Analysis Report</title>
</head>
<body>
{body}
</body>
</html>"""


def main():
    if len(sys.argv) < 2:
        print("Usage: generate-report.py <report.json> [output.pdf]", file=sys.stderr)
        sys.exit(1)

    report_path = Path(sys.argv[1])
    if not report_path.exists():
        print(f"Error: file not found: {report_path}", file=sys.stderr)
        sys.exit(1)

    with report_path.open() as f:
        report = json.load(f)

    if len(sys.argv) >= 3:
        pdf_path = Path(sys.argv[2])
    else:
        pdf_path = report_path.parent / "report.pdf"

    html_content = generate_html(report)
    HTML(string=html_content).write_pdf(
        str(pdf_path),
        stylesheets=[CSS(string=CSS_STYLES)],
    )

    print(f"PDF report written to: {pdf_path}")


if __name__ == "__main__":
    main()
