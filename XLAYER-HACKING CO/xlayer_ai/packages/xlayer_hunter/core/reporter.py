"""
XLayer AI Reporter - Professional vulnerability assessment report generator

Generates reports in multiple formats:
- JSON (machine readable)
- HTML (interactive dashboard)
- PDF (client presentation)
"""

import os
import json
from typing import Optional, List
from datetime import datetime
from pathlib import Path
from loguru import logger

from xlayer_hunter.models.target import AttackSurface
from xlayer_hunter.models.vulnerability import ValidatedVuln, Severity
from xlayer_hunter.models.report import (
    Report, Finding, Evidence, ScanMetadata,
    ExecutiveSummary, VulnerabilityStats, RiskRating, ReportFormat
)
from xlayer_hunter.config.settings import Settings, get_settings


HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XLayer AI Security Assessment Report</title>
    <style>
        :root {
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #16a34a;
            --info: #2563eb;
            --bg: #0f172a;
            --card: #1e293b;
            --text: #e2e8f0;
            --border: #334155;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        header {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
            padding: 2rem;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
        }
        h1 { font-size: 2rem; margin-bottom: 0.5rem; }
        .subtitle { color: #94a3b8; font-size: 1rem; }
        .card {
            background: var(--card);
            border-radius: 0.5rem;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border);
        }
        .card h2 {
            font-size: 1.25rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
        }
        .stat-box {
            text-align: center;
            padding: 1rem;
            border-radius: 0.5rem;
            background: rgba(255,255,255,0.05);
        }
        .stat-value { font-size: 2rem; font-weight: bold; }
        .stat-label { font-size: 0.875rem; color: #94a3b8; }
        .severity-critical { color: var(--critical); }
        .severity-high { color: var(--high); }
        .severity-medium { color: var(--medium); }
        .severity-low { color: var(--low); }
        .severity-info { color: var(--info); }
        .finding {
            border-left: 4px solid var(--border);
            padding-left: 1rem;
            margin-bottom: 1.5rem;
        }
        .finding.critical { border-color: var(--critical); }
        .finding.high { border-color: var(--high); }
        .finding.medium { border-color: var(--medium); }
        .finding.low { border-color: var(--low); }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }
        .finding-title { font-weight: 600; font-size: 1.1rem; }
        .badge {
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }
        .badge-critical { background: var(--critical); }
        .badge-high { background: var(--high); }
        .badge-medium { background: var(--medium); }
        .badge-low { background: var(--low); }
        .code-block {
            background: #0f172a;
            padding: 1rem;
            border-radius: 0.25rem;
            font-family: 'Consolas', monospace;
            font-size: 0.875rem;
            overflow-x: auto;
            margin: 0.5rem 0;
        }
        .remediation { margin-top: 1rem; }
        .remediation ul { margin-left: 1.5rem; }
        .remediation li { margin-bottom: 0.25rem; }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th { color: #94a3b8; font-weight: 600; }
        .risk-indicator {
            display: inline-block;
            padding: 0.5rem 1rem;
            border-radius: 0.25rem;
            font-weight: bold;
            font-size: 1.25rem;
        }
        .risk-critical { background: var(--critical); }
        .risk-high { background: var(--high); }
        .risk-medium { background: var(--medium); }
        .risk-low { background: var(--low); }
        .risk-secure { background: var(--info); }
        footer {
            text-align: center;
            padding: 2rem;
            color: #64748b;
            font-size: 0.875rem;
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>XLayer AI Security Assessment Report</h1>
            <p class="subtitle">Target: {{TARGET_URL}} | Generated: {{GENERATED_AT}}</p>
        </div>
    </header>
    
    <div class="container">
        <!-- Executive Summary -->
        <div class="card">
            <h2>Executive Summary</h2>
            <div style="display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem;">
                <span>Overall Risk Rating:</span>
                <span class="risk-indicator risk-{{RISK_CLASS}}">{{OVERALL_RISK}}</span>
            </div>
            <p>{{SUMMARY_TEXT}}</p>
            {{#if IMMEDIATE_ACTIONS}}
            <div style="margin-top: 1rem;">
                <strong>Immediate Actions Required:</strong>
                <ul style="margin-left: 1.5rem; margin-top: 0.5rem;">
                    {{IMMEDIATE_ACTIONS}}
                </ul>
            </div>
            {{/if}}
        </div>
        
        <!-- Statistics -->
        <div class="card">
            <h2>Vulnerability Statistics</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-value">{{TOTAL_VULNS}}</div>
                    <div class="stat-label">Total Findings</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value severity-critical">{{CRITICAL_COUNT}}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value severity-high">{{HIGH_COUNT}}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value severity-medium">{{MEDIUM_COUNT}}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value severity-low">{{LOW_COUNT}}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
        </div>
        
        <!-- Scan Information -->
        <div class="card">
            <h2>Scan Information</h2>
            <table>
                <tr><th>Scan ID</th><td>{{SCAN_ID}}</td></tr>
                <tr><th>Duration</th><td>{{DURATION}}</td></tr>
                <tr><th>Endpoints Scanned</th><td>{{ENDPOINTS_SCANNED}}</td></tr>
                <tr><th>Requests Made</th><td>{{REQUESTS_MADE}}</td></tr>
                <tr><th>Hunters Used</th><td>{{HUNTERS_USED}}</td></tr>
            </table>
        </div>
        
        <!-- Findings -->
        <div class="card">
            <h2>Detailed Findings</h2>
            {{FINDINGS_HTML}}
        </div>
    </div>
    
    <footer>
        <p>Generated by XLayer AI - Autonomous Web Vulnerability Hunter</p>
        <p>"Hack before hackers hack — Prove before you report"</p>
    </footer>
</body>
</html>
'''

FINDING_TEMPLATE = '''
<div class="finding {{SEVERITY_CLASS}}">
    <div class="finding-header">
        <span class="finding-title">{{FINDING_ID}}: {{TITLE}}</span>
        <span class="badge badge-{{SEVERITY_CLASS}}">{{SEVERITY}} (CVSS: {{CVSS}})</span>
    </div>
    <p><strong>Endpoint:</strong> {{ENDPOINT}}</p>
    <p><strong>Parameter:</strong> {{PARAMETER}}</p>
    <p style="margin-top: 0.5rem;">{{DESCRIPTION}}</p>
    
    <div style="margin-top: 1rem;">
        <strong>Proof of Concept:</strong>
        <div class="code-block">{{POC_CURL}}</div>
    </div>
    
    <div class="remediation">
        <strong>Remediation:</strong>
        <ul>
            {{REMEDIATION_ITEMS}}
        </ul>
    </div>
</div>
'''


class Reporter:
    """
    Report Generator for XLayer AI
    
    Generates professional penetration test reports with:
    - Executive summary for stakeholders
    - Technical details for developers
    - Proof of concept for reproduction
    - Remediation guidance
    """
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
    
    async def generate(
        self,
        metadata: ScanMetadata,
        attack_surface: AttackSurface,
        validated_vulns: List[ValidatedVuln],
        hypotheses_count: int = 0
    ) -> Report:
        """
        Generate complete vulnerability assessment report
        
        Args:
            metadata: Scan metadata
            attack_surface: Attack surface from recon
            validated_vulns: List of validated vulnerabilities
            hypotheses_count: Total hypotheses generated
            
        Returns:
            Complete Report object
        """
        logger.info(f"Generating report for {len(validated_vulns)} validated vulnerabilities")
        
        report = Report(
            metadata=metadata,
            attack_surface=attack_surface
        )
        
        for vuln in validated_vulns:
            finding = self._create_finding(vuln, len(report.findings) + 1)
            report.findings.append(finding)
        
        report.stats = VulnerabilityStats.from_findings(report.findings)
        report.stats.hypotheses_generated = hypotheses_count
        report.stats.hypotheses_validated = len(validated_vulns)
        report.stats.false_positives_avoided = hypotheses_count - len(validated_vulns)
        
        report.generate_executive_summary()
        
        report.methodology = self._get_methodology()
        report.scope = [metadata.target_url]
        report.limitations = self._get_limitations()
        
        await self._save_reports(report)
        
        return report
    
    def _create_finding(self, vuln: ValidatedVuln, index: int) -> Finding:
        """Create a finding from a validated vulnerability"""
        vuln_type_name = vuln.vuln_type.value.replace("_", " ").title()
        
        description = self._get_vuln_description(vuln)
        technical_details = self._get_technical_details(vuln)
        business_impact = self._get_business_impact(vuln)
        
        finding = Finding(
            finding_id=f"XL-{index:03d}",
            title=f"{vuln_type_name} in {vuln.parameter}",
            vulnerability=vuln,
            description=description,
            technical_details=technical_details,
            business_impact=business_impact
        )
        
        if vuln.evidence.screenshot_base64:
            finding.evidence.append(Evidence(
                evidence_type="screenshot",
                description="Screenshot of successful exploitation",
                data=vuln.evidence.screenshot_base64
            ))
        
        if vuln.evidence.extracted_data:
            finding.evidence.append(Evidence(
                evidence_type="extracted_data",
                description="Data extracted during exploitation",
                data=vuln.evidence.extracted_data
            ))
        
        return finding
    
    def _get_vuln_description(self, vuln: ValidatedVuln) -> str:
        """Get description for vulnerability type"""
        descriptions = {
            "sql_injection": f"A SQL injection vulnerability was discovered in the '{vuln.parameter}' parameter at {vuln.endpoint}. This vulnerability allows an attacker to execute arbitrary SQL commands against the database, potentially leading to complete database compromise.",
            "xss_reflected": f"A reflected Cross-Site Scripting (XSS) vulnerability was found in the '{vuln.parameter}' parameter at {vuln.endpoint}. This allows attackers to inject malicious JavaScript that executes in victims' browsers.",
            "xss_stored": f"A stored Cross-Site Scripting (XSS) vulnerability was discovered. Malicious scripts can be permanently stored and executed for all users viewing the affected content.",
            "auth_bypass": f"An authentication bypass vulnerability was found at {vuln.endpoint}. Attackers can gain unauthorized access without valid credentials.",
            "idor": f"An Insecure Direct Object Reference (IDOR) vulnerability exists in the '{vuln.parameter}' parameter. Attackers can access other users' data by manipulating object references.",
            "ssrf": f"A Server-Side Request Forgery (SSRF) vulnerability was found in the '{vuln.parameter}' parameter. Attackers can make the server perform requests to internal resources.",
            "lfi": f"A Local File Inclusion (LFI) vulnerability exists in the '{vuln.parameter}' parameter. Attackers can read sensitive files from the server.",
        }
        return descriptions.get(vuln.vuln_type.value, f"A {vuln.vuln_type.value} vulnerability was discovered.")
    
    def _get_technical_details(self, vuln: ValidatedVuln) -> str:
        """Get technical details for the finding"""
        details = [
            f"**Endpoint:** {vuln.endpoint}",
            f"**Method:** {vuln.hypothesis.method}",
            f"**Parameter:** {vuln.parameter}",
            f"**Payload Used:** `{vuln.payload_used}`",
            f"**CVSS Score:** {vuln.cvss_score}",
        ]
        
        if vuln.evidence.extracted_data:
            details.append(f"**Extracted Data:** {vuln.evidence.extracted_data[:100]}")
        
        return "\n".join(details)
    
    def _get_business_impact(self, vuln: ValidatedVuln) -> str:
        """Get business impact description"""
        impacts = {
            "sql_injection": "Critical business impact: Complete database compromise possible, including customer data, credentials, and financial information. Regulatory compliance violations (GDPR, PCI-DSS) likely.",
            "xss_reflected": "High business impact: User sessions can be hijacked, credentials stolen, and malware distributed to users. Reputation damage and potential legal liability.",
            "auth_bypass": "Critical business impact: Unauthorized access to user accounts and administrative functions. Complete compromise of user data and system integrity.",
            "idor": "High business impact: Unauthorized access to other users' personal data, documents, and financial information. Privacy violations and regulatory non-compliance.",
            "ssrf": "High business impact: Internal network exposure, cloud credential theft, and potential lateral movement within infrastructure.",
            "lfi": "High business impact: Sensitive configuration files, source code, and credentials may be exposed. Potential for remote code execution.",
        }
        return impacts.get(vuln.vuln_type.value, "Security vulnerability with potential data exposure and business disruption.")
    
    def _get_methodology(self) -> str:
        """Get scan methodology description"""
        return """
XLayer AI employs a comprehensive four-phase vulnerability assessment methodology:

1. **Reconnaissance Phase**: Automated discovery of attack surface including DNS resolution, port scanning, technology fingerprinting, and web crawling.

2. **Vulnerability Hunting Phase**: Parallel deployment of specialized vulnerability hunters (SQLi, XSS, Auth, SSRF, LFI) using context-aware payload selection.

3. **Exploitation Phase**: Real exploitation verification using headless browser automation. Only vulnerabilities that can be successfully exploited are reported (NO EXPLOIT = NO REPORT policy).

4. **Reporting Phase**: Generation of professional reports with proof-of-concept, evidence, and remediation guidance.
"""
    
    def _get_limitations(self) -> List[str]:
        """Get scan limitations"""
        return [
            "Scan limited to web application layer; infrastructure and network vulnerabilities not assessed",
            "Authentication-required areas not tested without valid credentials",
            "Rate limiting may have prevented complete coverage",
            "Client-side only vulnerabilities may require manual verification",
            "Business logic vulnerabilities require manual assessment"
        ]
    
    async def _save_reports(self, report: Report):
        """Save reports in configured formats"""
        output_dir = Path(self.settings.report.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        base_name = f"xlayer_report_{timestamp}"
        
        if "json" in self.settings.report.formats:
            json_path = output_dir / f"{base_name}.json"
            await self._save_json(report, json_path)
            logger.info(f"JSON report saved: {json_path}")
        
        if "html" in self.settings.report.formats:
            html_path = output_dir / f"{base_name}.html"
            await self._save_html(report, html_path)
            logger.info(f"HTML report saved: {html_path}")
    
    async def _save_json(self, report: Report, path: Path):
        """Save report as JSON"""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2, default=str)
    
    async def _save_html(self, report: Report, path: Path):
        """Save report as HTML"""
        html = HTML_TEMPLATE
        
        html = html.replace("{{TARGET_URL}}", report.metadata.target_url)
        html = html.replace("{{GENERATED_AT}}", report.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC"))
        html = html.replace("{{OVERALL_RISK}}", report.overall_risk.value.upper())
        html = html.replace("{{RISK_CLASS}}", report.overall_risk.value)
        
        summary_text = report.executive_summary.summary_text if report.executive_summary else "No findings to report."
        html = html.replace("{{SUMMARY_TEXT}}", summary_text)
        
        if report.executive_summary and report.executive_summary.immediate_actions:
            actions_html = "".join(f"<li>{a}</li>" for a in report.executive_summary.immediate_actions)
            html = html.replace("{{#if IMMEDIATE_ACTIONS}}", "")
            html = html.replace("{{/if}}", "")
            html = html.replace("{{IMMEDIATE_ACTIONS}}", actions_html)
        else:
            import re
            html = re.sub(r'\{\{#if IMMEDIATE_ACTIONS\}\}.*?\{\{/if\}\}', '', html, flags=re.DOTALL)
        
        html = html.replace("{{TOTAL_VULNS}}", str(report.stats.total))
        html = html.replace("{{CRITICAL_COUNT}}", str(report.stats.critical))
        html = html.replace("{{HIGH_COUNT}}", str(report.stats.high))
        html = html.replace("{{MEDIUM_COUNT}}", str(report.stats.medium))
        html = html.replace("{{LOW_COUNT}}", str(report.stats.low))
        
        html = html.replace("{{SCAN_ID}}", report.metadata.scan_id)
        html = html.replace("{{DURATION}}", f"{report.metadata.duration_seconds:.2f} seconds")
        html = html.replace("{{ENDPOINTS_SCANNED}}", str(report.metadata.endpoints_scanned))
        html = html.replace("{{REQUESTS_MADE}}", str(report.metadata.requests_made))
        html = html.replace("{{HUNTERS_USED}}", ", ".join(report.metadata.hunters_used))
        
        findings_html = ""
        for finding in report.findings:
            finding_html = FINDING_TEMPLATE
            finding_html = finding_html.replace("{{FINDING_ID}}", finding.finding_id)
            finding_html = finding_html.replace("{{TITLE}}", finding.title)
            finding_html = finding_html.replace("{{SEVERITY}}", finding.severity.value.upper())
            finding_html = finding_html.replace("{{SEVERITY_CLASS}}", finding.severity.value)
            finding_html = finding_html.replace("{{CVSS}}", str(finding.cvss_score))
            finding_html = finding_html.replace("{{ENDPOINT}}", finding.vulnerability.endpoint)
            finding_html = finding_html.replace("{{PARAMETER}}", finding.vulnerability.parameter)
            finding_html = finding_html.replace("{{DESCRIPTION}}", finding.description)
            
            poc_curl = finding.vulnerability.poc.curl_command or "N/A"
            finding_html = finding_html.replace("{{POC_CURL}}", poc_curl)
            
            remediation_items = "".join(
                f"<li>{r}</li>" for r in finding.vulnerability.remediation
            )
            finding_html = finding_html.replace("{{REMEDIATION_ITEMS}}", remediation_items)
            
            findings_html += finding_html
        
        if not findings_html:
            findings_html = "<p>No vulnerabilities were confirmed during this assessment.</p>"
        
        html = html.replace("{{FINDINGS_HTML}}", findings_html)
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
