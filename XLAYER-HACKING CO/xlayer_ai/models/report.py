"""
XLayer AI Report Models - Data structures for reports and findings
"""

from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from xlayer_ai.models.target import AttackSurface
from xlayer_ai.models.vulnerability import ValidatedVuln, Severity


class ReportFormat(str, Enum):
    """Report output formats"""
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    MARKDOWN = "markdown"


class RiskRating(str, Enum):
    """Overall risk rating"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    SECURE = "secure"


class Evidence(BaseModel):
    """Evidence attached to a finding"""
    evidence_type: str
    description: str
    data: Optional[str] = None
    file_path: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class Finding(BaseModel):
    """A single finding in the report"""
    finding_id: str
    title: str
    vulnerability: ValidatedVuln
    
    description: str
    technical_details: str
    business_impact: str
    
    evidence: List[Evidence] = Field(default_factory=list)
    
    @property
    def severity(self) -> Severity:
        return self.vulnerability.severity
    
    @property
    def cvss_score(self) -> float:
        return self.vulnerability.cvss_score


class ExecutiveSummary(BaseModel):
    """Executive summary section"""
    overall_risk: RiskRating
    summary_text: str
    key_findings: List[str] = Field(default_factory=list)
    immediate_actions: List[str] = Field(default_factory=list)
    compliance_notes: List[str] = Field(default_factory=list)


class ScanMetadata(BaseModel):
    """Metadata about the scan"""
    scan_id: str
    target_url: str
    started_at: datetime
    completed_at: datetime
    duration_seconds: float
    scanner_version: str = "1.0.0"
    hunters_used: List[str] = Field(default_factory=list)
    endpoints_scanned: int = 0
    requests_made: int = 0


class VulnerabilityStats(BaseModel):
    """Statistics about discovered vulnerabilities"""
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    
    hypotheses_generated: int = 0
    hypotheses_validated: int = 0
    false_positives_avoided: int = 0
    
    @classmethod
    def from_findings(cls, findings: List[Finding]) -> "VulnerabilityStats":
        """Calculate stats from findings list"""
        stats = cls(total=len(findings))
        for finding in findings:
            if finding.severity == Severity.CRITICAL:
                stats.critical += 1
            elif finding.severity == Severity.HIGH:
                stats.high += 1
            elif finding.severity == Severity.MEDIUM:
                stats.medium += 1
            elif finding.severity == Severity.LOW:
                stats.low += 1
            else:
                stats.info += 1
        return stats


class Report(BaseModel):
    """Complete vulnerability assessment report"""
    report_id: str = Field(default_factory=lambda: f"report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}")
    title: str = "XLayer AI Security Assessment Report"
    
    metadata: ScanMetadata
    executive_summary: Optional[ExecutiveSummary] = None
    
    attack_surface: Optional[AttackSurface] = None
    
    findings: List[Finding] = Field(default_factory=list)
    stats: VulnerabilityStats = Field(default_factory=VulnerabilityStats)
    
    methodology: str = ""
    scope: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    
    @property
    def overall_risk(self) -> RiskRating:
        """Calculate overall risk rating"""
        if self.stats.critical > 0:
            return RiskRating.CRITICAL
        elif self.stats.high > 0:
            return RiskRating.HIGH
        elif self.stats.medium > 0:
            return RiskRating.MEDIUM
        elif self.stats.low > 0:
            return RiskRating.LOW
        elif self.stats.info > 0:
            return RiskRating.INFORMATIONAL
        return RiskRating.SECURE
    
    def add_finding(self, vuln: ValidatedVuln, description: str, 
                    technical_details: str, business_impact: str) -> Finding:
        """Add a finding to the report"""
        finding = Finding(
            finding_id=f"XL-{len(self.findings) + 1:03d}",
            title=f"{vuln.vuln_type.value.replace('_', ' ').title()} in {vuln.parameter}",
            vulnerability=vuln,
            description=description,
            technical_details=technical_details,
            business_impact=business_impact
        )
        self.findings.append(finding)
        self.stats = VulnerabilityStats.from_findings(self.findings)
        return finding
    
    def generate_executive_summary(self) -> ExecutiveSummary:
        """Generate executive summary from findings"""
        risk = self.overall_risk
        
        if risk == RiskRating.CRITICAL:
            summary = "Critical security vulnerabilities were discovered that require immediate attention. These vulnerabilities could lead to complete system compromise."
        elif risk == RiskRating.HIGH:
            summary = "High severity vulnerabilities were identified that pose significant risk to the application and its data."
        elif risk == RiskRating.MEDIUM:
            summary = "Medium severity vulnerabilities were found that should be addressed in the near term."
        elif risk == RiskRating.LOW:
            summary = "Low severity vulnerabilities were identified that represent minor security concerns."
        else:
            summary = "No significant vulnerabilities were discovered during this assessment."
        
        key_findings = [
            f"{f.title} (CVSS: {f.cvss_score})" 
            for f in sorted(self.findings, key=lambda x: x.cvss_score, reverse=True)[:5]
        ]
        
        immediate_actions = []
        if self.stats.critical > 0:
            immediate_actions.append("Immediately patch critical vulnerabilities")
        if self.stats.high > 0:
            immediate_actions.append("Schedule remediation of high severity issues within 7 days")
        if any(f.vulnerability.vuln_type.value.startswith("sql") for f in self.findings):
            immediate_actions.append("Implement parameterized queries for all database operations")
        if any(f.vulnerability.vuln_type.value.startswith("xss") for f in self.findings):
            immediate_actions.append("Implement proper output encoding and Content Security Policy")
        
        self.executive_summary = ExecutiveSummary(
            overall_risk=risk,
            summary_text=summary,
            key_findings=key_findings,
            immediate_actions=immediate_actions
        )
        return self.executive_summary
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary"""
        return {
            "report_id": self.report_id,
            "title": self.title,
            "metadata": self.metadata.model_dump(),
            "executive_summary": self.executive_summary.model_dump() if self.executive_summary else None,
            "stats": self.stats.model_dump(),
            "findings": [f.model_dump() for f in self.findings],
            "overall_risk": self.overall_risk.value,
            "generated_at": self.generated_at.isoformat()
        }
