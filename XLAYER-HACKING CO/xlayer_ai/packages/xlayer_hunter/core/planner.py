"""
XLayer AI Planner Agent - Master orchestrator for the vulnerability hunting pipeline

The Planner Agent is the "brain" of XLayer AI, coordinating all phases:
1. RECON - Attack surface mapping
2. VULN_HUNT - Parallel vulnerability detection
3. EXPLOIT - Real exploitation validation
4. REPORT - Professional report generation
"""

import asyncio
import time
from enum import Enum
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
from loguru import logger

from xlayer_hunter.models.target import Target, AttackSurface
from xlayer_hunter.models.vulnerability import VulnHypothesis, ValidatedVuln, Confidence
from xlayer_hunter.models.report import Report, ScanMetadata
from xlayer_hunter.core.recon import ReconAgent
from xlayer_hunter.core.exploit import ExploitAgent
from xlayer_hunter.core.vuln_hunters.base import BaseHunter, HunterResult, run_hunters_parallel
from xlayer_hunter.core.vuln_hunters.sqli import SQLiHunter
from xlayer_hunter.core.vuln_hunters.xss import XSSHunter
from xlayer_hunter.core.vuln_hunters.auth import AuthHunter
from xlayer_hunter.core.vuln_hunters.ssrf import SSRFHunter
from xlayer_hunter.core.vuln_hunters.lfi import LFIHunter
from xlayer_hunter.tools.http_client import HTTPClient
from xlayer_hunter.tools.payload_manager import PayloadManager
from xlayer_hunter.config.settings import Settings, get_settings


class MissionState(str, Enum):
    """States of the vulnerability hunting mission"""
    IDLE = "idle"
    RECON = "recon"
    VULN_HUNT = "vuln_hunt"
    EXPLOIT = "exploit"
    REPORT = "report"
    COMPLETE = "complete"
    ERROR = "error"


@dataclass
class MissionContext:
    """Context maintained across all phases"""
    target_url: str
    started_at: datetime = field(default_factory=datetime.utcnow)
    
    state: MissionState = MissionState.IDLE
    
    attack_surface: Optional[AttackSurface] = None
    hypotheses: List[VulnHypothesis] = field(default_factory=list)
    validated_vulns: List[ValidatedVuln] = field(default_factory=list)
    report: Optional[Report] = None
    
    recon_duration: float = 0.0
    hunt_duration: float = 0.0
    exploit_duration: float = 0.0
    report_duration: float = 0.0
    
    hunters_used: List[str] = field(default_factory=list)
    endpoints_scanned: int = 0
    requests_made: int = 0
    
    errors: List[str] = field(default_factory=list)
    
    @property
    def total_duration(self) -> float:
        return (datetime.utcnow() - self.started_at).total_seconds()
    
    def to_metadata(self) -> ScanMetadata:
        """Convert context to scan metadata"""
        return ScanMetadata(
            scan_id=f"scan_{self.started_at.strftime('%Y%m%d_%H%M%S')}",
            target_url=self.target_url,
            started_at=self.started_at,
            completed_at=datetime.utcnow(),
            duration_seconds=self.total_duration,
            hunters_used=self.hunters_used,
            endpoints_scanned=self.endpoints_scanned,
            requests_made=self.requests_made
        )


class PlannerAgent:
    """
    Planner Agent - The brain of XLayer AI
    
    Orchestrates the complete vulnerability hunting pipeline:
    - Manages state transitions
    - Coordinates agents and tools
    - Makes strategic decisions
    - Handles errors and retries
    """
    
    HUNTER_MAP = {
        "sqli": SQLiHunter,
        "xss": XSSHunter,
        "auth": AuthHunter,
        "ssrf": SSRFHunter,
        "lfi": LFIHunter,
    }
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        
        self._http: Optional[HTTPClient] = None
        self._payloads: Optional[PayloadManager] = None
        self._context: Optional[MissionContext] = None
    
    async def __aenter__(self):
        self._http = HTTPClient(
            timeout=self.settings.scan.timeout,
            rate_limit=self.settings.scan.rate_limit,
            user_agent=self.settings.scan.user_agent,
            verify_ssl=self.settings.scan.verify_ssl
        )
        await self._http.start()
        
        self._payloads = PayloadManager()
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._http:
            await self._http.close()
    
    async def start_mission(
        self,
        target_url: str,
        hunters: Optional[List[str]] = None
    ) -> Report:
        """
        Start a complete vulnerability hunting mission
        
        Args:
            target_url: Target URL to scan
            hunters: Optional list of hunters to use (default: all)
            
        Returns:
            Complete vulnerability assessment report
        """
        logger.info(f"Starting XLayer AI mission on {target_url}")
        logger.info("=" * 60)
        
        self._context = MissionContext(target_url=target_url)
        
        if hunters:
            self._context.hunters_used = hunters
        else:
            self._context.hunters_used = self.settings.hunters
        
        try:
            await self._phase_recon()
            
            await self._phase_vuln_hunt()
            
            await self._phase_exploit()
            
            await self._phase_report()
            
            self._context.state = MissionState.COMPLETE
            
        except Exception as e:
            logger.error(f"Mission failed: {e}")
            self._context.state = MissionState.ERROR
            self._context.errors.append(str(e))
            raise
        
        logger.info("=" * 60)
        logger.info(f"Mission complete: {len(self._context.validated_vulns)} validated vulnerabilities")
        
        return self._context.report
    
    async def _phase_recon(self):
        """Phase 1: Reconnaissance"""
        logger.info("=" * 60)
        logger.info("PHASE 1: RECONNAISSANCE")
        logger.info("=" * 60)
        
        self._context.state = MissionState.RECON
        start_time = time.time()
        
        async with ReconAgent(
            settings=self.settings,
            http_client=self._http
        ) as recon:
            self._context.attack_surface = await recon.execute(self._context.target_url)
        
        self._context.recon_duration = time.time() - start_time
        self._context.endpoints_scanned = len(self._context.attack_surface.all_endpoints)
        
        logger.info(f"Recon complete in {self._context.recon_duration:.2f}s")
        logger.info(f"  - Endpoints: {len(self._context.attack_surface.all_endpoints)}")
        logger.info(f"  - Testable: {len(self._context.attack_surface.testable_endpoints)}")
        logger.info(f"  - Attack surface: {self._context.attack_surface.attack_surface_score}")
        
        self._adjust_hunters_based_on_recon()
    
    def _adjust_hunters_based_on_recon(self):
        """Adjust hunter selection based on recon results"""
        surface = self._context.attack_surface
        
        if not surface.testable_endpoints:
            logger.warning("No testable endpoints found - limited hunting possible")
            return
        
        if not surface.auth_endpoints and "auth" in self._context.hunters_used:
            logger.info("No auth endpoints found - skipping auth hunter")
            self._context.hunters_used.remove("auth")
        
        tech = surface.technology
        if tech.waf:
            logger.warning(f"WAF detected: {tech.waf} - payloads may be blocked")
    
    async def _phase_vuln_hunt(self):
        """Phase 2: Vulnerability Hunting (Parallel)"""
        logger.info("=" * 60)
        logger.info("PHASE 2: VULNERABILITY HUNTING")
        logger.info("=" * 60)
        
        self._context.state = MissionState.VULN_HUNT
        start_time = time.time()
        
        hunters = self._create_hunters()
        
        if not hunters:
            logger.warning("No hunters to run")
            return
        
        logger.info(f"Running {len(hunters)} hunters: {[h.name for h in hunters]}")
        
        results = await run_hunters_parallel(hunters, self._context.attack_surface)
        
        for result in results:
            self._context.hypotheses.extend(result.hypotheses)
            self._context.requests_made += result.payloads_sent
            
            if result.errors:
                self._context.errors.extend(result.errors[:5])
        
        self._context.hunt_duration = time.time() - start_time
        
        high_conf = sum(1 for h in self._context.hypotheses if h.confidence == Confidence.HIGH)
        med_conf = sum(1 for h in self._context.hypotheses if h.confidence == Confidence.MEDIUM)
        
        logger.info(f"Hunting complete in {self._context.hunt_duration:.2f}s")
        logger.info(f"  - Total hypotheses: {len(self._context.hypotheses)}")
        logger.info(f"  - High confidence: {high_conf}")
        logger.info(f"  - Medium confidence: {med_conf}")
    
    def _create_hunters(self) -> List[BaseHunter]:
        """Create hunter instances based on configuration"""
        hunters = []
        
        for hunter_name in self._context.hunters_used:
            hunter_class = self.HUNTER_MAP.get(hunter_name)
            
            if hunter_class:
                hunter = hunter_class(
                    http_client=self._http,
                    payload_manager=self._payloads,
                    settings=self.settings
                )
                hunters.append(hunter)
            else:
                logger.warning(f"Unknown hunter: {hunter_name}")
        
        return hunters
    
    async def _phase_exploit(self):
        """Phase 3: Exploitation (Proof or Nothing)"""
        logger.info("=" * 60)
        logger.info("PHASE 3: EXPLOITATION")
        logger.info("NO EXPLOIT = NO REPORT")
        logger.info("=" * 60)
        
        self._context.state = MissionState.EXPLOIT
        start_time = time.time()
        
        if not self._context.hypotheses:
            logger.info("No hypotheses to verify")
            return
        
        hypotheses_to_verify = [
            h for h in self._context.hypotheses
            if h.confidence in [Confidence.HIGH, Confidence.MEDIUM]
        ]
        
        logger.info(f"Verifying {len(hypotheses_to_verify)} hypotheses")
        
        async with ExploitAgent(
            http_client=self._http,
            payload_manager=self._payloads,
            settings=self.settings
        ) as exploit:
            self._context.validated_vulns = await exploit.verify_all(hypotheses_to_verify)
        
        self._context.exploit_duration = time.time() - start_time
        
        false_positives = len(hypotheses_to_verify) - len(self._context.validated_vulns)
        
        logger.info(f"Exploitation complete in {self._context.exploit_duration:.2f}s")
        logger.info(f"  - Validated: {len(self._context.validated_vulns)}")
        logger.info(f"  - False positives avoided: {false_positives}")
    
    async def _phase_report(self):
        """Phase 4: Report Generation"""
        logger.info("=" * 60)
        logger.info("PHASE 4: REPORT GENERATION")
        logger.info("=" * 60)
        
        self._context.state = MissionState.REPORT
        start_time = time.time()
        
        from xlayer_hunter.core.reporter import Reporter
        
        reporter = Reporter(settings=self.settings)
        
        self._context.report = await reporter.generate(
            metadata=self._context.to_metadata(),
            attack_surface=self._context.attack_surface,
            validated_vulns=self._context.validated_vulns,
            hypotheses_count=len(self._context.hypotheses)
        )
        
        self._context.report_duration = time.time() - start_time
        
        logger.info(f"Report generated in {self._context.report_duration:.2f}s")
        logger.info(f"  - Overall risk: {self._context.report.overall_risk.value}")
        logger.info(f"  - Findings: {len(self._context.report.findings)}")
    
    @property
    def context(self) -> Optional[MissionContext]:
        """Get current mission context"""
        return self._context
    
    @property
    def state(self) -> MissionState:
        """Get current mission state"""
        return self._context.state if self._context else MissionState.IDLE
