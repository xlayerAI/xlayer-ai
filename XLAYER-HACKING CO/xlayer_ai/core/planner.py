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

from xlayer_ai.models.target import Target, AttackSurface
from xlayer_ai.models.vulnerability import VulnHypothesis, ValidatedVuln, Confidence
from xlayer_ai.models.report import Report, ScanMetadata
from xlayer_ai.core.recon import ReconAgent
from xlayer_ai.core.exploit import ExploitAgent
from xlayer_ai.core.vuln_hunters import HUNTER_REGISTRY
from xlayer_ai.core.vuln_hunters.base import BaseHunter, HunterResult, run_hunters_parallel
from xlayer_ai.tools.http_client import HTTPClient, AuthConfig
from xlayer_ai.tools.payload_manager import PayloadManager
from xlayer_ai.config.settings import Settings, get_settings


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
    
    HUNTER_MAP = HUNTER_REGISTRY
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()

        self._http: Optional[HTTPClient] = None
        self._payloads: Optional[PayloadManager] = None
        self._context: Optional[MissionContext] = None
        self._llm = None

    def _build_auth_config(self) -> Optional[AuthConfig]:
        """Build HTTP auth configuration from settings (if enabled)."""
        auth = self.settings.auth
        if not auth.enabled:
            return None

        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}

        if auth.bearer_token:
            headers["Authorization"] = f"Bearer {auth.bearer_token}"
        if auth.api_key:
            headers[auth.api_key_header] = auth.api_key

        if auth.session_cookie and "=" in auth.session_cookie:
            name, value = auth.session_cookie.split("=", 1)
            if name.strip() and value:
                cookies[name.strip()] = value

        return AuthConfig(
            login_url=auth.login_url,
            username=auth.username,
            password=auth.password,
            username_field=auth.username_field,
            password_field=auth.password_field,
            cookies=cookies or None,
            headers=headers or None,
            success_url_contains=auth.success_url_contains,
            failure_text=auth.failure_text,
        )
    
    async def __aenter__(self):
        auth_config = self._build_auth_config()
        self._http = HTTPClient(
            timeout=self.settings.scan.timeout,
            rate_limit=self.settings.scan.rate_limit,
            user_agent=self.settings.scan.user_agent,
            verify_ssl=self.settings.scan.verify_ssl,
            auth=auth_config,
        )
        await self._http.start()

        self._payloads = PayloadManager()

        if self.settings.llm.is_enabled:
            try:
                from xlayer_ai.llm.engine import LLMEngine
                self._llm = LLMEngine(settings=self.settings)
                await self._llm.initialize()
                if not self._llm.is_ready:
                    logger.warning("LLM initialization failed - continuing without LLM")
                    self._llm = None
                else:
                    logger.info("LLM engine ready for intelligent analysis")
            except Exception as e:
                logger.warning(f"LLM setup failed: {e} - continuing without LLM")
                self._llm = None

        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._http:
            await self._http.close()
        if self._llm:
            await self._llm.close()
    
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
            self._context.hunters_used = list(self.settings.hunters)
        
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
        
        results = await run_hunters_parallel(
            hunters,
            self._context.attack_surface,
            max_concurrency=self.settings.scan.hunter_concurrency,
        )
        
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
                    settings=self.settings,
                    llm_engine=self._llm
                )
                hunters.append(hunter)
            else:
                logger.warning(f"Unknown hunter: {hunter_name}")
        
        return hunters
    
    async def _phase_exploit(self):
        """Phase 3: Exploitation (Proof or Nothing)

        Routing strategy:
          HIGH confidence → Coordinator + Solver (deep, 80-iter agentic path)
          MEDIUM confidence → ExploitAgent (fast deterministic path)

        If use_agentic_exploit is disabled, all hypotheses fall back to ExploitAgent.
        """
        logger.info("=" * 60)
        logger.info("PHASE 3: EXPLOITATION")
        logger.info("NO EXPLOIT = NO REPORT")
        logger.info("=" * 60)

        self._context.state = MissionState.EXPLOIT
        start_time = time.time()

        if not self._context.hypotheses:
            logger.info("No hypotheses to verify")
            return

        # Separate by confidence tier
        high_conf = [
            h for h in self._context.hypotheses
            if h.confidence == Confidence.HIGH
        ]
        med_conf = [
            h for h in self._context.hypotheses
            if h.confidence == Confidence.MEDIUM
        ]

        hypotheses_to_verify = high_conf + med_conf
        if not hypotheses_to_verify:
            logger.info("No HIGH/MEDIUM hypotheses — skipping exploitation")
            return

        logger.info(
            f"Verifying {len(hypotheses_to_verify)} hypotheses "
            f"(HIGH={len(high_conf)}, MEDIUM={len(med_conf)})"
        )

        from xlayer_ai.core.coordinator_result import merge_validated_vulns

        validated: List[ValidatedVuln] = []

        if self.settings.exploit.use_agentic_exploit and high_conf:
            # ── HIGH confidence → deep agentic path (Coordinator + Solver 80-iter) ──
            logger.info(f"[Exploit] Routing {len(high_conf)} HIGH-conf → Coordinator (deep)")
            agentic_results = await self._run_agentic_exploit(high_conf)
            validated.extend(agentic_results)
            logger.info(f"[Exploit] Coordinator validated {len(agentic_results)}/{len(high_conf)}")
        elif high_conf:
            # Agentic disabled — route HIGH to classic as fallback
            logger.info(f"[Exploit] Agentic disabled — routing HIGH-conf to ExploitAgent")
            classic_high = await self._run_classic_exploit(high_conf)
            validated.extend(classic_high)

        if med_conf:
            # ── MEDIUM confidence → fast classic path (ExploitAgent) ──
            logger.info(f"[Exploit] Routing {len(med_conf)} MEDIUM-conf → ExploitAgent (fast)")
            classic_med = await self._run_classic_exploit(med_conf)
            # Merge and deduplicate by (endpoint, parameter, vuln_type)
            validated = list(merge_validated_vulns(validated, classic_med, prefer="first"))
            logger.info(f"[Exploit] ExploitAgent validated {len(classic_med)}/{len(med_conf)}")

        self._context.validated_vulns = validated

        self._context.exploit_duration = time.time() - start_time

        false_positives = len(hypotheses_to_verify) - len(self._context.validated_vulns)

        logger.info(f"Exploitation complete in {self._context.exploit_duration:.2f}s")
        logger.info(f"  - Validated: {len(self._context.validated_vulns)}")
        logger.info(f"  - False positives avoided: {false_positives}")

    async def _run_classic_exploit(
        self,
        hypotheses_to_verify: List[VulnHypothesis],
    ) -> List[ValidatedVuln]:
        """Run legacy ExploitAgent verification path."""
        async with ExploitAgent(
            http_client=self._http,
            payload_manager=self._payloads,
            settings=self.settings,
            llm_engine=self._llm
        ) as exploit:
            return await exploit.verify_all(hypotheses_to_verify)

    async def _run_agentic_exploit(
        self,
        hypotheses_to_verify: List[VulnHypothesis],
    ) -> List[ValidatedVuln]:
        """
        Run Coordinator + Solver exploit path and convert results to ValidatedVuln.
        Falls back to classic path if model/provider is unsupported for engine LLM client.
        """
        from xlayer_ai.core.coordinator_result import coordinator_results_to_validated_vulns
        from xlayer_ai.engine.llm import LLMClient
        from xlayer_ai.src.agent.coordinator import Coordinator

        supported_providers = {"openai", "anthropic", "ollama"}
        provider = (self.settings.llm.provider or "openai").lower()
        if provider not in supported_providers:
            logger.warning(
                f"Agentic exploit provider '{provider}' not supported by engine LLMClient; using classic exploit path"
            )
            return await self._run_classic_exploit(hypotheses_to_verify)

        llm_client = LLMClient.from_settings()
        coordinator = Coordinator(llm=llm_client, settings=self.settings)
        raw_results = await coordinator.run(
            attack_surface=self._context.attack_surface,
            hunter_hypotheses=self._hypotheses_to_agentic_dicts(hypotheses_to_verify),
        )
        validated = coordinator_results_to_validated_vulns(raw_results)
        logger.info(f"Agentic exploit validated {len(validated)} findings")
        return validated

    def _hypotheses_to_agentic_dicts(self, hypotheses: List[VulnHypothesis]) -> List[Dict[str, Any]]:
        """Convert VulnHypothesis models to dict shape expected by Coordinator.build_attack_matrix()."""
        out: List[Dict[str, Any]] = []
        for h in hypotheses:
            out.append({
                "endpoint": h.endpoint,
                "parameter": h.parameter,
                "method": h.method,
                "vuln_type": h.vuln_type.value,
                "confidence": h.confidence.value,
                "confidence_score": h.confidence_score,
                "injection_type": h.context.get("injection_type", "unknown"),
                "trigger_payload": h.context.get("trigger_payload", ""),
                "suggested_payloads": h.suggested_payloads[:5],
                "indicators": [
                    {"indicator_type": i.indicator_type, "detail": i.detail}
                    for i in h.indicators
                ][:10],
            })
        return out
    
    async def _phase_report(self):
        """Phase 4: Report Generation"""
        logger.info("=" * 60)
        logger.info("PHASE 4: REPORT GENERATION")
        logger.info("=" * 60)
        
        self._context.state = MissionState.REPORT
        start_time = time.time()
        
        from xlayer_ai.core.reporter import Reporter
        
        reporter = Reporter(settings=self.settings, llm_engine=self._llm)
        
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
