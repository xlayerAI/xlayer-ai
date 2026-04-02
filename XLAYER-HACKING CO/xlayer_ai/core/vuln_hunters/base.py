"""
XLayer AI Base Hunter - Abstract base class for vulnerability hunters
"""

import asyncio
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
from loguru import logger

from xlayer_ai.models.target import AttackSurface, Endpoint
from xlayer_ai.models.vulnerability import (
    VulnHypothesis, VulnType, Confidence, VulnIndicator
)
from xlayer_ai.tools.http_client import HTTPClient
from xlayer_ai.tools.payload_manager import PayloadManager
from xlayer_ai.config.settings import Settings, get_settings
from xlayer_ai.llm.payload_generator import (
    AIPayloadGenerator, AttackContext, AttemptResult, FailureReason
)
from xlayer_ai.tools.adaptive_engine import AdaptiveEngine, SendResult, ProbeEngine


@dataclass
class HunterResult:
    """Result of a vulnerability hunt"""
    hunter_name: str
    hypotheses: List[VulnHypothesis] = field(default_factory=list)
    endpoints_tested: int = 0
    payloads_sent: int = 0
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    
    @property
    def findings_count(self) -> int:
        return len(self.hypotheses)
    
    @property
    def high_confidence_count(self) -> int:
        return sum(1 for h in self.hypotheses if h.confidence == Confidence.HIGH)


class BaseHunter(ABC):
    """
    Abstract base class for vulnerability hunters
    
    Each hunter specializes in detecting a specific vulnerability class.
    Hunters produce hypotheses that are later validated by the Exploit Agent.
    """
    
    name: str = "base"
    vuln_types: List[VulnType] = []
    
    def __init__(
        self,
        http_client: HTTPClient,
        payload_manager: PayloadManager,
        settings: Optional[Settings] = None,
        llm_engine=None
    ):
        self.http = http_client
        self.payloads = payload_manager
        self.settings = settings or get_settings()
        self._llm = llm_engine

        # AI adaptive engine setup
        self._ai_generator: Optional[AIPayloadGenerator] = (
            AIPayloadGenerator(llm_engine) if llm_engine else None
        )

        self._hypotheses: List[VulnHypothesis] = []
        self._endpoints_tested: int = 0
        self._payloads_sent: int = 0
        self._errors: List[str] = []
    
    @abstractmethod
    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        """
        Hunt for vulnerabilities in the attack surface
        
        Args:
            attack_surface: Complete attack surface from recon
            
        Returns:
            HunterResult with hypothesized vulnerabilities
        """
        pass
    
    async def test_endpoint(
        self,
        endpoint: Endpoint,
        payloads: List[str],
        parameter: str
    ) -> List[VulnHypothesis]:
        """
        Test an endpoint with multiple payloads
        
        Args:
            endpoint: Endpoint to test
            payloads: List of payloads to try
            parameter: Parameter to inject into
            
        Returns:
            List of hypotheses if vulnerabilities detected
        """
        hypotheses = []
        self._endpoints_tested += 1
        
        for payload in payloads:
            self._payloads_sent += 1
            
            try:
                result = await self._send_payload(endpoint, parameter, payload)
                
                if result:
                    hypothesis = self._analyze_response(
                        endpoint, parameter, payload, result
                    )
                    if hypothesis:
                        hypotheses.append(hypothesis)
                        
            except Exception as e:
                self._errors.append(f"{endpoint.url}: {str(e)}")
                logger.debug(f"Error testing {endpoint.url}: {e}")

        if not hypotheses and self._payloads_sent > 0:
            error_rate = len(self._errors) / max(self._payloads_sent, 1)
            if error_rate > 0.5:
                logger.warning(
                    f"{self.name}: High error rate ({error_rate:.0%}) testing "
                    f"{endpoint.url} - possible connectivity issue"
                )

        return hypotheses
    
    async def _send_payload(
        self,
        endpoint: Endpoint,
        parameter: str,
        payload: str
    ) -> Optional[Dict[str, Any]]:
        """Send a payload to an endpoint and return response data"""
        try:
            if endpoint.method.value == "GET":
                if "?" in endpoint.url:
                    url = f"{endpoint.url}&{parameter}={payload}"
                else:
                    url = f"{endpoint.url}?{parameter}={payload}"
                
                response = await self.http.get(url)
            else:
                data = {parameter: payload}
                response = await self.http.post(endpoint.url, data=data)
            
            return {
                "status": response.status,
                "headers": response.headers,
                "body": response.body,
                "elapsed_ms": response.elapsed_ms,
                "error": response.error
            }
            
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return None
    
    @abstractmethod
    def _analyze_response(
        self,
        endpoint: Endpoint,
        parameter: str,
        payload: str,
        response: Dict[str, Any]
    ) -> Optional[VulnHypothesis]:
        """
        Analyze response to determine if vulnerability exists
        
        Args:
            endpoint: Tested endpoint
            parameter: Tested parameter
            payload: Payload that was sent
            response: Response data
            
        Returns:
            VulnHypothesis if vulnerability indicators found
        """
        pass
    
    def _create_hypothesis(
        self,
        vuln_type: VulnType,
        endpoint: Endpoint,
        parameter: str,
        confidence: Confidence,
        indicators: List[VulnIndicator],
        suggested_payloads: List[str],
        context: Optional[Dict[str, Any]] = None
    ) -> VulnHypothesis:
        """Create a vulnerability hypothesis"""
        return VulnHypothesis(
            vuln_type=vuln_type,
            endpoint=endpoint.url,
            method=endpoint.method.value,
            parameter=parameter,
            confidence=confidence,
            indicators=indicators,
            suggested_payloads=suggested_payloads,
            context=context or {},
            hunter_name=self.name
        )
    
    def _build_result(self, duration: float) -> HunterResult:
        """Build the final hunter result"""
        return HunterResult(
            hunter_name=self.name,
            hypotheses=self._hypotheses,
            endpoints_tested=self._endpoints_tested,
            payloads_sent=self._payloads_sent,
            errors=self._errors,
            duration_seconds=duration
        )
    
    def _reset_state(self):
        """Reset hunter state for new hunt"""
        self._hypotheses = []
        self._endpoints_tested = 0
        self._payloads_sent = 0
        self._errors = []

    def _build_attack_context(
        self,
        endpoint: Endpoint,
        parameter: str,
        vuln_type: str,
        attack_surface: AttackSurface
    ) -> AttackContext:
        """Build AttackContext from endpoint + attack surface info"""
        tech = attack_surface.technology
        return AttackContext(
            url=endpoint.url,
            parameter=parameter,
            method=endpoint.method.value,
            vuln_type=vuln_type,
            server=tech.server or "unknown",
            language=tech.language or "unknown",
            framework=tech.framework or "unknown",
            database=tech.database or "unknown",
        )

    async def _adaptive_test(
        self,
        endpoint: Endpoint,
        parameter: str,
        static_payloads: List[str],
        ctx: AttackContext,
        success_fn,
        extra: Optional[Dict[str, Any]] = None
    ) -> List[AttemptResult]:
        """
        Run adaptive engine: static → WAF mutations → AI generated.
        Probe-first runs inside AdaptiveEngine (ProbeEngine); ctx holds
        observation (probe_status_quote, probe_body_snippet, waf) for payload choice.
        Returns all attempt results.
        """
        if not self._ai_generator:
            # No AI - just send static payloads
            results = []
            for p in static_payloads:
                r = await self._send_payload(endpoint, parameter, p)
                self._payloads_sent += 1
                if r:
                    attempt = AttemptResult(
                        payload=p,
                        status_code=r.get("status", 0),
                        response_body=r.get("body", "")[:300],
                        response_length=len(r.get("body", "")),
                        elapsed_ms=r.get("elapsed_ms", 0),
                        success=False
                    )
                    results.append(attempt)
            return results

        async def send_fn(ep, param, payload) -> SendResult:
            self._payloads_sent += 1
            r = await self._send_payload(ep, param, payload)
            if not r:
                return SendResult(payload=payload, status_code=0, body="",
                                  elapsed_ms=0, success=False, error="no response")
            return SendResult(
                payload=payload,
                status_code=r.get("status", 0),
                body=r.get("body", ""),
                elapsed_ms=r.get("elapsed_ms", 0),
                success=False,
                error=r.get("error"),
                headers=dict(r.get("headers", {})),
            )

        engine = AdaptiveEngine(
            ai_generator=self._ai_generator,
            payload_manager=self.payloads,
            send_fn=send_fn,
            success_fn=success_fn
        )
        return await engine.run(endpoint, parameter, ctx, static_payloads, extra)

    async def _llm_analyze_response(
        self,
        endpoint: Endpoint,
        parameter: str,
        payload: str,
        response: Dict[str, Any],
        vuln_type: str
    ) -> Optional[Dict[str, Any]]:
        """
        Use LLM to analyze a borderline response for vulnerability indicators.
        Only called when static analysis gives MEDIUM/LOW confidence.
        Returns None if LLM is unavailable.
        """
        if not self._llm or not self._llm.is_ready:
            return None

        try:
            result = await self._llm.analyze_response(
                response_body=response.get("body", "")[:2000],
                vuln_type=vuln_type,
                context={
                    "endpoint": endpoint.url,
                    "parameter": parameter,
                    "payload": payload,
                    "status_code": response.get("status"),
                    "elapsed_ms": response.get("elapsed_ms")
                }
            )
            return result
        except Exception as e:
            logger.debug(f"LLM analysis failed (non-critical): {e}")
            return None


async def run_hunters_parallel(
    hunters: List[BaseHunter],
    attack_surface: AttackSurface,
    max_concurrency: Optional[int] = None,
) -> List[HunterResult]:
    """
    Run multiple hunters in parallel
    
    Args:
        hunters: List of hunter instances
        attack_surface: Attack surface to hunt in
        
    Returns:
        List of results from all hunters
    """
    logger.info(f"Running {len(hunters)} hunters in parallel")
    
    tasks = []
    if max_concurrency and max_concurrency > 0:
        semaphore = asyncio.Semaphore(max_concurrency)

        async def _bounded_hunt(hunter: BaseHunter):
            async with semaphore:
                return await hunter.hunt(attack_surface)

        tasks = [_bounded_hunt(hunter) for hunter in hunters]
    else:
        tasks = [hunter.hunt(attack_surface) for hunter in hunters]

    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    valid_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.error(f"Hunter {hunters[i].name} failed: {result}")
            valid_results.append(HunterResult(
                hunter_name=hunters[i].name,
                errors=[str(result)]
            ))
        else:
            valid_results.append(result)
    
    total_hypotheses = sum(r.findings_count for r in valid_results)
    logger.info(f"Hunters complete: {total_hypotheses} total hypotheses")
    
    return valid_results
