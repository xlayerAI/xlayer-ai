"""
XLayer AI Base Hunter - Abstract base class for vulnerability hunters
"""

import asyncio
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
from loguru import logger

from xlayer_hunter.models.target import AttackSurface, Endpoint
from xlayer_hunter.models.vulnerability import (
    VulnHypothesis, VulnType, Confidence, VulnIndicator
)
from xlayer_hunter.tools.http_client import HTTPClient
from xlayer_hunter.tools.payload_manager import PayloadManager
from xlayer_hunter.config.settings import Settings, get_settings


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
        settings: Optional[Settings] = None
    ):
        self.http = http_client
        self.payloads = payload_manager
        self.settings = settings or get_settings()
        
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


async def run_hunters_parallel(
    hunters: List[BaseHunter],
    attack_surface: AttackSurface
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
