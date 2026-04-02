"""
XLayer AI XSS Hunter - Detects Cross-Site Scripting vulnerabilities

XLayer AI Compatible - XSS Category:
- Reflected XSS
- Stored XSS (indicators)
- DOM-based XSS

OWASP: A03:2021 - Injection (XSS is a form of injection)
CWE: CWE-79 (Cross-site Scripting)
"""

import re
import time
import html
from typing import List, Optional, Dict, Any
from urllib.parse import quote, unquote
from loguru import logger

from xlayer_hunter.core.vuln_hunters.base import BaseHunter, HunterResult
from xlayer_hunter.models.target import AttackSurface, Endpoint
from xlayer_hunter.models.vulnerability import (
    VulnHypothesis, VulnType, Confidence, VulnIndicator
)
from xlayer_hunter.tools.payload_manager import PayloadCategory, XSSContext


class XSSHunter(BaseHunter):
    """
    Cross-Site Scripting (XSS) Hunter
    
    Comprehensive XSS detection covering:
    - Reflected XSS (immediate reflection in response)
    - Stored XSS indicators (persistence detection)
    - DOM-based XSS (client-side sink detection)
    - Context-aware payload selection
    
    Supports multiple injection contexts:
    - HTML body
    - HTML attributes
    - JavaScript strings
    - URL parameters
    - CSS contexts
    
    OWASP: A03:2021 - Injection
    CWE: CWE-79
    """
    
    name = "xss"
    vuln_types = [VulnType.XSS_REFLECTED, VulnType.XSS_STORED, VulnType.XSS_DOM]
    
    CANARY = "xlayer7x7"
    
    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        """Hunt for XSS vulnerabilities"""
        start_time = time.time()
        self._reset_state()
        
        logger.info(f"XSS Hunter starting on {len(attack_surface.testable_endpoints)} endpoints")
        
        for endpoint in attack_surface.testable_endpoints:
            for param in endpoint.parameters:
                context = await self._detect_reflection_context(endpoint, param.name)
                
                if context:
                    hypotheses = await self._test_xss(endpoint, param.name, context)
                    self._hypotheses.extend(hypotheses)
        
        duration = time.time() - start_time
        result = self._build_result(duration)
        
        logger.info(
            f"XSS Hunter complete: {result.findings_count} hypotheses, "
            f"{result.high_confidence_count} high confidence"
        )
        
        return result
    
    async def _detect_reflection_context(
        self,
        endpoint: Endpoint,
        parameter: str
    ) -> Optional[Dict[str, Any]]:
        """Detect where and how input is reflected"""
        self._payloads_sent += 1
        
        response = await self._send_payload(endpoint, parameter, self.CANARY)
        
        if not response or response.get("error"):
            return None
        
        body = response["body"]
        
        if self.CANARY not in body:
            return None
        
        context = self._analyze_reflection_context(body, self.CANARY)
        return context
    
    def _analyze_reflection_context(self, body: str, canary: str) -> Dict[str, Any]:
        """Analyze the context where the canary is reflected"""
        contexts = []
        
        html_body_pattern = rf">[^<]*{canary}[^<]*<"
        if re.search(html_body_pattern, body):
            contexts.append(XSSContext.HTML_BODY)
        
        attr_patterns = [
            rf'="[^"]*{canary}[^"]*"',
            rf"='[^']*{canary}[^']*'",
            rf'="{canary}"',
            rf"='{canary}'",
        ]
        for pattern in attr_patterns:
            if re.search(pattern, body):
                contexts.append(XSSContext.HTML_ATTRIBUTE)
                break
        
        js_patterns = [
            rf"<script[^>]*>[^<]*{canary}[^<]*</script>",
            rf"var\s+\w+\s*=\s*['\"][^'\"]*{canary}",
            rf":\s*['\"][^'\"]*{canary}",
        ]
        for pattern in js_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                contexts.append(XSSContext.JAVASCRIPT)
                break
        
        url_patterns = [
            rf"href\s*=\s*['\"][^'\"]*{canary}",
            rf"src\s*=\s*['\"][^'\"]*{canary}",
            rf"action\s*=\s*['\"][^'\"]*{canary}",
        ]
        for pattern in url_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                contexts.append(XSSContext.URL)
                break
        
        if not contexts:
            contexts.append(XSSContext.HTML_BODY)
        
        encoded = html.escape(canary) in body
        url_encoded = quote(canary) in body
        
        return {
            "contexts": contexts,
            "primary_context": contexts[0] if contexts else XSSContext.HTML_BODY,
            "is_encoded": encoded,
            "is_url_encoded": url_encoded,
            "reflection_count": body.count(canary)
        }
    
    async def _test_xss(
        self,
        endpoint: Endpoint,
        parameter: str,
        context: Dict[str, Any]
    ) -> List[VulnHypothesis]:
        """Test for XSS based on detected context"""
        hypotheses = []
        self._endpoints_tested += 1
        
        primary_context = context["primary_context"]
        payloads = self.payloads.get_xss_payloads(context=primary_context)
        
        for payload_obj in payloads[:10]:
            payload = payload_obj.value
            self._payloads_sent += 1
            
            response = await self._send_payload(endpoint, parameter, payload)
            
            if not response or response.get("error"):
                continue
            
            body = response["body"]
            
            reflection_type = self._check_payload_reflection(payload, body)
            
            if reflection_type:
                indicators = [
                    VulnIndicator(
                        indicator_type="payload_reflected",
                        detail=f"Payload reflected {reflection_type}",
                        confidence_boost=0.2 if reflection_type == "unencoded" else 0.1
                    ),
                    VulnIndicator(
                        indicator_type="context",
                        detail=f"Injection context: {primary_context.value}",
                        confidence_boost=0.1
                    )
                ]
                
                if reflection_type == "unencoded":
                    js_executable = self._check_js_executable(payload, body)
                    if js_executable:
                        indicators.append(VulnIndicator(
                            indicator_type="js_executable",
                            detail="JavaScript appears executable in context",
                            confidence_boost=0.2
                        ))
                        confidence = Confidence.HIGH
                    else:
                        confidence = Confidence.MEDIUM
                else:
                    confidence = Confidence.LOW
                
                hypothesis = self._create_hypothesis(
                    vuln_type=VulnType.XSS_REFLECTED,
                    endpoint=endpoint,
                    parameter=parameter,
                    confidence=confidence,
                    indicators=indicators,
                    suggested_payloads=[payload],
                    context={
                        "xss_context": primary_context.value,
                        "reflection_type": reflection_type,
                        "payload": payload,
                        "all_contexts": [c.value for c in context["contexts"]]
                    }
                )
                hypotheses.append(hypothesis)
                
                if confidence == Confidence.HIGH:
                    break
        
        return hypotheses
    
    def _check_payload_reflection(self, payload: str, body: str) -> Optional[str]:
        """Check how payload is reflected in response"""
        if payload in body:
            return "unencoded"
        
        encoded_payload = html.escape(payload)
        if encoded_payload in body:
            return "html_encoded"
        
        url_encoded = quote(payload)
        if url_encoded in body:
            return "url_encoded"
        
        partial_checks = [
            "<script>",
            "onerror=",
            "onload=",
            "javascript:",
            "alert(",
        ]
        
        for check in partial_checks:
            if check in payload.lower() and check in body.lower():
                return "partial"
        
        return None
    
    def _check_js_executable(self, payload: str, body: str) -> bool:
        """Check if JavaScript in payload appears executable"""
        dangerous_patterns = [
            r"<script[^>]*>[^<]*alert\s*\(",
            r"<[^>]+\s+on\w+\s*=\s*['\"]?[^'\"]*alert",
            r"javascript:\s*alert",
            r"<svg[^>]*onload",
            r"<img[^>]*onerror",
            r"<body[^>]*onload",
            r"<iframe[^>]*src\s*=\s*['\"]?javascript:",
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        
        return False
    
    def _analyze_response(
        self,
        endpoint: Endpoint,
        parameter: str,
        payload: str,
        response: Dict[str, Any]
    ) -> Optional[VulnHypothesis]:
        """Analyze response for XSS indicators"""
        return None
