"""
XLayer AI Auth Hunter - Detects authentication and authorization vulnerabilities
"""

import re
import time
import json
from typing import List, Optional, Dict, Any
from loguru import logger

from xlayer_ai.core.vuln_hunters.base import BaseHunter, HunterResult
from xlayer_ai.models.target import AttackSurface, Endpoint, EndpointType
from xlayer_ai.models.vulnerability import (
    VulnHypothesis, VulnType, Confidence, VulnIndicator
)
from xlayer_ai.tools.payload_manager import PayloadCategory


class AuthHunter(BaseHunter):
    """
    Authentication/Authorization Hunter
    
    Detects:
    - Authentication bypass (SQL injection in login)
    - IDOR (Insecure Direct Object Reference)
    - Broken access control
    - Session management issues
    - JWT vulnerabilities
    """
    
    name = "auth"
    vuln_types = [VulnType.AUTH_BYPASS, VulnType.IDOR, VulnType.SESSION_FIXATION]
    
    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        """Hunt for authentication vulnerabilities"""
        start_time = time.time()
        self._reset_state()
        
        logger.info(f"Auth Hunter starting")
        
        static_bypass = [p.value for p in self.payloads.get_auth_bypass_payloads()]

        for endpoint in attack_surface.auth_endpoints:
            auth_hypotheses = await self._test_auth_bypass(endpoint)
            self._hypotheses.extend(auth_hypotheses)

            # AI adaptive if no high confidence found
            if not any(h.confidence.value == "high" for h in auth_hypotheses):
                for param in endpoint.parameters:
                    ctx = self._build_attack_context(endpoint, param.name, "auth", attack_surface)

                    def auth_success(r, _ctx):
                        body = r.body.lower()
                        return any(s in body for s in [
                            "welcome", "dashboard", "logout", "profile",
                            "token", "session", "authenticated"
                        ])

                    attempts = await self._adaptive_test(
                        endpoint, param.name, static_bypass, ctx, auth_success
                    )
                    for attempt in attempts:
                        if attempt.success:
                            self._hypotheses.append(self._create_hypothesis(
                                vuln_type=VulnType.AUTH_BYPASS,
                                endpoint=endpoint,
                                parameter=param.name,
                                confidence=Confidence.HIGH,
                                indicators=[VulnIndicator(
                                    indicator_type="ai_adaptive",
                                    detail=f"AI auth bypass: {attempt.payload[:60]}",
                                    confidence_boost=0.3
                                )],
                                suggested_payloads=[attempt.payload],
                                context={"ai_generated": True, "waf_bypassed": ctx.waf}
                            ))

        for endpoint in attack_surface.api_endpoints:
            idor_hypotheses = await self._test_idor(endpoint)
            self._hypotheses.extend(idor_hypotheses)

        for endpoint in attack_surface.testable_endpoints:
            if self._has_id_parameter(endpoint):
                idor_hypotheses = await self._test_idor(endpoint)
                self._hypotheses.extend(idor_hypotheses)

        duration = time.time() - start_time
        result = self._build_result(duration)
        
        logger.info(
            f"Auth Hunter complete: {result.findings_count} hypotheses, "
            f"{result.high_confidence_count} high confidence"
        )
        
        return result
    
    def _has_id_parameter(self, endpoint: Endpoint) -> bool:
        """Check if endpoint has ID-like parameters"""
        id_patterns = ["id", "user_id", "userid", "uid", "account", "profile"]
        for param in endpoint.parameters:
            if any(p in param.name.lower() for p in id_patterns):
                return True
        return False
    
    async def _test_auth_bypass(self, endpoint: Endpoint) -> List[VulnHypothesis]:
        """Test for authentication bypass vulnerabilities"""
        hypotheses = []
        self._endpoints_tested += 1
        
        bypass_payloads = self.payloads.get_auth_bypass_payloads()
        
        username_params = ["username", "user", "email", "login", "uname"]
        password_params = ["password", "pass", "pwd", "passwd"]
        
        username_param = None
        password_param = None
        
        for param in endpoint.parameters:
            param_lower = param.name.lower()
            if any(u in param_lower for u in username_params):
                username_param = param.name
            if any(p in param_lower for p in password_params):
                password_param = param.name
        
        if not username_param:
            return hypotheses
        
        for payload_obj in bypass_payloads:
            payload = payload_obj.value
            self._payloads_sent += 1
            
            data = {username_param: payload}
            if password_param:
                data[password_param] = "anything"
            
            try:
                response = await self.http.post(endpoint.url, data=data)
                
                if response.error:
                    continue
                
                bypass_indicators = self._check_auth_bypass_success(response)
                
                if bypass_indicators:
                    indicators = [
                        VulnIndicator(
                            indicator_type="auth_bypass",
                            detail=f"Potential bypass with payload: {payload[:30]}...",
                            confidence_boost=0.2
                        )
                    ]
                    indicators.extend(bypass_indicators)
                    
                    confidence = Confidence.MEDIUM

                    llm_result = await self._llm_analyze_response(
                        endpoint, username_param, payload,
                        {"body": response.body, "status": response.status},
                        "auth_bypass"
                    )
                    if llm_result and llm_result.get("vulnerable") and llm_result.get("confidence", 0) > 0.7:
                        confidence = Confidence.HIGH
                        indicators.append(VulnIndicator(
                            indicator_type="llm_analysis",
                            detail=f"LLM confirmed auth bypass with {llm_result.get('confidence', 0):.0%} confidence",
                            confidence_boost=0.2
                        ))

                    hypothesis = self._create_hypothesis(
                        vuln_type=VulnType.AUTH_BYPASS,
                        endpoint=endpoint,
                        parameter=username_param,
                        confidence=confidence,
                        indicators=indicators,
                        suggested_payloads=[payload],
                        context={
                            "bypass_type": "sqli" if "'" in payload else "logic",
                            "username_param": username_param,
                            "password_param": password_param,
                            "llm_confirmed": confidence == Confidence.HIGH
                        }
                    )
                    hypotheses.append(hypothesis)
                    
            except Exception as e:
                self._errors.append(f"Auth bypass test failed: {e}")
        
        return hypotheses
    
    def _check_auth_bypass_success(self, response) -> List[VulnIndicator]:
        """Check if authentication bypass was successful"""
        indicators = []
        
        success_patterns = [
            r"welcome",
            r"dashboard",
            r"logged.?in",
            r"success",
            r"profile",
            r"account",
            r"logout",
        ]
        
        for pattern in success_patterns:
            if re.search(pattern, response.body, re.IGNORECASE):
                indicators.append(VulnIndicator(
                    indicator_type="success_indicator",
                    detail=f"Found success pattern: {pattern}",
                    confidence_boost=0.1
                ))
        
        if response.cookies:
            session_cookies = ["session", "token", "auth", "jwt", "sid"]
            for cookie_name in response.cookies:
                if any(s in cookie_name.lower() for s in session_cookies):
                    indicators.append(VulnIndicator(
                        indicator_type="session_cookie",
                        detail=f"Session cookie set: {cookie_name}",
                        confidence_boost=0.15
                    ))
        
        if response.status in [200, 302] and response.redirects:
            for redirect in response.redirects:
                if any(p in redirect.lower() for p in ["dashboard", "home", "profile"]):
                    indicators.append(VulnIndicator(
                        indicator_type="redirect",
                        detail=f"Redirected to: {redirect}",
                        confidence_boost=0.1
                    ))
        
        return indicators
    
    async def _test_idor(self, endpoint: Endpoint) -> List[VulnHypothesis]:
        """Test for Insecure Direct Object Reference"""
        hypotheses = []
        
        id_params = []
        for param in endpoint.parameters:
            if any(p in param.name.lower() for p in ["id", "uid", "user", "account", "profile", "order"]):
                id_params.append(param)
        
        if not id_params:
            return hypotheses
        
        self._endpoints_tested += 1
        
        for param in id_params:
            original_value = param.sample_value or "1"
            
            try:
                original_id = int(original_value)
                test_ids = [
                    str(original_id + 1),
                    str(original_id - 1),
                    str(original_id + 100),
                    "0",
                    "-1",
                ]
            except ValueError:
                test_ids = ["1", "2", "admin", "test"]
            
            baseline_response = await self._send_payload(endpoint, param.name, original_value)
            if not baseline_response:
                continue
            
            baseline_length = len(baseline_response["body"])
            baseline_status = baseline_response["status"]
            
            for test_id in test_ids:
                self._payloads_sent += 1
                
                response = await self._send_payload(endpoint, param.name, test_id)
                
                if not response:
                    continue
                
                if response["status"] == 200:
                    response_length = len(response["body"])
                    
                    if response_length > 100 and abs(response_length - baseline_length) < baseline_length * 0.5:
                        different_content = self._check_different_data(
                            baseline_response["body"],
                            response["body"]
                        )
                        
                        if different_content:
                            indicators = [
                                VulnIndicator(
                                    indicator_type="idor_access",
                                    detail=f"Accessed different resource with ID: {test_id}",
                                    confidence_boost=0.2
                                ),
                                VulnIndicator(
                                    indicator_type="data_difference",
                                    detail="Response contains different data than baseline",
                                    confidence_boost=0.15
                                )
                            ]
                            
                            hypothesis = self._create_hypothesis(
                                vuln_type=VulnType.IDOR,
                                endpoint=endpoint,
                                parameter=param.name,
                                confidence=Confidence.MEDIUM,
                                indicators=indicators,
                                suggested_payloads=test_ids,
                                context={
                                    "original_id": original_value,
                                    "test_id": test_id,
                                    "baseline_length": baseline_length,
                                    "response_length": response_length
                                }
                            )
                            hypotheses.append(hypothesis)
                            break
        
        return hypotheses
    
    def _check_different_data(self, baseline: str, response: str) -> bool:
        """Check if response contains different data than baseline"""
        if baseline == response:
            return False
        
        data_patterns = [
            r'"id"\s*:\s*\d+',
            r'"user_?id"\s*:\s*\d+',
            r'"email"\s*:\s*"[^"]+"',
            r'"name"\s*:\s*"[^"]+"',
            r'"username"\s*:\s*"[^"]+"',
        ]
        
        for pattern in data_patterns:
            baseline_match = re.search(pattern, baseline)
            response_match = re.search(pattern, response)
            
            if baseline_match and response_match:
                if baseline_match.group() != response_match.group():
                    return True
        
        return len(response) > 100 and baseline != response
    
    def _analyze_response(
        self,
        endpoint: Endpoint,
        parameter: str,
        payload: str,
        response: Dict[str, Any]
    ) -> Optional[VulnHypothesis]:
        """Analyze response for auth vulnerabilities"""
        return None
