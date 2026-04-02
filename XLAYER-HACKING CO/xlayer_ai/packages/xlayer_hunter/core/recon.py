"""
XLayer AI Recon Agent - Attack surface reconnaissance and mapping
"""

import asyncio
import re
import hashlib
import time
from typing import Optional, Dict, List, Any, Set
from urllib.parse import urlparse
from loguru import logger

from xlayer_hunter.models.target import (
    Target, AttackSurface, TechnologyStack, ServiceInfo,
    Endpoint, EndpointType, HTTPMethod
)
from xlayer_hunter.tools.http_client import HTTPClient
from xlayer_hunter.tools.scanner import PortScanner, resolve_hostname, get_dns_records
from xlayer_hunter.tools.crawler import WebCrawler
from xlayer_hunter.config.settings import Settings, get_settings


TECH_SIGNATURES = {
    "server": {
        "nginx": [r"nginx", r"nginx/[\d.]+"],
        "apache": [r"apache", r"Apache/[\d.]+"],
        "iis": [r"Microsoft-IIS", r"IIS/[\d.]+"],
        "cloudflare": [r"cloudflare"],
        "gunicorn": [r"gunicorn"],
        "uvicorn": [r"uvicorn"],
    },
    "language": {
        "php": [r"X-Powered-By:.*PHP", r"\.php", r"PHPSESSID"],
        "python": [r"X-Powered-By:.*Python", r"wsgi", r"django", r"flask"],
        "node": [r"X-Powered-By:.*Express", r"connect\.sid"],
        "java": [r"X-Powered-By:.*Servlet", r"JSESSIONID", r"\.jsp"],
        "ruby": [r"X-Powered-By:.*Phusion", r"_session_id", r"\.rb"],
        "asp.net": [r"X-Powered-By:.*ASP\.NET", r"ASP\.NET", r"\.aspx"],
    },
    "framework": {
        "django": [r"csrfmiddlewaretoken", r"django", r"__admin__"],
        "flask": [r"Werkzeug", r"flask"],
        "laravel": [r"laravel_session", r"XSRF-TOKEN"],
        "rails": [r"X-Rails", r"_rails_", r"authenticity_token"],
        "express": [r"X-Powered-By:.*Express"],
        "spring": [r"X-Application-Context", r"JSESSIONID"],
        "wordpress": [r"wp-content", r"wp-includes", r"wp-json"],
        "drupal": [r"Drupal", r"drupal\.js", r"sites/default"],
        "joomla": [r"Joomla", r"joomla", r"option=com_"],
    },
    "database": {
        "mysql": [r"mysql", r"mysqli", r"MariaDB"],
        "postgresql": [r"postgres", r"pgsql", r"PostgreSQL"],
        "mongodb": [r"mongodb", r"mongoose"],
        "redis": [r"redis"],
        "sqlite": [r"sqlite"],
    },
    "frontend": {
        "react": [r"react", r"_reactRoot", r"__REACT"],
        "vue": [r"vue", r"__vue__", r"v-cloak"],
        "angular": [r"ng-version", r"ng-app", r"angular"],
        "jquery": [r"jquery", r"jQuery"],
        "bootstrap": [r"bootstrap"],
    },
    "waf": {
        "cloudflare": [r"cf-ray", r"__cfduid", r"cloudflare"],
        "akamai": [r"akamai", r"AkamaiGHost"],
        "aws_waf": [r"awswaf", r"x-amzn-waf"],
        "imperva": [r"incap_ses", r"visid_incap"],
        "sucuri": [r"sucuri", r"x-sucuri"],
        "modsecurity": [r"mod_security", r"NOYB"],
    },
    "cdn": {
        "cloudflare": [r"cf-cache-status", r"cf-ray"],
        "akamai": [r"X-Akamai"],
        "fastly": [r"X-Served-By.*cache", r"fastly"],
        "cloudfront": [r"X-Amz-Cf", r"cloudfront"],
    }
}

FAVICON_HASHES = {
    "wordpress": "2a9f5d8a7b3c4e1f",
    "drupal": "3b8e6c9d2a1f4e5c",
    "joomla": "4c7d5e8f1a2b3c4d",
}


class ReconAgent:
    """
    Reconnaissance Agent - Maps the attack surface of a target
    
    Phase 1 of XLayer AI pipeline:
    - DNS resolution
    - Port scanning
    - Technology detection
    - Web crawling
    - Entry point discovery
    """
    
    def __init__(
        self,
        settings: Optional[Settings] = None,
        http_client: Optional[HTTPClient] = None
    ):
        self.settings = settings or get_settings()
        self._http = http_client
        self._owns_http = http_client is None
    
    async def __aenter__(self):
        if self._http is None:
            self._http = HTTPClient(
                timeout=self.settings.scan.timeout,
                rate_limit=self.settings.scan.rate_limit,
                user_agent=self.settings.scan.user_agent,
                verify_ssl=self.settings.scan.verify_ssl
            )
            await self._http.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._owns_http and self._http:
            await self._http.close()
    
    async def execute(self, target_url: str) -> AttackSurface:
        """
        Execute full reconnaissance on target
        
        Args:
            target_url: Target URL to scan
            
        Returns:
            AttackSurface with complete mapping
        """
        start_time = time.time()
        logger.info(f"Starting reconnaissance on {target_url}")
        
        parsed = urlparse(target_url)
        hostname = parsed.netloc.split(":")[0]
        
        target = Target(
            url=target_url,
            hostname=hostname
        )
        
        attack_surface = AttackSurface(target=target)
        
        dns_task = self._resolve_dns(hostname)
        initial_response_task = self._http.get(target_url)
        
        dns_result, initial_response = await asyncio.gather(
            dns_task, initial_response_task
        )
        
        if dns_result:
            attack_surface.ip_addresses = dns_result.get("A", [])
            target.ip_address = attack_surface.ip_addresses[0] if attack_surface.ip_addresses else None
        
        if self.settings.port_scan.enabled and target.ip_address:
            port_result = await self._scan_ports(target.ip_address)
            attack_surface.open_ports = port_result.get("open_ports", [])
            attack_surface.services = port_result.get("services", [])
        
        if initial_response.is_success:
            tech_stack = await self._detect_technology(target_url, initial_response)
            attack_surface.technology = tech_stack
        
        robots_txt = await self._fetch_robots_txt(target_url)
        if robots_txt:
            attack_surface.robots_txt = robots_txt
        
        sitemap_urls = await self._fetch_sitemap(target_url)
        attack_surface.sitemap_urls = sitemap_urls
        
        crawler = WebCrawler(
            http_client=self._http,
            max_depth=self.settings.scan.max_depth,
            max_pages=self.settings.scan.max_pages
        )
        
        crawl_result = await crawler.crawl(target_url)
        
        attack_surface.endpoints = crawl_result.endpoints
        attack_surface.forms = crawl_result.forms
        attack_surface.api_endpoints = crawl_result.api_endpoints
        
        for endpoint in attack_surface.forms:
            if endpoint.endpoint_type == EndpointType.AUTH:
                attack_surface.auth_endpoints.append(endpoint)
        
        auth_patterns = ["login", "signin", "auth", "session", "oauth", "jwt"]
        for endpoint in attack_surface.all_endpoints:
            if any(p in endpoint.url.lower() for p in auth_patterns):
                if endpoint not in attack_surface.auth_endpoints:
                    attack_surface.auth_endpoints.append(endpoint)
        
        attack_surface.scan_duration_seconds = time.time() - start_time
        
        logger.info(
            f"Reconnaissance complete: "
            f"{len(attack_surface.all_endpoints)} endpoints, "
            f"{len(attack_surface.testable_endpoints)} testable, "
            f"score={attack_surface.attack_surface_score}"
        )
        
        return attack_surface
    
    async def _resolve_dns(self, hostname: str) -> Dict[str, List[str]]:
        """Resolve DNS records for hostname"""
        logger.debug(f"Resolving DNS for {hostname}")
        
        try:
            records = await get_dns_records(hostname)
            
            if records.get("A"):
                logger.debug(f"DNS A records: {records['A']}")
            
            return records
        except Exception as e:
            logger.warning(f"DNS resolution failed: {e}")
            return {}
    
    async def _scan_ports(self, ip_address: str) -> Dict[str, Any]:
        """Scan ports on target IP"""
        logger.debug(f"Scanning ports on {ip_address}")
        
        try:
            scanner = PortScanner(
                timeout=self.settings.port_scan.timeout,
                concurrent=self.settings.port_scan.concurrent
            )
            
            result = await scanner.scan_ports(
                ip_address,
                top_n=self.settings.port_scan.top_ports
            )
            
            services = [
                ServiceInfo(
                    port=s.port,
                    service=s.service,
                    banner=s.banner
                )
                for s in result.services
            ]
            
            return {
                "open_ports": result.open_ports,
                "services": services
            }
        except Exception as e:
            logger.warning(f"Port scan failed: {e}")
            return {"open_ports": [], "services": []}
    
    async def _detect_technology(
        self,
        url: str,
        response
    ) -> TechnologyStack:
        """Detect technology stack from response"""
        logger.debug("Detecting technology stack")
        
        tech = TechnologyStack()
        
        headers_str = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        body = response.body
        combined = headers_str + "\n" + body
        
        for category, signatures in TECH_SIGNATURES.items():
            for tech_name, patterns in signatures.items():
                for pattern in patterns:
                    if re.search(pattern, combined, re.IGNORECASE):
                        if category == "server":
                            tech.server = tech_name
                        elif category == "language":
                            tech.language = tech_name
                        elif category == "framework":
                            tech.framework = tech_name
                        elif category == "database":
                            tech.database = tech_name
                        elif category == "frontend":
                            tech.frontend = tech_name
                        elif category == "waf":
                            tech.waf = tech_name
                        elif category == "cdn":
                            tech.cdn = tech_name
                        break
        
        server_header = response.headers.get("server", "")
        if server_header and not tech.server:
            tech.server = server_header.split("/")[0].lower()
        
        powered_by = response.headers.get("x-powered-by", "")
        if powered_by:
            tech.additional["x-powered-by"] = powered_by
        
        try:
            favicon_response = await self._http.get(f"{url}/favicon.ico")
            if favicon_response.is_success:
                favicon_hash = hashlib.md5(favicon_response.body.encode()).hexdigest()[:16]
                for cms, known_hash in FAVICON_HASHES.items():
                    if favicon_hash == known_hash:
                        tech.cms = cms
                        break
        except Exception:
            pass
        
        logger.debug(f"Detected tech: {tech.model_dump(exclude_none=True)}")
        
        return tech
    
    async def _fetch_robots_txt(self, base_url: str) -> Optional[str]:
        """Fetch robots.txt content"""
        parsed = urlparse(base_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        
        try:
            response = await self._http.get(robots_url)
            if response.is_success:
                return response.body
        except Exception:
            pass
        
        return None
    
    async def _fetch_sitemap(self, base_url: str) -> List[str]:
        """Fetch and parse sitemap URLs"""
        parsed = urlparse(base_url)
        sitemap_urls = [
            f"{parsed.scheme}://{parsed.netloc}/sitemap.xml",
            f"{parsed.scheme}://{parsed.netloc}/sitemap_index.xml",
        ]
        
        discovered_urls = []
        
        for sitemap_url in sitemap_urls:
            try:
                response = await self._http.get(sitemap_url)
                if response.is_success:
                    urls = re.findall(r"<loc>(.*?)</loc>", response.body)
                    discovered_urls.extend(urls[:50])
                    break
            except Exception:
                pass
        
        return discovered_urls
    
    def get_hunter_recommendations(self, attack_surface: AttackSurface) -> List[str]:
        """
        Recommend which vulnerability hunters to activate based on attack surface
        
        Args:
            attack_surface: Completed attack surface map
            
        Returns:
            List of recommended hunter names
        """
        hunters = []
        
        if attack_surface.testable_endpoints:
            hunters.append("sqli")
            hunters.append("xss")
        
        if attack_surface.auth_endpoints:
            hunters.append("auth")
        
        if attack_surface.api_endpoints:
            hunters.append("ssrf")
            hunters.append("auth")
        
        tech = attack_surface.technology
        if tech.language in ["php", "python", "ruby", "node"]:
            hunters.append("lfi")
        
        if tech.framework in ["wordpress", "drupal", "joomla"]:
            hunters.append("lfi")
            hunters.append("sqli")
        
        if any(p in [80, 443, 8080, 8443] for p in attack_surface.open_ports):
            if "ssrf" not in hunters:
                hunters.append("ssrf")
        
        return list(set(hunters))
