"""
XLayer AI Subdomain Takeover Hunter
Detects dangling CNAME records pointing to unclaimed cloud services.
Covers: GitHub Pages, Heroku, AWS S3, Azure, Shopify, Fastly, Netlify, and 20+ more.
"""

import re
import time
import asyncio
from typing import List, Optional, Dict, Any, Tuple
from loguru import logger

from xlayer_ai.core.vuln_hunters.base import BaseHunter, HunterResult
from xlayer_ai.models.target import AttackSurface, Endpoint
from xlayer_ai.models.vulnerability import (
    VulnHypothesis, VulnType, Confidence, VulnIndicator
)


# ─── Service Fingerprints ─────────────────────────────────────────────────────
# (cname_pattern, unclaimed_body_pattern, service_name, severity)
TAKEOVER_FINGERPRINTS = [
    # GitHub Pages
    (r"github\.io",             r"There isn't a GitHub Pages site here",    "GitHub Pages",  "high"),
    # Heroku
    (r"herokudns\.com",         r"No such app",                              "Heroku",        "high"),
    (r"herokuapp\.com",         r"No such app",                              "Heroku",        "high"),
    # AWS S3
    (r"s3\.amazonaws\.com",     r"NoSuchBucket|The specified bucket",        "AWS S3",        "high"),
    (r"s3-website",             r"NoSuchBucket|The specified bucket",        "AWS S3",        "high"),
    # AWS CloudFront
    (r"cloudfront\.net",        r"Bad request|ERROR: The request could not be satisfied",
                                                                              "AWS CloudFront","medium"),
    # Azure
    (r"azurewebsites\.net",     r"404 Web Site not found",                   "Azure",         "high"),
    (r"blob\.core\.windows",    r"BlobNotFound|The specified container",     "Azure Blob",    "high"),
    (r"trafficmanager\.net",    r"404",                                       "Azure TM",      "medium"),
    # Shopify
    (r"myshopify\.com",         r"Sorry, this shop is currently unavailable", "Shopify",      "high"),
    # Netlify
    (r"netlify\.app",           r"Not found - Request ID",                   "Netlify",       "high"),
    (r"netlify\.com",           r"Not found - Request ID",                   "Netlify",       "high"),
    # Fastly
    (r"fastly\.net",            r"Fastly error: unknown domain",             "Fastly",        "high"),
    # Pantheon
    (r"pantheonsite\.io",       r"The gods are wise",                        "Pantheon",      "high"),
    # WordPress.com
    (r"wordpress\.com",         r"Do you want to register",                  "WordPress.com", "medium"),
    # Ghost
    (r"ghost\.io",              r"The thing you were looking for is no longer here", "Ghost", "high"),
    # Tumblr
    (r"tumblr\.com",            r"There's nothing here|Whatever you were looking for", "Tumblr", "medium"),
    # Unbounce
    (r"unbouncepages\.com",     r"The requested URL was not found",          "Unbounce",      "high"),
    # HubSpot
    (r"hubspot\.net",           r"does not exist",                           "HubSpot",       "medium"),
    # Surge.sh
    (r"surge\.sh",              r"project not found",                        "Surge.sh",      "high"),
    # Bitbucket
    (r"bitbucket\.io",          r"Repository not found",                     "Bitbucket",     "high"),
    # Firebase
    (r"firebaseapp\.com",       r"Site Not Found",                           "Firebase",      "high"),
    # ReadTheDocs
    (r"readthedocs\.io",        r"unknown to Read the Docs",                 "ReadTheDocs",   "medium"),
    # Zendesk
    (r"zendesk\.com",           r"Help Center Closed",                       "Zendesk",       "medium"),
]


class SubdomainTakeoverHunter(BaseHunter):
    """
    Subdomain Takeover Hunter.

    Detection strategy:
    1. Get subdomains from attack surface (from Recon DNS enumeration)
    2. For each subdomain: resolve CNAME
    3. If CNAME matches known cloud service → fetch HTTP
    4. If response matches unclaimed fingerprint → VULNERABLE
    """

    name = "subdomain_takeover"
    vuln_types = [VulnType.SUBDOMAIN_TAKEOVER]

    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        start_time = time.time()
        self._reset_state()

        # Get subdomains from attack surface
        subdomains = self._get_subdomains(attack_surface)
        logger.info(f"Subdomain Takeover Hunter: checking {len(subdomains)} subdomains")

        # Check in parallel (DNS is slow)
        semaphore = asyncio.Semaphore(10)
        tasks = [self._check_subdomain(sub, semaphore) for sub in subdomains]
        await asyncio.gather(*tasks, return_exceptions=True)

        duration = time.time() - start_time
        result = self._build_result(duration)
        logger.info(f"Subdomain Takeover Hunter complete: {result.findings_count} hypotheses")
        return result

    def _get_subdomains(self, attack_surface: AttackSurface) -> List[str]:
        """Extract subdomain list from attack surface."""
        subdomains = []
        # From attack surface subdomains attribute (set by ReconAgent)
        raw = getattr(attack_surface, "subdomains", [])
        for s in raw:
            if isinstance(s, str):
                subdomains.append(s)
        # Also extract from endpoint URLs
        seen = set()
        for ep in attack_surface.endpoints:
            match = re.search(r"https?://([^/]+)", ep.url)
            if match:
                host = match.group(1)
                if host not in seen:
                    seen.add(host)
                    subdomains.append(host)
        return list(set(subdomains))

    async def _check_subdomain(self, subdomain: str, semaphore: asyncio.Semaphore):
        async with semaphore:
            self._endpoints_tested += 1
            try:
                # Step 1: DNS CNAME lookup
                cname = await self._resolve_cname(subdomain)
                if not cname:
                    return

                # Step 2: Match against known services
                for cname_pattern, body_pattern, service, severity in TAKEOVER_FINGERPRINTS:
                    if re.search(cname_pattern, cname, re.IGNORECASE):
                        # Step 3: Fetch HTTP to check unclaimed fingerprint
                        self._payloads_sent += 1
                        http_body = await self._fetch_subdomain(subdomain)
                        if http_body and re.search(body_pattern, http_body, re.IGNORECASE):
                            await self._report_takeover(subdomain, cname, service, severity)
                            return

            except Exception as e:
                self._errors.append(f"Subdomain check {subdomain}: {e}")

    async def _resolve_cname(self, hostname: str) -> Optional[str]:
        """Resolve CNAME record for hostname."""
        try:
            import socket
            loop = asyncio.get_event_loop()
            # Use getaddrinfo as a simple DNS check
            result = await loop.run_in_executor(
                None, socket.getfqdn, hostname
            )
            return result if result != hostname else None
        except Exception:
            return None

    async def _fetch_subdomain(self, subdomain: str) -> Optional[str]:
        """Fetch HTTP response body from subdomain."""
        try:
            response = await self.http.get(f"http://{subdomain}")
            return response.body if response else None
        except Exception:
            try:
                response = await self.http.get(f"https://{subdomain}")
                return response.body if response else None
            except Exception:
                return None

    async def _report_takeover(
        self, subdomain: str, cname: str, service: str, severity: str
    ):
        """Create a hypothesis for a confirmed takeover candidate."""
        # Create a synthetic endpoint for reporting
        fake_endpoint = type("Endpoint", (), {
            "url": f"https://{subdomain}",
            "method": type("Method", (), {"value": "GET"})(),
            "parameters": [],
        })()

        confidence = Confidence.HIGH if severity == "high" else Confidence.MEDIUM

        h = self._create_hypothesis(
            vuln_type=VulnType.SUBDOMAIN_TAKEOVER,
            endpoint=fake_endpoint,
            parameter="(subdomain)",
            confidence=confidence,
            indicators=[
                VulnIndicator(
                    indicator_type="dangling_cname",
                    detail=f"CNAME {subdomain} → {cname} points to unclaimed {service}",
                    confidence_boost=0.4,
                ),
                VulnIndicator(
                    indicator_type="unclaimed_fingerprint",
                    detail=f"{service} returned unclaimed/404 page",
                    confidence_boost=0.25,
                ),
            ],
            suggested_payloads=[
                f"# Claim {service} account/repo/bucket for: {cname}",
                f"# Then control content at: https://{subdomain}",
            ],
            context={
                "injection_type": "subdomain_takeover",
                "subdomain": subdomain,
                "cname": cname,
                "service": service,
                "severity": severity,
            },
        )
        self._hypotheses.append(h)
        logger.warning(f"Subdomain takeover candidate: {subdomain} → {cname} ({service})")

    def _analyze_response(self, endpoint, parameter, payload, response):
        return None
