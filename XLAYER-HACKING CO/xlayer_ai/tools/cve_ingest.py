"""
CVE ingest (optional): fetch recent CVEs from NVD and expose for attack templates.

Usage:
  - Set XLAYER_NVD_API_KEY for higher rate limits (50 req/30s vs 5/30s).
  - Call fetch_recent_cves() to get a list of CVE summaries; downstream can map to payloads/templates.

NVD API 2.0: https://services.nvd.nist.gov/rest/json/cves/2.0
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


NVD_CVES_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class CVEEntry:
    """Minimal CVE record for attack template ingestion."""
    cve_id: str
    description: str
    severity: str
    references: List[str] = field(default_factory=list)
    published: str = ""
    products: List[str] = field(default_factory=list)


def _parse_cve(item: Dict[str, Any]) -> CVEEntry:
    cve_id = item.get("id", "")
    descriptions = item.get("descriptions", [])
    desc = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    refs = [r.get("url", "") for r in item.get("references", []) if r.get("url")]
    metrics = item.get("metrics", {}) or {}
    severity = "UNKNOWN"
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(k, [])
        if arr and arr[0].get("cvssData", {}).get("baseSeverity"):
            severity = arr[0]["cvssData"]["baseSeverity"]
            break
    published = item.get("published", "") or ""
    products = []
    for conf in item.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("match", []):
                cpe = m.get("criteria", "")
                if cpe and ":" in cpe:
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        products.append(parts[4])  # product name
    return CVEEntry(cve_id=cve_id, description=desc[:500], severity=severity, references=refs[:10], published=published, products=list(set(products)))


async def fetch_recent_cves(
    results_per_page: int = 20,
    api_key: Optional[str] = None,
) -> List[CVEEntry]:
    """
    Fetch recent CVEs from NVD API 2.0. Optional api_key for higher rate limit.
    Returns list of CVEEntry for downstream attack template generation.
    """
    try:
        import httpx
    except ImportError:
        return []
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                NVD_CVES_URL,
                params={"resultsPerPage": results_per_page, "startIndex": 0},
                headers=headers,
            )
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        from loguru import logger
        logger.debug(f"CVE ingest fetch failed: {e}")
        return []
    vulns = data.get("vulnerabilities", [])
    out = []
    for v in vulns:
        cve = v.get("cve")
        if cve:
            out.append(_parse_cve(cve))
    return out


def cve_entries_to_template_hints(entries: List[CVEEntry]) -> List[Dict[str, Any]]:
    """
    Convert CVE entries to minimal attack template hints (stretch: PoC parse not implemented).
    Returns list of dicts with cve_id, description, severity, refs for use in payload/template selection.
    """
    return [
        {
            "cve_id": e.cve_id,
            "description": e.description[:200],
            "severity": e.severity,
            "references": e.references[:3],
            "products": e.products[:5],
        }
        for e in entries
    ]
