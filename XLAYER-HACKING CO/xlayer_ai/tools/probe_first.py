"""
Probe-first: lightweight probe before full payloads.

Sends minimal probes (`'`, `<`) to capture status, body snippet, and WAF
signals. Observation is used for next payload choice (Solver context and
AdaptiveEngine ctx).
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from loguru import logger


@dataclass
class ProbeObservation:
    """Result of probe-first: use for payload choice and WAF awareness."""

    status_quote: int = 0      # status after injecting '
    status_lt: int = 0         # status after injecting <
    body_snippet: str = ""     # first ~500 chars of response (quote probe)
    body_snippet_lt: str = ""  # first ~300 chars for < probe (optional)
    waf_hint: str = ""         # e.g. "Cloudflare", "ModSecurity", ""
    headers_relevant: Dict[str, str] = field(default_factory=dict)  # WAF-related headers
    raw_status: Optional[int] = None   # baseline (no injection) if needed


# WAF header fingerprints (header_name: None = present means WAF, or list of substrings)
_WAF_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-amzn-requestid": "AWS WAF",
    "x-amz-cf-id": "AWS WAF",
    "x-iinfo": "Imperva",
    "x-sucuri-id": "Sucuri",
    "server": ["cloudflare", "akamaighost", "akamai"],
}
_WAF_BODY_SIGS = [
    ("cloudflare", "Cloudflare"),
    ("cf-ray", "Cloudflare"),
    ("mod_security", "ModSecurity"),
    ("modsecurity", "ModSecurity"),
    ("request blocked", "AWS WAF"),
    ("incapsula", "Imperva"),
    ("sucuri", "Sucuri"),
]


def _inject_param(url: str, param: str, value: str) -> str:
    """Put value into param in URL (query string); create param if missing."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment,
    ))


def _detect_waf_from_response(status: int, body: str, headers: Dict[str, str]) -> str:
    """Return WAF name or empty string."""
    headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
    for hdr, hint in _WAF_HEADERS.items():
        if hdr not in headers_lower:
            continue
        if isinstance(hint, list):
            for p in hint:
                if p in headers_lower[hdr]:
                    return p.title()
        else:
            return hint
    if status in (403, 406, 429, 503):
        body_lower = body.lower()
        for sig, name in _WAF_BODY_SIGS:
            if sig in body_lower:
                return name
        if "blocked" in body_lower or "forbidden" in body_lower or "not allowed" in body_lower:
            return "Generic WAF"
    return ""


def _snippet(body: str, max_len: int = 500) -> str:
    """First max_len chars, collapse newlines for readability."""
    if not body:
        return ""
    s = re.sub(r"\s+", " ", body.strip())[:max_len]
    return s + ("..." if len(body) > max_len else "")


async def run_probe_first(
    url: str,
    param: str,
    method: str = "GET",
    proxy: Optional[str] = None,
    timeout: float = 10.0,
    extra_headers: Optional[Dict[str, str]] = None,
) -> ProbeObservation:
    """
    Probe-first: send minimal probes (`'`, `<`), return observation.

    Use the result in Solver extra_context or AdaptiveEngine ctx for
    context-aware payload choice and WAF awareness.
    """
    import httpx

    obs = ProbeObservation()
    if not url or not param:
        return obs

    kwargs: Dict[str, Any] = {
        "timeout": timeout,
        "verify": False,
    }
    if proxy:
        kwargs["proxy"] = proxy
    headers = dict(extra_headers or {})

    async with httpx.AsyncClient(follow_redirects=True, **kwargs) as client:
        # Probe 1: single quote (SQLi / generic)
        url_quote = _inject_param(url, param, "'")
        try:
            if method.upper() == "GET":
                r = await client.get(url_quote, headers=headers)
            else:
                r = await client.post(url_quote, headers=headers)
            obs.status_quote = r.status_code
            obs.body_snippet = _snippet(r.text, 500)
            obs.headers_relevant = {
                k: v for k, v in r.headers.items()
                if k.lower() in {k2 for k2 in _WAF_HEADERS}
            }
            obs.waf_hint = _detect_waf_from_response(
                r.status_code, r.text, dict(r.headers)
            )
        except Exception as e:
            logger.debug(f"probe_first quote failed: {e}")
            obs.status_quote = -1
            obs.body_snippet = str(e)[:200]

        # Probe 2: < (XSS / tag break)
        url_lt = _inject_param(url, param, "<")
        try:
            if method.upper() == "GET":
                r2 = await client.get(url_lt, headers=headers)
            else:
                r2 = await client.post(url_lt, headers=headers)
            obs.status_lt = r2.status_code
            obs.body_snippet_lt = _snippet(r2.text, 300)
            if not obs.waf_hint:
                obs.waf_hint = _detect_waf_from_response(
                    r2.status_code, r2.text, dict(r2.headers)
                )
        except Exception as e:
            logger.debug(f"probe_first < failed: {e}")
            obs.status_lt = -1

    logger.debug(
        f"probe_first {url}: quote={obs.status_quote} lt={obs.status_lt} waf={obs.waf_hint or 'none'}"
    )
    return obs


def format_probe_observation_for_context(obs: ProbeObservation) -> str:
    """Format for Solver extra_context / LLM (use for payload choice)."""
    lines = [
        "Probe observation (use for payload choice):",
        f"  status(quote): {obs.status_quote}  status(<): {obs.status_lt}",
        f"  WAF hint: {obs.waf_hint or 'none'}",
    ]
    if obs.headers_relevant:
        lines.append("  WAF-related headers: " + ", ".join(f"{k}={v[:40]}" for k, v in list(obs.headers_relevant.items())[:5]))
    if obs.body_snippet:
        lines.append("  body_snippet: " + obs.body_snippet[:400].replace("\n", " "))
    return "\n".join(lines)
