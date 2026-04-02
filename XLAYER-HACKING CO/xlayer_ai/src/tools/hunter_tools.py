"""
Custom @tool wrappers around XLayer's 16 hunters.
(Uses engine.tool)

These tools are given to the XLayerLoop so it can call hunters
directly from its reasoning loop without going through the full pipeline.

Each tool:
- Takes (target_url, parameter, ...) as typed args
- Runs the hunter on a single endpoint/parameter
- Returns a JSON string the LLM can reason about
"""

import asyncio
import json
from typing import Optional
from urllib.parse import urlparse

from loguru import logger

# ── Custom tool decorator ─────────────────────────────────────────────────
from xlayer_ai.engine.tool import Tool, tool


# ── Helpers ────────────────────────────────────────────────────────────────

def _get_http_client():
    from xlayer_ai.tools.http_client import HTTPClient
    return HTTPClient()

def _get_payload_manager():
    from xlayer_ai.tools.payload_manager import PayloadManager
    return PayloadManager()

def _get_settings():
    from xlayer_ai.config.settings import get_settings
    return get_settings()

def _build_attack_surface(url: str, parameter: str, method: str = "GET"):
    """Build a minimal AttackSurface for a single endpoint/parameter."""
    from xlayer_ai.models.target import (
        AttackSurface,
        Endpoint,
        EndpointType,
        HTTPMethod,
        InputParameter,
        InputType,
        Target,
    )

    parsed = urlparse(url)
    param_obj = InputParameter(
        name=parameter,
        input_type=InputType.URL_PARAM,
        sample_value="test",
    )
    method_upper = method.upper()
    method_enum = HTTPMethod(method_upper) if method_upper in HTTPMethod._value2member_map_ else HTTPMethod.GET
    endpoint = Endpoint(
        url=url,
        method=method_enum,
        endpoint_type=EndpointType.API,
        parameters=[param_obj],
    )
    return AttackSurface(
        target=Target(
            url=f"{parsed.scheme}://{parsed.netloc}",
            hostname=parsed.hostname or parsed.netloc,
        ),
        endpoints=[endpoint],
    )

def _run_async(coro):
    """Run async coroutine from sync context safely."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result(timeout=60)
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)

def _format_result(hunter_name: str, result) -> dict:
    """Convert HunterResult to a clean dict the LLM can reason about."""
    hypotheses = []
    for h in result.hypotheses:
        hypotheses.append({
            "vuln_type": h.vuln_type.value if hasattr(h.vuln_type, "value") else str(h.vuln_type),
            "endpoint": h.endpoint,
            "parameter": h.parameter,
            "confidence": h.confidence.value if hasattr(h.confidence, "value") else str(h.confidence),
            "confidence_score": round(getattr(h, "confidence_score", 0), 2),
            "injection_type": h.context.get("injection_type", ""),
            "trigger_payload": h.context.get("trigger_payload", ""),
            "suggested_payloads": getattr(h, "suggested_payloads", [])[:3],
            "indicators": [
                {"type": getattr(i, "indicator_type", ""), "detail": getattr(i, "detail", "")}
                for i in getattr(h, "indicators", [])
            ],
        })
    return {
        "hunter": hunter_name,
        "endpoints_tested": getattr(result, "endpoints_tested", 0),
        "payloads_sent": getattr(result, "payloads_sent", 0),
        "hypotheses_count": getattr(result, "findings_count", len(hypotheses)),
        "high_confidence_count": getattr(result, "high_confidence_count", 0),
        "hypotheses": hypotheses,
        "errors": getattr(result, "errors", [])[:5],
    }


# ── SQLi ───────────────────────────────────────────────────────────────────

@tool
def run_sqli_hunter(target_url: str, parameter: str, method: str = "GET", db_hint: str = "generic") -> str:
    """
    Run the SQL Injection hunter on a specific endpoint parameter.
    Tests error-based, boolean-based, time-based, and union-based SQLi.

    Args:
        target_url: The full URL to test (e.g. https://example.com/search)
        parameter: The parameter name to inject into (e.g. q, id, user)
        method: HTTP method GET or POST
        db_hint: Optional DB type hint: mysql/postgresql/mssql/oracle/sqlite/generic
    """
    async def _run():
        from xlayer_ai.core.vuln_hunters.sqli import SQLiHunter
        http = _get_http_client()
        pm = _get_payload_manager()
        settings = _get_settings()
        async with http:
            hunter = SQLiHunter(http_client=http, payload_manager=pm, settings=settings)
            surface = _build_attack_surface(target_url, parameter, method)
            return await hunter.hunt(surface)
    try:
        result = _run_async(_run())
        return json.dumps(_format_result("sqli", result), indent=2)
    except Exception as e:
        logger.error(f"sqli_hunter error: {e}")
        return json.dumps({"error": str(e), "hunter": "sqli"})


# ── XSS ───────────────────────────────────────────────────────────────────

@tool
def run_xss_hunter(target_url: str, parameter: str, method: str = "GET") -> str:
    """
    Run the XSS hunter on a specific endpoint parameter.
    Tests reflected, stored, and DOM-based XSS.

    Args:
        target_url: The full URL to test
        parameter: The parameter name to inject into
        method: HTTP method GET or POST
    """
    async def _run():
        from xlayer_ai.core.vuln_hunters.xss import XSSHunter
        http = _get_http_client()
        pm = _get_payload_manager()
        settings = _get_settings()
        async with http:
            hunter = XSSHunter(http_client=http, payload_manager=pm, settings=settings)
            surface = _build_attack_surface(target_url, parameter, method)
            return await hunter.hunt(surface)
    try:
        result = _run_async(_run())
        return json.dumps(_format_result("xss", result), indent=2)
    except Exception as e:
        logger.error(f"xss_hunter error: {e}")
        return json.dumps({"error": str(e), "hunter": "xss"})


# ── Auth ───────────────────────────────────────────────────────────────────

@tool
def run_auth_hunter(target_url: str, parameter: str, method: str = "POST") -> str:
    """
    Run the Auth hunter on a login or auth endpoint.
    Tests auth bypass, weak credentials, session fixation, IDOR.

    Args:
        target_url: The full URL to test (login page or API endpoint)
        parameter: The parameter to test (username, token, session_id)
        method: HTTP method GET or POST
    """
    async def _run():
        from xlayer_ai.core.vuln_hunters.auth import AuthHunter
        http = _get_http_client()
        pm = _get_payload_manager()
        settings = _get_settings()
        async with http:
            hunter = AuthHunter(http_client=http, payload_manager=pm, settings=settings)
            surface = _build_attack_surface(target_url, parameter, method)
            return await hunter.hunt(surface)
    try:
        result = _run_async(_run())
        return json.dumps(_format_result("auth", result), indent=2)
    except Exception as e:
        logger.error(f"auth_hunter error: {e}")
        return json.dumps({"error": str(e), "hunter": "auth"})


# ── SSRF ───────────────────────────────────────────────────────────────────

@tool
def run_ssrf_hunter(target_url: str, parameter: str, method: str = "GET", oob_url: str = "") -> str:
    """
    Run the SSRF hunter on a URL-accepting parameter.
    Tests open SSRF, blind SSRF via OOB, cloud metadata access.

    Args:
        target_url: The full URL to test
        parameter: The parameter that accepts URLs (url, dest, redirect, path)
        method: HTTP method GET or POST
        oob_url: Optional OOB callback URL for blind SSRF detection
    """
    async def _run():
        from xlayer_ai.core.vuln_hunters.ssrf import SSRFHunter
        http = _get_http_client()
        pm = _get_payload_manager()
        settings = _get_settings()
        async with http:
            hunter = SSRFHunter(http_client=http, payload_manager=pm, settings=settings)
            surface = _build_attack_surface(target_url, parameter, method)
            return await hunter.hunt(surface)
    try:
        result = _run_async(_run())
        return json.dumps(_format_result("ssrf", result), indent=2)
    except Exception as e:
        logger.error(f"ssrf_hunter error: {e}")
        return json.dumps({"error": str(e), "hunter": "ssrf"})


# ── LFI ───────────────────────────────────────────────────────────────────

@tool
def run_lfi_hunter(target_url: str, parameter: str, method: str = "GET") -> str:
    """
    Run the LFI hunter on a file-accepting parameter.
    Tests path traversal, LFI, log poisoning, PHP wrappers.

    Args:
        target_url: The full URL to test
        parameter: The parameter that accepts file paths (file, path, page, include)
        method: HTTP method GET or POST
    """
    async def _run():
        from xlayer_ai.core.vuln_hunters.lfi import LFIHunter
        http = _get_http_client()
        pm = _get_payload_manager()
        settings = _get_settings()
        async with http:
            hunter = LFIHunter(http_client=http, payload_manager=pm, settings=settings)
            surface = _build_attack_surface(target_url, parameter, method)
            return await hunter.hunt(surface)
    try:
        result = _run_async(_run())
        return json.dumps(_format_result("lfi", result), indent=2)
    except Exception as e:
        logger.error(f"lfi_hunter error: {e}")
        return json.dumps({"error": str(e), "hunter": "lfi"})


# ── SSTI ───────────────────────────────────────────────────────────────────

@tool
def run_ssti_hunter(target_url: str, parameter: str, method: str = "GET") -> str:
    """
    Run the SSTI hunter on a template-rendering parameter.
    Tests Jinja2, Twig, Freemarker, Velocity, ERB, Smarty, Mako, SpEL.

    Args:
        target_url: The full URL to test
        parameter: The parameter that renders user input in a template
        method: HTTP method GET or POST
    """
    async def _run():
        from xlayer_ai.core.vuln_hunters.ssti import SSTIHunter
        http = _get_http_client()
        pm = _get_payload_manager()
        settings = _get_settings()
        async with http:
            hunter = SSTIHunter(http_client=http, payload_manager=pm, settings=settings)
            surface = _build_attack_surface(target_url, parameter, method)
            return await hunter.hunt(surface)
    try:
        result = _run_async(_run())
        return json.dumps(_format_result("ssti", result), indent=2)
    except Exception as e:
        logger.error(f"ssti_hunter error: {e}")
        return json.dumps({"error": str(e), "hunter": "ssti"})


# ── RCE ───────────────────────────────────────────────────────────────────

@tool
def run_rce_hunter(target_url: str, parameter: str, method: str = "GET") -> str:
    """
    Run the RCE hunter on a command-accepting parameter.
    Tests time-based, output-based, and echo reflection command injection.

    Args:
        target_url: The full URL to test
        parameter: The parameter to inject OS commands into
        method: HTTP method GET or POST
    """
    async def _run():
        from xlayer_ai.core.vuln_hunters.rce import RCEHunter
        http = _get_http_client()
        pm = _get_payload_manager()
        settings = _get_settings()
        async with http:
            hunter = RCEHunter(http_client=http, payload_manager=pm, settings=settings)
            surface = _build_attack_surface(target_url, parameter, method)
            return await hunter.hunt(surface)
    try:
        result = _run_async(_run())
        return json.dumps(_format_result("rce", result), indent=2)
    except Exception as e:
        logger.error(f"rce_hunter error: {e}")
        return json.dumps({"error": str(e), "hunter": "rce"})


# ── XXE ───────────────────────────────────────────────────────────────────

@tool
def run_xxe_hunter(target_url: str, parameter: str, method: str = "POST") -> str:
    """
    Run the XXE hunter on an XML-accepting endpoint.
    Tests file read, SSRF via XXE, error-based, OOB XXE.

    Args:
        target_url: The full URL to test (must accept XML input)
        parameter: The XML parameter or body field to inject into
        method: HTTP method usually POST for XML endpoints
    """
    async def _run():
        from xlayer_ai.core.vuln_hunters.xxe import XXEHunter
        http = _get_http_client()
        pm = _get_payload_manager()
        settings = _get_settings()
        async with http:
            hunter = XXEHunter(http_client=http, payload_manager=pm, settings=settings)
            surface = _build_attack_surface(target_url, parameter, method)
            return await hunter.hunt(surface)
    try:
        result = _run_async(_run())
        return json.dumps(_format_result("xxe", result), indent=2)
    except Exception as e:
        logger.error(f"xxe_hunter error: {e}")
        return json.dumps({"error": str(e), "hunter": "xxe"})


# ── Open Redirect ──────────────────────────────────────────────────────────

@tool
def run_open_redirect_hunter(target_url: str, parameter: str, method: str = "GET") -> str:
    """
    Run the Open Redirect hunter on a redirect-accepting parameter.
    Tests 18 bypass techniques including URL encoding and subdomain tricks.

    Args:
        target_url: The full URL to test
        parameter: The parameter that accepts redirect destinations (url, next, redirect, return)
        method: HTTP method GET or POST
    """
    async def _run():
        from xlayer_ai.core.vuln_hunters.open_redirect import OpenRedirectHunter
        http = _get_http_client()
        pm = _get_payload_manager()
        settings = _get_settings()
        async with http:
            hunter = OpenRedirectHunter(http_client=http, payload_manager=pm, settings=settings)
            surface = _build_attack_surface(target_url, parameter, method)
            return await hunter.hunt(surface)
    try:
        result = _run_async(_run())
        return json.dumps(_format_result("open_redirect", result), indent=2)
    except Exception as e:
        logger.error(f"open_redirect_hunter error: {e}")
        return json.dumps({"error": str(e), "hunter": "open_redirect"})


# ── CORS ───────────────────────────────────────────────────────────────────

@tool
def run_cors_hunter(target_url: str, parameter: str = "origin", method: str = "GET") -> str:
    """
    Run the CORS misconfiguration hunter on an endpoint.
    Tests origin reflection, null origin, wildcard with credentials.

    Args:
        target_url: The full URL to test for CORS issues
        parameter: Not used directly but kept for consistent interface
        method: HTTP method GET or POST
    """
    async def _run():
        from xlayer_ai.core.vuln_hunters.cors import CORSHunter
        http = _get_http_client()
        pm = _get_payload_manager()
        settings = _get_settings()
        async with http:
            hunter = CORSHunter(http_client=http, payload_manager=pm, settings=settings)
            surface = _build_attack_surface(target_url, parameter, method)
            return await hunter.hunt(surface)
    try:
        result = _run_async(_run())
        return json.dumps(_format_result("cors", result), indent=2)
    except Exception as e:
        logger.error(f"cors_hunter error: {e}")
        return json.dumps({"error": str(e), "hunter": "cors"})


# ── CSRF ───────────────────────────────────────────────────────────────────

@tool
def run_csrf_hunter(target_url: str, parameter: str = "csrf_token", method: str = "POST") -> str:
    """
    Run the CSRF hunter on a form-submitting endpoint.
    Tests for missing token, token bypass, SameSite cookie absence.

    Args:
        target_url: The full URL of the state-changing endpoint
        parameter: CSRF token parameter name if present
        method: HTTP method usually POST for state-changing endpoints
    """
    async def _run():
        from xlayer_ai.core.vuln_hunters.csrf import CSRFHunter
        http = _get_http_client()
        pm = _get_payload_manager()
        settings = _get_settings()
        async with http:
            hunter = CSRFHunter(http_client=http, payload_manager=pm, settings=settings)
            surface = _build_attack_surface(target_url, parameter, method)
            return await hunter.hunt(surface)
    try:
        result = _run_async(_run())
        return json.dumps(_format_result("csrf", result), indent=2)
    except Exception as e:
        logger.error(f"csrf_hunter error: {e}")
        return json.dumps({"error": str(e), "hunter": "csrf"})


# ── GraphQL ────────────────────────────────────────────────────────────────

@tool
def run_graphql_hunter(target_url: str, parameter: str = "query", method: str = "POST") -> str:
    """
    Run the GraphQL hunter on a GraphQL endpoint.
    Tests introspection enabled, batch queries, depth limit bypass, injection in arguments.

    Args:
        target_url: The full GraphQL endpoint URL
        parameter: Usually query or variables
        method: HTTP method usually POST for GraphQL
    """
    async def _run():
        from xlayer_ai.core.vuln_hunters.graphql import GraphQLHunter
        http = _get_http_client()
        pm = _get_payload_manager()
        settings = _get_settings()
        async with http:
            hunter = GraphQLHunter(http_client=http, payload_manager=pm, settings=settings)
            surface = _build_attack_surface(target_url, parameter, method)
            return await hunter.hunt(surface)
    try:
        result = _run_async(_run())
        return json.dumps(_format_result("graphql", result), indent=2)
    except Exception as e:
        logger.error(f"graphql_hunter error: {e}")
        return json.dumps({"error": str(e), "hunter": "graphql"})


# ── Race Condition ─────────────────────────────────────────────────────────

@tool
def run_race_condition_hunter(target_url: str, parameter: str, method: str = "POST") -> str:
    """
    Run the Race Condition hunter on a critical state-changing endpoint.
    Sends N=15 parallel requests and detects multiple success responses.

    Args:
        target_url: The full URL of the endpoint to race (coupon, transfer, purchase)
        parameter: The critical parameter (coupon_code, amount, token)
        method: HTTP method usually POST
    """
    async def _run():
        from xlayer_ai.core.vuln_hunters.race_condition import RaceConditionHunter
        http = _get_http_client()
        pm = _get_payload_manager()
        settings = _get_settings()
        async with http:
            hunter = RaceConditionHunter(http_client=http, payload_manager=pm, settings=settings)
            surface = _build_attack_surface(target_url, parameter, method)
            return await hunter.hunt(surface)
    try:
        result = _run_async(_run())
        return json.dumps(_format_result("race_condition", result), indent=2)
    except Exception as e:
        logger.error(f"race_condition_hunter error: {e}")
        return json.dumps({"error": str(e), "hunter": "race_condition"})


# ── Deserialization ────────────────────────────────────────────────────────

@tool
def run_deserialization_hunter(target_url: str, parameter: str, method: str = "POST") -> str:
    """
    Run the Deserialization hunter on an endpoint that processes serialized objects.
    Tests Java, PHP, Python, .NET deserialization gadget chains.

    Args:
        target_url: The full URL to test
        parameter: The parameter that accepts serialized data
        method: HTTP method usually POST
    """
    async def _run():
        from xlayer_ai.core.vuln_hunters.deserialization import DeserializationHunter
        http = _get_http_client()
        pm = _get_payload_manager()
        settings = _get_settings()
        async with http:
            hunter = DeserializationHunter(http_client=http, payload_manager=pm, settings=settings)
            surface = _build_attack_surface(target_url, parameter, method)
            return await hunter.hunt(surface)
    try:
        result = _run_async(_run())
        return json.dumps(_format_result("deserialization", result), indent=2)
    except Exception as e:
        logger.error(f"deserialization_hunter error: {e}")
        return json.dumps({"error": str(e), "hunter": "deserialization"})


# ── HTTP Smuggling ────────────────────────────────────────────────────────

@tool
def run_http_smuggling_hunter(target_url: str, parameter: str = "", method: str = "POST") -> str:
    """
    Run the HTTP Smuggling hunter on an endpoint behind a reverse proxy.
    Tests CL.TE, TE.CL, and TE.TE request smuggling techniques.

    Args:
        target_url: The full URL to test for HTTP request smuggling
        parameter: Not directly used but kept for consistent interface
        method: HTTP method usually POST for smuggling
    """
    async def _run():
        from xlayer_ai.core.vuln_hunters.http_smuggling import HTTPSmugglingHunter
        http = _get_http_client()
        pm = _get_payload_manager()
        settings = _get_settings()
        async with http:
            hunter = HTTPSmugglingHunter(http_client=http, payload_manager=pm, settings=settings)
            surface = _build_attack_surface(target_url, parameter or "body", method)
            return await hunter.hunt(surface)
    try:
        result = _run_async(_run())
        return json.dumps(_format_result("http_smuggling", result), indent=2)
    except Exception as e:
        logger.error(f"http_smuggling_hunter error: {e}")
        return json.dumps({"error": str(e), "hunter": "http_smuggling"})


# ── Subdomain Takeover ────────────────────────────────────────────────────

@tool
def run_subdomain_takeover_hunter(target_url: str, parameter: str = "", method: str = "GET") -> str:
    """
    Run the Subdomain Takeover hunter. Checks if subdomains point to
    unclaimed services (S3, Heroku, GitHub Pages, Azure, etc.).

    Args:
        target_url: The base domain or subdomain URL to check
        parameter: Not directly used but kept for consistent interface
        method: HTTP method GET
    """
    async def _run():
        from xlayer_ai.core.vuln_hunters.subdomain_takeover import SubdomainTakeoverHunter
        http = _get_http_client()
        pm = _get_payload_manager()
        settings = _get_settings()
        async with http:
            hunter = SubdomainTakeoverHunter(http_client=http, payload_manager=pm, settings=settings)
            surface = _build_attack_surface(target_url, parameter or "host", method)
            return await hunter.hunt(surface)
    try:
        result = _run_async(_run())
        return json.dumps(_format_result("subdomain_takeover", result), indent=2)
    except Exception as e:
        logger.error(f"subdomain_takeover_hunter error: {e}")
        return json.dumps({"error": str(e), "hunter": "subdomain_takeover"})


# ── HTTP Probe (custom request) ─────────────────────────────────────────────

@tool
def http_probe(
    url: str,
    method: str = "GET",
    params: str = "",
    body: str = "",
    headers: str = "",
    payload_in_param: str = "",
    payload: str = "",
    cookies: str = "",
    content_type: str = "",
    raw_body: str = "",
    follow_redirects: str = "true",
    timeout: str = "15",
) -> str:
    """
    Send a custom HTTP request and return response details.
    Use this to manually test specific payloads the LLM wants to try.
    Supports JSON, XML, GraphQL raw bodies, cookies, and redirect chain tracking.

    Args:
        url: Full URL to send request to
        method: HTTP method GET POST PUT PATCH DELETE HEAD OPTIONS
        params: JSON string of query params like {"key": "value"}
        body: JSON string of POST body like {"key": "value"}
        headers: JSON string of extra headers like {"X-Foo": "bar"}
        payload_in_param: Parameter name to inject payload into
        payload: Payload value to inject into payload_in_param
        cookies: JSON string of cookies like {"session": "abc123", "token": "xyz"}
        content_type: Override Content-Type (e.g. application/xml, application/graphql)
        raw_body: Raw string body for XML/GraphQL/text payloads (overrides body if set)
        follow_redirects: Whether to follow redirects true or false
        timeout: Request timeout in seconds
    """
    async def _run():
        import time
        import httpx
        try:
            from xlayer_ai.tools.pacing import apply_pacing
            await apply_pacing()
        except Exception:
            pass
        extra_params = json.loads(params) if params else {}
        extra_body = json.loads(body) if body else {}
        extra_headers = json.loads(headers) if headers else {}
        cookie_jar = json.loads(cookies) if cookies else {}
        do_follow = follow_redirects.lower() in ("true", "1", "yes")
        req_timeout = int(timeout) if timeout else 15

        if payload_in_param and payload:
            extra_params[payload_in_param] = payload

        # Content-Type override
        if content_type:
            extra_headers["Content-Type"] = content_type

        # Cookies → Cookie header
        if cookie_jar:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookie_jar.items())
            extra_headers["Cookie"] = cookie_str

        # Build request kwargs
        req_kwargs = {
            "method": method.upper(),
            "url": url,
            "params": extra_params or None,
            "headers": extra_headers,
        }

        # raw_body takes priority over JSON body
        if raw_body:
            req_kwargs["content"] = raw_body.encode("utf-8")
        elif extra_body:
            req_kwargs["json"] = extra_body

        start = time.monotonic()
        redirect_chain = []

        async with httpx.AsyncClient(
            follow_redirects=do_follow,
            timeout=req_timeout,
            verify=False,
        ) as client:
            response = await client.request(**req_kwargs)

            # Track redirect chain
            if hasattr(response, "history") and response.history:
                for r in response.history:
                    redirect_chain.append({
                        "status": r.status_code,
                        "url": str(r.url),
                        "location": r.headers.get("location", ""),
                    })

        elapsed_ms = (time.monotonic() - start) * 1000

        # Extract Set-Cookie headers
        set_cookies = [
            v for k, v in response.headers.multi_items()
            if k.lower() == "set-cookie"
        ]

        return {
            "status_code": response.status_code,
            "elapsed_ms": round(elapsed_ms, 1),
            "content_length": len(response.content),
            "content_type": response.headers.get("content-type", ""),
            "redirect_url": str(response.url),
            "redirect_chain": redirect_chain,
            "set_cookies": set_cookies,
            "headers": dict(response.headers),
            "body_snippet": response.text[:3000],
        }
    try:
        result = _run_async(_run())
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "url": url})


# ── Shell Exec (terminal access) ──────────────────────────────────────────

# Destructive patterns blocked in shell_exec
_SHELL_BLOCKED = [
    "rm -rf", "mkfs", "dd if=", "shutdown", "reboot",
    "chmod 777", ":(){ :|:", "fork bomb", "> /dev/sd",
]

@tool
def shell_exec(command: str, timeout: str = "30", stdin_data: str = "") -> str:
    """
    Execute a shell command and return output. Use for curl, sqlmap, ffuf,
    python3 scripts, nmap, and other CLI tools the solver needs.
    Destructive commands (rm -rf, mkfs, etc.) are blocked.

    Args:
        command: Shell command to execute (e.g. curl -s https://target.com/api)
        timeout: Execution timeout in seconds
        stdin_data: Optional data to pipe into stdin
    """
    import subprocess
    import os
    import time as _time

    cmd_lower = command.lower()
    for blocked in _SHELL_BLOCKED:
        if blocked in cmd_lower:
            return json.dumps({
                "error": f"blocked_command: '{blocked}' pattern not allowed",
                "exit_code": -1,
            })

    req_timeout = int(timeout) if timeout else 30
    req_timeout = min(req_timeout, 120)  # hard cap 2 min

    # Restricted env — no secrets leaked
    safe_env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
    }

    start = _time.monotonic()
    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            timeout=req_timeout,
            input=stdin_data.encode("utf-8") if stdin_data else None,
            env=safe_env,
        )
        elapsed_ms = (_time.monotonic() - start) * 1000
        return json.dumps({
            "exit_code": proc.returncode,
            "stdout": proc.stdout.decode("utf-8", errors="replace")[:5000],
            "stderr": proc.stderr.decode("utf-8", errors="replace")[:2000],
            "timed_out": False,
            "elapsed_ms": round(elapsed_ms, 1),
        })
    except subprocess.TimeoutExpired:
        elapsed_ms = (_time.monotonic() - start) * 1000
        return json.dumps({
            "exit_code": -9,
            "stdout": "",
            "stderr": "command timed out",
            "timed_out": True,
            "elapsed_ms": round(elapsed_ms, 1),
        })
    except Exception as e:
        return json.dumps({"error": str(e), "exit_code": -1})


# ── Registries ─────────────────────────────────────────────────────────────

ALL_HUNTER_TOOLS: list[Tool] = [
    run_sqli_hunter,
    run_xss_hunter,
    run_auth_hunter,
    run_ssrf_hunter,
    run_lfi_hunter,
    run_ssti_hunter,
    run_rce_hunter,
    run_xxe_hunter,
    run_open_redirect_hunter,
    run_cors_hunter,
    run_csrf_hunter,
    run_graphql_hunter,
    run_race_condition_hunter,
    run_deserialization_hunter,
    run_http_smuggling_hunter,
    run_subdomain_takeover_hunter,
    http_probe,
    shell_exec,
]

# Add browser tools (Playwright-based) — lazy import to avoid hard dependency
try:
    from xlayer_ai.src.tools.browser_tool import BROWSER_TOOLS
    ALL_HUNTER_TOOLS.extend(BROWSER_TOOLS)
except ImportError:
    pass  # playwright not installed — browser tools unavailable

VULN_TOOL_MAP: dict[str, Tool] = {
    "sqli": run_sqli_hunter,
    "sql_injection": run_sqli_hunter,
    "xss": run_xss_hunter,
    "xss_reflected": run_xss_hunter,
    "xss_stored": run_xss_hunter,
    "auth": run_auth_hunter,
    "auth_bypass": run_auth_hunter,
    "ssrf": run_ssrf_hunter,
    "lfi": run_lfi_hunter,
    "path_traversal": run_lfi_hunter,
    "ssti": run_ssti_hunter,
    "template_injection": run_ssti_hunter,
    "rce": run_rce_hunter,
    "command_injection": run_rce_hunter,
    "xxe": run_xxe_hunter,
    "open_redirect": run_open_redirect_hunter,
    "cors": run_cors_hunter,
    "cors_misconfiguration": run_cors_hunter,
    "csrf": run_csrf_hunter,
    "graphql": run_graphql_hunter,
    "graphql_injection": run_graphql_hunter,
    "race_condition": run_race_condition_hunter,
    "deserialization": run_deserialization_hunter,
    "insecure_deserialization": run_deserialization_hunter,
    "http_smuggling": run_http_smuggling_hunter,
    "request_smuggling": run_http_smuggling_hunter,
    "subdomain_takeover": run_subdomain_takeover_hunter,
}
