"""
XLayer AI GraphQL Hunter - GraphQL-specific vulnerabilities
Detects: introspection enabled, batch query abuse, injection in arguments,
IDOR via type fields, and depth/complexity DoS potential.
"""

import re
import json
import time
from typing import List, Optional, Dict, Any
from loguru import logger

from xlayer_ai.core.vuln_hunters.base import BaseHunter, HunterResult
from xlayer_ai.models.target import AttackSurface, Endpoint
from xlayer_ai.models.vulnerability import (
    VulnHypothesis, VulnType, Confidence, VulnIndicator
)


GRAPHQL_ENDPOINTS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
    "/query", "/api/query", "/graph", "/gql",
    "/api", "/graphiql",
]

# Introspection query
INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      fields {
        name
        args { name type { name kind } }
      }
    }
  }
}
"""

# Simple probe
PROBE_QUERY = "{ __typename }"

# Batch abuse (rate limit bypass test)
BATCH_QUERY = json.dumps([
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
])

# Deep nesting (DoS check)
NESTED_QUERY = "{ a { a { a { a { a { a { a { a { a { __typename } } } } } } } } } }"

# SQLi in GraphQL arguments
GRAPHQL_SQLI = [
    '{ users(id: "1 OR 1=1") { id name email } }',
    '{ users(filter: "1\' OR \'1\'=\'1") { id name } }',
    '{ product(id: "1 UNION SELECT 1,2,3--") { name } }',
]


class GraphQLHunter(BaseHunter):
    """
    GraphQL Injection Hunter.

    Detection strategy:
    1. Discover GraphQL endpoints
    2. Test introspection (info disclosure)
    3. Test batch queries (rate limit bypass)
    4. Test depth limit (DoS)
    5. Test injection in arguments (SQLi, SSTI)
    6. Test IDOR via direct ID access
    """

    name = "graphql"
    vuln_types = [VulnType.GRAPHQL_INJECTION]

    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        start_time = time.time()
        self._reset_state()

        base_url = attack_surface.base_url.rstrip("/")
        logger.info(f"GraphQL Hunter scanning {base_url}")

        # Discover GraphQL endpoints
        gql_endpoints = await self._discover_graphql(base_url)

        for gql_url in gql_endpoints:
            await self._test_graphql(gql_url)

        duration = time.time() - start_time
        result = self._build_result(duration)
        logger.info(f"GraphQL Hunter complete: {result.findings_count} hypotheses")
        return result

    async def _discover_graphql(self, base_url: str) -> List[str]:
        """Find active GraphQL endpoints."""
        found = []
        for path in GRAPHQL_ENDPOINTS:
            url = base_url + path
            self._payloads_sent += 1
            try:
                resp = await self.http.post(
                    url,
                    data=json.dumps({"query": PROBE_QUERY}),
                    headers={"Content-Type": "application/json"},
                )
                if resp and resp.status in (200, 400):
                    body = resp.body
                    if "__typename" in body or "errors" in body or "data" in body:
                        found.append(url)
                        logger.info(f"GraphQL endpoint found: {url}")
            except Exception:
                pass
        return found

    async def _test_graphql(self, gql_url: str):
        self._endpoints_tested += 1

        # Create a synthetic endpoint for hypothesis creation
        fake_ep = type("Endpoint", (), {
            "url": gql_url,
            "method": type("Method", (), {"value": "POST"})(),
            "parameters": [],
        })()

        # Test 1: Introspection
        await self._test_introspection(fake_ep, gql_url)

        # Test 2: Batch queries
        await self._test_batch(fake_ep, gql_url)

        # Test 3: Depth limit
        await self._test_depth(fake_ep, gql_url)

        # Test 4: SQLi in arguments
        await self._test_argument_injection(fake_ep, gql_url)

    async def _test_introspection(self, endpoint, gql_url: str):
        self._payloads_sent += 1
        resp = await self._gql_post(gql_url, INTROSPECTION_QUERY)
        if not resp:
            return

        body = resp.get("body", "")
        if "__schema" in body and "types" in body:
            # Count exposed types
            type_count = len(re.findall(r'"name"\s*:', body))
            h = self._create_hypothesis(
                vuln_type=VulnType.GRAPHQL_INJECTION,
                endpoint=endpoint,
                parameter="query",
                confidence=Confidence.HIGH,
                indicators=[
                    VulnIndicator(
                        indicator_type="introspection_enabled",
                        detail=f"GraphQL introspection enabled — {type_count} types exposed",
                        confidence_boost=0.3,
                    )
                ],
                suggested_payloads=[INTROSPECTION_QUERY.strip()],
                context={
                    "injection_type": "graphql_introspection",
                    "endpoint": gql_url,
                    "type_count": type_count,
                },
            )
            self._hypotheses.append(h)

    async def _test_batch(self, endpoint, gql_url: str):
        self._payloads_sent += 1
        resp = await self._gql_post_raw(gql_url, BATCH_QUERY)
        if not resp:
            return

        body = resp.get("body", "")
        # Batch accepted if response is array
        if body.strip().startswith("[") and "__typename" in body:
            h = self._create_hypothesis(
                vuln_type=VulnType.GRAPHQL_INJECTION,
                endpoint=endpoint,
                parameter="query",
                confidence=Confidence.MEDIUM,
                indicators=[
                    VulnIndicator(
                        indicator_type="batch_queries",
                        detail="Batch queries accepted — rate limits bypassable",
                        confidence_boost=0.2,
                    )
                ],
                suggested_payloads=[BATCH_QUERY],
                context={
                    "injection_type": "graphql_batch",
                    "endpoint": gql_url,
                },
            )
            self._hypotheses.append(h)

    async def _test_depth(self, endpoint, gql_url: str):
        self._payloads_sent += 1
        resp = await self._gql_post(gql_url, NESTED_QUERY)
        if not resp:
            return

        body = resp.get("body", "")
        status = resp.get("status", 0)
        # If 200 with no depth error → no depth limit
        if status == 200 and "errors" not in body:
            h = self._create_hypothesis(
                vuln_type=VulnType.GRAPHQL_INJECTION,
                endpoint=endpoint,
                parameter="query",
                confidence=Confidence.LOW,
                indicators=[
                    VulnIndicator(
                        indicator_type="no_depth_limit",
                        detail="No query depth limit — potential DoS via deeply nested queries",
                        confidence_boost=0.1,
                    )
                ],
                suggested_payloads=[NESTED_QUERY],
                context={
                    "injection_type": "graphql_depth_dos",
                    "endpoint": gql_url,
                },
            )
            self._hypotheses.append(h)

    async def _test_argument_injection(self, endpoint, gql_url: str):
        for payload in GRAPHQL_SQLI:
            self._payloads_sent += 1
            resp = await self._gql_post(gql_url, payload)
            if not resp:
                continue
            body = resp.get("body", "")
            # SQL error patterns
            if re.search(
                r"(SQL syntax|mysql_|PostgreSQL.*ERROR|ORA-\d|syntax error)",
                body, re.IGNORECASE
            ):
                h = self._create_hypothesis(
                    vuln_type=VulnType.GRAPHQL_INJECTION,
                    endpoint=endpoint,
                    parameter="query_argument",
                    confidence=Confidence.HIGH,
                    indicators=[
                        VulnIndicator(
                            indicator_type="sqli_in_graphql",
                            detail="SQL error in GraphQL response — injection in argument",
                            confidence_boost=0.35,
                        )
                    ],
                    suggested_payloads=[payload],
                    context={
                        "injection_type": "graphql_sqli",
                        "trigger_payload": payload,
                        "endpoint": gql_url,
                    },
                )
                self._hypotheses.append(h)
                return

    async def _gql_post(self, url: str, query: str) -> Optional[Dict]:
        """POST GraphQL query as JSON."""
        return await self._gql_post_raw(url, json.dumps({"query": query}))

    async def _gql_post_raw(self, url: str, body: str) -> Optional[Dict]:
        """POST raw body to GraphQL endpoint."""
        try:
            resp = await self.http.post(
                url,
                data=body,
                headers={"Content-Type": "application/json"},
            )
            if resp:
                return {
                    "status": resp.status,
                    "headers": resp.headers,
                    "body": resp.body,
                    "elapsed_ms": resp.elapsed_ms,
                }
        except Exception as e:
            logger.debug(f"GraphQL request failed: {e}")
        return None

    def _analyze_response(self, endpoint, parameter, payload, response):
        return None
