"""
Coordinator result → ValidatedVuln conversion and merge helpers.

Use when integrating Coordinator + XLayerLoop into the main pipeline:
1. coordinator_results_to_validated_vulns() — convert Coordinator.run() dict list to List[ValidatedVuln]
2. merge_validated_vulns() — merge multiple ValidatedVuln lists and dedupe by (endpoint, parameter, vuln_type)
"""

from datetime import datetime
from typing import Dict, List, Any

from xlayer_ai.models.vulnerability import (
    ValidatedVuln,
    VulnHypothesis,
    VulnType,
    Severity,
    Confidence,
    ExploitEvidence,
    ProofOfConcept,
)


# Coordinator vuln_type string (from attack matrix) → VulnType enum
VULN_TYPE_FROM_COORDINATOR: Dict[str, VulnType] = {
    "sqli": VulnType.SQLI,
    "xss_reflected": VulnType.XSS_REFLECTED,
    "xss_stored": VulnType.XSS_STORED,
    "xss": VulnType.XSS_REFLECTED,
    "auth_bypass": VulnType.AUTH_BYPASS,
    "ssrf": VulnType.SSRF,
    "lfi": VulnType.LFI,
    "ssti": VulnType.SSTI,
    "rce": VulnType.COMMAND_INJECTION,
    "xxe": VulnType.XXE,
    "open_redirect": VulnType.OPEN_REDIRECT,
    "cors": VulnType.CORS_MISCONFIGURATION,
    "csrf": VulnType.CSRF,
    "path_traversal": VulnType.PATH_TRAVERSAL,
    "graphql": VulnType.GRAPHQL_INJECTION,
    "race_condition": VulnType.RACE_CONDITION,
    "deserialization": VulnType.DESERIALIZATION,
    "http_smuggling": VulnType.HTTP_REQUEST_SMUGGLING,
    "subdomain_takeover": VulnType.SUBDOMAIN_TAKEOVER,
}

# Default CVSS when not in exploit.CVSS_SCORES; VulnType -> score
DEFAULT_CVSS: float = 7.0
CVSS_BY_TYPE: Dict[VulnType, float] = {
    VulnType.SQLI: 9.1,
    VulnType.XSS_REFLECTED: 6.1,
    VulnType.XSS_STORED: 7.2,
    VulnType.XSS_DOM: 6.1,
    VulnType.AUTH_BYPASS: 9.8,
    VulnType.IDOR: 7.5,
    VulnType.SESSION_FIXATION: 6.5,
    VulnType.SSRF: 8.6,
    VulnType.LFI: 7.5,
    VulnType.RFI: 9.1,
    VulnType.PATH_TRAVERSAL: 5.3,
    VulnType.COMMAND_INJECTION: 9.8,
    VulnType.XXE: 7.5,
    VulnType.CSRF: 4.3,
    VulnType.OPEN_REDIRECT: 4.7,
    VulnType.INFO_DISCLOSURE: 5.3,
    VulnType.SSTI: 8.6,
    VulnType.SUBDOMAIN_TAKEOVER: 8.0,
    VulnType.RACE_CONDITION: 7.5,
    VulnType.DESERIALIZATION: 9.8,
    VulnType.GRAPHQL_INJECTION: 6.5,
    VulnType.CORS_MISCONFIGURATION: 6.5,
    VulnType.HTTP_REQUEST_SMUGGLING: 8.5,
}

SEVERITY_MAP = [
    ((9.0, 10.0), Severity.CRITICAL),
    ((7.0, 8.9), Severity.HIGH),
    ((4.0, 6.9), Severity.MEDIUM),
    ((0.1, 3.9), Severity.LOW),
    ((0.0, 0.0), Severity.INFO),
]


def _cvss_to_severity(score: float) -> Severity:
    for (lo, hi), sev in SEVERITY_MAP:
        if lo <= score <= hi:
            return sev
    return Severity.MEDIUM


def coordinator_result_to_validated_vuln(raw: Dict[str, Any]) -> ValidatedVuln:
    """
    Convert one Coordinator.run() result dict (found=True, confidence>=0.72) to ValidatedVuln.

    Expects keys: target_url, parameter, vuln_type (str), working_payload, proof_response,
    confidence, injection_type, poc_script, oob_confirmed, etc.
    """
    vuln_type_str = (raw.get("vuln_type") or "sqli").strip().lower()
    vuln_type = VULN_TYPE_FROM_COORDINATOR.get(vuln_type_str, VulnType.SQLI)
    endpoint = raw.get("target_url", "")
    parameter = raw.get("parameter", "")
    payload = raw.get("working_payload") or "(agentic solver)"
    proof = (raw.get("proof_response") or "")[:2000]
    poc_script = raw.get("poc_script") or ""

    hypothesis = VulnHypothesis(
        vuln_type=vuln_type,
        endpoint=endpoint,
        method=raw.get("method", "GET"),
        parameter=parameter,
        confidence=Confidence.HIGH,
        context={
            "injection_type": raw.get("injection_type", ""),
            "oob_confirmed": raw.get("oob_confirmed", False),
            "iterations_used": raw.get("iterations_used", 0),
            "techniques_tried": raw.get("techniques_tried", []),
        },
        hunter_name="coordinator_solver",
    )

    cvss = CVSS_BY_TYPE.get(vuln_type, DEFAULT_CVSS)
    severity = _cvss_to_severity(cvss)

    evidence = ExploitEvidence(
        response_snippet=proof or None,
        extracted_data=proof[:500] if proof else None,
    )
    poc = ProofOfConcept(
        reproduction_steps=["Re-run request with payload from evidence."],
        python_script=poc_script if poc_script else None,
    )

    return ValidatedVuln(
        hypothesis=hypothesis,
        severity=severity,
        cvss_score=cvss,
        payload_used=payload,
        execution_method="agentic_solver",
        evidence=evidence,
        poc=poc,
        impact={"proof_snippet": proof[:500], "oob_confirmed": raw.get("oob_confirmed", False)},
    )


def coordinator_results_to_validated_vulns(raw_list: List[Dict[str, Any]]) -> List[ValidatedVuln]:
    """
    Convert Coordinator.run() output (list of dicts) to List[ValidatedVuln].
    Only includes entries with found=True and confidence >= 0.72.
    """
    out: List[ValidatedVuln] = []
    for r in raw_list:
        if not r.get("found"):
            continue
        if r.get("confidence", 0) < 0.72:
            continue
        try:
            out.append(coordinator_result_to_validated_vuln(r))
        except Exception as e:
            from loguru import logger
            logger.warning("Skip coordinator result to ValidatedVuln: {}", e)
    return out


def _validated_key(v: ValidatedVuln) -> tuple:
    """Key for deduplication: (endpoint, parameter, vuln_type)."""
    return (v.endpoint, v.parameter, v.vuln_type.value)


def merge_validated_vulns(
    *lists: List[ValidatedVuln],
    prefer: str = "first",
) -> List[ValidatedVuln]:
    """
    Merge multiple lists of ValidatedVuln and dedupe by (endpoint, parameter, vuln_type).

    prefer: "first" = keep first occurrence; "last" = keep last (overwrite).
    Useful when merging Coordinator results with ExploitAgent results: same finding
    from both → single entry (e.g. prefer "first" to keep ExploitAgent's browser proof).
    """
    seen: Dict[tuple, ValidatedVuln] = {}
    order: List[ValidatedVuln] = []
    for lst in lists:
        for v in lst:
            key = _validated_key(v)
            if key in seen:
                if prefer == "last":
                    old_idx = next(i for i, x in enumerate(order) if _validated_key(x) == key)
                    order[old_idx] = v
                    seen[key] = v
            else:
                seen[key] = v
                order.append(v)
    return order
