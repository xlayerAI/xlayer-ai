"""
engine/cross_synthesis.py — Cross-finding Synthesis

Correlates partial and confirmed findings across different vuln types.
Two weak signals together can constitute a critical finding:

  CORS open + partial XSS  → credential steal chain
  JWT weakness + admin EP  → JWT admin token forge
  SSRF partial + AWS used  → cloud metadata endpoint
  SQLi partial + LFI part  → file read → code exec chain
  Auth bypass + IDOR part  → privilege escalation + data leak

Called after Step 5 in coordinator — sees ALL results (confirmed + partial).
Returns synthesized findings with elevated confidence, tagged "synthesized=True".
Also feeds back SpawnSpecs for chains that need targeted verification.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from loguru import logger

from xlayer_ai.engine.agent_spawner import SpawnSpec
from xlayer_ai.engine.logical_surface_map.graph import LogicalSurface


# ── Synthesis rules ───────────────────────────────────────────────────────────

@dataclass
class SynthesisRule:
    """
    A rule that fires when both trigger_a and trigger_b are present.

    Triggers match vuln_type names OR surface tokens (cors_open, waf_detected, etc.).
    Partial findings (found=False, conf>=min_conf) count toward triggers.
    """
    name: str
    trigger_a: Set[str]         # vuln_types or surface tokens that satisfy A
    trigger_b: Set[str]         # vuln_types or surface tokens that satisfy B
    severity: str               # "critical", "high", "medium"
    description: str
    spawn_vuln_type: Optional[str] = None   # if set, spawn a new solver for this
    min_conf: float = 0.25                  # minimum confidence for partial finding to count


_SYNTHESIS_RULES: List[SynthesisRule] = [
    SynthesisRule(
        name="cors_xss_credential_steal",
        trigger_a={"cors", "cors_open"},
        trigger_b={"xss", "xss_reflected", "xss_stored"},
        severity="critical",
        description=(
            "CORS misconfiguration + XSS: attacker can steal authenticated session "
            "from a victim's browser by combining the two weaknesses."
        ),
        spawn_vuln_type="cors",
    ),
    SynthesisRule(
        name="jwt_admin_token_forge",
        trigger_a={"jwt_bypass", "jwt_crack", "jwt_none_alg", "jwt_weak_secret"},
        trigger_b={"auth_bypass", "idor"},
        severity="critical",
        description=(
            "JWT weakness + auth boundary: forged admin-level JWT likely grants "
            "full admin access to protected endpoints."
        ),
        spawn_vuln_type="jwt_bypass",
    ),
    SynthesisRule(
        name="ssrf_cloud_metadata",
        trigger_a={"ssrf"},
        trigger_b={"third_party_aws_s3", "aws_access_key_leaked", "third_party_firebase"},
        severity="critical",
        description=(
            "SSRF + cloud service in use: SSRF may reach cloud metadata endpoint "
            "(http://169.254.169.254) to steal IAM credentials."
        ),
        spawn_vuln_type="ssrf",
    ),
    SynthesisRule(
        name="sqli_lfi_code_exec",
        trigger_a={"sqli"},
        trigger_b={"lfi", "rce"},
        severity="critical",
        description=(
            "SQL injection + LFI/RCE partial signals: SQLi can read server files "
            "via LOAD_FILE(); combined with LFI this may achieve code execution."
        ),
        spawn_vuln_type="sqli",
    ),
    SynthesisRule(
        name="auth_bypass_privilege_escalation",
        trigger_a={"auth_bypass"},
        trigger_b={"idor"},
        severity="critical",
        description=(
            "Auth bypass + IDOR: bypassing authentication and iterating resource IDs "
            "combines into full data exfiltration."
        ),
        spawn_vuln_type="idor",
    ),
    SynthesisRule(
        name="ssti_rce_chain",
        trigger_a={"ssti"},
        trigger_b={"rce"},
        severity="critical",
        description=(
            "SSTI + RCE signal: server-side template injection often escalates to "
            "remote code execution. Multiple partial signals increase confidence."
        ),
        spawn_vuln_type="ssti",
    ),
    SynthesisRule(
        name="xxe_ssrf_chain",
        trigger_a={"xxe"},
        trigger_b={"ssrf"},
        severity="high",
        description=(
            "XXE + SSRF: XXE can be used as an SSRF vector for internal network access "
            "and cloud metadata exfiltration."
        ),
        spawn_vuln_type="xxe",
    ),
    SynthesisRule(
        name="secret_leak_full_access",
        trigger_a={"stripe_secret_leaked", "aws_access_key_leaked", "sendgrid_key_leaked",
                   "openai_key_leaked", "github_pat_leaked"},
        trigger_b={"auth_bypass", "idor", "sqli"},
        severity="critical",
        description=(
            "Leaked third-party API key + exploitable endpoint: a leaked secret key "
            "combined with any auth weakness gives broad system access."
        ),
        min_conf=0.0,  # keys are confirmed by pattern — no confidence required
    ),
    SynthesisRule(
        name="open_redirect_phishing_chain",
        trigger_a={"open_redirect"},
        trigger_b={"xss", "xss_reflected"},
        severity="high",
        description=(
            "Open redirect + XSS: open redirect can bypass CSP and deliver XSS payload "
            "from a trusted domain — effective phishing chain."
        ),
    ),
    SynthesisRule(
        name="cve_rce_chain",
        trigger_a={"cve_spring", "cve_laravel", "cve_rails"},
        trigger_b={"rce", "ssti", "deserialization"},
        severity="critical",
        description=(
            "Detected CVE-affected framework + RCE/SSTI signal: framework CVE may be "
            "directly exploitable for remote code execution."
        ),
        spawn_vuln_type="rce",
    ),
]


# ── Synthesizer ───────────────────────────────────────────────────────────────

class CrossFindingSynthesizer:
    """
    Correlates all solver results + LSM surface tokens to detect chained findings.

    Inputs:
      - all_results: List[Dict] — all solver outcomes (confirmed + partial)
      - surface: LogicalSurface — full LSM findings (tokens extracted from it)

    Returns:
      - synthesized_findings: List[Dict] — new chained findings (tagged synthesized=True)
      - new_specs: List[SpawnSpec] — optional follow-up solver tasks for chain verification
    """

    def synthesize(
        self,
        all_results: List[Dict],
        surface: LogicalSurface,
    ) -> tuple:
        """
        Returns (synthesized_findings, new_specs).
        """
        # Build a flat token set from all results + surface
        active_tokens = self._build_token_set(all_results, surface)

        logger.debug(f"[CrossSynthesis] Active tokens ({len(active_tokens)}): {active_tokens}")

        synthesized: List[Dict] = []
        new_specs: List[SpawnSpec] = []
        fired_rules: Set[str] = set()

        for rule in _SYNTHESIS_RULES:
            if rule.name in fired_rules:
                continue

            # Check both triggers satisfied
            a_token = active_tokens & rule.trigger_a
            b_token = active_tokens & rule.trigger_b

            if not a_token or not b_token:
                continue

            # Find the actual findings that triggered A and B (for evidence)
            a_finding = self._find_matching(all_results, rule.trigger_a, rule.min_conf)
            b_finding = self._find_matching(all_results, rule.trigger_b, rule.min_conf)

            # Derive synthesized confidence from components
            a_conf = a_finding.get("confidence", 0.5) if a_finding else 0.5
            b_conf = b_finding.get("confidence", 0.5) if b_finding else 0.5
            synth_conf = min(round((a_conf + b_conf) / 2 + 0.15, 3), 0.92)

            finding = {
                "vuln_type":   rule.name,
                "severity":    rule.severity,
                "description": rule.description,
                "found":       True,
                "confidence":  synth_conf,
                "synthesized": True,
                "components":  list(a_token | b_token),
                "target_url":  self._pick_target(a_finding, b_finding, surface),
                "proof_response": (
                    f"Cross-finding synthesis: {list(a_token)[0]} + {list(b_token)[0]} "
                    f"→ {rule.name} (conf={synth_conf:.2f})"
                ),
            }
            synthesized.append(finding)
            fired_rules.add(rule.name)

            logger.success(
                f"[CrossSynthesis] {rule.name} [{rule.severity.upper()}] "
                f"conf={synth_conf:.2f} | {list(a_token)[0]} + {list(b_token)[0]}"
            )

            # Optionally spawn a follow-up solver to validate the chain
            if rule.spawn_vuln_type:
                target = finding["target_url"]
                if target:
                    new_specs.append(SpawnSpec(
                        agent_type=rule.spawn_vuln_type,
                        endpoint=target,
                        evidence={
                            "synthesis_trigger": rule.name,
                            "component_a":       list(a_token)[0],
                            "component_b":       list(b_token)[0],
                            "a_finding":         a_finding or {},
                            "b_finding":         b_finding or {},
                        },
                        priority="critical",
                        initial_confidence=synth_conf,
                        method="GET",
                    ))

        if synthesized:
            logger.info(
                f"[CrossSynthesis] {len(synthesized)} synthesized finding(s), "
                f"{len(new_specs)} follow-up agent(s)"
            )

        return synthesized, new_specs

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _build_token_set(
        self, all_results: List[Dict], surface: LogicalSurface
    ) -> Set[str]:
        """Build a flat set of all active tokens from results + surface."""
        tokens: Set[str] = set()

        # From solver results (confirmed + partial)
        for r in all_results:
            conf = r.get("confidence", 0)
            if r.get("found") or conf >= 0.25:
                vt = r.get("vuln_type", "")
                if vt:
                    tokens.add(vt)

        # From surface: JWT issues
        for j in surface.jwt_issues:
            issues = j.get("issues", [])
            if any("none" in i.lower() for i in issues):
                tokens.add("jwt_none_alg")
            if any("weak" in i.lower() or "hs256" in i.lower() for i in issues):
                tokens.add("jwt_weak_secret")

        # CORS
        if surface.cors_open:
            tokens.add("cors_open")

        # Supply chain tokens
        for sc in surface.supply_chain_findings:
            tok = sc.get("token", "")
            if tok:
                tokens.add(tok)
            # Also add finding_type=cve_hint as cve_{service}
            if sc.get("type") == "cve_hint":
                tokens.add(f"cve_{sc.get('service', '')}")

        # Behavioral fingerprint tokens
        for profile in surface.behavior_profiles.values():
            for tok in getattr(profile, "to_tokens", lambda: [])():
                tokens.add(tok)

        return tokens

    @staticmethod
    def _find_matching(
        all_results: List[Dict], trigger: Set[str], min_conf: float
    ) -> Optional[Dict]:
        """Find the first result whose vuln_type matches any trigger token."""
        for r in all_results:
            if r.get("vuln_type", "") in trigger:
                if r.get("found") or r.get("confidence", 0) >= min_conf:
                    return r
        return None

    @staticmethod
    def _pick_target(
        a_finding: Optional[Dict],
        b_finding: Optional[Dict],
        surface: LogicalSurface,
    ) -> str:
        """Pick the best target URL for the synthesized chain."""
        for f in (a_finding, b_finding):
            if f and f.get("target_url"):
                return f["target_url"]
        return surface.base_url
