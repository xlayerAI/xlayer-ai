"""
Code Audit / Bug Finding generator.
Produces code review entries with planted vulnerabilities and detailed analysis.
"""

import random
from typing import List, Dict, Any
from ..templates import CategoryGenerator, pick_complexity, pick_severity, format_entry
from ..code_snippets import SNIPPET_GENERATORS, generate_random_snippet
from ..knowledge_base import CWE_DB, OWASP_TOP10, APP_CONTEXTS


INSTRUCTIONS = [
    "Review the following code for security vulnerabilities. Identify each issue, explain the root cause, and provide a secure fix.",
    "Perform a security audit of the code below. For each vulnerability found, specify the CWE, severity, affected line, and remediation.",
    "Analyze the following code snippet from a security perspective. What vulnerabilities exist, and how could an attacker exploit them?",
    "You are conducting a code review for a security-sensitive application. Examine the following code and report all security findings.",
    "Identify all security flaws in the code below. For each flaw, explain the attack vector, impact, and how to fix it securely.",
    "As a security engineer, review this code for OWASP Top 10 vulnerabilities. Provide detailed findings with severity ratings.",
    "Examine the following code for injection vulnerabilities, authentication flaws, and data exposure risks. Document each finding.",
    "Conduct a static analysis review of this code. Report each vulnerability with its CWE classification and a remediation plan.",
    "Review this code as if preparing a security assessment report. Identify vulnerabilities, rate their severity, and suggest fixes.",
    "Analyze the following code for common security anti-patterns. Explain why each pattern is dangerous and show the secure alternative.",
    "Perform a thorough security code review. Focus on input validation, authentication, authorization, and data handling.",
    "Examine this code for vulnerabilities that could be exploited in a production environment. Provide actionable remediation steps.",
    "Review the following function for security issues. Consider both the immediate vulnerability and any downstream impacts.",
    "As a penetration tester reviewing source code (white-box assessment), identify all exploitable vulnerabilities below.",
    "Analyze the following code for security weaknesses. Classify each finding by severity (Critical/High/Medium/Low) with CWE references.",
    "Review this code snippet and identify any security vulnerabilities. Explain how each could be exploited and provide secure alternatives.",
    "Examine the code below for potential security issues. What changes would you recommend to make this code production-safe?",
    "Audit the following code for compliance with secure coding standards. Flag all deviations and provide corrective actions.",
]

CONTEXTS = [
    "This code is part of a {app} handling user authentication.",
    "The following code is from a {app}'s API endpoint processing user requests.",
    "This function is used in a {app} to handle file operations.",
    "The code below is from a {app}'s data retrieval module.",
    "This snippet is from a {app}'s backend service handling sensitive data.",
    "The following code processes user input in a {app}.",
    "This function manages database queries in a {app}.",
    "The code below handles session management for a {app}.",
    "This endpoint processes payment data in a {app}.",
    "The following code manages user uploads in a {app}.",
]


def _make_multi_vuln_input(rng: random.Random, complexity: str):
    """Generate input with 1-3 vulnerabilities based on complexity."""
    vuln_counts = {"beginner": 1, "intermediate": 1, "advanced": 2, "expert": 3}
    count = vuln_counts[complexity]

    # Pick distinct snippet types
    snippet_keys = list(SNIPPET_GENERATORS.keys())
    chosen = rng.sample(snippet_keys, min(count, len(snippet_keys)))

    snippets = []
    for key in chosen:
        vuln_code, fix_code, info = SNIPPET_GENERATORS[key](rng)
        snippets.append((vuln_code, fix_code, info))

    return snippets


class CodeAuditGenerator(CategoryGenerator):
    category = "code_audit"
    id_prefix = "xld-audit"

    def generate_entries(self, rng: random.Random, count: int, start_id: int,
                         complexity_weights) -> List[Dict[str, Any]]:
        entries = []
        for i in range(count):
            complexity = pick_complexity(rng, complexity_weights)
            snippets = _make_multi_vuln_input(rng, complexity)
            app_ctx = rng.choice(APP_CONTEXTS)
            context_line = rng.choice(CONTEXTS).format(app=app_ctx)

            # Build input
            input_text = f"{context_line}\n\n"
            for idx, (vuln_code, _, info) in enumerate(snippets):
                if len(snippets) > 1:
                    input_text += f"### Code Block {idx + 1} ({info['language'].title()})\n"
                input_text += f"```{info['language']}\n{vuln_code}\n```\n\n"

            # Build output
            output_text = f"## Security Code Review Report\n\n"
            output_text += f"**Application Context:** {app_ctx}\n"
            output_text += f"**Findings:** {len(snippets)} vulnerability{'ies' if len(snippets) > 1 else 'y'}\n\n"

            for idx, (vuln_code, fix_code, info) in enumerate(snippets):
                cwe_info = CWE_DB.get(info["cwe"], {})
                owasp_cat = cwe_info.get("owasp", "N/A")
                owasp_name = OWASP_TOP10.get(owasp_cat, "N/A")

                output_text += f"### Finding {idx + 1}: {info['name']}\n\n"
                output_text += f"**Severity:** {info['severity'].upper()}\n"
                output_text += f"**CWE:** {info['cwe']} ({cwe_info.get('name', info['name'])})\n"
                output_text += f"**OWASP:** {owasp_cat} - {owasp_name}\n"
                output_text += f"**Language:** {info['language'].title()}\n"
                output_text += f"**Affected Line:** {info['line']}\n\n"
                output_text += f"**Root Cause:**\n{info['root_cause']}\n\n"

                # Exploitation scenario
                output_text += "**Exploitation Scenario:**\n"
                if "injection" in info["cwe"].lower() or info["cwe"] in ["CWE-89", "CWE-78", "CWE-79"]:
                    output_text += f"An attacker can craft malicious input to exploit the {info['name']} vulnerability. "
                    output_text += f"Since user input is not properly validated or sanitized before use, "
                    output_text += f"the attacker can inject malicious payloads that the application will execute.\n\n"
                elif "CWE-120" in info["cwe"] or "CWE-134" in info["cwe"]:
                    output_text += f"An attacker can send oversized input to trigger the {info['name']}. "
                    output_text += f"This corrupts memory and can lead to arbitrary code execution "
                    output_text += f"by overwriting return addresses or function pointers.\n\n"
                else:
                    output_text += f"An attacker can exploit this {info['name']} vulnerability to "
                    output_text += f"gain unauthorized access or compromise the application's security posture.\n\n"

                output_text += f"**Remediation:**\n{info['fix_desc']}\n\n"
                output_text += f"**Secure Code:**\n```{info['language']}\n{fix_code}\n```\n\n"

            # Summary
            output_text += "### Summary\n"
            severities = [s[2]["severity"] for s in snippets]
            output_text += f"Total findings: {len(snippets)} | "
            for sev in ["critical", "high", "medium", "low"]:
                c = severities.count(sev)
                if c > 0:
                    output_text += f"{sev.title()}: {c} | "
            output_text = output_text.rstrip(" | ") + "\n"
            output_text += "\nRemediation of these findings should be prioritized based on severity and exploitability."

            primary_cwe = snippets[0][2]["cwe"]
            title_parts = [s[2]["name"] for s in snippets[:2]]
            title = f"Code Audit: {', '.join(title_parts)} in {snippets[0][2]['language'].title()}"

            entry = format_entry(
                entry_id=self.make_id(start_id + i),
                title=title,
                severity=pick_severity(rng, complexity),
                cwe=primary_cwe,
                instruction=rng.choice(INSTRUCTIONS),
                input_text=input_text.strip(),
                output_text=output_text.strip(),
            )
            entries.append(entry)
        return entries
