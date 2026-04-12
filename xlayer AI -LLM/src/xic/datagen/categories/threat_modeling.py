"""
Threat Modeling generator.
Produces STRIDE analysis, attack tree construction, and threat assessment entries.
"""

import random
from typing import List, Dict, Any
from ..templates import CategoryGenerator, pick_complexity, pick_severity, format_entry, rand_ip, rand_domain, rand_port, rand_var_name, rand_func_name, rand_table_name, rand_path
from ..knowledge_base import CWE_DB, OWASP_TOP10, MITRE_ATTACK, APP_CONTEXTS, PRODUCTS, CLOUD_SERVICES, FRAMEWORKS, PROTOCOLS


# ── Instruction pools ──────────────────────────────────────────────────────────

STRIDE_INSTRUCTIONS = [
    "Perform a STRIDE threat analysis on the following system architecture. Identify threats for each STRIDE category and recommend mitigations.",
    "Apply the STRIDE threat modeling methodology to this system. For each component and data flow, enumerate potential threats and assign risk ratings.",
    "Conduct a comprehensive STRIDE analysis for the described architecture. Map each threat to relevant CWEs and MITRE ATT&CK techniques.",
    "As a security architect, perform STRIDE threat modeling on this system design. Prioritize threats by likelihood and impact.",
    "Using the STRIDE framework, analyze the following system for security threats. Provide a structured threat catalog with mitigations.",
    "Evaluate the described system architecture using STRIDE. Identify trust boundaries, data flows, and threats at each boundary crossing.",
]

ATTACK_TREE_INSTRUCTIONS = [
    "Construct an attack tree for compromising the described system. Identify the root goal, sub-goals, and leaf-level attack steps.",
    "Build a detailed attack tree analysis for the given scenario. Include AND/OR nodes, estimated difficulty, and likelihood for each path.",
    "Create an attack tree that maps out all plausible attack paths against this system. Annotate each node with required capabilities and mitigations.",
    "Develop a comprehensive attack tree for the described target. Rank attack paths by feasibility and potential impact.",
    "Design an attack tree for the following system. Include both technical and social engineering attack vectors at each decision node.",
]

DFD_INSTRUCTIONS = [
    "Analyze the following data flow diagram for security concerns. Identify where sensitive data crosses trust boundaries and recommend protections.",
    "Review this data flow description and identify security-relevant trust boundaries. For each boundary crossing, enumerate potential threats.",
    "Perform a security-focused data flow analysis on the described system. Highlight unprotected channels and data-at-rest concerns.",
    "Evaluate the data flows in this architecture for confidentiality, integrity, and availability risks. Recommend encryption and access control measures.",
]

RISK_MATRIX_INSTRUCTIONS = [
    "Create a risk assessment matrix for the threats identified in the following system. Rate each threat by likelihood and impact.",
    "Build a threat prioritization matrix for the described architecture. Assign DREAD scores and recommend a remediation timeline.",
    "Develop a risk register for the following system. For each identified threat, provide likelihood, impact, risk rating, and recommended controls.",
    "Perform a quantitative risk assessment for the described threats. Calculate residual risk after proposed mitigations.",
]

TRUST_BOUNDARY_INSTRUCTIONS = [
    "Identify all trust boundaries in the following system architecture. For each boundary, describe what protections should be in place.",
    "Map the trust boundaries in this system design. Analyze what happens when data crosses each boundary and identify missing security controls.",
]

ALL_INSTRUCTIONS = (
    STRIDE_INSTRUCTIONS + ATTACK_TREE_INSTRUCTIONS + DFD_INSTRUCTIONS +
    RISK_MATRIX_INSTRUCTIONS + TRUST_BOUNDARY_INSTRUCTIONS
)

# ── System architecture templates ─────────────────────────────────────────────

SYSTEM_COMPONENTS = [
    "Web Frontend (React SPA)", "API Gateway (Kong/NGINX)", "Authentication Service",
    "Authorization Service (RBAC)", "User Management Microservice", "Payment Processing Service",
    "Order Management Service", "Notification Service (Email/SMS)", "File Storage Service",
    "Search/Indexing Service", "Reporting/Analytics Engine", "Admin Dashboard",
    "Mobile Backend (BFF)", "Message Queue (RabbitMQ/Kafka)", "Cache Layer (Redis)",
    "Database Cluster (PostgreSQL)", "Object Storage (S3-compatible)", "CDN Edge Nodes",
    "Load Balancer", "Service Mesh (Istio/Linkerd)", "Logging/Monitoring Stack",
    "CI/CD Pipeline", "Secrets Management (Vault)", "Identity Provider (OIDC/SAML)",
]

DATA_TYPES = [
    "user credentials (passwords, tokens)", "personally identifiable information (PII)",
    "payment card data (PCI-DSS scope)", "health records (HIPAA-regulated PHI)",
    "session tokens and cookies", "API keys and service credentials",
    "audit logs and access records", "encrypted configuration data",
    "user-generated content (files, images)", "financial transaction records",
    "geolocation data", "behavioral analytics data", "internal service certificates",
    "customer communication records", "compliance and regulatory documents",
]

DEPLOYMENT_ENVS = [
    "AWS multi-region with VPC peering",
    "Azure with hub-and-spoke network topology",
    "GCP with shared VPC and private Google access",
    "hybrid cloud (on-prem VMware + AWS)",
    "Kubernetes cluster on bare metal with Calico CNI",
    "multi-cloud (AWS primary, GCP disaster recovery)",
    "on-premises data center with DMZ architecture",
    "edge computing deployment with central cloud backend",
]

STRIDE_CATEGORIES = [
    ("Spoofing", "An attacker impersonates a legitimate entity", "CWE-287"),
    ("Tampering", "An attacker modifies data in transit or at rest", "CWE-345"),
    ("Repudiation", "An attacker denies having performed an action", "CWE-778"),
    ("Information Disclosure", "Sensitive data is exposed to unauthorized parties", "CWE-200"),
    ("Denial of Service", "The system is rendered unavailable", "CWE-400"),
    ("Elevation of Privilege", "An attacker gains unauthorized access levels", "CWE-269"),
]

THREAT_ACTORS = [
    "external attacker (opportunistic)", "external attacker (targeted APT)",
    "malicious insider (employee)", "compromised third-party vendor",
    "automated bot/scanner", "nation-state actor",
    "disgruntled former employee", "competitor engaging in corporate espionage",
    "hacktivist group", "supply chain attacker",
]

ATTACK_GOALS = [
    "Exfiltrate customer PII database",
    "Compromise payment processing to steal card data",
    "Gain persistent administrative access to production",
    "Disrupt service availability during peak hours",
    "Modify financial records without detection",
    "Intercept inter-service communications",
    "Inject malicious code into the CI/CD pipeline",
    "Compromise user sessions at scale",
    "Access encrypted secrets and key material",
    "Pivot from DMZ to internal network segments",
    "Tamper with audit logs to cover tracks",
    "Establish covert command-and-control channel",
]


def _build_architecture_description(rng, app_context, complexity):
    """Generate a realistic system architecture description."""
    num_components = rng.randint(3, 6) if complexity in ("beginner", "intermediate") else rng.randint(5, 9)
    components = rng.sample(SYSTEM_COMPONENTS, min(num_components, len(SYSTEM_COMPONENTS)))
    data_items = rng.sample(DATA_TYPES, rng.randint(2, 5))
    env = rng.choice(DEPLOYMENT_ENVS)
    protocol_set = rng.sample(PROTOCOLS, rng.randint(3, 6))

    desc = f"## System: {app_context.title()}\n\n"
    desc += f"**Deployment:** {env}\n\n"
    desc += "**Components:**\n"
    for c in components:
        desc += f"- {c}\n"
    desc += "\n**Sensitive Data Handled:**\n"
    for d in data_items:
        desc += f"- {d}\n"
    desc += f"\n**Protocols in Use:** {', '.join(protocol_set)}\n"

    desc += "\n**Data Flows:**\n"
    for i in range(min(len(components) - 1, 4)):
        src = components[i]
        dst = components[(i + 1) % len(components)]
        data = rng.choice(data_items)
        proto = rng.choice(protocol_set)
        desc += f"- {src} -> {dst} via {proto} (carries {data})\n"

    if complexity in ("advanced", "expert"):
        desc += f"\n**External Integrations:**\n"
        ext_services = rng.sample([
            "Third-party OAuth provider", "External payment gateway (Stripe/Adyen)",
            "SMS/Email delivery service (Twilio/SendGrid)", "Cloud-based WAF (Cloudflare)",
            "External logging (Datadog/Splunk)", "Third-party analytics (Segment)",
            "CDN provider (Akamai/CloudFront)", "DNS provider (Route53/Cloudflare)",
        ], rng.randint(2, 4))
        for svc in ext_services:
            desc += f"- {svc}\n"

    return desc, components, data_items


def _generate_stride_entry(rng, complexity, idx, prefix):
    """Generate a STRIDE threat modeling entry."""
    app_context = rng.choice(APP_CONTEXTS)
    desc, components, data_items = _build_architecture_description(rng, app_context, complexity)
    severity = pick_severity(rng, complexity)
    actor = rng.choice(THREAT_ACTORS)

    output = f"## STRIDE Threat Model: {app_context.title()}\n\n"
    output += f"**Threat Actor Profile:** {actor}\n"
    output += f"**Analysis Complexity:** {complexity.title()}\n\n"

    # Generate threats for each STRIDE category
    for cat_name, cat_desc, cat_cwe in STRIDE_CATEGORIES:
        output += f"### {cat_name}\n\n"
        output += f"**Definition:** {cat_desc}\n\n"

        num_threats = rng.randint(1, 3) if complexity in ("beginner", "intermediate") else rng.randint(2, 4)
        for t in range(num_threats):
            target_comp = rng.choice(components)
            target_data = rng.choice(data_items)
            technique_id = rng.choice(list(MITRE_ATTACK.keys()))
            technique = MITRE_ATTACK[technique_id]

            output += f"**Threat {cat_name[0]}{t+1}:** {cat_name} of {target_comp}\n"
            output += f"- **Description:** An attacker targeting {target_data} via {target_comp} "
            output += f"could exploit weaknesses to {cat_desc.lower()}.\n"
            output += f"- **MITRE ATT&CK:** {technique_id} ({technique['name']}) - {technique['tactic']}\n"
            output += f"- **CWE:** {cat_cwe}\n"
            output += f"- **Likelihood:** {rng.choice(['Low', 'Medium', 'High'])}\n"
            output += f"- **Impact:** {rng.choice(['Low', 'Medium', 'High', 'Critical'])}\n"
            output += f"- **Mitigation:** "

            mitigations = {
                "Spoofing": [
                    "Implement mutual TLS authentication between services",
                    "Enforce multi-factor authentication for all user accounts",
                    "Use short-lived JWT tokens with audience validation",
                    "Deploy certificate pinning for mobile clients",
                ],
                "Tampering": [
                    "Enable integrity checking with HMAC signatures on all inter-service messages",
                    "Implement database-level row integrity checksums",
                    "Use immutable infrastructure with signed container images",
                    "Deploy file integrity monitoring on critical configuration files",
                ],
                "Repudiation": [
                    "Implement centralized, tamper-evident audit logging",
                    "Use cryptographic timestamps for all critical transactions",
                    "Enable database audit trails with append-only storage",
                    "Deploy SIEM with automated correlation and alerting",
                ],
                "Information Disclosure": [
                    "Encrypt all data at rest using AES-256-GCM",
                    "Enforce TLS 1.3 for all data in transit",
                    "Implement field-level encryption for PII",
                    "Deploy data loss prevention (DLP) controls at network boundaries",
                ],
                "Denial of Service": [
                    "Implement rate limiting and request throttling at the API gateway",
                    "Deploy auto-scaling with circuit breakers for all services",
                    "Use CDN with DDoS mitigation for public-facing endpoints",
                    "Configure resource quotas and limits in the orchestration layer",
                ],
                "Elevation of Privilege": [
                    "Enforce principle of least privilege across all service accounts",
                    "Implement RBAC with regular access reviews",
                    "Deploy runtime security monitoring for privilege escalation attempts",
                    "Use network segmentation to limit blast radius of compromised services",
                ],
            }
            output += rng.choice(mitigations[cat_name]) + "\n\n"

    output += "### Summary and Prioritization\n\n"
    output += "| Priority | Threat | Category | Risk Rating |\n"
    output += "|----------|--------|----------|-------------|\n"
    for i, (cat_name, _, _) in enumerate(STRIDE_CATEGORIES):
        risk = rng.choice(["Low", "Medium", "High", "Critical"])
        output += f"| {i+1} | {cat_name} of {rng.choice(components)} | {cat_name} | {risk} |\n"
    output += "\n"

    output += "### Recommended Next Steps\n"
    output += "1. Address Critical and High risk threats in the current sprint\n"
    output += "2. Schedule Medium risk mitigations for the next release cycle\n"
    output += "3. Add threat model review to the SDLC gate for design changes\n"
    output += "4. Conduct follow-up penetration testing to validate mitigations\n"

    cwe_choice = rng.choice([c[2] for c in STRIDE_CATEGORIES])
    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"STRIDE Threat Model: {app_context.title()}",
        severity=severity,
        cwe=cwe_choice,
        instruction=rng.choice(STRIDE_INSTRUCTIONS),
        input_text=desc,
        output_text=output,
    )


def _generate_attack_tree_entry(rng, complexity, idx, prefix):
    """Generate an attack tree analysis entry."""
    app_context = rng.choice(APP_CONTEXTS)
    goal = rng.choice(ATTACK_GOALS)
    actor = rng.choice(THREAT_ACTORS)
    severity = pick_severity(rng, complexity)
    desc, components, data_items = _build_architecture_description(rng, app_context, complexity)

    input_text = f"**Target System:** {app_context.title()}\n"
    input_text += f"**Attack Goal:** {goal}\n"
    input_text += f"**Threat Actor:** {actor}\n\n"
    input_text += desc

    output = f"## Attack Tree Analysis\n\n"
    output += f"**Root Goal:** {goal}\n"
    output += f"**Actor:** {actor}\n\n"

    output += "### Attack Tree Structure\n\n"
    output += f"```\nROOT: {goal}\n"

    # Generate attack tree branches
    branch_templates = [
        ("Exploit Application Vulnerability", [
            ("Identify vulnerable component", "Reconnaissance scan or public CVE database", "Low"),
            ("Develop or obtain exploit", "Craft payload targeting the vulnerability", "Medium"),
            ("Deliver exploit to target", "Send crafted request to vulnerable endpoint", "Medium"),
            ("Achieve code execution", "Execute payload in application context", "High"),
        ]),
        ("Compromise Authentication", [
            ("Obtain valid credentials", "Credential stuffing or phishing campaign", "Medium"),
            ("Bypass MFA mechanism", "SIM swap, push fatigue, or TOTP replay", "High"),
            ("Hijack active session", "Steal session cookie via XSS or network sniffing", "Medium"),
            ("Forge authentication token", "Exploit weak signing key or algorithm confusion", "High"),
        ]),
        ("Abuse Insider Access", [
            ("Identify accessible sensitive data", "Map data stores accessible to current role", "Low"),
            ("Escalate privileges", "Exploit misconfigured RBAC or role inheritance", "Medium"),
            ("Exfiltrate data", "Copy data via authorized channels or covert means", "Medium"),
            ("Cover tracks", "Modify or delete audit logs", "High"),
        ]),
        ("Supply Chain Attack", [
            ("Identify third-party dependency", "Enumerate libraries and vendor integrations", "Low"),
            ("Compromise dependency", "Inject malicious code into upstream package", "High"),
            ("Propagate to target", "Wait for target to update the compromised dependency", "Medium"),
            ("Execute malicious payload", "Trigger backdoor via normal application flow", "High"),
        ]),
        ("Network-Level Attack", [
            ("Gain network position", "Compromise adjacent host or perform ARP spoofing", "Medium"),
            ("Intercept communications", "Capture unencrypted or weakly encrypted traffic", "Medium"),
            ("Inject/modify traffic", "Perform MITM to alter requests or responses", "High"),
            ("Pivot to internal segments", "Use compromised host to reach isolated networks", "High"),
        ]),
    ]

    num_branches = rng.randint(2, 3) if complexity in ("beginner", "intermediate") else rng.randint(3, 5)
    selected_branches = rng.sample(branch_templates, min(num_branches, len(branch_templates)))

    for b_idx, (branch_name, steps) in enumerate(selected_branches):
        connector = "OR" if b_idx > 0 else "AND"
        output += f"  [{connector}] {branch_name}\n"
        for step_name, step_detail, step_difficulty in steps:
            output += f"    [AND] {step_name}\n"
            output += f"          Method: {step_detail}\n"
            output += f"          Difficulty: {step_difficulty}\n"

    output += "```\n\n"

    output += "### Path Analysis\n\n"
    for b_idx, (branch_name, steps) in enumerate(selected_branches):
        difficulty_map = {"Low": 1, "Medium": 2, "High": 3}
        total_diff = sum(difficulty_map.get(s[2], 2) for s in steps)
        feasibility = "High" if total_diff <= 5 else "Medium" if total_diff <= 8 else "Low"
        output += f"**Path {b_idx+1}: {branch_name}**\n"
        output += f"- Steps required: {len(steps)}\n"
        output += f"- Overall feasibility: {feasibility}\n"
        output += f"- Estimated time: {rng.choice(['hours', 'days', 'weeks'])}\n"
        output += f"- Detection likelihood: {rng.choice(['Low', 'Medium', 'High'])}\n\n"

    output += "### Mitigation Priorities\n\n"
    for b_idx, (branch_name, steps) in enumerate(selected_branches):
        output += f"**Against {branch_name}:**\n"
        for step_name, _, _ in steps[:2]:
            output += f"- Block '{step_name}' step with appropriate controls\n"
        output += "\n"

    cwe_id = rng.choice(list(CWE_DB.keys()))
    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Attack Tree: {goal}",
        severity=severity,
        cwe=cwe_id,
        instruction=rng.choice(ATTACK_TREE_INSTRUCTIONS),
        input_text=input_text,
        output_text=output,
    )


def _generate_dfd_entry(rng, complexity, idx, prefix):
    """Generate a data flow diagram security analysis entry."""
    app_context = rng.choice(APP_CONTEXTS)
    severity = pick_severity(rng, complexity)
    desc, components, data_items = _build_architecture_description(rng, app_context, complexity)

    input_text = f"**System:** {app_context.title()}\n\n"
    input_text += "**Data Flow Diagram Description:**\n\n"
    input_text += desc

    output = f"## Data Flow Security Analysis: {app_context.title()}\n\n"

    # Identify trust boundaries
    boundary_pairs = [
        ("External Users / Internet", "DMZ / Public-Facing Services"),
        ("DMZ / Public-Facing Services", "Internal Application Tier"),
        ("Internal Application Tier", "Data Storage Tier"),
        ("Application Services", "External Third-Party APIs"),
        ("CI/CD Pipeline", "Production Environment"),
        ("Admin Network", "Production Network"),
    ]
    num_boundaries = rng.randint(2, 4) if complexity in ("beginner", "intermediate") else rng.randint(3, 6)
    selected_boundaries = rng.sample(boundary_pairs, min(num_boundaries, len(boundary_pairs)))

    output += "### Trust Boundaries Identified\n\n"
    for i, (zone_a, zone_b) in enumerate(selected_boundaries, 1):
        output += f"**TB-{i}:** {zone_a} <-> {zone_b}\n"
        data_crossing = rng.choice(data_items)
        proto = rng.choice(PROTOCOLS)
        output += f"- Data crossing: {data_crossing}\n"
        output += f"- Protocol: {proto}\n"
        output += f"- Current protection: {rng.choice(['TLS 1.2', 'TLS 1.3', 'mTLS', 'None (plaintext)', 'IPSec VPN', 'SSH tunnel'])}\n\n"

    output += "### Threat Analysis per Boundary\n\n"
    for i, (zone_a, zone_b) in enumerate(selected_boundaries, 1):
        output += f"**TB-{i} ({zone_a} <-> {zone_b}):**\n\n"
        threats = [
            f"Data interception: {rng.choice(data_items)} could be captured in transit",
            f"Unauthorized access: Missing authentication at the boundary allows lateral movement",
            f"Data tampering: Messages crossing this boundary lack integrity verification",
            f"Injection attacks: Input from {zone_a} not sanitized before reaching {zone_b}",
            f"Information leakage: Error messages from {zone_b} expose internal details to {zone_a}",
        ]
        for threat in rng.sample(threats, rng.randint(2, 3)):
            output += f"- {threat}\n"
        output += "\n"

    output += "### Recommendations\n\n"
    recommendations = [
        "Enforce mTLS for all inter-service communication across trust boundaries",
        "Implement API gateway with request validation at every boundary crossing",
        "Deploy network segmentation with micro-segmentation within the application tier",
        "Add integrity checking (HMAC/digital signatures) for all cross-boundary data",
        "Implement data classification and apply encryption based on sensitivity level",
        "Deploy intrusion detection sensors at each trust boundary",
        "Establish monitoring and alerting for anomalous cross-boundary traffic patterns",
    ]
    for j, rec in enumerate(rng.sample(recommendations, rng.randint(4, 6)), 1):
        output += f"{j}. {rec}\n"

    cwe_id = rng.choice(list(CWE_DB.keys()))
    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"DFD Security Analysis: {app_context.title()}",
        severity=severity,
        cwe=cwe_id,
        instruction=rng.choice(DFD_INSTRUCTIONS),
        input_text=input_text,
        output_text=output,
    )


def _generate_risk_matrix_entry(rng, complexity, idx, prefix):
    """Generate a risk matrix / threat prioritization entry."""
    app_context = rng.choice(APP_CONTEXTS)
    severity = pick_severity(rng, complexity)
    desc, components, data_items = _build_architecture_description(rng, app_context, complexity)

    input_text = f"**System:** {app_context.title()}\n\n"
    input_text += desc
    input_text += "\n**Task:** Create a risk assessment matrix for the threats in this system.\n"

    output = f"## Risk Assessment Matrix: {app_context.title()}\n\n"

    # Generate threat entries
    threat_templates = [
        ("Unauthorized data access via broken access control", "CWE-284", "auth"),
        ("SQL injection in search functionality", "CWE-89", "injection"),
        ("Cross-site scripting in user-generated content", "CWE-79", "injection"),
        ("Session hijacking via insecure cookie handling", "CWE-384", "auth"),
        ("Credential stuffing against login endpoint", "CWE-307", "auth"),
        ("Server-side request forgery via URL parameter", "CWE-918", "injection"),
        ("Insecure deserialization in API endpoints", "CWE-502", "injection"),
        ("Denial of service via resource exhaustion", "CWE-400", "dos"),
        ("Privilege escalation via IDOR", "CWE-639", "auth"),
        ("Information disclosure via verbose error messages", "CWE-209", "disclosure"),
        ("Man-in-the-middle attack on internal services", "CWE-319", "crypto"),
        ("Container escape from compromised microservice", "CWE-269", "auth"),
    ]

    num_threats = rng.randint(5, 8) if complexity in ("beginner", "intermediate") else rng.randint(8, 12)
    selected_threats = rng.sample(threat_templates, min(num_threats, len(threat_templates)))

    likelihoods = ["Very Low", "Low", "Medium", "High", "Very High"]
    impacts = ["Negligible", "Minor", "Moderate", "Major", "Catastrophic"]

    output += "### Risk Matrix\n\n"
    output += "| # | Threat | CWE | Likelihood | Impact | Risk Score | Risk Level | Target Component |\n"
    output += "|---|--------|-----|------------|--------|------------|------------|------------------|\n"

    risk_entries = []
    for t_idx, (threat_name, cwe_id, category) in enumerate(selected_threats, 1):
        likelihood = rng.choice(likelihoods)
        impact = rng.choice(impacts)
        l_score = likelihoods.index(likelihood) + 1
        i_score = impacts.index(impact) + 1
        risk_score = l_score * i_score
        if risk_score >= 16:
            risk_level = "Critical"
        elif risk_score >= 10:
            risk_level = "High"
        elif risk_score >= 5:
            risk_level = "Medium"
        else:
            risk_level = "Low"
        component = rng.choice(components)
        output += f"| {t_idx} | {threat_name} | {cwe_id} | {likelihood} | {impact} | {risk_score} | {risk_level} | {component} |\n"
        risk_entries.append((threat_name, risk_level, risk_score, component))

    output += "\n### Risk Level Distribution\n\n"
    for level in ["Critical", "High", "Medium", "Low"]:
        count = sum(1 for _, rl, _, _ in risk_entries if rl == level)
        output += f"- **{level}:** {count} threats\n"
    output += "\n"

    # Sort by risk score descending for remediation plan
    risk_entries.sort(key=lambda x: x[2], reverse=True)

    output += "### Remediation Priority\n\n"
    for r_idx, (threat_name, risk_level, risk_score, component) in enumerate(risk_entries[:5], 1):
        timeline = {
            "Critical": "Immediate (within 24 hours)",
            "High": "Short-term (within 1 week)",
            "Medium": "Medium-term (within 1 month)",
            "Low": "Long-term (next quarter)",
        }
        output += f"{r_idx}. **{threat_name}** ({risk_level}, score={risk_score})\n"
        output += f"   - Affected: {component}\n"
        output += f"   - Timeline: {timeline.get(risk_level, 'TBD')}\n"
        output += f"   - Owner: {rng.choice(['Security Team', 'Platform Engineering', 'Application Team', 'DevOps', 'Infrastructure'])}\n\n"

    output += "### Residual Risk Notes\n\n"
    output += "After implementing recommended mitigations, conduct a follow-up assessment to validate "
    output += "risk reduction. Residual risk should be formally accepted by the system owner "
    output += "and documented in the risk register.\n"

    cwe_id = rng.choice([t[1] for t in selected_threats])
    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Risk Matrix: {app_context.title()}",
        severity=severity,
        cwe=cwe_id,
        instruction=rng.choice(RISK_MATRIX_INSTRUCTIONS),
        input_text=input_text,
        output_text=output,
    )


class ThreatModelingGenerator(CategoryGenerator):
    category = "threat_modeling"
    id_prefix = "xld-threat"

    def generate_entries(self, rng: random.Random, count: int, start_id: int,
                         complexity_weights) -> List[Dict[str, Any]]:
        entries = []
        # Distribute: 35% STRIDE, 25% attack tree, 20% DFD, 20% risk matrix
        stride_count = int(count * 0.35)
        tree_count = int(count * 0.25)
        dfd_count = int(count * 0.20)
        risk_count = count - stride_count - tree_count - dfd_count

        idx = start_id
        for _ in range(stride_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_stride_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        for _ in range(tree_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_attack_tree_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        for _ in range(dfd_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_dfd_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        for _ in range(risk_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_risk_matrix_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        return entries
