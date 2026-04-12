"""
Network Security generator.
Produces network security assessment entries covering firewall rules, protocol
vulnerabilities, TLS configuration, IDS/IPS, DNS security, VPN, and DMZ
architecture analysis.
Target: 6000 entries.
"""

import random
from typing import List, Dict, Any
from ..templates import (
    CategoryGenerator, pick_complexity, pick_severity, format_entry,
    rand_ip, rand_domain, rand_port, rand_var_name, rand_func_name,
    rand_table_name, rand_path,
)
from ..knowledge_base import (
    CWE_DB, OWASP_TOP10, MITRE_ATTACK, APP_CONTEXTS, PRODUCTS,
    CLOUD_SERVICES, FRAMEWORKS, PROTOCOLS,
)

# ── Instruction pools ──────────────────────────────────────────────────────

FIREWALL_INSTRUCTIONS = [
    "Analyze the following firewall ruleset for security weaknesses. Identify overly permissive rules, ordering issues, and missing deny-all defaults.",
    "Review this firewall configuration and assess whether it follows the principle of least privilege. Identify rules that should be tightened.",
    "Evaluate the firewall ACLs below for common misconfigurations. Determine if the ruleset provides adequate network segmentation.",
    "As a network security engineer, audit the following firewall rules. Identify shadowed rules, redundancies, and security gaps.",
]

PROTOCOL_INSTRUCTIONS = [
    "Analyze the following network protocol configuration for security vulnerabilities. Identify weak ciphers, insecure protocol versions, and missing protections.",
    "Review this protocol implementation from a security perspective. What attacks does this configuration leave the network vulnerable to?",
    "Assess the security of the network protocol usage described below. Identify outdated or insecure protocol configurations.",
    "Evaluate the following network service configuration for protocol-level vulnerabilities and recommend hardening measures.",
]

TLS_INSTRUCTIONS = [
    "Review the following TLS/SSL configuration for security weaknesses. Check protocol versions, cipher suites, and certificate handling.",
    "Perform a TLS security assessment on the configuration below. Identify any settings that could enable downgrade attacks or weak encryption.",
    "Analyze this TLS configuration for compliance with current security best practices. Identify deprecated features and missing protections.",
    "Evaluate the SSL/TLS settings for this server. Determine if the configuration is vulnerable to BEAST, POODLE, CRIME, or other known attacks.",
]

NETWORK_SEGMENT_INSTRUCTIONS = [
    "Analyze the following network architecture for segmentation weaknesses. Identify paths that could allow lateral movement between zones.",
    "Review this network topology and assess whether critical assets are properly isolated. Identify segmentation gaps.",
    "Evaluate the network segmentation strategy below. Determine if an attacker who compromises one zone could pivot to sensitive segments.",
]

DNS_INSTRUCTIONS = [
    "Analyze the following DNS configuration for security issues. Check for zone transfer permissions, DNSSEC, and resolver security.",
    "Review this DNS setup for vulnerabilities including cache poisoning, amplification, and information disclosure risks.",
]

PORT_SCAN_INSTRUCTIONS = [
    "Analyze the following port scan results from a security perspective. Identify high-risk services, unexpected open ports, and recommended actions.",
    "Review these network scan results and prioritize the findings by risk. Identify services that should not be exposed.",
    "Assess the attack surface revealed by this port scan. What are the most critical services to address, and what mitigations are recommended?",
]

VPN_INSTRUCTIONS = [
    "Analyze the following VPN configuration for security weaknesses. Check encryption algorithms, authentication methods, and split tunneling settings.",
    "Review this VPN setup from a security perspective. Identify misconfigurations that could compromise confidentiality or allow unauthorized access.",
]

TRAFFIC_INSTRUCTIONS = [
    "Analyze the following network traffic pattern for anomalies. Identify potential indicators of compromise or malicious activity.",
    "Review the network traffic summary below for signs of data exfiltration, command-and-control communication, or lateral movement.",
]

ALL_INSTRUCTIONS = (
    FIREWALL_INSTRUCTIONS + PROTOCOL_INSTRUCTIONS + TLS_INSTRUCTIONS +
    NETWORK_SEGMENT_INSTRUCTIONS + DNS_INSTRUCTIONS + PORT_SCAN_INSTRUCTIONS +
    VPN_INSTRUCTIONS + TRAFFIC_INSTRUCTIONS
)

# ── Network data templates ─────────────────────────────────────────────────

COMMON_SERVICES = [
    (22, "SSH"), (23, "Telnet"), (25, "SMTP"), (53, "DNS"),
    (80, "HTTP"), (110, "POP3"), (135, "MSRPC"), (139, "NetBIOS"),
    (143, "IMAP"), (443, "HTTPS"), (445, "SMB"), (993, "IMAPS"),
    (995, "POP3S"), (1433, "MSSQL"), (1521, "Oracle"), (3306, "MySQL"),
    (3389, "RDP"), (5432, "PostgreSQL"), (5900, "VNC"), (6379, "Redis"),
    (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"), (9200, "Elasticsearch"),
    (27017, "MongoDB"),
]

RISKY_SERVICES = [
    (23, "Telnet"), (21, "FTP"), (135, "MSRPC"), (139, "NetBIOS"),
    (445, "SMB"), (3389, "RDP"), (5900, "VNC"), (6379, "Redis"),
    (9200, "Elasticsearch"), (27017, "MongoDB"), (11211, "Memcached"),
]

FIREWALL_ACTIONS = ["ALLOW", "DENY", "DROP", "REJECT"]

NETWORK_ZONES = [
    "DMZ", "Internal", "Management", "Production", "Development",
    "Database", "PCI", "Guest", "IoT", "SCADA",
]

TLS_VERSIONS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]

WEAK_CIPHERS = [
    "RC4-SHA", "DES-CBC3-SHA", "NULL-SHA", "EXPORT-DES40",
    "ADH-AES128-SHA", "RC4-MD5", "DES-CBC-SHA",
]

STRONG_CIPHERS = [
    "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256",
]

VPN_PROTOCOLS_LIST = ["OpenVPN", "WireGuard", "IPSec/IKEv2", "L2TP/IPSec", "PPTP", "SSTP"]

NETWORK_CWES = [
    "CWE-284", "CWE-311", "CWE-319", "CWE-326", "CWE-327",
    "CWE-295", "CWE-400", "CWE-668", "CWE-200", "CWE-923",
]


# ── Scenario builder helpers ───────────────────────────────────────────────

def _build_firewall_scenario(rng, complexity, domain):
    num_rules = rng.randint(6, 12) if complexity in ("advanced", "expert") else rng.randint(4, 7)
    rules = []
    issues = []

    for i in range(num_rules):
        action = rng.choice(FIREWALL_ACTIONS[:2])  # ALLOW/DENY
        src = rng.choice(["any", rand_ip(rng), rand_ip(rng, internal=True),
                          f"{rand_ip(rng, internal=True)}/24", "0.0.0.0/0"])
        dst = rng.choice(["any", rand_ip(rng, internal=True), f"{rand_ip(rng, internal=True)}/24",
                          rand_ip(rng)])
        port = rng.choice([str(p[0]) for p in COMMON_SERVICES] + ["any", "1-65535"])
        proto = rng.choice(["tcp", "udp", "any"])

        rules.append({"id": i + 1, "action": action, "src": src, "dst": dst,
                       "port": port, "proto": proto})

        if src == "any" and dst == "any" and action == "ALLOW":
            issues.append(f"Rule {i+1}: ALLOW any-to-any (completely open)")
        elif src == "0.0.0.0/0" and action == "ALLOW" and port in ["22", "3389", "445"]:
            svc = [s for s in COMMON_SERVICES if str(s[0]) == port]
            svc_name = svc[0][1] if svc else port
            issues.append(f"Rule {i+1}: {svc_name} (port {port}) open to the internet")
        elif port == "any" and action == "ALLOW":
            issues.append(f"Rule {i+1}: ALLOW on all ports from {src}")
        elif port == "1-65535" and action == "ALLOW":
            issues.append(f"Rule {i+1}: Full port range open ({src} -> {dst})")

    # Ensure at least one issue
    if not issues:
        rules.append({"id": num_rules + 1, "action": "ALLOW", "src": "0.0.0.0/0",
                       "dst": "any", "port": "3389", "proto": "tcp"})
        issues.append(f"Rule {num_rules+1}: RDP (port 3389) open to the internet")

    # Check for missing deny-all
    last_rule = rules[-1]
    if last_rule["action"] != "DENY" or last_rule["src"] != "any":
        issues.append("Missing implicit deny-all rule at the end of the ruleset")

    input_text = f"## Firewall Ruleset Review\n\n"
    input_text += f"**Device:** fw-{rng.choice(['core','edge','dmz','branch'])}-{rng.randint(1,5):02d}\n"
    input_text += f"**Zones:** {rng.choice(NETWORK_ZONES)} -> {rng.choice(NETWORK_ZONES)}\n\n"
    input_text += f"```\n{'ID':<4} {'ACTION':<8} {'SOURCE':<20} {'DEST':<20} {'PORT':<10} {'PROTO':<6}\n"
    input_text += f"{'-'*68}\n"
    for r in rules:
        input_text += f"{r['id']:<4} {r['action']:<8} {r['src']:<20} {r['dst']:<20} {r['port']:<10} {r['proto']:<6}\n"
    input_text += f"```"

    cwe = rng.choice(["CWE-284", "CWE-668", "CWE-732"])
    cwe_info = CWE_DB.get(cwe, {"name": "Access Control", "severity": ["high"]})

    output = f"## Firewall Ruleset Security Assessment\n\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** HIGH\n"
    output += f"**Total Rules Reviewed:** {len(rules)}\n"
    output += f"**Issues Found:** {len(issues)}\n\n"
    output += f"### Findings\n\n"

    for i, issue in enumerate(issues, 1):
        output += f"**{i}. {issue}**\n"
        if "any-to-any" in issue:
            output += f"This rule effectively disables the firewall for all traffic. "
            output += f"It should be removed and replaced with specific allow rules.\n\n"
        elif "internet" in issue.lower():
            output += f"Exposing this service to the internet creates a high-risk attack surface. "
            output += f"Restrict source IPs to known management networks or use VPN access.\n\n"
        elif "all ports" in issue.lower() or "full port range" in issue.lower():
            output += f"Allowing all ports violates the principle of least privilege. "
            output += f"Define specific ports required for the application.\n\n"
        elif "deny-all" in issue.lower():
            output += f"Without a default deny rule, any traffic not explicitly matched will "
            output += f"be implicitly allowed (depending on the firewall platform). Always end "
            output += f"with an explicit `DENY any any any` rule.\n\n"

    output += f"### Remediation\n"
    output += f"1. **Add default deny** - Append `DENY any any any any` as the final rule.\n"
    output += f"2. **Restrict management ports** - Limit SSH/RDP to management VLAN only.\n"
    output += f"3. **Remove overly broad rules** - Replace `any` sources/ports with specific values.\n"
    output += f"4. **Implement logging** - Enable logging on all DENY and critical ALLOW rules.\n"
    output += f"5. **Regular review** - Schedule quarterly firewall rule audits.\n"

    if complexity in ("advanced", "expert"):
        output += f"\n### Optimized Ruleset\n"
        output += f"```\nID   ACTION   SOURCE               DEST                 PORT       PROTO\n"
        output += f"{'='*68}\n"
        output += f"1    ALLOW    10.0.10.0/24         10.0.20.0/24         443        tcp\n"
        output += f"2    ALLOW    10.0.10.0/24         10.0.20.0/24         80         tcp\n"
        output += f"3    ALLOW    10.0.1.0/28          10.0.0.0/8           22         tcp\n"
        output += f"4    DENY     any                  any                  any        any\n"
        output += f"```"

    return cwe, input_text, output, f"Firewall Misconfigurations: {len(issues)} issues found"


def _build_tls_scenario(rng, complexity, domain):
    enabled_versions = rng.sample(TLS_VERSIONS, k=rng.randint(2, 5))
    enabled_versions.sort(key=lambda v: TLS_VERSIONS.index(v))
    ciphers = rng.sample(WEAK_CIPHERS + STRONG_CIPHERS, k=rng.randint(4, 8))
    weak_found = [c for c in ciphers if c in WEAK_CIPHERS]
    deprecated_versions = [v for v in enabled_versions if v in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")]

    hsts = rng.random() < 0.4
    ocsp_stapling = rng.random() < 0.3
    cert_days = rng.choice([30, 90, 365, 730, 825])

    input_text = f"## TLS Configuration Review\n\n"
    input_text += f"**Server:** {domain}:{rng.choice([443, 8443])}\n\n"
    input_text += f"```\n# TLS Configuration\n"
    input_text += f"ssl_protocols: {' '.join(enabled_versions)}\n"
    input_text += f"ssl_ciphers: {':'.join(ciphers)}\n"
    input_text += f"ssl_prefer_server_ciphers: {'on' if rng.random() < 0.5 else 'off'}\n"
    input_text += f"ssl_session_tickets: {'on' if rng.random() < 0.6 else 'off'}\n"
    input_text += f"ssl_certificate_days_remaining: {cert_days}\n"
    input_text += f"hsts_enabled: {str(hsts).lower()}\n"
    input_text += f"ocsp_stapling: {str(ocsp_stapling).lower()}\n"
    input_text += f"```"

    cwe = rng.choice(["CWE-326", "CWE-327", "CWE-295", "CWE-319"])
    cwe_info = CWE_DB.get(cwe, {"name": "Crypto Weakness", "severity": ["medium", "high"]})

    output = f"## TLS Security Assessment\n\n"
    output += f"**Server:** {domain}\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** {'CRITICAL' if 'SSLv2' in enabled_versions else 'HIGH' if deprecated_versions else 'MEDIUM'}\n\n"
    output += f"### Findings\n\n"

    finding = 1
    if deprecated_versions:
        output += f"**{finding}. Deprecated Protocol Versions Enabled**\n"
        output += f"The following deprecated protocols are enabled: {', '.join(deprecated_versions)}. "
        output += f"These protocols have known vulnerabilities:\n"
        for dv in deprecated_versions:
            if dv == "SSLv2":
                output += f"- **SSLv2**: DROWN attack, fundamentally broken encryption\n"
            elif dv == "SSLv3":
                output += f"- **SSLv3**: POODLE attack, CBC padding oracle vulnerability\n"
            elif dv == "TLSv1.0":
                output += f"- **TLSv1.0**: BEAST attack, PCI DSS non-compliant since June 2018\n"
            elif dv == "TLSv1.1":
                output += f"- **TLSv1.1**: Deprecated by RFC 8996, no longer supported by browsers\n"
        output += f"\n"
        finding += 1

    if weak_found:
        output += f"**{finding}. Weak Cipher Suites**\n"
        output += f"The following weak or broken ciphers are enabled:\n"
        for wc in weak_found:
            if "RC4" in wc:
                output += f"- `{wc}` - RC4 is cryptographically broken\n"
            elif "DES" in wc:
                output += f"- `{wc}` - DES/3DES has insufficient key length\n"
            elif "NULL" in wc:
                output += f"- `{wc}` - NULL cipher provides no encryption\n"
            elif "EXPORT" in wc:
                output += f"- `{wc}` - Export cipher has intentionally weakened encryption\n"
            elif "ADH" in wc:
                output += f"- `{wc}` - Anonymous DH is vulnerable to MITM attacks\n"
        output += f"\n"
        finding += 1

    if not hsts:
        output += f"**{finding}. Missing HSTS Header**\n"
        output += f"Without HTTP Strict Transport Security, clients may connect via HTTP first, "
        output += f"enabling SSL stripping attacks (e.g., sslstrip).\n\n"
        finding += 1

    if cert_days > 397:
        output += f"**{finding}. Long Certificate Validity**\n"
        output += f"Certificate validity of {cert_days} days exceeds the CA/B Forum maximum of 397 days. "
        output += f"Long-lived certificates increase exposure if the key is compromised.\n\n"
        finding += 1

    output += f"### Recommended Configuration\n"
    output += f"```\nssl_protocols: TLSv1.2 TLSv1.3\n"
    output += f"ssl_ciphers: {':'.join(STRONG_CIPHERS[:3])}\n"
    output += f"ssl_prefer_server_ciphers: on\n"
    output += f"ssl_session_tickets: off\n"
    output += f"hsts_enabled: true  # max-age=31536000; includeSubDomains; preload\n"
    output += f"ocsp_stapling: true\n"
    output += f"```"

    return cwe, input_text, output, f"TLS Weaknesses on {domain}"


def _build_port_scan_scenario(rng, complexity, domain):
    target_ip = rand_ip(rng)
    num_ports = rng.randint(5, 12)
    open_services = rng.sample(COMMON_SERVICES, k=num_ports)
    risky = [s for s in open_services if s in RISKY_SERVICES]

    input_text = f"## Port Scan Results\n\n"
    input_text += f"**Target:** {target_ip} ({domain})\n"
    input_text += f"**Scan Type:** TCP SYN Scan\n"
    input_text += f"**Scan Time:** 2024-{rng.randint(1,12):02d}-{rng.randint(1,28):02d} {rng.randint(0,23):02d}:{rng.randint(0,59):02d}\n\n"
    input_text += f"```\nPORT      STATE    SERVICE         VERSION\n"
    for port, svc in open_services:
        state = rng.choice(["open", "open", "open", "filtered"])
        version = f"{svc.lower()}-{rng.randint(1,10)}.{rng.randint(0,9)}"
        input_text += f"{port:<9} {state:<8} {svc:<15} {version}\n"
    input_text += f"```\n\n"
    input_text += f"**OS Detection:** {rng.choice(['Linux 4.x/5.x', 'Windows Server 2019', 'FreeBSD 13', 'Ubuntu 22.04'])}\n"
    input_text += f"**Scan Coverage:** {num_ports} ports open out of 65535 scanned"

    cwe = rng.choice(["CWE-200", "CWE-668", "CWE-284"])
    cwe_info = CWE_DB.get(cwe, {"name": "Exposure", "severity": ["medium"]})

    output = f"## Port Scan Analysis\n\n"
    output += f"**Target:** {target_ip} ({domain})\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Overall Risk:** {'HIGH' if risky else 'MEDIUM'}\n\n"

    output += f"### Risk Assessment by Service\n\n"

    # Categorize by risk
    critical_ports = [s for s in open_services if s[0] in (23, 21, 135, 139, 5900, 11211)]
    high_ports = [s for s in open_services if s[0] in (445, 3389, 6379, 9200, 27017)]
    medium_ports = [s for s in open_services if s not in critical_ports and s not in high_ports]

    if critical_ports:
        output += f"**CRITICAL Risk Services:**\n"
        for port, svc in critical_ports:
            output += f"- **Port {port} ({svc})** - "
            if port == 23:
                output += f"Telnet transmits credentials in cleartext. Must be replaced with SSH.\n"
            elif port == 21:
                output += f"FTP transmits data in cleartext. Replace with SFTP or SCP.\n"
            elif port == 5900:
                output += f"VNC often has weak authentication. Use SSH tunneling or VPN instead.\n"
            else:
                output += f"This service should not be exposed externally.\n"
        output += f"\n"

    if high_ports:
        output += f"**HIGH Risk Services:**\n"
        for port, svc in high_ports:
            output += f"- **Port {port} ({svc})** - "
            if port == 3389:
                output += f"RDP is heavily targeted by brute-force and BlueKeep-type exploits. Restrict to VPN.\n"
            elif port == 6379:
                output += f"Redis typically has no authentication by default. Bind to localhost only.\n"
            elif port == 9200:
                output += f"Elasticsearch may expose data without authentication. Never expose publicly.\n"
            elif port == 27017:
                output += f"MongoDB default configuration allows unauthenticated access. Enable auth.\n"
            else:
                output += f"Restrict access to trusted networks only.\n"
        output += f"\n"

    output += f"### Recommendations\n"
    output += f"1. **Close unnecessary ports** - Disable services not required for business functions.\n"
    output += f"2. **Restrict access** - Use firewall rules to limit source IPs for management services.\n"
    output += f"3. **Encrypt communications** - Replace cleartext protocols (Telnet, FTP) with encrypted alternatives.\n"
    output += f"4. **Update services** - Ensure all exposed services are running patched versions.\n"
    output += f"5. **Enable authentication** - Configure authentication on all database and cache services.\n"
    output += f"6. **Regular scanning** - Schedule monthly vulnerability scans of the external perimeter.\n"

    return cwe, input_text, output, f"Port Scan Analysis: {num_ports} services on {target_ip}"


def _build_dns_scenario(rng, complexity, domain):
    zone_transfer = rng.random() < 0.5
    dnssec = rng.random() < 0.3
    recursive = rng.random() < 0.4
    open_resolver = rng.random() < 0.3

    ns_ip = rand_ip(rng)
    internal_records = [
        f"admin.{domain.split('.', 1)[-1]}    A    {rand_ip(rng, internal=True)}",
        f"db.{domain.split('.', 1)[-1]}        A    {rand_ip(rng, internal=True)}",
        f"vpn.{domain.split('.', 1)[-1]}       A    {rand_ip(rng)}",
        f"staging.{domain.split('.', 1)[-1]}   A    {rand_ip(rng, internal=True)}",
    ]

    input_text = f"## DNS Configuration Review\n\n"
    input_text += f"**DNS Server:** {ns_ip} (ns1.{domain.split('.', 1)[-1]})\n\n"
    input_text += f"```\n# DNS server configuration\n"
    input_text += f"allow-transfer {{ {'any' if zone_transfer else '10.0.0.0/8'}; }};\n"
    input_text += f"recursion {'yes' if recursive else 'no'};\n"
    input_text += f"dnssec-enable {'yes' if dnssec else 'no'};\n"
    input_text += f"allow-query {{ {'any' if open_resolver else '10.0.0.0/8; 172.16.0.0/12'}; }};\n"
    input_text += f"version \"BIND {rng.choice(['9.11.5', '9.16.1', '9.18.0'])}\";\n"
    input_text += f"```\n\n"

    if zone_transfer:
        input_text += f"**Zone Transfer Result (AXFR):**\n```\n"
        for rec in internal_records:
            input_text += f"{rec}\n"
        input_text += f"```"

    cwe = rng.choice(["CWE-200", "CWE-284", "CWE-668"])
    cwe_info = CWE_DB.get(cwe, {"name": "DNS Exposure", "severity": ["medium"]})

    output = f"## DNS Security Assessment\n\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** {'HIGH' if zone_transfer else 'MEDIUM'}\n\n"
    output += f"### Findings\n\n"

    finding = 1
    if zone_transfer:
        output += f"**{finding}. Unrestricted Zone Transfers (AXFR)**\n"
        output += f"The DNS server allows zone transfers from any IP (`allow-transfer {{ any }}`). "
        output += f"This exposes the complete DNS zone to anyone, revealing internal hostnames, "
        output += f"IP addresses, and network topology. Attackers use this for reconnaissance.\n\n"
        finding += 1

    if open_resolver:
        output += f"**{finding}. Open DNS Resolver**\n"
        output += f"The server accepts queries from any source. Open resolvers are abused for "
        output += f"DNS amplification DDoS attacks and can be used for DNS cache poisoning.\n\n"
        finding += 1

    if recursive:
        output += f"**{finding}. Recursion Enabled**\n"
        output += f"Recursion is enabled, which on an authoritative server increases the attack surface "
        output += f"for cache poisoning and can be abused as an open resolver.\n\n"
        finding += 1

    if not dnssec:
        output += f"**{finding}. DNSSEC Not Enabled**\n"
        output += f"Without DNSSEC, DNS responses cannot be cryptographically verified. "
        output += f"This makes the zone vulnerable to DNS spoofing and cache poisoning attacks.\n\n"
        finding += 1

    output += f"**{finding}. Version String Disclosed**\n"
    output += f"The BIND version is exposed in the DNS response, aiding attackers in identifying "
    output += f"known vulnerabilities for that specific version.\n\n"

    output += f"### Remediation\n"
    output += f"1. **Restrict zone transfers** - `allow-transfer {{ <secondary-NS-IPs> }};`\n"
    output += f"2. **Disable open resolver** - Restrict queries to internal networks.\n"
    output += f"3. **Separate roles** - Use dedicated servers for authoritative and recursive DNS.\n"
    output += f"4. **Enable DNSSEC** - Sign zones and validate responses.\n"
    output += f"5. **Hide version** - Set `version \"not disclosed\";`\n"
    output += f"6. **Rate limit responses** - Enable DNS response rate limiting (RRL).\n"

    return cwe, input_text, output, f"DNS Security Issues on ns1.{domain.split('.', 1)[-1]}"


def _build_vpn_scenario(rng, complexity, domain):
    vpn_proto = rng.choice(VPN_PROTOCOLS_LIST)
    is_weak = vpn_proto in ("PPTP", "L2TP/IPSec")

    input_text = f"## VPN Configuration Review\n\n"
    input_text += f"**VPN Server:** vpn.{domain.split('.', 1)[-1]} ({rand_ip(rng)})\n"
    input_text += f"**Protocol:** {vpn_proto}\n\n"
    input_text += f"```\n# VPN Configuration\n"

    issues = []
    if vpn_proto == "PPTP":
        input_text += f"protocol: pptp\n"
        input_text += f"encryption: mppe-128\n"
        input_text += f"authentication: mschapv2\n"
        issues.append("PPTP is cryptographically broken (MS-CHAPv2 crackable in <24hrs)")
    elif vpn_proto == "OpenVPN":
        cipher = rng.choice(["AES-256-GCM", "AES-128-CBC", "BF-CBC", "DES-CBC"])
        auth = rng.choice(["SHA256", "SHA1", "MD5"])
        input_text += f"protocol: openvpn\ncipher: {cipher}\nauth: {auth}\n"
        input_text += f"tls-auth: {'yes' if rng.random() < 0.5 else 'no'}\n"
        if cipher in ("BF-CBC", "DES-CBC"):
            issues.append(f"Weak cipher: {cipher}")
        if auth in ("MD5", "SHA1"):
            issues.append(f"Weak HMAC algorithm: {auth}")
    elif vpn_proto == "WireGuard":
        input_text += f"protocol: wireguard\ncipher: ChaCha20-Poly1305\n"
        input_text += f"key_exchange: Curve25519\n"
    elif vpn_proto == "IPSec/IKEv2":
        phase1 = rng.choice(["AES256-SHA256-DH14", "3DES-SHA1-DH2", "AES128-MD5-DH5"])
        input_text += f"protocol: ipsec-ikev2\nphase1: {phase1}\n"
        if "3DES" in phase1 or "MD5" in phase1 or "DH2" in phase1:
            issues.append(f"Weak Phase 1 parameters: {phase1}")

    split_tunnel = rng.random() < 0.5
    mfa = rng.random() < 0.4
    input_text += f"split_tunneling: {str(split_tunnel).lower()}\n"
    input_text += f"mfa_required: {str(mfa).lower()}\n"
    input_text += f"idle_timeout: {rng.choice([0, 300, 1800, 3600, 86400])}\n"
    input_text += f"concurrent_sessions: {rng.choice([0, 1, 5, 'unlimited'])}\n"
    input_text += f"```"

    if split_tunnel:
        issues.append("Split tunneling enabled (corporate traffic may bypass VPN)")
    if not mfa:
        issues.append("Multi-factor authentication not required")

    if not issues:
        issues.append("VPN logs not forwarded to SIEM for monitoring")

    cwe = rng.choice(["CWE-327", "CWE-311", "CWE-287"])
    cwe_info = CWE_DB.get(cwe, {"name": "Crypto/Auth", "severity": ["medium", "high"]})

    output = f"## VPN Security Assessment\n\n"
    output += f"**Protocol:** {vpn_proto}\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** {'CRITICAL' if is_weak else 'HIGH' if issues else 'MEDIUM'}\n\n"
    output += f"### Findings\n\n"

    for i, issue in enumerate(issues, 1):
        output += f"**{i}. {issue}**\n"
        if "pptp" in issue.lower():
            output += f"PPTP uses MS-CHAPv2 authentication which can be cracked by capturing "
            output += f"the handshake and brute-forcing it. Migrate to WireGuard or IPSec/IKEv2.\n\n"
        elif "split tunnel" in issue.lower():
            output += f"With split tunneling, only traffic destined for the corporate network goes "
            output += f"through the VPN. Other traffic goes directly to the internet, bypassing "
            output += f"corporate security controls (DLP, IDS, content filtering).\n\n"
        elif "mfa" in issue.lower():
            output += f"Without MFA, compromised VPN credentials provide direct network access. "
            output += f"VPN is a high-value target and must require a second factor.\n\n"
        elif "cipher" in issue.lower() or "hmac" in issue.lower() or "phase" in issue.lower():
            output += f"Using weak cryptographic algorithms undermines the confidentiality of "
            output += f"the VPN tunnel. Upgrade to modern algorithms.\n\n"
        else:
            output += f"Without centralized log monitoring, compromised VPN sessions may go "
            output += f"undetected for extended periods.\n\n"

    output += f"### Remediation\n"
    output += f"1. **Use modern protocols** - Prefer WireGuard or IPSec/IKEv2 over PPTP/L2TP.\n"
    output += f"2. **Strong encryption** - Use AES-256-GCM or ChaCha20-Poly1305.\n"
    output += f"3. **Enforce MFA** - Require TOTP or hardware keys for VPN authentication.\n"
    output += f"4. **Evaluate split tunneling** - Use full tunnel for sensitive environments.\n"
    output += f"5. **Set idle timeouts** - Disconnect inactive sessions after 30 minutes.\n"
    output += f"6. **Limit concurrent sessions** - Allow 1 session per user to detect credential sharing.\n"

    return cwe, input_text, output, f"VPN Security: {vpn_proto} Misconfiguration"


def _build_network_segmentation_scenario(rng, complexity, domain):
    zones = rng.sample(NETWORK_ZONES, k=rng.randint(4, 6))
    subnets = {z: f"10.{10+i}.0.0/24" for i, z in enumerate(zones)}

    input_text = f"## Network Segmentation Review\n\n"
    input_text += f"**Organization:** {domain.split('.', 1)[-1]}\n\n"
    input_text += f"### Network Zones\n"
    for z, s in subnets.items():
        input_text += f"- **{z}**: {s}\n"
    input_text += f"\n### Inter-Zone Access Matrix\n"
    input_text += f"```\n{'FROM/TO':<14}"
    for z in zones:
        input_text += f" {z[:8]:<10}"
    input_text += f"\n{'-'*(14 + 10*len(zones))}\n"

    matrix = {}
    for src in zones:
        matrix[src] = {}
        row = f"{src[:12]:<14}"
        for dst in zones:
            if src == dst:
                access = "FULL"
            elif src == "DMZ" and dst in ("Database", "PCI", "Management"):
                access = rng.choice(["FULL", "LIMITED", "NONE"])
            elif src == "Guest" and dst != "DMZ":
                access = rng.choice(["NONE", "FULL"])  # FULL is a finding
            else:
                access = rng.choice(["FULL", "LIMITED", "NONE", "NONE"])
            matrix[src][dst] = access
            row += f" {access:<10}"
        input_text += f"{row}\n"
    input_text += f"```"

    issues = []
    if "Guest" in matrix:
        for dst, access in matrix["Guest"].items():
            if access == "FULL" and dst != "Guest":
                issues.append(f"Guest zone has FULL access to {dst} zone")

    if "DMZ" in matrix:
        for dst, access in matrix["DMZ"].items():
            if access == "FULL" and dst in ("Database", "PCI", "Management"):
                issues.append(f"DMZ has unrestricted access to {dst} zone")

    for src in zones:
        if src not in ("Management",) and "Management" in matrix.get(src, {}):
            if matrix[src].get("Management") == "FULL":
                issues.append(f"{src} zone can reach Management zone (flat network risk)")

    if not issues:
        issues.append("No network monitoring between zones (no IDS/IPS)")

    cwe = rng.choice(["CWE-284", "CWE-668"])
    cwe_info = CWE_DB.get(cwe, {"name": "Access Control", "severity": ["high"]})

    output = f"## Network Segmentation Assessment\n\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** HIGH\n\n"
    output += f"### Findings\n\n"

    for i, issue in enumerate(issues, 1):
        output += f"**{i}. {issue}**\n"
        if "guest" in issue.lower():
            output += f"Guest networks must be completely isolated from internal infrastructure. "
            output += f"Only internet access and potentially DMZ web services should be allowed.\n\n"
        elif "dmz" in issue.lower():
            output += f"The DMZ should only communicate with internal zones through specific, "
            output += f"well-defined ports (e.g., database port only). Full access from DMZ to "
            output += f"internal zones defeats the purpose of the DMZ architecture.\n\n"
        elif "management" in issue.lower():
            output += f"Management interfaces should only be accessible from a dedicated management "
            output += f"VLAN with jump box access. Unrestricted access from other zones enables "
            output += f"lateral movement to critical infrastructure.\n\n"
        else:
            output += f"Without inter-zone monitoring, lateral movement between segments cannot "
            output += f"be detected. Deploy IDS/IPS at zone boundaries.\n\n"

    output += f"### Recommended Architecture\n"
    output += f"1. **Isolate Guest** - Guest network should only reach the internet via a filtered gateway.\n"
    output += f"2. **DMZ restrictions** - DMZ should have one-way access to specific internal service ports.\n"
    output += f"3. **Management isolation** - Access only via hardened jump boxes with MFA.\n"
    output += f"4. **Micro-segmentation** - Apply workload-level policies within zones.\n"
    output += f"5. **Monitor boundaries** - Deploy IDS/IPS at every zone transition point.\n"
    output += f"6. **Zero trust** - Verify identity and context for every cross-zone connection.\n"

    return cwe, input_text, output, f"Segmentation Weaknesses: {len(issues)} issues"


def _build_traffic_anomaly_scenario(rng, complexity, domain):
    src_ip = rand_ip(rng)
    dst_ip = rand_ip(rng, internal=True)
    attack_type = rng.choice(["exfiltration", "c2", "lateral", "ddos", "scanning"])

    technique_id = rng.choice(list(MITRE_ATTACK.keys()))
    technique = MITRE_ATTACK[technique_id]

    input_text = f"## Network Traffic Anomaly Report\n\n"
    input_text += f"**Detection Time:** 2024-{rng.randint(1,12):02d}-{rng.randint(1,28):02d} {rng.randint(0,23):02d}:{rng.randint(0,59):02d}:{rng.randint(0,59):02d}\n"
    input_text += f"**Source:** {src_ip}\n"
    input_text += f"**Destination:** {dst_ip}\n\n"

    if attack_type == "exfiltration":
        input_text += f"**Anomaly Details:**\n"
        input_text += f"- Protocol: DNS\n"
        input_text += f"- DNS query rate: {rng.randint(500, 5000)} queries/minute (baseline: ~50/min)\n"
        input_text += f"- Average query length: {rng.randint(80, 200)} characters (baseline: ~30)\n"
        input_text += f"- Unique subdomains: {rng.randint(1000, 10000)} in last hour\n"
        input_text += f"- Target domain: {rng.choice(['cdn-assets', 'update-service', 'cloud-sync'])}.{rng.choice(['xyz', 'top', 'tk'])}\n"
        input_text += f"- Data volume: {rng.randint(50, 500)} MB over DNS in 2 hours\n"
    elif attack_type == "c2":
        input_text += f"**Anomaly Details:**\n"
        input_text += f"- Protocol: HTTPS (port 443)\n"
        input_text += f"- Beacon interval: ~{rng.choice([30, 60, 120, 300])} seconds (regular pattern)\n"
        input_text += f"- Packet sizes: Consistent {rng.randint(100, 500)} bytes\n"
        input_text += f"- JA3 hash: {rng.randint(10000,99999)}{rng.randint(10000,99999)}\n"
        input_text += f"- Destination: Unresolvable domain / recently registered domain\n"
        input_text += f"- Certificate: Self-signed, subject CN does not match domain\n"
    elif attack_type == "scanning":
        input_text += f"**Anomaly Details:**\n"
        input_text += f"- Protocol: TCP\n"
        input_text += f"- Connection attempts: {rng.randint(5000, 50000)} in {rng.randint(5, 30)} minutes\n"
        input_text += f"- Unique destination ports: {rng.randint(100, 1000)}\n"
        input_text += f"- SYN-only packets: {rng.randint(80, 99)}%\n"
        input_text += f"- Target subnet: {rand_ip(rng, internal=True)}/24\n"
    elif attack_type == "lateral":
        input_text += f"**Anomaly Details:**\n"
        input_text += f"- Protocols: SMB, RDP, WMI\n"
        input_text += f"- Source: {dst_ip} (internal server)\n"
        input_text += f"- Targets: {rng.randint(5, 20)} internal hosts in 10 minutes\n"
        input_text += f"- Authentication failures: {rng.randint(50, 200)}\n"
        input_text += f"- Successful connections: {rng.randint(2, 10)}\n"
        input_text += f"- Time: Outside business hours (03:00-05:00)\n"
    else:  # ddos
        input_text += f"**Anomaly Details:**\n"
        input_text += f"- Protocol: UDP\n"
        input_text += f"- Packet rate: {rng.randint(100000, 1000000)} pps\n"
        input_text += f"- Bandwidth: {rng.randint(1, 40)} Gbps\n"
        input_text += f"- Source IPs: {rng.randint(1000, 50000)} unique addresses\n"
        input_text += f"- Amplification factor: {rng.choice(['DNS', 'NTP', 'memcached', 'SSDP'])}\n"

    cwe = rng.choice(["CWE-400", "CWE-200", "CWE-284"])
    cwe_info = CWE_DB.get(cwe, {"name": "Network Threat", "severity": ["high"]})

    output = f"## Network Traffic Anomaly Analysis\n\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**MITRE ATT&CK:** {technique_id} - {technique['name']} ({technique['tactic']})\n"
    output += f"**Severity:** {'CRITICAL' if attack_type in ('exfiltration', 'c2', 'lateral') else 'HIGH'}\n\n"

    output += f"### Assessment\n\n"
    if attack_type == "exfiltration":
        output += f"**Classification:** DNS Tunneling / Data Exfiltration\n\n"
        output += f"The traffic pattern is consistent with DNS tunneling for data exfiltration. "
        output += f"The abnormally high query rate, long query strings, and large number of unique "
        output += f"subdomains indicate that data is being encoded into DNS queries and sent to "
        output += f"an attacker-controlled authoritative DNS server.\n\n"
    elif attack_type == "c2":
        output += f"**Classification:** Command & Control Beaconing\n\n"
        output += f"The regular beacon interval with consistent packet sizes is indicative of "
        output += f"malware communicating with a command-and-control server. The self-signed "
        output += f"certificate and recently registered domain are additional red flags.\n\n"
    elif attack_type == "scanning":
        output += f"**Classification:** Internal Network Reconnaissance\n\n"
        output += f"The high volume of SYN-only packets across many ports indicates a port scan. "
        output += f"This is likely an attacker (or compromised host) mapping the internal network "
        output += f"after gaining initial access.\n\n"
    elif attack_type == "lateral":
        output += f"**Classification:** Lateral Movement Attempt\n\n"
        output += f"The use of administrative protocols (SMB, RDP, WMI) to reach multiple internal "
        output += f"hosts during off-hours is a strong indicator of lateral movement. The pattern "
        output += f"of authentication failures followed by successes suggests credential stuffing "
        output += f"with stolen credentials.\n\n"
    else:
        output += f"**Classification:** Volumetric DDoS Attack\n\n"
        output += f"The traffic volume and packet rate far exceed normal baselines. The high number "
        output += f"of source IPs indicates a distributed attack, likely using amplification.\n\n"

    output += f"### Immediate Actions\n"
    output += f"1. **Isolate** - Quarantine the source/target system from the network.\n"
    output += f"2. **Capture** - Preserve full packet captures for forensic analysis.\n"
    output += f"3. **Block** - Add firewall rules to block the identified IOCs.\n"
    output += f"4. **Alert** - Notify the incident response team.\n"
    output += f"5. **Investigate** - Check the source system for malware/compromise.\n"

    return cwe, input_text, output, f"Network Anomaly: {attack_type.title()} Detected"


def _build_acl_scenario(rng, complexity, domain):
    num_entries = rng.randint(5, 10)
    acl_name = f"ACL-{rng.choice(['WEB', 'DB', 'MGMT', 'APP', 'DMZ'])}-{rng.randint(1,99):02d}"

    input_text = f"## Access Control List Review\n\n"
    input_text += f"**ACL Name:** {acl_name}\n"
    input_text += f"**Applied To:** {rng.choice(['GigabitEthernet0/1', 'Vlan100', 'Tunnel0', 'Port-channel1'])}\n"
    input_text += f"**Direction:** {rng.choice(['inbound', 'outbound'])}\n\n"
    input_text += f"```\n"

    issues = []
    for i in range(num_entries):
        action = rng.choice(["permit", "permit", "deny"])
        proto = rng.choice(["ip", "tcp", "udp", "icmp"])
        src = rng.choice(["any", f"host {rand_ip(rng, internal=True)}",
                          f"{rand_ip(rng, internal=True)} 0.0.0.255"])
        dst = rng.choice(["any", f"host {rand_ip(rng, internal=True)}",
                          f"{rand_ip(rng, internal=True)} 0.0.0.255"])
        port_spec = ""
        if proto in ("tcp", "udp"):
            port_spec = f" eq {rng.choice([22, 80, 443, 3306, 8080, 'any'])}"

        line = f"{i*10+10} {action} {proto} {src} {dst}{port_spec}"
        input_text += f"{line}\n"

        if src == "any" and dst == "any" and action == "permit":
            issues.append(f"Entry {i*10+10}: permit any-to-any ({proto})")
        elif port_spec.strip() == "eq any" and action == "permit":
            issues.append(f"Entry {i*10+10}: all ports permitted")

    input_text += f"```"

    if not issues:
        issues.append(f"No explicit deny at end of ACL")
        issues.append(f"No logging on deny entries for security monitoring")

    cwe = rng.choice(["CWE-284", "CWE-732"])
    cwe_info = CWE_DB.get(cwe, {"name": "Access Control", "severity": ["medium", "high"]})

    output = f"## ACL Security Assessment\n\n"
    output += f"**ACL:** {acl_name}\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** {'HIGH' if any('any-to-any' in i for i in issues) else 'MEDIUM'}\n\n"
    output += f"### Findings\n\n"

    for i, issue in enumerate(issues, 1):
        output += f"**{i}. {issue}**\n"
        if "any-to-any" in issue:
            output += f"This entry effectively allows all traffic and should be replaced with "
            output += f"specific permit entries for required communications.\n\n"
        elif "all ports" in issue:
            output += f"Permitting all ports violates least privilege. Specify only required ports.\n\n"
        elif "deny" in issue.lower():
            output += f"While most platforms have an implicit deny, an explicit deny entry with "
            output += f"logging provides visibility into blocked traffic for security monitoring.\n\n"
        elif "logging" in issue.lower():
            output += f"Without logging on deny entries, security teams cannot monitor blocked "
            output += f"traffic for threat detection and incident response.\n\n"

    output += f"### Remediation\n"
    output += f"1. Replace overly broad entries with specific source/destination/port rules.\n"
    output += f"2. Add `deny ip any any log` as the final entry.\n"
    output += f"3. Review and remove unused or duplicate entries.\n"
    output += f"4. Document the purpose of each ACL entry.\n"
    output += f"5. Schedule quarterly ACL reviews.\n"

    return cwe, input_text, output, f"ACL Misconfigurations in {acl_name}"


# ── Scenario dispatch ──────────────────────────────────────────────────────

SCENARIO_BUILDERS = [
    (_build_firewall_scenario, 0.20),
    (_build_tls_scenario, 0.15),
    (_build_port_scan_scenario, 0.15),
    (_build_dns_scenario, 0.10),
    (_build_vpn_scenario, 0.10),
    (_build_network_segmentation_scenario, 0.10),
    (_build_traffic_anomaly_scenario, 0.10),
    (_build_acl_scenario, 0.10),
]

SCENARIO_FUNCS = [b[0] for b in SCENARIO_BUILDERS]
SCENARIO_WEIGHTS = [b[1] for b in SCENARIO_BUILDERS]


# ── Generator class ────────────────────────────────────────────────────────

class NetworkSecurityGenerator(CategoryGenerator):
    category = "network_security"
    id_prefix = "xld-net"

    def generate_entries(self, rng: random.Random, count: int, start_id: int,
                         complexity_weights: Dict[str, float]) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        idx = start_id

        for _ in range(count):
            complexity = pick_complexity(rng, complexity_weights)
            severity = pick_severity(rng, complexity)
            domain = rand_domain(rng)

            builder = rng.choices(SCENARIO_FUNCS, weights=SCENARIO_WEIGHTS, k=1)[0]
            cwe, input_text, output_text, title = builder(rng, complexity, domain)
            instruction = rng.choice(ALL_INSTRUCTIONS)

            entries.append(format_entry(
                entry_id=self.make_id(idx),
                title=title,
                severity=severity,
                cwe=cwe,
                instruction=instruction,
                input_text=input_text,
                output_text=output_text,
            ))
            idx += 1

        return entries
