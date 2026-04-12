"""
Structured reference data: CWEs, OWASP Top 10, MITRE ATT&CK, products, protocols.
Used across all category generators for realistic cross-referencing.
"""

# ── Top CWEs (100 most relevant for cybersecurity training) ──────────────────

CWE_DB = {
    "CWE-20": {"name": "Improper Input Validation", "category": "input", "owasp": "A03:2021", "severity": ["medium", "high"]},
    "CWE-22": {"name": "Path Traversal", "category": "input", "owasp": "A01:2021", "severity": ["high", "critical"]},
    "CWE-77": {"name": "Command Injection", "category": "injection", "owasp": "A03:2021", "severity": ["critical"]},
    "CWE-78": {"name": "OS Command Injection", "category": "injection", "owasp": "A03:2021", "severity": ["critical"]},
    "CWE-79": {"name": "Cross-site Scripting (XSS)", "category": "injection", "owasp": "A03:2021", "severity": ["medium", "high"]},
    "CWE-89": {"name": "SQL Injection", "category": "injection", "owasp": "A03:2021", "severity": ["high", "critical"]},
    "CWE-90": {"name": "LDAP Injection", "category": "injection", "owasp": "A03:2021", "severity": ["high"]},
    "CWE-94": {"name": "Code Injection", "category": "injection", "owasp": "A03:2021", "severity": ["critical"]},
    "CWE-95": {"name": "Eval Injection", "category": "injection", "owasp": "A03:2021", "severity": ["critical"]},
    "CWE-98": {"name": "PHP Remote File Inclusion", "category": "injection", "owasp": "A03:2021", "severity": ["critical"]},
    "CWE-113": {"name": "HTTP Response Splitting", "category": "injection", "owasp": "A03:2021", "severity": ["medium"]},
    "CWE-116": {"name": "Improper Encoding or Escaping", "category": "injection", "owasp": "A03:2021", "severity": ["medium", "high"]},
    "CWE-120": {"name": "Buffer Copy without Checking Size", "category": "memory", "owasp": "A06:2021", "severity": ["critical"]},
    "CWE-121": {"name": "Stack-based Buffer Overflow", "category": "memory", "owasp": "A06:2021", "severity": ["critical"]},
    "CWE-122": {"name": "Heap-based Buffer Overflow", "category": "memory", "owasp": "A06:2021", "severity": ["critical"]},
    "CWE-125": {"name": "Out-of-bounds Read", "category": "memory", "owasp": "A06:2021", "severity": ["medium", "high"]},
    "CWE-126": {"name": "Buffer Over-read", "category": "memory", "owasp": "A06:2021", "severity": ["medium", "high"]},
    "CWE-129": {"name": "Improper Validation of Array Index", "category": "memory", "owasp": "A06:2021", "severity": ["high"]},
    "CWE-134": {"name": "Uncontrolled Format String", "category": "memory", "owasp": "A06:2021", "severity": ["critical"]},
    "CWE-190": {"name": "Integer Overflow", "category": "memory", "owasp": "A06:2021", "severity": ["high", "critical"]},
    "CWE-191": {"name": "Integer Underflow", "category": "memory", "owasp": "A06:2021", "severity": ["high"]},
    "CWE-200": {"name": "Information Exposure", "category": "disclosure", "owasp": "A01:2021", "severity": ["low", "medium"]},
    "CWE-209": {"name": "Error Message Information Leak", "category": "disclosure", "owasp": "A01:2021", "severity": ["low", "medium"]},
    "CWE-215": {"name": "Insertion of Sensitive Information Into Debugging Code", "category": "disclosure", "owasp": "A01:2021", "severity": ["medium"]},
    "CWE-250": {"name": "Execution with Unnecessary Privileges", "category": "auth", "owasp": "A04:2021", "severity": ["medium", "high"]},
    "CWE-252": {"name": "Unchecked Return Value", "category": "logic", "owasp": "A06:2021", "severity": ["medium"]},
    "CWE-256": {"name": "Plaintext Storage of Password", "category": "crypto", "owasp": "A02:2021", "severity": ["high"]},
    "CWE-259": {"name": "Hard-coded Password", "category": "crypto", "owasp": "A02:2021", "severity": ["high", "critical"]},
    "CWE-269": {"name": "Improper Privilege Management", "category": "auth", "owasp": "A04:2021", "severity": ["high"]},
    "CWE-276": {"name": "Incorrect Default Permissions", "category": "auth", "owasp": "A01:2021", "severity": ["medium", "high"]},
    "CWE-284": {"name": "Improper Access Control", "category": "auth", "owasp": "A01:2021", "severity": ["high", "critical"]},
    "CWE-285": {"name": "Improper Authorization", "category": "auth", "owasp": "A01:2021", "severity": ["high"]},
    "CWE-287": {"name": "Improper Authentication", "category": "auth", "owasp": "A07:2021", "severity": ["high", "critical"]},
    "CWE-290": {"name": "Authentication Bypass by Spoofing", "category": "auth", "owasp": "A07:2021", "severity": ["high"]},
    "CWE-295": {"name": "Improper Certificate Validation", "category": "crypto", "owasp": "A02:2021", "severity": ["high"]},
    "CWE-306": {"name": "Missing Authentication for Critical Function", "category": "auth", "owasp": "A07:2021", "severity": ["critical"]},
    "CWE-307": {"name": "Improper Restriction of Excessive Authentication Attempts", "category": "auth", "owasp": "A07:2021", "severity": ["medium"]},
    "CWE-311": {"name": "Missing Encryption of Sensitive Data", "category": "crypto", "owasp": "A02:2021", "severity": ["high"]},
    "CWE-312": {"name": "Cleartext Storage of Sensitive Information", "category": "crypto", "owasp": "A02:2021", "severity": ["high"]},
    "CWE-319": {"name": "Cleartext Transmission of Sensitive Information", "category": "crypto", "owasp": "A02:2021", "severity": ["medium", "high"]},
    "CWE-321": {"name": "Use of Hard-coded Cryptographic Key", "category": "crypto", "owasp": "A02:2021", "severity": ["high"]},
    "CWE-326": {"name": "Inadequate Encryption Strength", "category": "crypto", "owasp": "A02:2021", "severity": ["medium", "high"]},
    "CWE-327": {"name": "Use of Broken Crypto Algorithm", "category": "crypto", "owasp": "A02:2021", "severity": ["high"]},
    "CWE-330": {"name": "Use of Insufficiently Random Values", "category": "crypto", "owasp": "A02:2021", "severity": ["medium", "high"]},
    "CWE-345": {"name": "Insufficient Verification of Data Authenticity", "category": "auth", "owasp": "A08:2021", "severity": ["medium", "high"]},
    "CWE-346": {"name": "Origin Validation Error", "category": "auth", "owasp": "A07:2021", "severity": ["medium"]},
    "CWE-347": {"name": "Improper Verification of Cryptographic Signature", "category": "crypto", "owasp": "A02:2021", "severity": ["high"]},
    "CWE-352": {"name": "Cross-Site Request Forgery (CSRF)", "category": "auth", "owasp": "A01:2021", "severity": ["medium", "high"]},
    "CWE-362": {"name": "Race Condition", "category": "logic", "owasp": "A04:2021", "severity": ["medium", "high"]},
    "CWE-369": {"name": "Divide By Zero", "category": "logic", "owasp": "A06:2021", "severity": ["low"]},
    "CWE-377": {"name": "Insecure Temporary File", "category": "logic", "owasp": "A01:2021", "severity": ["medium"]},
    "CWE-384": {"name": "Session Fixation", "category": "auth", "owasp": "A07:2021", "severity": ["medium", "high"]},
    "CWE-400": {"name": "Uncontrolled Resource Consumption", "category": "dos", "owasp": "A06:2021", "severity": ["medium", "high"]},
    "CWE-401": {"name": "Memory Leak", "category": "memory", "owasp": "A06:2021", "severity": ["medium"]},
    "CWE-416": {"name": "Use After Free", "category": "memory", "owasp": "A06:2021", "severity": ["critical"]},
    "CWE-425": {"name": "Direct Request (Forced Browsing)", "category": "auth", "owasp": "A01:2021", "severity": ["medium"]},
    "CWE-426": {"name": "Untrusted Search Path", "category": "injection", "owasp": "A06:2021", "severity": ["high"]},
    "CWE-434": {"name": "Unrestricted Upload of Dangerous File", "category": "input", "owasp": "A04:2021", "severity": ["high", "critical"]},
    "CWE-436": {"name": "Interpretation Conflict", "category": "logic", "owasp": "A06:2021", "severity": ["medium"]},
    "CWE-451": {"name": "UI Misrepresentation of Critical Information", "category": "logic", "owasp": "A06:2021", "severity": ["medium"]},
    "CWE-472": {"name": "Web Parameter Tampering", "category": "input", "owasp": "A04:2021", "severity": ["medium"]},
    "CWE-476": {"name": "NULL Pointer Dereference", "category": "memory", "owasp": "A06:2021", "severity": ["medium"]},
    "CWE-502": {"name": "Deserialization of Untrusted Data", "category": "injection", "owasp": "A08:2021", "severity": ["critical"]},
    "CWE-522": {"name": "Insufficiently Protected Credentials", "category": "crypto", "owasp": "A02:2021", "severity": ["high"]},
    "CWE-532": {"name": "Insertion of Sensitive Information into Log File", "category": "disclosure", "owasp": "A09:2021", "severity": ["medium"]},
    "CWE-538": {"name": "Insertion of Sensitive Information into Externally-Accessible File", "category": "disclosure", "owasp": "A01:2021", "severity": ["medium", "high"]},
    "CWE-548": {"name": "Exposure of Information Through Directory Listing", "category": "disclosure", "owasp": "A01:2021", "severity": ["low", "medium"]},
    "CWE-552": {"name": "Files Accessible to External Parties", "category": "disclosure", "owasp": "A01:2021", "severity": ["medium", "high"]},
    "CWE-565": {"name": "Reliance on Cookies without Validation", "category": "auth", "owasp": "A07:2021", "severity": ["medium"]},
    "CWE-601": {"name": "Open Redirect", "category": "input", "owasp": "A01:2021", "severity": ["medium"]},
    "CWE-611": {"name": "XML External Entity (XXE)", "category": "injection", "owasp": "A05:2021", "severity": ["high", "critical"]},
    "CWE-613": {"name": "Insufficient Session Expiration", "category": "auth", "owasp": "A07:2021", "severity": ["medium"]},
    "CWE-614": {"name": "Sensitive Cookie Without Secure Flag", "category": "crypto", "owasp": "A02:2021", "severity": ["low", "medium"]},
    "CWE-639": {"name": "Insecure Direct Object Reference (IDOR)", "category": "auth", "owasp": "A01:2021", "severity": ["high"]},
    "CWE-640": {"name": "Weak Password Recovery Mechanism", "category": "auth", "owasp": "A07:2021", "severity": ["medium", "high"]},
    "CWE-643": {"name": "XPath Injection", "category": "injection", "owasp": "A03:2021", "severity": ["high"]},
    "CWE-668": {"name": "Exposure of Resource to Wrong Sphere", "category": "auth", "owasp": "A01:2021", "severity": ["medium", "high"]},
    "CWE-676": {"name": "Use of Potentially Dangerous Function", "category": "memory", "owasp": "A06:2021", "severity": ["medium"]},
    "CWE-732": {"name": "Incorrect Permission Assignment", "category": "auth", "owasp": "A01:2021", "severity": ["high"]},
    "CWE-749": {"name": "Exposed Dangerous Method or Function", "category": "auth", "owasp": "A04:2021", "severity": ["high"]},
    "CWE-754": {"name": "Improper Check for Unusual Conditions", "category": "logic", "owasp": "A06:2021", "severity": ["medium"]},
    "CWE-770": {"name": "Allocation without Limits", "category": "dos", "owasp": "A06:2021", "severity": ["medium", "high"]},
    "CWE-776": {"name": "XML Entity Expansion (Billion Laughs)", "category": "dos", "owasp": "A05:2021", "severity": ["high"]},
    "CWE-787": {"name": "Out-of-bounds Write", "category": "memory", "owasp": "A06:2021", "severity": ["critical"]},
    "CWE-798": {"name": "Hard-coded Credentials", "category": "crypto", "owasp": "A07:2021", "severity": ["critical"]},
    "CWE-829": {"name": "Inclusion of Functionality from Untrusted Control Sphere", "category": "injection", "owasp": "A08:2021", "severity": ["high"]},
    "CWE-862": {"name": "Missing Authorization", "category": "auth", "owasp": "A01:2021", "severity": ["high", "critical"]},
    "CWE-863": {"name": "Incorrect Authorization", "category": "auth", "owasp": "A01:2021", "severity": ["high"]},
    "CWE-916": {"name": "Use of Password Hash With Insufficient Effort", "category": "crypto", "owasp": "A02:2021", "severity": ["high"]},
    "CWE-918": {"name": "Server-Side Request Forgery (SSRF)", "category": "injection", "owasp": "A10:2021", "severity": ["high", "critical"]},
    "CWE-922": {"name": "Insecure Storage of Sensitive Information", "category": "crypto", "owasp": "A02:2021", "severity": ["medium", "high"]},
    "CWE-923": {"name": "Improper Restriction of Communication Channel", "category": "auth", "owasp": "A07:2021", "severity": ["medium"]},
    "CWE-942": {"name": "Overly Permissive CORS Policy", "category": "auth", "owasp": "A01:2021", "severity": ["medium", "high"]},
    "CWE-1021": {"name": "Improper Restriction of Rendered UI (Clickjacking)", "category": "auth", "owasp": "A01:2021", "severity": ["medium"]},
    "CWE-1236": {"name": "CSV Injection", "category": "injection", "owasp": "A03:2021", "severity": ["medium"]},
}


# ── OWASP Top 10 (2021) ─────────────────────────────────────────────────────

OWASP_TOP10 = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery (SSRF)",
}


# ── MITRE ATT&CK Techniques (subset of ~80 most relevant) ───────────────────

MITRE_ATTACK = {
    "T1001": {"name": "Data Obfuscation", "tactic": "Command and Control"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1005": {"name": "Data from Local System", "tactic": "Collection"},
    "T1007": {"name": "System Service Discovery", "tactic": "Discovery"},
    "T1010": {"name": "Application Window Discovery", "tactic": "Discovery"},
    "T1016": {"name": "System Network Configuration Discovery", "tactic": "Discovery"},
    "T1018": {"name": "Remote System Discovery", "tactic": "Discovery"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion"},
    "T1033": {"name": "System Owner/User Discovery", "tactic": "Discovery"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},
    "T1040": {"name": "Network Sniffing", "tactic": "Credential Access"},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery"},
    "T1047": {"name": "Windows Management Instrumentation", "tactic": "Execution"},
    "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence"},
    "T1055": {"name": "Process Injection", "tactic": "Privilege Escalation"},
    "T1056": {"name": "Input Capture", "tactic": "Collection"},
    "T1057": {"name": "Process Discovery", "tactic": "Discovery"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"},
    "T1069": {"name": "Permission Groups Discovery", "tactic": "Discovery"},
    "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1072": {"name": "Software Deployment Tools", "tactic": "Lateral Movement"},
    "T1074": {"name": "Data Staged", "tactic": "Collection"},
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access"},
    "T1082": {"name": "System Information Discovery", "tactic": "Discovery"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery"},
    "T1090": {"name": "Proxy", "tactic": "Command and Control"},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence"},
    "T1102": {"name": "Web Service", "tactic": "Command and Control"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
    "T1106": {"name": "Native API", "tactic": "Execution"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1112": {"name": "Modify Registry", "tactic": "Defense Evasion"},
    "T1113": {"name": "Screen Capture", "tactic": "Collection"},
    "T1119": {"name": "Automated Collection", "tactic": "Collection"},
    "T1132": {"name": "Data Encoding", "tactic": "Command and Control"},
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access"},
    "T1134": {"name": "Access Token Manipulation", "tactic": "Privilege Escalation"},
    "T1135": {"name": "Network Share Discovery", "tactic": "Discovery"},
    "T1136": {"name": "Create Account", "tactic": "Persistence"},
    "T1140": {"name": "Deobfuscate/Decode Files or Information", "tactic": "Defense Evasion"},
    "T1176": {"name": "Browser Extensions", "tactic": "Persistence"},
    "T1185": {"name": "Browser Session Hijacking", "tactic": "Collection"},
    "T1189": {"name": "Drive-by Compromise", "tactic": "Initial Access"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1195": {"name": "Supply Chain Compromise", "tactic": "Initial Access"},
    "T1197": {"name": "BITS Jobs", "tactic": "Persistence"},
    "T1199": {"name": "Trusted Relationship", "tactic": "Initial Access"},
    "T1200": {"name": "Hardware Additions", "tactic": "Initial Access"},
    "T1201": {"name": "Password Policy Discovery", "tactic": "Discovery"},
    "T1203": {"name": "Exploitation for Client Execution", "tactic": "Execution"},
    "T1204": {"name": "User Execution", "tactic": "Execution"},
    "T1210": {"name": "Exploitation of Remote Services", "tactic": "Lateral Movement"},
    "T1211": {"name": "Exploitation for Defense Evasion", "tactic": "Defense Evasion"},
    "T1212": {"name": "Exploitation for Credential Access", "tactic": "Credential Access"},
    "T1213": {"name": "Data from Information Repositories", "tactic": "Collection"},
    "T1218": {"name": "System Binary Proxy Execution", "tactic": "Defense Evasion"},
    "T1219": {"name": "Remote Access Software", "tactic": "Command and Control"},
    "T1222": {"name": "File and Directory Permissions Modification", "tactic": "Defense Evasion"},
    "T1484": {"name": "Domain Policy Modification", "tactic": "Defense Evasion"},
    "T1485": {"name": "Data Destruction", "tactic": "Impact"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1489": {"name": "Service Stop", "tactic": "Impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1491": {"name": "Defacement", "tactic": "Impact"},
    "T1495": {"name": "Firmware Corruption", "tactic": "Impact"},
    "T1498": {"name": "Network Denial of Service", "tactic": "Impact"},
    "T1505": {"name": "Server Software Component", "tactic": "Persistence"},
    "T1518": {"name": "Software Discovery", "tactic": "Discovery"},
    "T1525": {"name": "Implant Internal Image", "tactic": "Persistence"},
    "T1530": {"name": "Data from Cloud Storage", "tactic": "Collection"},
    "T1534": {"name": "Internal Spearphishing", "tactic": "Lateral Movement"},
    "T1537": {"name": "Transfer Data to Cloud Account", "tactic": "Exfiltration"},
    "T1539": {"name": "Steal Web Session Cookie", "tactic": "Credential Access"},
    "T1543": {"name": "Create or Modify System Process", "tactic": "Persistence"},
    "T1546": {"name": "Event Triggered Execution", "tactic": "Persistence"},
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": "Lateral Movement"},
    "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access"},
    "T1553": {"name": "Subvert Trust Controls", "tactic": "Defense Evasion"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "Credential Access"},
    "T1556": {"name": "Modify Authentication Process", "tactic": "Persistence"},
    "T1557": {"name": "Adversary-in-the-Middle", "tactic": "Credential Access"},
    "T1558": {"name": "Steal or Forge Kerberos Tickets", "tactic": "Credential Access"},
    "T1559": {"name": "Inter-Process Communication", "tactic": "Execution"},
    "T1560": {"name": "Archive Collected Data", "tactic": "Collection"},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion"},
    "T1563": {"name": "Remote Service Session Hijacking", "tactic": "Lateral Movement"},
    "T1564": {"name": "Hide Artifacts", "tactic": "Defense Evasion"},
    "T1565": {"name": "Data Manipulation", "tactic": "Impact"},
    "T1566": {"name": "Phishing", "tactic": "Initial Access"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    "T1568": {"name": "Dynamic Resolution", "tactic": "Command and Control"},
    "T1569": {"name": "System Services", "tactic": "Execution"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement"},
    "T1571": {"name": "Non-Standard Port", "tactic": "Command and Control"},
    "T1572": {"name": "Protocol Tunneling", "tactic": "Command and Control"},
    "T1573": {"name": "Encrypted Channel", "tactic": "Command and Control"},
    "T1574": {"name": "Hijack Execution Flow", "tactic": "Persistence"},
    "T1578": {"name": "Modify Cloud Compute Infrastructure", "tactic": "Defense Evasion"},
    "T1580": {"name": "Cloud Infrastructure Discovery", "tactic": "Discovery"},
    "T1583": {"name": "Acquire Infrastructure", "tactic": "Resource Development"},
    "T1585": {"name": "Establish Accounts", "tactic": "Resource Development"},
    "T1586": {"name": "Compromise Accounts", "tactic": "Resource Development"},
    "T1588": {"name": "Obtain Capabilities", "tactic": "Resource Development"},
    "T1589": {"name": "Gather Victim Identity Information", "tactic": "Reconnaissance"},
    "T1590": {"name": "Gather Victim Network Information", "tactic": "Reconnaissance"},
    "T1591": {"name": "Gather Victim Org Information", "tactic": "Reconnaissance"},
    "T1592": {"name": "Gather Victim Host Information", "tactic": "Reconnaissance"},
    "T1595": {"name": "Active Scanning", "tactic": "Reconnaissance"},
    "T1598": {"name": "Phishing for Information", "tactic": "Reconnaissance"},
}


# ── Products and technologies for realistic CVE generation ───────────────────

PRODUCTS = [
    {"name": "Apache HTTP Server", "vendor": "Apache", "versions": ["2.4.49", "2.4.50", "2.4.51", "2.4.52", "2.4.53", "2.4.54"],
     "common_vulns": ["CWE-22", "CWE-79", "CWE-400", "CWE-787"]},
    {"name": "Apache Tomcat", "vendor": "Apache", "versions": ["9.0.50", "9.0.55", "9.0.60", "10.0.10", "10.0.20", "10.1.0"],
     "common_vulns": ["CWE-200", "CWE-400", "CWE-502", "CWE-22"]},
    {"name": "nginx", "vendor": "F5", "versions": ["1.20.0", "1.20.1", "1.21.0", "1.22.0", "1.23.0", "1.24.0"],
     "common_vulns": ["CWE-787", "CWE-400", "CWE-125", "CWE-22"]},
    {"name": "OpenSSL", "vendor": "OpenSSL Project", "versions": ["1.1.1k", "1.1.1l", "1.1.1m", "3.0.0", "3.0.1", "3.0.2"],
     "common_vulns": ["CWE-120", "CWE-787", "CWE-190", "CWE-476"]},
    {"name": "Node.js", "vendor": "OpenJS Foundation", "versions": ["14.18.0", "16.13.0", "18.0.0", "18.12.0", "20.0.0", "20.5.0"],
     "common_vulns": ["CWE-94", "CWE-78", "CWE-400", "CWE-22"]},
    {"name": "Django", "vendor": "Django Software Foundation", "versions": ["3.2.10", "3.2.15", "4.0.0", "4.0.5", "4.1.0", "4.2.0"],
     "common_vulns": ["CWE-89", "CWE-79", "CWE-352", "CWE-22"]},
    {"name": "Spring Framework", "vendor": "VMware", "versions": ["5.3.15", "5.3.18", "5.3.20", "6.0.0", "6.0.5", "6.0.10"],
     "common_vulns": ["CWE-94", "CWE-917", "CWE-502", "CWE-22"]},
    {"name": "WordPress", "vendor": "WordPress.org", "versions": ["5.8", "5.9", "6.0", "6.1", "6.2", "6.3"],
     "common_vulns": ["CWE-79", "CWE-89", "CWE-434", "CWE-352"]},
    {"name": "PostgreSQL", "vendor": "PostgreSQL Global Dev Group", "versions": ["13.5", "13.8", "14.0", "14.5", "15.0", "15.3"],
     "common_vulns": ["CWE-89", "CWE-269", "CWE-200", "CWE-284"]},
    {"name": "MySQL", "vendor": "Oracle", "versions": ["8.0.26", "8.0.28", "8.0.30", "8.0.32", "8.0.33", "8.0.34"],
     "common_vulns": ["CWE-89", "CWE-284", "CWE-200", "CWE-120"]},
    {"name": "Redis", "vendor": "Redis Ltd", "versions": ["6.2.6", "6.2.8", "7.0.0", "7.0.4", "7.0.8", "7.2.0"],
     "common_vulns": ["CWE-78", "CWE-120", "CWE-190", "CWE-306"]},
    {"name": "Elasticsearch", "vendor": "Elastic", "versions": ["7.16.0", "7.17.0", "8.0.0", "8.3.0", "8.6.0", "8.8.0"],
     "common_vulns": ["CWE-94", "CWE-200", "CWE-284", "CWE-611"]},
    {"name": "Docker", "vendor": "Docker Inc", "versions": ["20.10.12", "20.10.17", "20.10.21", "23.0.0", "23.0.6", "24.0.0"],
     "common_vulns": ["CWE-269", "CWE-284", "CWE-22", "CWE-668"]},
    {"name": "Kubernetes", "vendor": "CNCF", "versions": ["1.23.0", "1.24.0", "1.25.0", "1.26.0", "1.27.0", "1.28.0"],
     "common_vulns": ["CWE-284", "CWE-269", "CWE-200", "CWE-862"]},
    {"name": "GitLab", "vendor": "GitLab Inc", "versions": ["14.8", "14.10", "15.0", "15.5", "15.10", "16.0"],
     "common_vulns": ["CWE-79", "CWE-918", "CWE-22", "CWE-284"]},
    {"name": "Jenkins", "vendor": "Jenkins Project", "versions": ["2.319", "2.332", "2.346", "2.361", "2.375", "2.401"],
     "common_vulns": ["CWE-79", "CWE-352", "CWE-94", "CWE-502"]},
    {"name": "Grafana", "vendor": "Grafana Labs", "versions": ["8.3.0", "8.5.0", "9.0.0", "9.3.0", "9.5.0", "10.0.0"],
     "common_vulns": ["CWE-22", "CWE-284", "CWE-918", "CWE-639"]},
    {"name": "HashiCorp Vault", "vendor": "HashiCorp", "versions": ["1.9.0", "1.10.0", "1.11.0", "1.12.0", "1.13.0", "1.14.0"],
     "common_vulns": ["CWE-284", "CWE-287", "CWE-200", "CWE-269"]},
    {"name": "MongoDB", "vendor": "MongoDB Inc", "versions": ["5.0.5", "5.0.10", "6.0.0", "6.0.5", "6.0.8", "7.0.0"],
     "common_vulns": ["CWE-89", "CWE-284", "CWE-200", "CWE-94"]},
    {"name": "RabbitMQ", "vendor": "VMware", "versions": ["3.9.0", "3.9.15", "3.10.0", "3.10.10", "3.11.0", "3.12.0"],
     "common_vulns": ["CWE-284", "CWE-79", "CWE-400", "CWE-306"]},
]


# ── Network protocols ────────────────────────────────────────────────────────

PROTOCOLS = [
    "HTTP", "HTTPS", "DNS", "SSH", "FTP", "SFTP", "SMTP", "IMAP", "POP3",
    "LDAP", "LDAPS", "SMB", "RDP", "VNC", "Telnet", "SNMP", "NTP", "DHCP",
    "BGP", "OSPF", "TLS", "IPSec", "WireGuard", "OpenVPN", "Kerberos",
    "RADIUS", "TACACS+", "SIP", "MQTT", "AMQP", "gRPC", "WebSocket",
]


# ── Cloud services for misconfig scenarios ───────────────────────────────────

CLOUD_SERVICES = {
    "aws": [
        {"service": "S3", "misconfigs": ["public bucket", "missing encryption", "no versioning", "overly permissive bucket policy"]},
        {"service": "IAM", "misconfigs": ["wildcard permissions", "no MFA", "long-lived access keys", "overly permissive role"]},
        {"service": "EC2", "misconfigs": ["open security group", "public IP on internal instance", "unencrypted EBS", "IMDSv1 enabled"]},
        {"service": "Lambda", "misconfigs": ["overly permissive execution role", "env var secrets", "public function URL", "no VPC"]},
        {"service": "RDS", "misconfigs": ["public accessibility", "no encryption at rest", "default credentials", "no audit logging"]},
        {"service": "SQS", "misconfigs": ["public queue policy", "no encryption", "no dead-letter queue", "overly permissive access"]},
        {"service": "EKS", "misconfigs": ["public API endpoint", "default service account", "no network policies", "privileged pods"]},
        {"service": "CloudFront", "misconfigs": ["HTTP allowed", "no WAF", "permissive CORS", "origin access identity missing"]},
    ],
    "azure": [
        {"service": "Blob Storage", "misconfigs": ["public container", "no encryption", "shared access signatures with no expiry"]},
        {"service": "Active Directory", "misconfigs": ["guest access enabled", "no conditional access", "legacy auth protocols"]},
        {"service": "Virtual Machines", "misconfigs": ["open NSG rules", "public IP", "no disk encryption", "password auth enabled"]},
        {"service": "Key Vault", "misconfigs": ["overly permissive access policies", "no soft delete", "no purge protection"]},
        {"service": "AKS", "misconfigs": ["public API", "default namespace", "no pod security", "no network policies"]},
    ],
    "gcp": [
        {"service": "Cloud Storage", "misconfigs": ["allUsers access", "no uniform bucket-level access", "no retention policy"]},
        {"service": "IAM", "misconfigs": ["primitive roles used", "service account key exposed", "domain-wide delegation"]},
        {"service": "Compute Engine", "misconfigs": ["default service account", "public IP", "no shielded VM", "serial port enabled"]},
        {"service": "GKE", "misconfigs": ["legacy ABAC", "public endpoint", "default node service account", "no workload identity"]},
        {"service": "Cloud Functions", "misconfigs": ["allUsers invoker", "env var secrets", "no VPC connector"]},
    ],
}


# ── Application contexts for realistic scenarios ─────────────────────────────

APP_CONTEXTS = [
    "e-commerce platform", "healthcare records system", "online banking application",
    "social media platform", "HR management system", "IoT device management portal",
    "CI/CD pipeline dashboard", "customer support ticketing system", "payment processing gateway",
    "file sharing service", "project management tool", "video conferencing application",
    "email marketing platform", "inventory management system", "travel booking platform",
    "food delivery application", "real estate listing portal", "education/LMS platform",
    "government services portal", "cryptocurrency exchange", "ride-sharing application",
    "insurance claims portal", "supply chain management system", "telemedicine platform",
]


# ── Common frameworks by language ────────────────────────────────────────────

FRAMEWORKS = {
    "python": ["Django", "Flask", "FastAPI", "Tornado", "aiohttp"],
    "javascript": ["Express.js", "Koa", "Fastify", "Next.js", "Nest.js"],
    "java": ["Spring Boot", "Jakarta EE", "Micronaut", "Quarkus", "Play"],
    "csharp": ["ASP.NET Core", "ASP.NET MVC", "Blazor"],
    "go": ["Gin", "Echo", "Fiber", "Chi", "net/http"],
    "php": ["Laravel", "Symfony", "CodeIgniter", "Slim"],
    "ruby": ["Rails", "Sinatra", "Hanami"],
    "rust": ["Actix-web", "Rocket", "Axum", "Warp"],
}


# ── Helper functions ─────────────────────────────────────────────────────────

def get_cwe(cwe_id: str) -> dict:
    """Get CWE info by ID, returns empty dict if not found."""
    return CWE_DB.get(cwe_id, {})


def get_cwe_by_category(category: str) -> list:
    """Get all CWE IDs matching a category."""
    return [k for k, v in CWE_DB.items() if v["category"] == category]


def get_attack_technique(technique_id: str) -> dict:
    """Get MITRE ATT&CK technique info."""
    return MITRE_ATTACK.get(technique_id, {})


def get_techniques_by_tactic(tactic: str) -> list:
    """Get all technique IDs for a given tactic."""
    return [k for k, v in MITRE_ATTACK.items() if v["tactic"] == tactic]
