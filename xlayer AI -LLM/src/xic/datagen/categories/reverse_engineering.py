"""
Reverse Engineering generator (DEFENSIVE focus).
Produces entries about binary analysis, disassembly interpretation, malware
analysis methodology, and protocol reverse engineering for defensive purposes.
NEVER includes content that teaches creating malware.
"""

import random
from typing import List, Dict, Any
from ..templates import CategoryGenerator, pick_complexity, pick_severity, format_entry, rand_ip, rand_domain, rand_port, rand_var_name, rand_func_name, rand_table_name, rand_path
from ..knowledge_base import CWE_DB, OWASP_TOP10, MITRE_ATTACK, APP_CONTEXTS, PRODUCTS, CLOUD_SERVICES, FRAMEWORKS, PROTOCOLS


# ── Instruction pools ──────────────────────────────────────────────────────────

BINARY_ANALYSIS_INSTRUCTIONS = [
    "Analyze the following binary analysis scenario. Describe the methodology for examining this binary for defensive security purposes.",
    "As a security researcher, explain how to approach the analysis of this binary sample. Focus on identifying indicators of compromise (IOCs) and understanding its behavior.",
    "Describe the defensive reverse engineering methodology for the following binary. Explain what tools and techniques a malware analyst would use.",
    "Provide a structured analysis approach for examining this binary. Focus on safe analysis practices and extraction of threat intelligence.",
    "Explain the reverse engineering workflow for analyzing this sample in a sandboxed environment. What behavioral and static indicators should an analyst look for?",
]

DISASSEMBLY_INSTRUCTIONS = [
    "Interpret the following disassembly snippet. Explain what the code does and identify any security-relevant behavior patterns.",
    "Analyze this assembly code fragment from a security perspective. Describe the operations being performed and any suspicious patterns.",
    "As a reverse engineer, explain the functionality shown in this disassembly. Identify API calls, control flow patterns, and potential indicators of malicious behavior.",
    "Review this disassembly listing and describe the program logic. Focus on identifying techniques that are commonly used in malware.",
    "Explain the behavior of the following assembly code. Map any observed techniques to MITRE ATT&CK where applicable.",
]

CONTROL_FLOW_INSTRUCTIONS = [
    "Analyze the control flow graph described below. Identify obfuscation techniques, anti-analysis patterns, and the true program logic.",
    "Examine the following control flow patterns for signs of code obfuscation or anti-debugging techniques. Explain what the original logic likely does.",
    "Review the described control flow for defensive analysis. Identify branching patterns that indicate evasion, packing, or anti-analysis behavior.",
]

STRING_ANALYSIS_INSTRUCTIONS = [
    "Analyze the following strings extracted from a binary sample. Categorize them by type (URLs, file paths, registry keys, API names) and assess their significance.",
    "Review the string artifacts from this binary. Identify indicators of compromise (IOCs), potential C2 infrastructure, and behavioral clues.",
    "As a threat analyst, examine the extracted strings and determine what capabilities and behaviors they suggest about the binary.",
]

API_TRACING_INSTRUCTIONS = [
    "Analyze the following API call trace from a sandboxed execution. Identify the sequence of operations and map them to potential malicious behaviors.",
    "Review this Windows API call log from dynamic analysis. Explain what the program is doing and identify any suspicious behavior patterns.",
    "Examine the system call trace below and determine the program's behavior. Map observed API sequences to MITRE ATT&CK techniques.",
]

PROTOCOL_RE_INSTRUCTIONS = [
    "Analyze the following captured network traffic patterns for protocol reverse engineering. Identify the communication structure, encoding, and any security concerns.",
    "Examine this network protocol exchange captured during dynamic analysis. Describe the protocol structure, identify authentication/encryption mechanisms, and note security weaknesses.",
]

FIRMWARE_INSTRUCTIONS = [
    "Describe the methodology for analyzing the following firmware image for security vulnerabilities. What tools and techniques would you use?",
    "Analyze the described firmware configuration for security issues. Focus on identifying hardcoded credentials, insecure update mechanisms, and exposed interfaces.",
    "Review the following firmware analysis scenario. Explain the approach for extracting and examining the filesystem, identifying services, and finding vulnerabilities.",
]

MALWARE_METHODOLOGY_INSTRUCTIONS = [
    "Describe the safe malware analysis methodology for the following sample type. Cover static analysis, dynamic analysis, and reporting phases.",
    "As a malware analyst, outline the analysis workflow for examining this sample. Include environment setup, analysis steps, and IOC extraction.",
    "Explain the defensive analysis approach for understanding this type of threat. Cover triage, behavioral analysis, and threat intelligence generation.",
]

ALL_INSTRUCTIONS = (
    BINARY_ANALYSIS_INSTRUCTIONS + DISASSEMBLY_INSTRUCTIONS +
    CONTROL_FLOW_INSTRUCTIONS + STRING_ANALYSIS_INSTRUCTIONS +
    API_TRACING_INSTRUCTIONS + PROTOCOL_RE_INSTRUCTIONS +
    FIRMWARE_INSTRUCTIONS + MALWARE_METHODOLOGY_INSTRUCTIONS
)

# ── Scenario templates ─────────────────────────────────────────────────────────

BINARY_TYPES = [
    "Windows PE executable (.exe)", "Windows DLL (.dll)", "Linux ELF executable",
    "macOS Mach-O binary", "Android APK package", "iOS application binary",
    "Windows service executable", "Browser extension (CRX/XPI)", "Java JAR archive",
    ".NET assembly (managed code)", "Python compiled bytecode (.pyc)",
    "Go compiled binary", "Rust compiled binary",
]

SAMPLE_CATEGORIES = [
    "Trojan dropper", "Ransomware sample", "Information stealer",
    "Remote Access Tool (RAT)", "Cryptominer", "Adware/PUP",
    "Banking trojan", "Botnet agent", "Rootkit",
    "Wiper malware", "Keylogger", "Backdoor",
]

ANALYSIS_TOOLS = [
    ("IDA Pro / Ghidra", "Interactive disassembler for static analysis"),
    ("x64dbg / OllyDbg", "Dynamic debugger for runtime analysis"),
    ("Process Monitor", "System call and file/registry activity monitor"),
    ("Wireshark / tcpdump", "Network traffic capture and analysis"),
    ("YARA", "Pattern matching for malware classification"),
    ("Cuckoo Sandbox / ANY.RUN", "Automated sandbox for behavioral analysis"),
    ("PE-bear / CFF Explorer", "PE file structure analysis"),
    ("Volatility", "Memory forensics framework"),
    ("Binwalk", "Firmware analysis and extraction tool"),
    ("strings / FLOSS", "String extraction including obfuscated strings"),
    ("Detect It Easy (DIE)", "Packer and compiler detection"),
    ("Radare2 / Cutter", "Open-source reverse engineering framework"),
]

EVASION_TECHNIQUES = [
    ("Anti-VM detection", "Checks for VM artifacts (registry keys, MAC addresses, device drivers) to avoid sandbox analysis"),
    ("Anti-debugging", "Uses IsDebuggerPresent, NtQueryInformationProcess, or timing checks to detect debuggers"),
    ("Process hollowing", "Creates a suspended legitimate process and replaces its memory with malicious code"),
    ("DLL side-loading", "Places a malicious DLL in the search path of a legitimate application to get loaded"),
    ("String obfuscation", "Encodes or encrypts strings at compile time and decodes them at runtime to evade static detection"),
    ("API hashing", "Resolves API functions by hash at runtime instead of using import table entries"),
    ("Code injection", "Injects code into a running legitimate process to execute in its context"),
    ("Timestomping", "Modifies file timestamps to blend in with legitimate system files"),
    ("UPX / custom packing", "Compresses or encrypts the binary to hide its true contents from static analysis"),
    ("Environment keying", "Only executes payload when specific environment conditions are met (hostname, domain, locale)"),
]

DISASM_SNIPPETS = [
    {
        "name": "Anti-debugging check via PEB",
        "code": """mov eax, dword ptr fs:[0x30]    ; Access Process Environment Block (PEB)
movzx eax, byte ptr [eax+0x02]  ; Read BeingDebugged flag at PEB+0x02
test eax, eax                    ; Check if flag is set
jnz detected                     ; Jump if debugger is detected
; ... normal execution continues ...
detected:
    xor eax, eax                 ; Clear registers
    push 0
    call ExitProcess             ; Terminate if debugger found""",
        "explanation": "This code reads the BeingDebugged flag from the Process Environment Block (PEB) "
                      "structure. The PEB is accessed via the Thread Environment Block (TEB) at fs:[0x30] on "
                      "32-bit Windows. If the BeingDebugged byte (offset 0x02) is non-zero, the program "
                      "detects a debugger and terminates via ExitProcess. This is one of the simplest "
                      "anti-debugging techniques.",
        "technique": "T1622",
        "category": "anti-debug",
    },
    {
        "name": "Dynamic API resolution via hash",
        "code": """push ebx                        ; Save registers
mov esi, [ebp+8]                ; Pointer to module base
mov eax, [esi+0x3C]             ; e_lfanew - PE header offset
mov edx, [esi+eax+0x78]        ; Export directory RVA
add edx, esi                    ; Export directory VA
mov ecx, [edx+0x18]            ; Number of exported names
mov ebx, [edx+0x20]            ; AddressOfNames RVA
add ebx, esi                    ; AddressOfNames VA
hash_loop:
    dec ecx
    mov eax, [ebx+ecx*4]       ; Get name RVA
    add eax, esi                ; Get name VA
    call compute_hash           ; Hash the function name
    cmp eax, [ebp+0xC]         ; Compare with target hash
    jnz hash_loop               ; Continue if no match
; ... resolve function address ...""",
        "explanation": "This code walks the PE export table to resolve API functions by hash rather "
                      "than by name. It accesses the module's export directory, iterates through exported "
                      "function names, computes a hash of each name, and compares it against a target hash "
                      "value. This technique avoids placing API names in the import table, making static "
                      "analysis more difficult. Analysts can identify the hashing algorithm and pre-compute "
                      "hashes to determine which APIs are being resolved.",
        "technique": "T1027",
        "category": "obfuscation",
    },
    {
        "name": "File system enumeration",
        "code": """lea ecx, [ebp-0x140]            ; Buffer for WIN32_FIND_DATA
push ecx                         ; lpFindFileData
push offset search_pattern       ; "C:\\Users\\*.*"
call FindFirstFileW              ; Start file enumeration
mov [ebp-0x04], eax              ; Save search handle
test eax, eax
jz done
enum_loop:
    lea eax, [ebp-0x140]
    ; Check if directory
    test dword ptr [eax], 0x10   ; FILE_ATTRIBUTE_DIRECTORY
    jnz skip_file
    ; Process file...
    call process_file
skip_file:
    lea ecx, [ebp-0x140]
    push ecx
    push [ebp-0x04]
    call FindNextFileW
    test eax, eax
    jnz enum_loop
done:""",
        "explanation": "This code uses FindFirstFileW/FindNextFileW to enumerate files in the "
                      "C:\\Users directory. It iterates through directory entries, checking the "
                      "FILE_ATTRIBUTE_DIRECTORY flag to distinguish files from directories. The "
                      "'process_file' function is called for each file found. This pattern is commonly "
                      "seen in information stealers that search for documents, credentials, or "
                      "cryptocurrency wallets, as well as in ransomware that enumerates files for encryption.",
        "technique": "T1083",
        "category": "collection",
    },
    {
        "name": "Registry persistence",
        "code": """push 0                           ; Reserved
push KEY_SET_VALUE               ; samDesired
push 0                           ; ulOptions
lea eax, [ebp-0x08]
push eax                         ; phkResult
push offset run_key              ; "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
push HKEY_CURRENT_USER           ; hKey
call RegOpenKeyExW
test eax, eax
jnz error
push path_len                    ; cbData
push offset exe_path             ; lpData (path to executable)
push REG_SZ                      ; dwType
push offset value_name           ; lpValueName ("WindowsUpdate")
push [ebp-0x08]                  ; hKey handle
call RegSetValueExW""",
        "explanation": "This code opens the HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run "
                      "registry key and sets a new value to establish persistence. The value name is "
                      "disguised as 'WindowsUpdate' and points to the malware executable path. This is "
                      "one of the most common persistence mechanisms: programs listed in this Run key "
                      "are automatically executed when the user logs in. Defenders should monitor this "
                      "key for unauthorized changes.",
        "technique": "T1547",
        "category": "persistence",
    },
]

STRING_ARTIFACT_SETS = [
    {
        "name": "C2 communication indicators",
        "strings": [
            "hxxps://update-service[.]example[.]com/api/check",
            "hxxps://cdn-static[.]example[.]net/config.json",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "POST /gate.php HTTP/1.1",
            "Content-Type: application/x-www-form-urlencoded",
            "cmd=beacon&id=%s&ver=%s",
            "Base64EncodedPayload==",
        ],
        "analysis": "URLs suggest command-and-control infrastructure. The custom User-Agent string "
                   "mimics a legitimate browser for evasion. The '/gate.php' endpoint with "
                   "parameterized POST data indicates a structured C2 protocol. The 'cmd=beacon' "
                   "pattern suggests periodic check-in behavior.",
    },
    {
        "name": "Information stealer indicators",
        "strings": [
            "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
            "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\",
            "SELECT origin_url, username_value, password_value FROM logins",
            "wallet.dat", "*.kdbx",
            "\\AppData\\Roaming\\Telegram Desktop\\tdata\\",
            "\\AppData\\Local\\Microsoft\\Outlook\\",
            "\\Desktop\\", "\\Documents\\", "*.pdf", "*.docx", "*.xlsx",
        ],
        "analysis": "Paths reference browser credential storage locations for Chrome and Firefox. "
                   "The SQL query targets Chrome's Login Data SQLite database. References to "
                   "wallet.dat (cryptocurrency), .kdbx (KeePass), Telegram, and Outlook indicate "
                   "broad credential and data theft capabilities. Document extension patterns "
                   "suggest document exfiltration.",
    },
    {
        "name": "Ransomware indicators",
        "strings": [
            "Your files have been encrypted",
            ".locked", ".encrypted", ".crypt",
            "RSA-2048", "AES-256",
            "DECRYPT_INSTRUCTIONS.txt",
            "bitcoin:", "bc1q",
            "DO NOT attempt to decrypt files yourself",
            "shadow copy", "vssadmin delete shadows",
            "bcdedit /set {default} recoveryenabled No",
        ],
        "analysis": "File extension patterns and ransom note text are clear ransomware indicators. "
                   "References to RSA-2048 and AES-256 describe the encryption scheme (hybrid "
                   "encryption). Bitcoin addresses indicate cryptocurrency payment demands. "
                   "Commands targeting Volume Shadow Copies (vssadmin) and Windows recovery "
                   "(bcdedit) indicate anti-recovery measures to prevent file restoration.",
    },
    {
        "name": "System reconnaissance indicators",
        "strings": [
            "cmd.exe /c systeminfo", "cmd.exe /c ipconfig /all",
            "cmd.exe /c net user", "cmd.exe /c net localgroup administrators",
            "cmd.exe /c tasklist", "cmd.exe /c wmic process list brief",
            "cmd.exe /c netstat -an", "cmd.exe /c arp -a",
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "HARDWARE\\DESCRIPTION\\System\\CentralProcessor",
        ],
        "analysis": "Shell commands for system enumeration reveal reconnaissance behavior. The "
                   "commands gather system configuration (systeminfo), network info (ipconfig, "
                   "netstat, arp), user accounts (net user, net localgroup), and running processes "
                   "(tasklist, wmic). Registry paths target OS version and hardware information. "
                   "This pattern is typical of the initial reconnaissance phase after successful "
                   "compromise.",
    },
]

API_TRACE_SCENARIOS = [
    {
        "name": "Process injection via CreateRemoteThread",
        "trace": [
            "OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1234) -> 0x00000068",
            "VirtualAllocEx(0x68, NULL, 4096, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE) -> 0x00890000",
            "WriteProcessMemory(0x68, 0x00890000, <shellcode>, 287, NULL) -> TRUE",
            "CreateRemoteThread(0x68, NULL, 0, 0x00890000, NULL, 0, NULL) -> 0x0000009C",
            "CloseHandle(0x68) -> TRUE",
        ],
        "analysis": "This API sequence shows classic process injection via CreateRemoteThread. "
                   "The program opens a target process with full access rights, allocates "
                   "executable memory in the remote process, writes shellcode into it, and "
                   "creates a remote thread to execute the injected code. This technique allows "
                   "the injected code to run in the context of a legitimate process, evading "
                   "process-level security controls.",
        "technique": "T1055",
        "mitre_name": "Process Injection",
    },
    {
        "name": "Credential access via LSASS",
        "trace": [
            "OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, FALSE, <lsass_pid>) -> 0x000000A4",
            "NtQueryInformationProcess(0xA4, ProcessBasicInformation, ...) -> STATUS_SUCCESS",
            "ReadProcessMemory(0xA4, 0x7FFE0000, ..., 4096, ...) -> TRUE",
            "ReadProcessMemory(0xA4, <wdigest_addr>, ..., 2048, ...) -> TRUE",
            "ReadProcessMemory(0xA4, <kerberos_addr>, ..., 4096, ...) -> TRUE",
            "CloseHandle(0xA4) -> TRUE",
        ],
        "analysis": "This trace shows memory reading from the LSASS (Local Security Authority "
                   "Subsystem Service) process. LSASS stores credentials in memory for SSO "
                   "purposes. The reads target specific offsets corresponding to the WDigest "
                   "and Kerberos authentication providers. This is the technique used by tools "
                   "like Mimikatz to extract plaintext passwords and Kerberos tickets from memory.",
        "technique": "T1003",
        "mitre_name": "OS Credential Dumping",
    },
    {
        "name": "File encryption sequence",
        "trace": [
            "FindFirstFileW(L\"C:\\Users\\*.*\", ...) -> 0x000000B0",
            "GetFileAttributesW(L\"C:\\Users\\user\\Documents\\report.docx\") -> FILE_ATTRIBUTE_NORMAL",
            "CreateFileW(L\"report.docx\", GENERIC_READ|GENERIC_WRITE, ...) -> 0x000000C4",
            "ReadFile(0xC4, buffer, 4096, ...) -> TRUE",
            "CryptGenKey(hProv, CALG_AES_256, CRYPT_EXPORTABLE, ...) -> TRUE",
            "CryptEncrypt(hKey, 0, TRUE, 0, buffer, ...) -> TRUE",
            "WriteFile(0xC4, encrypted_buffer, ...) -> TRUE",
            "MoveFileW(L\"report.docx\", L\"report.docx.locked\") -> TRUE",
            "FindNextFileW(0xB0, ...) -> TRUE",
        ],
        "analysis": "This API sequence shows ransomware file encryption behavior. The program "
                   "enumerates files in the Users directory, reads each file, generates an "
                   "AES-256 key using CryptoAPI, encrypts the file contents, writes the encrypted "
                   "data back, and renames the file with a '.locked' extension. The use of "
                   "CRYPT_EXPORTABLE flag suggests the symmetric key will be encrypted with an "
                   "asymmetric key and sent to the attacker for ransom.",
        "technique": "T1486",
        "mitre_name": "Data Encrypted for Impact",
    },
]

FIRMWARE_SCENARIOS = [
    {
        "name": "IoT device firmware analysis",
        "description": "A firmware image (16MB) from a consumer IoT device (smart camera) has been "
                      "obtained for security analysis. The device runs an embedded Linux distribution "
                      "and exposes a web interface on port 80 and a telnet service on port 23.",
        "findings": [
            "Firmware uses SquashFS filesystem - extractable with binwalk/unsquashfs",
            "BusyBox v1.24.1 with telnetd enabled by default",
            "Web server running lighttpd with CGI scripts for device management",
            "Hardcoded root password hash in /etc/shadow: root:$1$abc:...: (MD5crypt)",
            "SSL certificate with private key embedded in firmware image",
            "Update mechanism uses HTTP (not HTTPS) with no signature verification",
            "UPnP service enabled with no authentication required",
            "Debug serial console (UART) accessible on PCB test points",
        ],
    },
    {
        "name": "Router firmware security review",
        "description": "A firmware image from a SOHO router has been provided for security audit. "
                      "The device runs a customized OpenWrt derivative with a proprietary web "
                      "management interface and supports remote management.",
        "findings": [
            "Firmware based on OpenWrt 19.07 (outdated, multiple known CVEs)",
            "Custom CGI scripts written in C with buffer overflow vulnerabilities",
            "DNS service (dnsmasq) configured with DHCP and DNS rebinding not blocked",
            "Remote management enabled on WAN interface by default",
            "Hardcoded API key for cloud management service in binary",
            "Firmware update mechanism verifies MD5 checksum only (no cryptographic signature)",
            "JTAG debugging interface accessible without hardware modification",
            "Default Wi-Fi password derived from last 6 characters of MAC address",
        ],
    },
]


def _generate_binary_analysis_entry(rng, complexity, idx, prefix):
    """Generate a binary analysis methodology entry."""
    severity = pick_severity(rng, complexity)
    binary_type = rng.choice(BINARY_TYPES)
    sample_cat = rng.choice(SAMPLE_CATEGORIES)
    tools = rng.sample(ANALYSIS_TOOLS, rng.randint(4, 7))
    evasions = rng.sample(EVASION_TECHNIQUES, rng.randint(2, 5))

    file_hash = ''.join(rng.choices('0123456789abcdef', k=64))
    file_size = rng.randint(50, 5000)

    input_text = f"**Sample Information:**\n"
    input_text += f"- Type: {binary_type}\n"
    input_text += f"- Suspected category: {sample_cat}\n"
    input_text += f"- SHA-256: {file_hash}\n"
    input_text += f"- File size: {file_size} KB\n"
    input_text += f"- Source: Captured from incident response on a {rng.choice(APP_CONTEXTS)}\n\n"
    input_text += "**Task:** Describe the analysis methodology for this sample.\n"

    output = f"## Binary Analysis Methodology: {sample_cat}\n\n"
    output += f"**Sample Type:** {binary_type}\n"
    output += f"**SHA-256:** {file_hash}\n\n"

    output += "### Phase 1: Environment Setup\n\n"
    output += "1. **Isolated analysis environment:** Use a dedicated VM with snapshots, "
    output += "network-isolated from production systems\n"
    output += "2. **Tool preparation:** Ensure all analysis tools are up to date and configured\n"
    output += "3. **Network simulation:** Configure FakeNet-NG or INetSim to simulate internet services\n"
    output += "4. **Snapshot:** Take a clean VM snapshot before introducing the sample\n\n"

    output += "### Phase 2: Static Analysis\n\n"
    output += "**Recommended Tools:**\n"
    for tool_name, tool_desc in tools[:4]:
        output += f"- **{tool_name}:** {tool_desc}\n"
    output += "\n"

    output += "**Static Analysis Steps:**\n"
    output += "1. Compute file hashes (MD5, SHA-1, SHA-256) and check against threat intelligence databases\n"
    output += "2. Identify file type, compiler, packer, and entropy analysis using DIE/PEiD\n"
    output += "3. Extract strings (both ASCII/Unicode and obfuscated) using FLOSS\n"
    output += "4. Analyze PE/ELF headers, imports, exports, and sections\n"
    output += "5. Scan with YARA rules for known malware family signatures\n"

    if complexity in ("advanced", "expert"):
        output += "6. Disassemble and decompile critical functions in Ghidra/IDA\n"
        output += "7. Identify cryptographic constants and algorithms\n"
        output += "8. Map imported APIs to potential MITRE ATT&CK techniques\n"
    output += "\n"

    output += "### Phase 3: Dynamic Analysis\n\n"
    output += "1. Execute sample in sandboxed environment with monitoring enabled\n"
    output += "2. Capture filesystem changes (created, modified, deleted files)\n"
    output += "3. Record registry modifications (Windows) or config file changes (Linux)\n"
    output += "4. Log network connections and DNS queries\n"
    output += "5. Monitor process creation and injection activities\n"
    output += "6. Capture memory dumps for analysis with Volatility\n\n"

    if evasions:
        output += "### Evasion Techniques to Watch For\n\n"
        for tech_name, tech_desc in evasions:
            output += f"- **{tech_name}:** {tech_desc}\n"
        output += "\n"

    output += "### Phase 4: Reporting\n\n"
    output += "1. Document all IOCs: file hashes, network indicators, file paths, registry keys\n"
    output += "2. Map behaviors to MITRE ATT&CK framework\n"
    output += "3. Generate YARA signatures for detection\n"
    output += "4. Write Snort/Suricata rules for network-level detection\n"
    output += "5. Share IOCs via STIX/TAXII with trusted threat intelligence partners\n"

    technique_id = rng.choice(list(MITRE_ATTACK.keys()))
    cwe_id = rng.choice(list(CWE_DB.keys()))
    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Binary Analysis: {sample_cat} ({binary_type})",
        severity=severity,
        cwe=cwe_id,
        instruction=rng.choice(BINARY_ANALYSIS_INSTRUCTIONS),
        input_text=input_text,
        output_text=output,
    )


def _generate_disassembly_entry(rng, complexity, idx, prefix):
    """Generate a disassembly interpretation entry."""
    severity = pick_severity(rng, complexity)
    snippet = rng.choice(DISASM_SNIPPETS)

    input_text = f"**Context:** Disassembly extracted during analysis of a suspicious binary.\n"
    input_text += f"**Section:** {snippet['name']}\n\n"
    input_text += f"```asm\n{snippet['code']}\n```\n\n"
    input_text += "**Task:** Explain what this code does and identify any security-relevant behavior.\n"

    technique = MITRE_ATTACK.get(snippet["technique"], {"name": "Unknown", "tactic": "Unknown"})

    output = f"## Disassembly Analysis: {snippet['name']}\n\n"
    output += f"### Behavior\n\n"
    output += f"{snippet['explanation']}\n\n"

    output += f"### MITRE ATT&CK Mapping\n\n"
    output += f"- **Technique:** {snippet['technique']} - {technique['name']}\n"
    output += f"- **Tactic:** {technique['tactic']}\n"
    output += f"- **Category:** {snippet['category'].replace('_', ' ').title()}\n\n"

    output += "### Detection Guidance\n\n"
    detection_map = {
        "anti-debug": [
            "Monitor for processes reading PEB fields associated with debugging detection",
            "Deploy anti-anti-debugging plugins in analysis tools (ScyllaHide, TitanHide)",
            "Use kernel-mode debuggers that are harder to detect from user-mode",
            "Patch the BeingDebugged flag in the PEB during dynamic analysis",
        ],
        "obfuscation": [
            "Identify common API hashing algorithms (djb2, CRC32, ROR13) and build hash lookup tables",
            "Use dynamic analysis to log resolved API addresses and correlate with known functions",
            "Look for GetProcAddress/LoadLibrary patterns as indicators of dynamic resolution",
            "Extract hash constants and match against pre-computed dictionaries of Windows API hashes",
        ],
        "collection": [
            "Monitor for excessive file enumeration activity (FindFirstFile/FindNextFile in rapid succession)",
            "Alert on access to known sensitive file locations (browser data, cryptocurrency wallets, documents)",
            "Implement data loss prevention (DLP) rules for bulk file access patterns",
            "Log and alert on abnormal file read activity from non-standard processes",
        ],
        "persistence": [
            "Monitor Run/RunOnce registry keys for unauthorized modifications",
            "Deploy registry auditing with Sysmon Event ID 12/13/14",
            "Use Group Policy to restrict write access to persistence registry locations",
            "Implement application whitelisting to prevent unauthorized executables from running at startup",
        ],
    }
    detections = detection_map.get(snippet["category"], ["Monitor for this behavior pattern using endpoint detection tools"])
    for det in detections:
        output += f"- {det}\n"

    cwe_id = rng.choice(list(CWE_DB.keys()))
    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Disassembly Analysis: {snippet['name']}",
        severity=severity,
        cwe=cwe_id,
        instruction=rng.choice(DISASSEMBLY_INSTRUCTIONS),
        input_text=input_text,
        output_text=output,
    )


def _generate_string_analysis_entry(rng, complexity, idx, prefix):
    """Generate a string analysis entry."""
    severity = pick_severity(rng, complexity)
    artifact_set = rng.choice(STRING_ARTIFACT_SETS)

    input_text = f"**Context:** Strings extracted from a suspicious binary during triage.\n"
    input_text += f"**Category:** {artifact_set['name']}\n\n"
    input_text += "**Extracted Strings:**\n```\n"
    for s in artifact_set["strings"]:
        input_text += f"{s}\n"
    input_text += "```\n\n"
    input_text += "**Task:** Analyze these strings and determine their significance.\n"

    output = f"## String Analysis: {artifact_set['name']}\n\n"
    output += f"### Analysis\n\n"
    output += f"{artifact_set['analysis']}\n\n"

    output += "### IOC Extraction\n\n"
    output += "| Type | Value | Confidence |\n"
    output += "|------|-------|------------|\n"
    for s in artifact_set["strings"]:
        if "hxxp" in s or "http" in s.lower():
            output += f"| URL | {s} | High |\n"
        elif "\\AppData" in s or "\\Users" in s:
            output += f"| File Path | {s} | Medium |\n"
        elif "SELECT" in s or "FROM" in s:
            output += f"| SQL Query | {s} | High |\n"
        elif "cmd" in s.lower() or "exe" in s.lower():
            output += f"| Command | {s} | High |\n"
        elif "." in s and "/" not in s and "\\" not in s and len(s) < 30:
            output += f"| File Extension | {s} | Medium |\n"

    output += "\n### Recommended Actions\n\n"
    output += "1. Search network logs for connections to identified URLs/domains\n"
    output += "2. Check endpoint telemetry for file access patterns matching identified paths\n"
    output += "3. Create detection signatures (YARA, Snort) based on extracted indicators\n"
    output += "4. Share IOCs with threat intelligence community via STIX/TAXII\n"
    output += "5. Correlate indicators with known threat actor TTPs\n"

    cwe_id = rng.choice(list(CWE_DB.keys()))
    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"String Analysis: {artifact_set['name']}",
        severity=severity,
        cwe=cwe_id,
        instruction=rng.choice(STRING_ANALYSIS_INSTRUCTIONS),
        input_text=input_text,
        output_text=output,
    )


def _generate_api_trace_entry(rng, complexity, idx, prefix):
    """Generate an API call trace analysis entry."""
    severity = pick_severity(rng, complexity)
    scenario = rng.choice(API_TRACE_SCENARIOS)

    input_text = f"**Context:** API call trace captured during sandboxed execution.\n"
    input_text += f"**Scenario:** {scenario['name']}\n\n"
    input_text += "**API Call Log:**\n```\n"
    for call in scenario["trace"]:
        input_text += f"{call}\n"
    input_text += "```\n\n"
    input_text += "**Task:** Analyze the API call sequence and determine the program behavior.\n"

    technique = MITRE_ATTACK.get(scenario["technique"], {"name": scenario["mitre_name"], "tactic": "Unknown"})

    output = f"## API Trace Analysis: {scenario['name']}\n\n"
    output += f"### Behavior Analysis\n\n"
    output += f"{scenario['analysis']}\n\n"

    output += f"### MITRE ATT&CK Classification\n\n"
    output += f"- **Technique:** {scenario['technique']} - {scenario['mitre_name']}\n"
    output += f"- **Tactic:** {technique['tactic']}\n\n"

    output += "### Detection Strategies\n\n"
    output += "1. Deploy endpoint detection and response (EDR) with API monitoring capabilities\n"
    output += "2. Configure Sysmon for process access, memory allocation, and thread creation events\n"
    output += "3. Implement behavioral detection rules for the observed API call patterns\n"
    output += "4. Monitor for privilege escalation indicators (process access with elevated permissions)\n"
    output += "5. Correlate suspicious API patterns across multiple hosts for campaign detection\n\n"

    output += "### Incident Response Actions\n\n"
    output += "1. Isolate the affected host from the network\n"
    output += "2. Capture memory dump for forensic analysis\n"
    output += "3. Identify the target process and assess impact\n"
    output += "4. Scan for additional compromised hosts using generated IOCs\n"
    output += "5. Preserve evidence chain for potential legal proceedings\n"

    cwe_id = rng.choice(list(CWE_DB.keys()))
    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"API Trace: {scenario['name']}",
        severity=severity,
        cwe=cwe_id,
        instruction=rng.choice(API_TRACING_INSTRUCTIONS),
        input_text=input_text,
        output_text=output,
    )


def _generate_firmware_entry(rng, complexity, idx, prefix):
    """Generate a firmware analysis entry."""
    severity = pick_severity(rng, complexity)
    scenario = rng.choice(FIRMWARE_SCENARIOS)

    input_text = f"**Scenario:** {scenario['name']}\n\n"
    input_text += f"{scenario['description']}\n\n"
    input_text += "**Task:** Describe the analysis methodology and identify security issues.\n"

    output = f"## Firmware Security Analysis: {scenario['name']}\n\n"

    output += "### Analysis Methodology\n\n"
    output += "1. **Acquisition:** Obtain firmware via vendor download, UART/JTAG extraction, or SPI flash dump\n"
    output += "2. **Extraction:** Use binwalk to identify and extract embedded filesystems, kernels, and bootloaders\n"
    output += "3. **Filesystem analysis:** Mount extracted filesystem, enumerate services, binaries, and configuration files\n"
    output += "4. **Static analysis:** Search for hardcoded credentials, insecure configurations, and known vulnerable components\n"
    output += "5. **Emulation:** Use QEMU/Firmadyne to emulate the firmware for dynamic testing\n"
    output += "6. **Network analysis:** Scan emulated device for exposed services and test for common vulnerabilities\n\n"

    output += "### Security Findings\n\n"
    for i, finding in enumerate(scenario["findings"], 1):
        sev = rng.choice(["Low", "Medium", "High", "Critical"])
        output += f"**{i}. [{sev}]** {finding}\n\n"

    output += "### Recommended Firmware Security Controls\n\n"
    controls = [
        "Implement secure boot with cryptographic signature verification of firmware images",
        "Use encrypted firmware update mechanism with TLS and code signing",
        "Remove or disable debug interfaces (UART, JTAG, telnet) in production builds",
        "Generate unique per-device credentials during manufacturing",
        "Implement secure key storage using hardware security elements (TPM, secure enclave)",
        "Keep base OS and libraries updated with security patches",
        "Minimize attack surface by removing unnecessary services and tools",
        "Implement network segmentation and access controls for management interfaces",
        "Enable secure boot chain from bootloader through kernel to application",
        "Conduct regular firmware security assessments using automated scanning tools",
    ]
    for j, ctrl in enumerate(rng.sample(controls, rng.randint(5, 8)), 1):
        output += f"{j}. {ctrl}\n"

    cwe_id = rng.choice(["CWE-798", "CWE-259", "CWE-311", "CWE-319", "CWE-276"])
    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Firmware Analysis: {scenario['name']}",
        severity=severity,
        cwe=cwe_id,
        instruction=rng.choice(FIRMWARE_INSTRUCTIONS),
        input_text=input_text,
        output_text=output,
    )


def _generate_methodology_entry(rng, complexity, idx, prefix):
    """Generate a malware analysis methodology entry."""
    severity = pick_severity(rng, complexity)
    sample_cat = rng.choice(SAMPLE_CATEGORIES)
    binary_type = rng.choice(BINARY_TYPES)

    input_text = f"**Sample Type:** {sample_cat}\n"
    input_text += f"**Binary Format:** {binary_type}\n"
    input_text += f"**Source:** Submitted by SOC team from a {rng.choice(APP_CONTEXTS)} incident\n\n"
    input_text += f"**Task:** Outline the safe analysis methodology for this {sample_cat} sample.\n"

    output = f"## Malware Analysis Methodology: {sample_cat}\n\n"
    output += f"**Sample:** {binary_type}\n"
    output += f"**Category:** {sample_cat}\n\n"

    output += "### Safety Precautions\n\n"
    output += "- **NEVER** execute malware samples on production or network-connected systems\n"
    output += "- Use a purpose-built analysis VM with snapshots and no shared folders\n"
    output += "- Disable clipboard sharing and USB passthrough in the hypervisor\n"
    output += "- Use a dedicated air-gapped analysis network or network simulation tools\n"
    output += "- Wear appropriate PPE if handling physical media from incident response\n\n"

    output += "### Phase 1: Triage (5-15 minutes)\n\n"
    output += "1. Compute file hashes and check VirusTotal/MalwareBazaar for prior analysis\n"
    output += "2. Identify file type, entropy, and packing status\n"
    output += "3. Extract basic metadata (compile timestamp, sections, imports)\n"
    output += "4. Make an initial classification decision: known family, new variant, or unknown\n\n"

    output += "### Phase 2: Static Analysis (30-120 minutes)\n\n"
    output += "1. If packed: identify packer and attempt automated unpacking\n"
    output += "2. Extract and analyze embedded strings (plaintext and obfuscated)\n"
    output += "3. Review import table and identify notable API groupings\n"
    output += "4. Disassemble key functions: entry point, main(), WinMain()\n"
    output += "5. Identify cryptographic routines, C2 protocol handlers, and persistence code\n"
    output += "6. Extract embedded configurations, URLs, keys, or certificates\n\n"

    output += "### Phase 3: Dynamic Analysis (30-120 minutes)\n\n"
    output += "1. Set up monitoring (ProcMon, Sysmon, Wireshark, FakeNet-NG)\n"
    output += "2. Execute sample and observe initial behavior\n"
    output += "3. Interact with C2 simulation if applicable\n"
    output += "4. Document all filesystem, registry, process, and network changes\n"
    output += "5. Capture memory dumps at key execution points\n\n"

    output += "### Phase 4: Advanced Analysis (as needed)\n\n"
    output += "1. Debug critical code paths to understand complex logic\n"
    output += "2. Decrypt or decode obfuscated payloads and configurations\n"
    output += "3. Reverse engineer custom protocols and encryption schemes\n"
    output += "4. Conduct code similarity analysis against known malware families\n\n"

    output += "### Phase 5: Reporting and IOC Generation\n\n"
    output += "1. Write technical analysis report with executive summary\n"
    output += "2. Generate machine-readable IOCs (STIX 2.1 format)\n"
    output += "3. Create YARA detection signatures\n"
    output += "4. Develop network detection rules (Snort/Suricata)\n"
    output += "5. Map all behaviors to MITRE ATT&CK framework\n"
    output += "6. Share threat intelligence with trusted partners and ISACs\n"

    cwe_id = rng.choice(list(CWE_DB.keys()))
    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Analysis Methodology: {sample_cat}",
        severity=severity,
        cwe=cwe_id,
        instruction=rng.choice(MALWARE_METHODOLOGY_INSTRUCTIONS),
        input_text=input_text,
        output_text=output,
    )


class ReverseEngineeringGenerator(CategoryGenerator):
    category = "reverse_engineering"
    id_prefix = "xld-re"

    def generate_entries(self, rng: random.Random, count: int, start_id: int,
                         complexity_weights) -> List[Dict[str, Any]]:
        entries = []
        # Distribute: 20% binary analysis, 20% disassembly, 15% strings, 15% API trace,
        #             15% firmware, 15% methodology
        binary_count = int(count * 0.20)
        disasm_count = int(count * 0.20)
        string_count = int(count * 0.15)
        api_count = int(count * 0.15)
        firmware_count = int(count * 0.15)
        method_count = count - binary_count - disasm_count - string_count - api_count - firmware_count

        idx = start_id
        for _ in range(binary_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_binary_analysis_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        for _ in range(disasm_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_disassembly_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        for _ in range(string_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_string_analysis_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        for _ in range(api_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_api_trace_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        for _ in range(firmware_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_firmware_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        for _ in range(method_count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_methodology_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        return entries
