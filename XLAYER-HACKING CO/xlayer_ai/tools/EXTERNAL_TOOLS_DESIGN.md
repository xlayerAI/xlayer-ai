# Nmap, Burp, र अरू hacking tools को काम गर्ने तरिका

यो doc मा: **nmap, Burp Suite, र जति पनि hacking tools** को जस्तो काम गर्ने tool वा script run गर्न **possible छ** र **कसरी** गर्ने भन्ने design र usage।

---

## 1. Possible छ? — हाँ, दुई तरिकाले

| तरिका | के हो | उदाहरण |
|--------|--------|--------|
| **Native tools** | बाहिरी binary (nmap, nikto, etc.) लाई allowlist बाट subprocess ले run गर्ने | `run_nmap`, `run_allowlisted_tool` |
| **JIT script** | Agent ले Python script लेख्छ, JIT sandbox मा run हुन्छ (pure Python, no binary) | nmap जस्तो port scan, Burp जस्तो HTTP fuzz |

---

## 2. Native tools — बाहिरी binary run गर्ने

### 2.1 कसरी काम गर्छ

- **Allowlist**: केवल रजिस्टर गरिएका commands मात्र run हुन्छन् (जस्तै `nmap`).
- **Subprocess**: Main process बाट `subprocess.run([binary, ...args], timeout=...)`; shell **use हुँदैन** (command injection रोक्न).
- **Tools**: `src/tools/external_tools.py` मा:
  - **`run_nmap`**: `target_host`, `ports`, `scan_type`, `timeout_seconds` — सीधा nmap को काम गर्छ।
  - **`run_allowlisted_tool`**: कुनै allowlisted tool को नाम र JSON args दिएर generic run।

### 2.2 Nmap

- Agent ले tool call: `run_nmap(target_host="example.com", ports="80,443,8080", scan_type="connect", timeout_seconds=60)`.
- System मा nmap install र PATH मा हुनुपर्छ। नभएको भए JSON मा error आउँछ र hint: "use JIT port-scan script".

### 2.3 Burp Suite

- **Burp** GUI/Java app हो; direct binary एकै किसिमले run गर्न मिल्दैन।
- **Option A**: Burp Suite Pro को REST API भए: नयाँ tool `run_burp_scan` जस्तो बनाएर त्यो API लाई call गर्न सकिन्छ।
- **Option B**: Burp जस्तो **recon / fuzz** को लागि:
  - **HTTP replay/fuzz**: अहिले नै `http_probe` + hunters + **JIT** (httpx) ले coverage छ।
  - Intruder-style fuzz: JIT मा httpx ले loop चलाएर parameter/header/body fuzz गर्न सकिन्छ।

### 2.4 अरू tools (nikto, ffuf, etc.)

- **Allowlist मा थप्ने**: `external_tools.py` मा `ALLOWED_BINARIES` मा नाम थप्ने (जस्तै `"nikto"`, `"ffuf"`).
- **Run गर्ने**: `run_allowlisted_tool(tool_name="nikto", args_json='["-h", "https://example.com"]', timeout_seconds=90)` वा नयाँ dedicated tool (जस्तै `run_nikto`) बनाउने।

---

## 3. JIT script — nmap/Burp जस्तो काम (pure Python)

### 3.1 Nmap जस्तो: port scan

- JIT मा **socket** pre-import गरिएको छ (outbound मात्र; `socket.bind` blocked).
- Agent ले script लेख्छ जस्तै:

```python
# url = target from context (e.g. from state)
from urllib.parse import urlparse
parsed = urlparse(url)
host = parsed.hostname or parsed.netloc.split(":")[0]
common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080]
open_ports = []
for port in common_ports:
    try:
        s = socket.create_connection((host, port), timeout=2)
        open_ports.append(port)
        s.close()
    except (socket.error, OSError):
        pass
print(json.dumps({"host": host, "open_ports": open_ports}))
```

- यो script JIT मा run हुन्छ, कुनै nmap binary चाहिँदैन।

### 3.2 Burp जस्तो: HTTP fuzz / repeater

- JIT मा **httpx** already छ।
- Agent ले parameter वा header fuzz गर्ने script लेख्छ (loop मा `httpx.get/post`), response status/length/body analyze गर्छ — Burp Repeater/Intruder जस्तो use case।

### 3.3 Safety

- JIT मा **BLOCKED_PATTERNS**: `subprocess`, `socket.bind`, `127.0.0.1`, `open('/etc/passwd')`, etc.
- Port scan: केवल **outbound** `socket.create_connection`; bind वा localhost target मनाइएको छ।

---

## 4. Summary

| Goal | तरिका |
|------|--------|
| **Nmap को काम** | Native: `run_nmap`। नभए: JIT मा socket ले port-scan script। |
| **Burp जस्तो काम** | HTTP: `http_probe` + JIT (httpx) fuzz। Burp API: भएको भए नयाँ tool थप्ने। |
| **अरू hacking tools** | Allowlist मा binary थपेर `run_allowlisted_tool` वा dedicated tool (जस्तै `run_nikto`)। |
| **कुनै specific tool को script** | JIT मा Python script लेखेर run गर्ने वा `register_tool_name` ले persistent tool बनाउने। |

---

## 5. Files

- **Native tools**: `src/tools/external_tools.py` — `run_nmap`, `run_allowlisted_tool`, `EXTERNAL_TOOLS`.
- **JIT**: `src/tools/jit_engine.py` — `SAFE_PRELUDE` मा `socket` + httpx; BLOCKED_PATTERNS मा bind/localhost।
- **Registry**: Coordinator मा `all_tools = ALL_HUNTER_TOOLS + EXTERNAL_TOOLS + [jit_tool]`।

यो design अनुसार nmap को काम, Burp जस्तो काम, र जति पनि allowlisted hacking tools को काम tool वा script बाट run गर्न **possible छ** र **कसरी** गर्ने भन्ने स्पष्ट छ।
