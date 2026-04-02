# XLayer AI - Autonomous Web Vulnerability Hunter

> "Hack before hackers hack — Prove before you report"

XLayer AI is an autonomous web vulnerability hunting system that identifies, validates, and exploits security vulnerabilities in web applications using a 4-phase architecture.

## Core Philosophy

**NO EXPLOIT = NO REPORT**

XLayer AI only reports vulnerabilities that have been successfully exploited. This eliminates false positives and provides proof-of-concept for every finding.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    XLayer AI Architecture                   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  User Input: URL ──► Planner Agent (Brain)                  │
│                            │                                │
│                            ▼                                │
│              ┌─────────────────────────┐                    │
│              │   Phase 1: Recon        │                    │
│              │   - Tech stack detect   │                    │
│              │   - Endpoint mapping    │                    │
│              │   - Entry point hunt    │                    │
│              └───────────┬─────────────┘                    │
│                          │                                  │
│                          ▼                                  │
│              ┌─────────────────────────┐                    │
│              │   Phase 2: Vuln Hunt    │                    │
│              │   (Parallel Agents)     │                    │
│              │   SQLi │ XSS │ Auth     │                    │
│              │   SSRF │ LFI           │                    │
│              └───────────┬─────────────┘                    │
│                          │                                  │
│                          ▼                                  │
│              ┌─────────────────────────┐                    │
│              │   Phase 3: Exploit      │                    │
│              │   (Proof or Nothing)    │                    │
│              │   - Real payloads       │                    │
│              │   - Headless browser    │                    │
│              │   - Evidence capture    │                    │
│              └───────────┬─────────────┘                    │
│                          │                                  │
│                          ▼                                  │
│              ┌─────────────────────────┐                    │
│              │   Phase 4: Report       │                    │
│              │   - Only proven risks   │                    │
│              │   - Copy-paste PoCs     │                    │
│              │   - Professional format │                    │
│              └─────────────────────────┘                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Installation

```bash
# Clone the repository
cd xlayer-ai/xlayer_ai

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium

# Configure environment
cp .env.example .env
# Edit .env with your settings
```

## Usage

### Basic Scan

```bash
python -m xlayer_ai scan https://target.com
```

### With Options

```bash
# Specific hunters
python -m xlayer_ai scan https://target.com --hunters sqli,xss

# Custom depth and output
python -m xlayer_ai scan https://target.com --depth 2 --output ./my-reports

# Skip exploitation (hypothesis only)
python -m xlayer_ai scan https://target.com --no-exploit

# Adjust rate limiting
python -m xlayer_ai scan https://target.com --rate-limit 1.0
```

### View Configuration

```bash
python -m xlayer_ai config --show
```

### List Hunters

```bash
python -m xlayer_ai hunters
```

## Vulnerability Hunters

| Hunter | Detects |
|--------|---------|
| **sqli** | SQL Injection (Error, Boolean, Time-based, Union) |
| **xss** | Cross-Site Scripting (Reflected, DOM, Stored) |
| **auth** | Auth Bypass, IDOR, Session Issues |
| **ssrf** | Server-Side Request Forgery, Cloud Metadata |
| **lfi** | Local File Inclusion, Path Traversal |

## Configuration

Configure via environment variables or `.env` file:

```bash
# LLM Provider
XLAYER_LLM__PROVIDER=openai
XLAYER_LLM__API_KEY=your-key

# Scan Settings
XLAYER_SCAN__MAX_DEPTH=3
XLAYER_SCAN__RATE_LIMIT=0.5

# Enabled Hunters
XLAYER_HUNTERS=sqli,xss,auth,ssrf,lfi
```

## Output

XLayer AI generates professional reports in multiple formats:

- **JSON** - Machine-readable for integration
- **HTML** - Interactive dashboard with evidence
- **PDF** - Client-ready presentation (optional)

Reports include:
- Executive summary with risk rating
- Technical findings with CVSS scores
- Proof-of-concept (curl commands, screenshots)
- Remediation guidance

## Project Structure

```
xlayer_ai/
├── core/
│   ├── planner.py          # Master orchestrator
│   ├── recon.py            # Reconnaissance agent
│   ├── exploit.py          # Exploitation agent
│   ├── reporter.py         # Report generator
│   └── vuln_hunters/       # Vulnerability hunters
│       ├── sqli.py
│       ├── xss.py
│       ├── auth.py
│       ├── ssrf.py
│       └── lfi.py
├── tools/
│   ├── http_client.py      # Async HTTP client
│   ├── scanner.py          # Port scanner
│   ├── crawler.py          # Web crawler
│   ├── browser.py          # Headless browser
│   └── payload_manager.py  # Payload database
├── models/
│   ├── target.py           # Target models
│   ├── vulnerability.py    # Vulnerability models
│   └── report.py           # Report models
├── llm/
│   └── engine.py           # LLM integration
├── config/
│   ├── settings.py         # Configuration
│   └── payloads/           # Payload YAML files
├── utils/
│   ├── logger.py           # Logging
│   └── validators.py       # Input validation
└── main.py                 # CLI entry point
```

## Legal Disclaimer

XLayer AI is intended for authorized security testing only. Always obtain proper authorization before scanning any target. Unauthorized access to computer systems is illegal.

## License

MIT License - See LICENSE file for details.
