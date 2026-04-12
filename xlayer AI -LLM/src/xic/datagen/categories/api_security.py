"""
API Security generator.
Produces REST/GraphQL API security assessment entries covering BOLA, JWT,
OAuth, rate limiting, mass assignment, and other API-specific vulnerabilities.
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

BOLA_INSTRUCTIONS = [
    "Analyze the following API endpoint for Broken Object-Level Authorization (BOLA) vulnerabilities. Identify how an attacker could access other users' resources.",
    "Review this API implementation for IDOR/BOLA issues. Determine if the endpoint properly validates resource ownership before returning data.",
    "Assess this REST API endpoint for authorization bypass vulnerabilities. Check whether object-level access control is enforced.",
    "Evaluate whether the following API request/response pair exposes a Broken Object-Level Authorization flaw. Provide remediation steps.",
]

RATE_LIMIT_INSTRUCTIONS = [
    "Analyze the following API configuration for rate limiting weaknesses. Determine if the API is vulnerable to abuse through excessive requests.",
    "Review this API endpoint's throttling configuration. Identify gaps that could allow denial-of-service or brute-force attacks.",
    "Assess the rate limiting strategy for the following API. Are there bypasses or weaknesses an attacker could exploit?",
    "Evaluate the API's resource consumption controls. Identify missing or misconfigured rate limits and recommend improvements.",
]

JWT_INSTRUCTIONS = [
    "Analyze the following JWT configuration for security vulnerabilities. Check for algorithm confusion, weak secrets, and missing validations.",
    "Review this JWT-based authentication implementation. Identify misconfigurations that could allow token forgery or replay attacks.",
    "Assess the security of the JWT token handling in this API. Check claims validation, expiration, and signing algorithm.",
    "Evaluate the following JWT implementation for common security pitfalls. Provide a detailed analysis of each issue found.",
]

OAUTH_INSTRUCTIONS = [
    "Analyze the following OAuth 2.0 implementation for security flaws. Check redirect URI validation, state parameter, and scope handling.",
    "Review this OAuth flow for authorization code interception, CSRF, and open redirect vulnerabilities.",
    "Assess the OAuth 2.0 configuration below. Identify deviations from security best practices and potential attack vectors.",
]

GENERAL_API_INSTRUCTIONS = [
    "Perform a comprehensive security assessment of the following API endpoint. Analyze authentication, authorization, input validation, and data exposure.",
    "Review this API definition for security vulnerabilities according to the OWASP API Security Top 10. Document each finding.",
    "Analyze the following API request and response for excessive data exposure, mass assignment, and injection vulnerabilities.",
    "Assess this GraphQL API configuration for introspection abuse, query depth attacks, and authorization bypass vulnerabilities.",
    "Review the following API security configuration. Identify missing security headers, CORS issues, and authentication weaknesses.",
    "Evaluate this API endpoint for mass assignment vulnerabilities. Determine if client-supplied data could modify protected fields.",
    "Analyze the following API key management implementation. Check for key exposure, rotation, and scope limitation issues.",
]

ALL_INSTRUCTIONS = (
    BOLA_INSTRUCTIONS + RATE_LIMIT_INSTRUCTIONS + JWT_INSTRUCTIONS +
    OAUTH_INSTRUCTIONS + GENERAL_API_INSTRUCTIONS
)

# ── Topic categories and templates ─────────────────────────────────────────

API_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]

API_RESOURCES = [
    "users", "accounts", "orders", "invoices", "payments", "profiles",
    "documents", "settings", "reports", "messages", "notifications",
    "subscriptions", "products", "tickets", "appointments", "records",
]

AUTH_SCHEMES = [
    "Bearer JWT", "API Key in header", "API Key in query param",
    "Basic Auth", "OAuth 2.0 Bearer", "Session Cookie", "HMAC Signature",
]

JWT_ALGORITHMS = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "none"]

GRAPHQL_TYPES = [
    "User", "Account", "Order", "Product", "Payment", "Transaction",
    "Document", "Report", "Message", "Notification",
]

OAUTH_GRANT_TYPES = [
    "authorization_code", "implicit", "client_credentials",
    "password", "refresh_token",
]

SENSITIVE_FIELDS = [
    "ssn", "password_hash", "credit_card", "api_secret", "internal_notes",
    "salary", "medical_record", "private_key", "bank_account", "tax_id",
]

RESPONSE_HEADERS_GOOD = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-RateLimit-Limit": "100",
    "X-RateLimit-Remaining": "42",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'",
}

RESPONSE_HEADERS_BAD = {
    "Access-Control-Allow-Origin": "*",
    "X-Powered-By": "Express",
    "Server": "Apache/2.4.49",
}

API_CWES = [
    "CWE-284", "CWE-285", "CWE-287", "CWE-306", "CWE-307",
    "CWE-345", "CWE-346", "CWE-352", "CWE-639", "CWE-862",
    "CWE-863", "CWE-200", "CWE-209", "CWE-400", "CWE-770",
    "CWE-89", "CWE-79", "CWE-918", "CWE-942", "CWE-20",
]


# ── Scenario builder helpers ───────────────────────────────────────────────

def _build_bola_scenario(rng, complexity, domain):
    resource = rng.choice(API_RESOURCES)
    method = rng.choice(["GET", "PUT", "DELETE", "PATCH"])
    user_id = rng.randint(1000, 9999)
    victim_id = user_id + rng.randint(1, 500)
    path = f"/api/v{rng.choice(['1','2','3'])}/{resource}/{victim_id}"
    auth = rng.choice(AUTH_SCHEMES[:3])

    input_text = f"## API Endpoint Under Review\n\n"
    input_text += f"**Endpoint:** {method} https://{domain}{path}\n"
    input_text += f"**Authentication:** {auth}\n"
    input_text += f"**Authenticated User ID:** {user_id}\n\n"
    input_text += f"```http\n{method} {path} HTTP/1.1\n"
    input_text += f"Host: {domain}\n"
    input_text += f"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.{{\"sub\":\"{user_id}\",\"role\":\"user\"}}.sig\n"
    input_text += f"Content-Type: application/json\n```\n\n"
    input_text += f"**Response (200 OK):**\n```json\n{{\n"
    input_text += f"  \"id\": {victim_id},\n"
    input_text += f"  \"email\": \"victim@example.com\",\n"
    input_text += f"  \"name\": \"Victim User\",\n"

    if complexity in ("advanced", "expert"):
        sens = rng.choice(SENSITIVE_FIELDS)
        input_text += f"  \"{sens}\": \"REDACTED_VALUE\",\n"

    input_text += f"  \"created_at\": \"2024-01-15T10:30:00Z\"\n}}\n```"

    cwe = "CWE-639"
    cwe_info = CWE_DB.get(cwe, {"name": "IDOR", "severity": ["high"]})

    output = f"## BOLA / IDOR Vulnerability Analysis\n\n"
    output += f"**Finding:** Broken Object-Level Authorization on `{method} {path}`\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** HIGH\n"
    output += f"**OWASP API Security:** API1:2023 - Broken Object-Level Authorization\n\n"
    output += f"### Vulnerability Description\n"
    output += f"The endpoint `{path}` does not validate that the authenticated user (ID: {user_id}) "
    output += f"has authorization to access the resource belonging to user {victim_id}. The server "
    output += f"only verifies that the request carries a valid authentication token, but does not "
    output += f"check whether the token's subject (`sub` claim) matches the requested resource owner.\n\n"
    output += f"### Attack Scenario\n"
    output += f"1. Attacker authenticates as user {user_id} and receives a valid JWT.\n"
    output += f"2. Attacker modifies the resource ID in the URL from `{user_id}` to `{victim_id}`.\n"
    output += f"3. The API returns the victim's data without verifying ownership.\n"
    output += f"4. Attacker can enumerate resource IDs ({victim_id-10}..{victim_id+10}) to exfiltrate bulk data.\n\n"
    output += f"### Impact\n"
    output += f"- Unauthorized access to other users' {resource}\n"
    output += f"- Potential mass data exfiltration via ID enumeration\n"
    output += f"- Privacy violations and regulatory non-compliance (GDPR, HIPAA)\n\n"

    if complexity in ("advanced", "expert"):
        output += f"### Technical Root Cause\n"
        output += f"The API handler retrieves the resource by ID from the database without applying "
        output += f"a WHERE clause filtering on the authenticated user's ID. Example vulnerable pattern:\n\n"
        output += f"```python\n# VULNERABLE: No ownership check\n"
        output += f"@app.route('/api/v2/{resource}/<int:id>')\n"
        output += f"@require_auth\n"
        output += f"def get_{resource[:-1]}(id):\n"
        output += f"    return db.query({resource.title()}).filter_by(id=id).first()\n```\n\n"

    output += f"### Remediation\n"
    output += f"1. **Enforce ownership checks** - Validate that `resource.owner_id == authenticated_user.id` before returning data.\n"
    output += f"2. **Use indirect references** - Replace sequential IDs with UUIDs to prevent enumeration.\n"
    output += f"3. **Implement authorization middleware** - Use a centralized policy engine (e.g., OPA, Casbin).\n"
    output += f"4. **Add logging** - Log all access attempts with user ID and resource ID for audit trails.\n\n"

    output += f"### Secure Implementation\n"
    output += f"```python\n@app.route('/api/v2/{resource}/<uuid:id>')\n"
    output += f"@require_auth\n"
    output += f"def get_{resource[:-1]}(id):\n"
    output += f"    item = db.query({resource.title()}).filter_by(id=id, owner_id=current_user.id).first()\n"
    output += f"    if not item:\n"
    output += f"        raise NotFound()  # same error for missing and unauthorized\n"
    output += f"    return item\n```"

    return cwe, input_text, output, f"BOLA in {method} {path}"


def _build_jwt_scenario(rng, complexity, domain):
    alg = rng.choice(JWT_ALGORITHMS)
    is_weak = alg in ("none", "HS256", "HS384")
    path = f"/api/v{rng.choice(['1','2'])}/auth/token"

    issues = []
    config_lines = []
    config_lines.append(f"JWT_ALGORITHM = \"{alg}\"")

    if alg == "none":
        issues.append("Algorithm 'none' allows unsigned tokens")
        config_lines.append("JWT_VERIFY_SIGNATURE = False")
    elif alg.startswith("HS"):
        secret = rng.choice(["secret", "password123", "jwt_secret", "changeme", "mysecretkey"])
        issues.append(f"Weak shared secret: '{secret}'")
        config_lines.append(f"JWT_SECRET = \"{secret}\"")
    else:
        config_lines.append("JWT_PUBLIC_KEY_FILE = \"/etc/app/public.pem\"")
        config_lines.append("JWT_PRIVATE_KEY_FILE = \"/etc/app/private.pem\"")

    exp_minutes = rng.choice([0, 60, 1440, 43200, 525600])
    if exp_minutes == 0:
        issues.append("No token expiration configured")
        config_lines.append("JWT_EXPIRATION = None  # no expiry")
    elif exp_minutes > 10080:
        issues.append(f"Excessive token lifetime: {exp_minutes} minutes ({exp_minutes//1440} days)")
        config_lines.append(f"JWT_EXPIRATION = {exp_minutes}  # minutes")
    else:
        config_lines.append(f"JWT_EXPIRATION = {exp_minutes}  # minutes")

    if rng.random() < 0.5:
        issues.append("Missing audience (aud) claim validation")
        config_lines.append("JWT_VERIFY_AUD = False")
    if rng.random() < 0.4:
        issues.append("Missing issuer (iss) claim validation")
        config_lines.append("JWT_VERIFY_ISS = False")
    if rng.random() < 0.3:
        issues.append("No token revocation mechanism")
        config_lines.append("JWT_BLACKLIST_ENABLED = False")

    cwe = rng.choice(["CWE-287", "CWE-345", "CWE-327", "CWE-306"])
    cwe_info = CWE_DB.get(cwe, {"name": "Authentication Flaw", "severity": ["high"]})

    input_text = f"## JWT Configuration Review\n\n"
    input_text += f"**Application:** https://{domain}\n"
    input_text += f"**Token Endpoint:** POST {path}\n\n"
    input_text += f"```python\n# JWT configuration\n"
    for line in config_lines:
        input_text += f"{line}\n"
    input_text += f"```\n\n"
    input_text += f"**Sample Token Header:**\n```json\n{{\n  \"alg\": \"{alg}\",\n  \"typ\": \"JWT\"\n}}\n```"

    output = f"## JWT Security Assessment\n\n"
    output += f"**Target:** https://{domain}\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** {'CRITICAL' if alg == 'none' else 'HIGH' if is_weak else 'MEDIUM'}\n\n"
    output += f"### Findings\n\n"

    for i, issue in enumerate(issues, 1):
        output += f"**{i}. {issue}**\n"
        if "none" in issue.lower():
            output += f"The `alg: none` setting allows attackers to craft unsigned tokens that the server "
            output += f"will accept as valid. An attacker can set arbitrary claims (e.g., `admin: true`) "
            output += f"without possessing any cryptographic key.\n\n"
        elif "weak shared secret" in issue.lower():
            output += f"The JWT signing secret is easily guessable. Attackers can brute-force the secret "
            output += f"using tools like `jwt_tool` or `hashcat`, then forge valid tokens with arbitrary claims.\n\n"
        elif "expiration" in issue.lower():
            output += f"Without proper expiration, compromised tokens remain valid indefinitely. "
            output += f"This eliminates any time-based defense against stolen credentials.\n\n"
        elif "excessive token lifetime" in issue.lower():
            output += f"A token lifetime of {exp_minutes} minutes ({exp_minutes//1440} days) significantly "
            output += f"increases the window for token theft and replay attacks.\n\n"
        elif "audience" in issue.lower():
            output += f"Without audience validation, tokens issued for one service can be replayed against "
            output += f"other services sharing the same signing key (cross-service token confusion).\n\n"
        elif "issuer" in issue.lower():
            output += f"Without issuer validation, the API may accept tokens from unexpected identity providers.\n\n"
        elif "revocation" in issue.lower():
            output += f"Without a token blacklist or revocation mechanism, there is no way to invalidate "
            output += f"active tokens when a user logs out, changes password, or is deactivated.\n\n"

    output += f"### Remediation\n"
    output += f"1. **Use asymmetric algorithms** (RS256/ES256) - prevent key compromise from enabling token forgery.\n"
    output += f"2. **Set short expiration** - use 15-30 minute access tokens with refresh token rotation.\n"
    output += f"3. **Validate all claims** - verify `iss`, `aud`, `exp`, `nbf`, and `sub` on every request.\n"
    output += f"4. **Implement token revocation** - use a blocklist (Redis-backed) for logout/password change.\n"
    output += f"5. **Rotate signing keys** - implement key rotation with proper `kid` (Key ID) header support.\n\n"

    output += f"### Secure Configuration\n"
    output += f"```python\nJWT_ALGORITHM = \"RS256\"\n"
    output += f"JWT_EXPIRATION = 15  # minutes\n"
    output += f"JWT_REFRESH_EXPIRATION = 1440  # 1 day\n"
    output += f"JWT_VERIFY_AUD = True\n"
    output += f"JWT_VERIFY_ISS = True\n"
    output += f"JWT_AUDIENCE = \"https://{domain}\"\n"
    output += f"JWT_ISSUER = \"https://auth.{domain.split('.', 1)[-1]}\"\n"
    output += f"JWT_BLACKLIST_ENABLED = True\n```"

    title = f"JWT Misconfiguration: {', '.join(issues[:2])}"
    return cwe, input_text, output, title[:120]


def _build_rate_limit_scenario(rng, complexity, domain):
    path = f"/api/v{rng.choice(['1','2'])}/{rng.choice(['auth/login', 'auth/reset-password', 'users/search', 'export/data', 'upload', 'payments/process'])}"
    method = rng.choice(["POST", "GET"])

    has_global_limit = rng.random() < 0.3
    has_endpoint_limit = rng.random() < 0.2
    has_user_limit = rng.random() < 0.25

    input_text = f"## API Rate Limiting Configuration\n\n"
    input_text += f"**Endpoint:** {method} https://{domain}{path}\n\n"
    input_text += f"```yaml\n# Rate limiting configuration\n"
    input_text += f"rate_limiting:\n"
    if has_global_limit:
        input_text += f"  global:\n    requests_per_minute: 10000\n    burst: 500\n"
    else:
        input_text += f"  global: null  # disabled\n"
    if has_endpoint_limit:
        input_text += f"  endpoint:\n    \"{path}\":\n      requests_per_minute: 1000\n"
    else:
        input_text += f"  per_endpoint: null  # no per-endpoint limits\n"
    if has_user_limit:
        input_text += f"  per_user:\n    requests_per_minute: 200\n    key: \"x-api-key\"\n"
    else:
        input_text += f"  per_user: null  # no per-user limits\n"
    input_text += f"  ip_whitelist:\n    - \"10.0.0.0/8\"\n    - \"0.0.0.0/0\"  # WARNING\n"
    input_text += f"```"

    cwe = rng.choice(["CWE-400", "CWE-770", "CWE-307"])
    cwe_info = CWE_DB.get(cwe, {"name": "Resource Consumption", "severity": ["medium", "high"]})

    output = f"## Rate Limiting Security Assessment\n\n"
    output += f"**Endpoint:** {method} {path}\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** {'HIGH' if '/auth/' in path else 'MEDIUM'}\n\n"
    output += f"### Findings\n\n"

    finding = 1
    if not has_global_limit:
        output += f"**{finding}. No Global Rate Limit**\n"
        output += f"The API lacks a global request rate limit. This allows an attacker to send "
        output += f"unlimited requests, potentially causing resource exhaustion or service degradation.\n\n"
        finding += 1
    elif has_global_limit:
        output += f"**{finding}. Excessive Global Rate Limit**\n"
        output += f"The global limit of 10,000 requests/minute with a burst of 500 is extremely generous "
        output += f"and may not effectively prevent abuse.\n\n"
        finding += 1

    if not has_endpoint_limit and "/auth/" in path:
        output += f"**{finding}. Missing Per-Endpoint Limit on Authentication**\n"
        output += f"The `{path}` endpoint handles authentication but has no dedicated rate limit. "
        output += f"This makes it vulnerable to credential stuffing and brute-force attacks.\n\n"
        finding += 1

    if not has_user_limit:
        output += f"**{finding}. No Per-User Rate Limiting**\n"
        output += f"Without per-user limits, a single user or API key can consume the entire "
        output += f"rate limit allocation, causing a denial of service for other users.\n\n"
        finding += 1

    output += f"**{finding}. IP Whitelist Bypass (0.0.0.0/0)**\n"
    output += f"The IP whitelist includes `0.0.0.0/0`, which matches ALL IPv4 addresses. "
    output += f"This effectively disables rate limiting for every client.\n\n"
    finding += 1

    output += f"### Recommended Configuration\n"
    output += f"```yaml\nrate_limiting:\n"
    output += f"  global:\n    requests_per_minute: 600\n    burst: 30\n"
    output += f"  endpoint:\n"
    output += f"    \"/api/v*/auth/*\":\n      requests_per_minute: 10\n      burst: 3\n"
    output += f"      block_duration: 300  # 5 min lockout\n"
    output += f"  per_user:\n    requests_per_minute: 60\n    key: \"authenticated_user_id\"\n"
    output += f"  ip_whitelist:\n    - \"10.0.0.0/8\"  # internal only\n"
    output += f"  response_headers: true  # expose X-RateLimit-* headers\n"
    output += f"  retry_after: true\n```"

    return cwe, input_text, output, f"Rate Limiting Weakness on {method} {path}"


def _build_oauth_scenario(rng, complexity, domain):
    grant = rng.choice(OAUTH_GRANT_TYPES)
    client_id = f"client_{rng.randint(100,999)}"

    issues = []
    config = {}
    config["grant_type"] = grant
    config["client_id"] = client_id
    config["redirect_uris"] = [f"https://{domain}/callback"]

    if rng.random() < 0.5:
        config["redirect_uris"].append(f"https://{domain}/callback/../../../evil.com")
        issues.append("Path traversal in redirect URI allows open redirect")

    if rng.random() < 0.5:
        config["redirect_uris"].append("http://localhost:8080/callback")
        issues.append("HTTP (non-TLS) redirect URI accepted")

    if grant == "implicit":
        issues.append("Implicit grant type exposes tokens in URL fragment (deprecated in OAuth 2.1)")

    if rng.random() < 0.4:
        config["state_required"] = False
        issues.append("State parameter not required (CSRF vulnerability)")
    else:
        config["state_required"] = True

    if rng.random() < 0.4:
        config["pkce_required"] = False
        issues.append("PKCE not enforced (authorization code interception risk)")
    else:
        config["pkce_required"] = True

    if rng.random() < 0.3:
        config["scope"] = ["*"]
        issues.append("Wildcard scope grants unrestricted access")
    else:
        config["scope"] = ["read:profile", "read:email"]

    if not issues:
        issues.append("Token endpoint does not enforce client authentication")

    import json
    config_json = json.dumps(config, indent=2)

    cwe = rng.choice(["CWE-287", "CWE-346", "CWE-601", "CWE-352"])
    cwe_info = CWE_DB.get(cwe, {"name": "Auth Flaw", "severity": ["high"]})

    input_text = f"## OAuth 2.0 Configuration Review\n\n"
    input_text += f"**Authorization Server:** https://auth.{domain.split('.', 1)[-1]}\n"
    input_text += f"**Client Application:** https://{domain}\n\n"
    input_text += f"```json\n{config_json}\n```"

    output = f"## OAuth 2.0 Security Assessment\n\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** HIGH\n\n"
    output += f"### Grant Type: `{grant}`\n\n"
    output += f"### Security Findings\n\n"

    for i, issue in enumerate(issues, 1):
        output += f"**{i}. {issue}**\n"
        if "redirect" in issue.lower() and "traversal" in issue.lower():
            output += f"The redirect URI list includes a path-traversal pattern that could redirect "
            output += f"the authorization code or token to an attacker-controlled domain. Redirect URIs "
            output += f"must be exact-match validated, not prefix-matched.\n\n"
        elif "http" in issue.lower() and "non-tls" in issue.lower():
            output += f"Accepting HTTP redirect URIs allows tokens/codes to be transmitted in cleartext, "
            output += f"enabling network-level interception (e.g., on public Wi-Fi).\n\n"
        elif "implicit" in issue.lower():
            output += f"The implicit grant type returns access tokens directly in the URL fragment, "
            output += f"exposing them to browser history, referrer headers, and browser extensions. "
            output += f"It has been removed in OAuth 2.1.\n\n"
        elif "state" in issue.lower():
            output += f"Without the `state` parameter, the authorization flow is vulnerable to CSRF. "
            output += f"An attacker can initiate an OAuth flow and trick a victim into completing it, "
            output += f"linking the attacker's account.\n\n"
        elif "pkce" in issue.lower():
            output += f"Without PKCE (Proof Key for Code Exchange), the authorization code is vulnerable "
            output += f"to interception by malicious apps on the same device or network.\n\n"
        elif "wildcard scope" in issue.lower():
            output += f"A wildcard scope grants the client full access to all APIs and resources, "
            output += f"violating the principle of least privilege.\n\n"
        else:
            output += f"The token endpoint should require client authentication (client_secret or "
            output += f"private_key_jwt) to prevent unauthorized token exchange.\n\n"

    output += f"### Remediation\n"
    output += f"1. **Use Authorization Code + PKCE** - Migrate away from implicit grant.\n"
    output += f"2. **Exact-match redirect URIs** - Validate redirect URIs with exact string comparison.\n"
    output += f"3. **Enforce HTTPS** - Reject HTTP redirect URIs in all environments.\n"
    output += f"4. **Require state parameter** - Generate a cryptographically random state per request.\n"
    output += f"5. **Minimize scopes** - Grant only the minimum scopes required by the client.\n"
    output += f"6. **Rotate client secrets** - Implement automatic secret rotation.\n"

    title = f"OAuth 2.0 Flaws: {issues[0]}"
    return cwe, input_text, output, title[:120]


def _build_mass_assignment_scenario(rng, complexity, domain):
    resource = rng.choice(["user", "account", "profile", "order", "subscription"])
    method = rng.choice(["POST", "PUT", "PATCH"])
    path = f"/api/v2/{resource}s"
    framework = rng.choice(["Express.js", "Django", "Spring Boot", "Rails", "FastAPI"])

    writable_fields = rng.sample(["name", "email", "phone", "address", "bio", "avatar_url"], k=3)
    protected_fields = rng.sample(["role", "is_admin", "permissions", "balance", "discount_rate",
                                    "verified", "plan_tier", "credit_limit"], k=rng.randint(2, 4))

    payload = {f: f"user_value_{i}" for i, f in enumerate(writable_fields)}
    payload.update({f: "ATTACKER_INJECTED" for f in protected_fields[:2]})

    import json

    input_text = f"## API Endpoint: {method} {path}\n\n"
    input_text += f"**Framework:** {framework}\n"
    input_text += f"**Description:** Update {resource} profile information\n\n"
    input_text += f"**Request Body:**\n```json\n{json.dumps(payload, indent=2)}\n```\n\n"
    input_text += f"**Server-side handler:**\n```python\n"
    input_text += f"@app.route('{path}/<int:id>', methods=['{method}'])\n"
    input_text += f"@require_auth\n"
    input_text += f"def update_{resource}(id):\n"
    input_text += f"    {resource} = {resource.title()}.query.get(id)\n"
    input_text += f"    for key, value in request.json.items():\n"
    input_text += f"        setattr({resource}, key, value)  # mass assignment\n"
    input_text += f"    db.session.commit()\n"
    input_text += f"    return jsonify({resource}.to_dict())\n```"

    cwe = "CWE-915" if "CWE-915" in CWE_DB else "CWE-284"
    cwe_info = CWE_DB.get(cwe, {"name": "Mass Assignment", "severity": ["high"]})

    output = f"## Mass Assignment Vulnerability Analysis\n\n"
    output += f"**Finding:** Mass Assignment in `{method} {path}`\n"
    output += f"**CWE:** {cwe} ({cwe_info.get('name', 'Improper Access Control')})\n"
    output += f"**Severity:** HIGH\n"
    output += f"**OWASP API Security:** API6:2023 - Unrestricted Access to Sensitive Business Flows\n\n"
    output += f"### Vulnerability Description\n"
    output += f"The endpoint directly maps all client-supplied JSON fields to the {resource} model "
    output += f"attributes without filtering. An attacker can inject protected fields such as "
    output += f"`{', '.join(protected_fields)}` to modify data they should not have access to.\n\n"
    output += f"### Exploitation Example\n"
    output += f"An attacker sends a {method} request with additional fields:\n"
    output += f"```json\n{{\n"
    for pf in protected_fields:
        if pf == "is_admin":
            output += f"  \"{pf}\": true,\n"
        elif pf == "role":
            output += f"  \"{pf}\": \"admin\",\n"
        elif pf in ("balance", "credit_limit", "discount_rate"):
            output += f"  \"{pf}\": 999999,\n"
        else:
            output += f"  \"{pf}\": \"elevated_value\",\n"
    output += f"}}\n```\n\n"
    output += f"### Impact\n"
    output += f"- **Privilege escalation** if `role` or `is_admin` is overwritten\n"
    output += f"- **Financial manipulation** if `balance` or `discount_rate` is modified\n"
    output += f"- **Business logic bypass** via direct attribute modification\n\n"
    output += f"### Remediation\n"
    output += f"1. **Use an allowlist** - Explicitly define which fields can be updated by the user.\n"
    output += f"2. **Use DTOs/schemas** - Separate input validation schemas from database models.\n"
    output += f"3. **Read-only decorators** - Mark sensitive fields as read-only in the ORM.\n\n"
    output += f"### Secure Implementation\n"
    output += f"```python\nALLOWED_FIELDS = {set(writable_fields)}\n\n"
    output += f"@app.route('{path}/<int:id>', methods=['{method}'])\n"
    output += f"@require_auth\n"
    output += f"def update_{resource}(id):\n"
    output += f"    {resource} = {resource.title()}.query.get(id)\n"
    output += f"    data = request.json\n"
    output += f"    for key, value in data.items():\n"
    output += f"        if key in ALLOWED_FIELDS:\n"
    output += f"            setattr({resource}, key, value)\n"
    output += f"    db.session.commit()\n"
    output += f"    return jsonify({resource}.to_dict())\n```"

    return cwe, input_text, output, f"Mass Assignment in {method} {path}"


def _build_graphql_scenario(rng, complexity, domain):
    gql_type = rng.choice(GRAPHQL_TYPES)
    issues = []

    introspection_enabled = rng.random() < 0.6
    max_depth = rng.choice([0, 5, 10, 50, 100])
    max_complexity = rng.choice([0, 100, 1000, 10000])

    input_text = f"## GraphQL API Configuration\n\n"
    input_text += f"**Endpoint:** POST https://{domain}/graphql\n\n"
    input_text += f"```yaml\ngraphql:\n"
    input_text += f"  introspection: {str(introspection_enabled).lower()}\n"
    input_text += f"  max_depth: {max_depth if max_depth > 0 else 'null  # unlimited'}\n"
    input_text += f"  max_complexity: {max_complexity if max_complexity > 0 else 'null  # unlimited'}\n"
    input_text += f"  playground: true\n"
    input_text += f"  debug: true\n"
    input_text += f"```\n\n"

    if introspection_enabled:
        issues.append("Introspection enabled in production")
    if max_depth == 0 or max_depth > 20:
        issues.append(f"No query depth limit (DoS via nested queries)")
    if max_complexity == 0 or max_complexity > 5000:
        issues.append("No query complexity limit")
    issues.append("GraphQL Playground enabled in production")
    issues.append("Debug mode enabled (verbose error messages)")

    input_text += f"**Sample Query (no auth required):**\n"
    input_text += f"```graphql\nquery {{\n"
    input_text += f"  __schema {{\n    types {{\n      name\n      fields {{\n        name\n        type {{ name }}\n      }}\n    }}\n  }}\n}}\n```"

    cwe = rng.choice(["CWE-200", "CWE-400", "CWE-284"])
    cwe_info = CWE_DB.get(cwe, {"name": "Info Exposure", "severity": ["medium"]})

    output = f"## GraphQL Security Assessment\n\n"
    output += f"**Endpoint:** https://{domain}/graphql\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** HIGH\n\n"
    output += f"### Findings\n\n"

    for i, issue in enumerate(issues, 1):
        output += f"**{i}. {issue}**\n"
        if "introspection" in issue.lower():
            output += f"Introspection allows any client to query the complete schema, revealing all types, "
            output += f"fields, mutations, and their arguments. This provides attackers a roadmap of the "
            output += f"entire API surface, including internal-only fields and deprecated endpoints.\n\n"
        elif "depth" in issue.lower():
            output += f"Without a query depth limit, attackers can craft deeply nested queries that cause "
            output += f"exponential resource consumption on the server:\n"
            output += f"```graphql\nquery {{ {gql_type.lower()} {{ friends {{ friends {{ friends {{ ... }} }} }} }} }}\n```\n\n"
        elif "complexity" in issue.lower():
            output += f"Without complexity analysis, expensive queries with many fields and relations "
            output += f"can overwhelm the server. Each resolver may trigger database queries, leading "
            output += f"to N+1 problems at scale.\n\n"
        elif "playground" in issue.lower():
            output += f"The GraphQL Playground (or GraphiQL) provides an interactive query builder that "
            output += f"aids attackers in exploring and exploiting the API.\n\n"
        elif "debug" in issue.lower():
            output += f"Debug mode exposes stack traces, query plans, and internal error details that "
            output += f"reveal implementation specifics useful for further attacks.\n\n"

    output += f"### Remediation\n"
    output += f"1. **Disable introspection** in production (`introspection: false`).\n"
    output += f"2. **Set query depth limit** to 10-15 levels maximum.\n"
    output += f"3. **Enable query complexity analysis** with a reasonable threshold (e.g., 1000).\n"
    output += f"4. **Disable Playground/GraphiQL** in production.\n"
    output += f"5. **Disable debug mode** - return generic error messages.\n"
    output += f"6. **Implement field-level authorization** on sensitive types.\n"
    output += f"7. **Use persisted queries** to prevent arbitrary query execution.\n"

    title = f"GraphQL Security: {', '.join(issues[:2])}"
    return cwe, input_text, output, title[:120]


def _build_data_exposure_scenario(rng, complexity, domain):
    resource = rng.choice(API_RESOURCES)
    method = "GET"
    path = f"/api/v{rng.choice(['1','2'])}/{resource}"
    sensitive = rng.sample(SENSITIVE_FIELDS, k=rng.randint(2, 4))
    safe_fields = ["id", "name", "created_at", "status", "type"]

    all_fields = safe_fields + sensitive
    rng.shuffle(all_fields)

    import json
    response_obj = {}
    for f in all_fields:
        if f in sensitive:
            response_obj[f] = "***SENSITIVE_DATA***"
        elif f == "id":
            response_obj[f] = rng.randint(1000, 9999)
        else:
            response_obj[f] = f"sample_{f}_value"

    input_text = f"## API Response Review\n\n"
    input_text += f"**Endpoint:** {method} https://{domain}{path}\n"
    input_text += f"**Description:** List {resource} (paginated)\n\n"
    input_text += f"**Response (200 OK):**\n```json\n{json.dumps({'data': [response_obj], 'total': 150, 'page': 1}, indent=2)}\n```\n\n"
    input_text += f"**Response Headers:**\n```\n"
    for k, v in RESPONSE_HEADERS_BAD.items():
        input_text += f"{k}: {v}\n"
    input_text += f"```"

    cwe = rng.choice(["CWE-200", "CWE-209", "CWE-532"])
    cwe_info = CWE_DB.get(cwe, {"name": "Information Exposure", "severity": ["medium"]})

    output = f"## Excessive Data Exposure Analysis\n\n"
    output += f"**Endpoint:** {method} {path}\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**OWASP API Security:** API3:2023 - Broken Object Property Level Authorization\n"
    output += f"**Severity:** HIGH\n\n"
    output += f"### Findings\n\n"
    output += f"**1. Sensitive Fields in Response**\n"
    output += f"The API response includes the following sensitive fields that should not be exposed:\n"
    for s in sensitive:
        output += f"- `{s}` - should never be returned in API responses\n"
    output += f"\n"
    output += f"**2. Insecure Response Headers**\n"
    output += f"- `Access-Control-Allow-Origin: *` - allows any domain to make cross-origin requests\n"
    output += f"- `X-Powered-By: Express` - reveals server technology\n"
    output += f"- `Server: Apache/2.4.49` - reveals server software and version\n\n"
    output += f"**3. Missing Security Headers**\n"
    for k, v in list(RESPONSE_HEADERS_GOOD.items())[:4]:
        output += f"- Missing `{k}: {v}`\n"
    output += f"\n"
    output += f"### Remediation\n"
    output += f"1. **Use response DTOs** - Define explicit response schemas that exclude sensitive fields.\n"
    output += f"2. **Remove server fingerprinting** - Strip `Server`, `X-Powered-By` headers.\n"
    output += f"3. **Restrict CORS** - Set `Access-Control-Allow-Origin` to specific trusted domains.\n"
    output += f"4. **Add security headers** - Include all recommended security response headers.\n"
    output += f"5. **Implement field-level filtering** based on the caller's role/permissions.\n"

    return cwe, input_text, output, f"Excessive Data Exposure in {method} {path}"


def _build_api_key_scenario(rng, complexity, domain):
    locations = [
        ("query parameter", f"GET https://{domain}/api/data?api_key=sk_live_abc123xyz789"),
        ("URL path", f"GET https://{domain}/api/sk_live_abc123xyz789/data"),
        ("custom header", f"GET https://{domain}/api/data\nX-API-Key: sk_live_abc123xyz789"),
        ("request body", f"POST https://{domain}/api/data\n{{\"api_key\": \"sk_live_abc123xyz789\"}}"),
    ]
    loc_name, loc_example = rng.choice(locations)

    input_text = f"## API Key Usage Review\n\n"
    input_text += f"**Application:** https://{domain}\n\n"
    input_text += f"**Observed API Key Transmission:**\n```\n{loc_example}\n```\n\n"
    input_text += f"**Additional Observations:**\n"
    input_text += f"- API key has no expiration date\n"
    input_text += f"- Same key used across development and production\n"
    input_text += f"- Key provides full read/write access to all endpoints\n"
    input_text += f"- No IP restriction on key usage\n"
    input_text += f"- Key visible in client-side JavaScript source\n"

    cwe = rng.choice(["CWE-522", "CWE-312", "CWE-798"])
    cwe_info = CWE_DB.get(cwe, {"name": "Credential Exposure", "severity": ["high"]})

    output = f"## API Key Security Assessment\n\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** CRITICAL\n\n"
    output += f"### Findings\n\n"
    output += f"**1. API Key in {loc_name.title()}**\n"
    if "query" in loc_name:
        output += f"API keys in query parameters are logged in server access logs, browser history, "
        output += f"proxy logs, and referrer headers. This is the highest-risk transmission method.\n\n"
    elif "path" in loc_name:
        output += f"API keys embedded in URL paths appear in access logs and can be cached by CDNs.\n\n"
    elif "body" in loc_name:
        output += f"While better than query params, keys in request bodies are logged by some "
        output += f"application firewalls and debugging tools.\n\n"
    else:
        output += f"Using a dedicated header is acceptable, but the header name should follow "
        output += f"standard conventions (e.g., `Authorization: Bearer <token>`).\n\n"

    output += f"**2. No Key Expiration**\nStatic keys that never expire increase the window of compromise.\n\n"
    output += f"**3. No Environment Separation**\nUsing the same key across environments means a development leak compromises production.\n\n"
    output += f"**4. Excessive Permissions**\nThe key has full access; a compromised key grants an attacker complete control.\n\n"
    output += f"**5. Client-Side Exposure**\nAPI keys in client-side JavaScript are visible to anyone inspecting the page source.\n\n"

    output += f"### Remediation\n"
    output += f"1. **Transmit keys via `Authorization` header** only (never in URLs).\n"
    output += f"2. **Set expiration** - Rotate keys every 90 days maximum.\n"
    output += f"3. **Separate environments** - Use distinct keys for dev, staging, production.\n"
    output += f"4. **Apply least privilege** - Scope keys to specific endpoints and methods.\n"
    output += f"5. **Use backend proxy** - Never expose API keys in client-side code.\n"
    output += f"6. **Restrict by IP** - Bind production keys to known server IPs.\n"
    output += f"7. **Monitor usage** - Alert on unusual key usage patterns.\n"

    return cwe, input_text, output, f"API Key Exposure via {loc_name.title()}"


def _build_injection_api_scenario(rng, complexity, domain):
    attack_type = rng.choice(["sql", "nosql", "graphql", "header", "ssrf"])
    path = f"/api/v{rng.choice(['1','2'])}/{rng.choice(API_RESOURCES)}"

    if attack_type == "sql":
        param = rng.choice(["search", "filter", "sort", "id", "name"])
        payload = rng.choice([
            f"' OR '1'='1' --",
            f"1; DROP TABLE users--",
            f"' UNION SELECT username,password FROM users--",
        ])
        input_text = f"## API Request Analysis\n\n"
        input_text += f"**Endpoint:** GET https://{domain}{path}?{param}={payload}\n\n"
        input_text += f"**Server Handler:**\n```python\n"
        input_text += f"query = f\"SELECT * FROM items WHERE {param} = '{{request.args['{param}']}}'\"\n"
        input_text += f"result = db.execute(query)\n```"
        cwe = "CWE-89"
        title = f"SQL Injection via API parameter '{param}'"

    elif attack_type == "nosql":
        input_text = f"## API Request Analysis\n\n"
        input_text += f"**Endpoint:** POST https://{domain}{path}/search\n\n"
        input_text += f"**Request Body:**\n```json\n{{\n"
        input_text += f"  \"username\": {{\"$gt\": \"\"}},\n"
        input_text += f"  \"password\": {{\"$gt\": \"\"}}\n}}\n```\n\n"
        input_text += f"**Server Handler:**\n```javascript\n"
        input_text += f"const result = await db.collection('users').findOne(req.body);\n```"
        cwe = "CWE-89"
        title = "NoSQL Injection via API request body"

    elif attack_type == "ssrf":
        input_text = f"## API Request Analysis\n\n"
        input_text += f"**Endpoint:** POST https://{domain}{path}/import\n\n"
        input_text += f"**Request Body:**\n```json\n{{\n"
        input_text += f"  \"source_url\": \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"\n}}\n```\n\n"
        input_text += f"**Server Handler:**\n```python\n"
        input_text += f"url = request.json['source_url']\n"
        input_text += f"response = requests.get(url)  # unvalidated URL\n"
        input_text += f"return process_import(response.content)\n```"
        cwe = "CWE-918"
        title = "SSRF via API import endpoint"

    else:
        input_text = f"## API Request Analysis\n\n"
        input_text += f"**Endpoint:** GET https://{domain}{path}\n\n"
        input_text += f"**Request Headers:**\n```\nX-Forwarded-For: 127.0.0.1\nX-Custom-Header: {{{{7*7}}}}\n```\n\n"
        input_text += f"**Server Handler:**\n```python\n"
        input_text += f"log.info(f\"Request from {{request.headers['X-Forwarded-For']}}\")\n"
        input_text += f"template = request.headers.get('X-Custom-Header', '')\n"
        input_text += f"rendered = jinja2.Template(template).render()\n```"
        cwe = "CWE-94"
        title = "Template Injection via API header"

    cwe_info = CWE_DB.get(cwe, {"name": "Injection", "severity": ["high", "critical"]})

    output = f"## API Injection Vulnerability Analysis\n\n"
    output += f"**Finding:** {title}\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** CRITICAL\n\n"
    output += f"### Description\n"
    output += f"The API endpoint `{path}` is vulnerable to injection because user-controlled input "
    output += f"is passed directly into a sensitive operation without sanitization or parameterization.\n\n"
    output += f"### Impact\n"
    if attack_type == "sql":
        output += f"- Data exfiltration via UNION-based queries\n"
        output += f"- Authentication bypass\n"
        output += f"- Data modification or deletion\n\n"
    elif attack_type == "nosql":
        output += f"- Authentication bypass via operator injection\n"
        output += f"- Data exfiltration\n"
        output += f"- Denial of service via expensive queries\n\n"
    elif attack_type == "ssrf":
        output += f"- Access to cloud metadata service (AWS/GCP/Azure credentials)\n"
        output += f"- Internal network scanning\n"
        output += f"- Access to internal services behind the firewall\n\n"
    else:
        output += f"- Remote code execution via template injection\n"
        output += f"- Server-side data access\n"
        output += f"- Full system compromise\n\n"

    output += f"### Remediation\n"
    if attack_type == "sql":
        output += f"1. **Use parameterized queries** - Never concatenate user input into SQL.\n"
        output += f"2. **Use an ORM** - Let the framework handle query construction.\n"
        output += f"3. **Input validation** - Validate and sanitize all parameters.\n"
    elif attack_type == "nosql":
        output += f"1. **Sanitize input** - Strip MongoDB operators (`$gt`, `$ne`, `$regex`) from input.\n"
        output += f"2. **Use schema validation** - Enforce expected types on all fields.\n"
        output += f"3. **Use Mongoose** - Leverage schema-based query construction.\n"
    elif attack_type == "ssrf":
        output += f"1. **Validate URLs** - Allowlist permitted domains and protocols (HTTPS only).\n"
        output += f"2. **Block internal IPs** - Reject requests to RFC1918, link-local, and loopback.\n"
        output += f"3. **Use IMDSv2** - Require session tokens for cloud metadata access.\n"
    else:
        output += f"1. **Never use user input in templates** - Separate data from template logic.\n"
        output += f"2. **Use sandboxed template engines** - Enable auto-escaping.\n"
        output += f"3. **Validate headers** - Strip or reject headers with template syntax.\n"

    return cwe, input_text, output, title


def _build_versioning_scenario(rng, complexity, domain):
    old_version = rng.choice(["v1", "v0", "v1-beta"])
    new_version = rng.choice(["v2", "v3"])
    path_old = f"/api/{old_version}/{rng.choice(API_RESOURCES)}"
    path_new = f"/api/{new_version}/{rng.choice(API_RESOURCES)}"

    input_text = f"## API Versioning Security Review\n\n"
    input_text += f"**Application:** https://{domain}\n\n"
    input_text += f"**Active Endpoints Discovered:**\n"
    input_text += f"- `{path_new}` (current, documented)\n"
    input_text += f"- `{path_old}` (legacy, still responding)\n\n"
    input_text += f"**Observations:**\n"
    input_text += f"- Legacy endpoint {path_old} does not require authentication\n"
    input_text += f"- Legacy endpoint returns additional fields not in {new_version}\n"
    input_text += f"- No deprecation headers on legacy responses\n"
    input_text += f"- API documentation only covers {new_version}\n"

    cwe = rng.choice(["CWE-284", "CWE-306", "CWE-200"])
    cwe_info = CWE_DB.get(cwe, {"name": "Access Control", "severity": ["medium", "high"]})

    output = f"## API Versioning Security Assessment\n\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**Severity:** HIGH\n\n"
    output += f"### Findings\n\n"
    output += f"**1. Legacy API Without Authentication**\n"
    output += f"The `{path_old}` endpoint is still active and does not enforce authentication. "
    output += f"This is a common issue when new API versions add security controls but legacy "
    output += f"versions remain accessible with weaker (or no) protections.\n\n"
    output += f"**2. Shadow API Surface**\n"
    output += f"Undocumented legacy endpoints expand the attack surface. Attackers routinely "
    output += f"scan for older API versions to find endpoints with weaker security.\n\n"
    output += f"**3. Excessive Data Exposure on Legacy Endpoint**\n"
    output += f"The legacy endpoint returns fields that were removed from {new_version} "
    output += f"for security reasons, potentially exposing sensitive data.\n\n"
    output += f"### Remediation\n"
    output += f"1. **Decommission legacy endpoints** - Remove or redirect {old_version} APIs.\n"
    output += f"2. **Apply uniform auth** - Ensure all API versions share the same auth middleware.\n"
    output += f"3. **API inventory** - Maintain a complete catalog of all active endpoints.\n"
    output += f"4. **Sunset headers** - Add `Sunset` and `Deprecation` headers to legacy APIs.\n"
    output += f"5. **API gateway** - Route all traffic through a gateway that enforces security policy.\n"

    return cwe, input_text, output, f"Insecure Legacy API: {path_old} still active"


# ── Scenario dispatch ──────────────────────────────────────────────────────

SCENARIO_BUILDERS = [
    (_build_bola_scenario, 0.18),
    (_build_jwt_scenario, 0.15),
    (_build_rate_limit_scenario, 0.12),
    (_build_oauth_scenario, 0.12),
    (_build_mass_assignment_scenario, 0.10),
    (_build_graphql_scenario, 0.10),
    (_build_data_exposure_scenario, 0.08),
    (_build_api_key_scenario, 0.05),
    (_build_injection_api_scenario, 0.05),
    (_build_versioning_scenario, 0.05),
]

SCENARIO_FUNCS = [b[0] for b in SCENARIO_BUILDERS]
SCENARIO_WEIGHTS = [b[1] for b in SCENARIO_BUILDERS]


# ── Generator class ────────────────────────────────────────────────────────

class APISecurityGenerator(CategoryGenerator):
    category = "api_security"
    id_prefix = "xld-api"

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
