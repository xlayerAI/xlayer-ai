"""
engine/chain/patterns.py — Built-in Attack Chain Templates

These are statically defined, battle-tested chains.
The engine also learns new ones at runtime via PatternDistiller.
"""

from .models import ChainPattern, ChainStep

CHAIN_PATTERNS: list = [

    # ── JWT ──────────────────────────────────────────────────────────────────

    ChainPattern(
        name="jwt_alg_none_admin",
        description="JWT algorithm=none accepted → forge admin token → admin access",
        requires={"jwt_none_alg", "admin_endpoint"},
        severity="critical",
        steps=[
            ChainStep(
                name="forge_none_jwt",
                description="Forge JWT with alg=none and role=admin",
                input_keys=["jwt_token"],
                output_keys=["forged_jwt"],
            ),
            ChainStep(
                name="access_admin_endpoint",
                description="Use forged JWT on admin endpoint",
                input_keys=["forged_jwt", "admin_endpoint"],
                output_keys=["admin_response", "admin_access"],
            ),
        ],
    ),

    ChainPattern(
        name="jwt_weak_secret_admin",
        description="JWT HS256 weak secret → crack → forge admin → admin access",
        requires={"jwt_weak_secret", "admin_endpoint"},
        severity="critical",
        steps=[
            ChainStep(
                name="crack_jwt_secret",
                description="Brute-force HS256 JWT secret using common wordlist",
                input_keys=["jwt_token"],
                output_keys=["jwt_secret"],
            ),
            ChainStep(
                name="forge_admin_jwt",
                description="Re-sign JWT with cracked secret, role=admin",
                input_keys=["jwt_token", "jwt_secret"],
                output_keys=["forged_jwt"],
            ),
            ChainStep(
                name="access_admin_endpoint",
                description="Use forged JWT on admin endpoint",
                input_keys=["forged_jwt", "admin_endpoint"],
                output_keys=["admin_response", "admin_access"],
            ),
        ],
    ),

    # ── SSRF ─────────────────────────────────────────────────────────────────

    ChainPattern(
        name="ssrf_aws_metadata",
        description="SSRF confirmed → probe AWS metadata → extract IAM credentials",
        requires={"ssrf_confirmed"},
        severity="critical",
        steps=[
            ChainStep(
                name="probe_metadata_endpoint",
                description="Use SSRF to reach http://169.254.169.254/latest/meta-data/",
                input_keys=["ssrf_endpoint", "ssrf_param"],
                output_keys=["iam_role_name", "metadata_response"],
            ),
            ChainStep(
                name="extract_iam_credentials",
                description="Fetch IAM role credentials from metadata endpoint",
                input_keys=["ssrf_endpoint", "ssrf_param", "iam_role_name"],
                output_keys=["aws_access_key", "aws_secret_key", "aws_token"],
            ),
        ],
    ),

    ChainPattern(
        name="ssrf_internal_service",
        description="SSRF → probe internal network → access internal services",
        requires={"ssrf_confirmed"},
        severity="high",
        steps=[
            ChainStep(
                name="probe_internal_hosts",
                description="Scan common internal IPs via SSRF (10.x, 172.x, 192.168.x)",
                input_keys=["ssrf_endpoint", "ssrf_param"],
                output_keys=["internal_hosts", "open_ports"],
            ),
            ChainStep(
                name="access_internal_service",
                description="Access discovered internal service",
                input_keys=["ssrf_endpoint", "ssrf_param", "internal_hosts"],
                output_keys=["internal_response"],
            ),
        ],
    ),

    # ── IDOR ─────────────────────────────────────────────────────────────────

    ChainPattern(
        name="idor_privilege_escalation",
        description="IDOR on user resource → modify own role → admin escalation",
        requires={"idor_confirmed", "role_param"},
        severity="critical",
        steps=[
            ChainStep(
                name="enumerate_user_ids",
                description="IDOR: access adjacent user IDs to find admin accounts",
                input_keys=["idor_endpoint", "idor_param"],
                output_keys=["admin_user_id", "user_data"],
            ),
            ChainStep(
                name="modify_role_to_admin",
                description="IDOR: modify own account role field to admin",
                input_keys=["idor_endpoint", "idor_param"],
                output_keys=["escalation_response"],
            ),
            ChainStep(
                name="verify_admin_access",
                description="Verify admin access after role escalation",
                input_keys=["admin_endpoint"],
                output_keys=["admin_access_confirmed"],
            ),
        ],
    ),

    # ── Info Disclosure ───────────────────────────────────────────────────────

    ChainPattern(
        name="secret_leak_to_auth",
        description="Secret found in JS/response → use secret to authenticate",
        requires={"secret_leaked", "auth_endpoint"},
        severity="critical",
        steps=[
            ChainStep(
                name="extract_leaked_secret",
                description="Retrieve and classify the leaked secret",
                input_keys=["secret_value", "secret_key"],
                output_keys=["extracted_credential"],
            ),
            ChainStep(
                name="authenticate_with_secret",
                description="Use leaked secret to authenticate to auth endpoint",
                input_keys=["extracted_credential", "auth_endpoint"],
                output_keys=["session_token", "auth_response"],
            ),
            ChainStep(
                name="access_protected_resources",
                description="Use obtained session to access protected endpoints",
                input_keys=["session_token"],
                output_keys=["protected_response"],
            ),
        ],
    ),

    ChainPattern(
        name="debug_endpoint_to_rce",
        description="Debug/actuator endpoint exposes shell or eval → RCE",
        requires={"debug_endpoint", "command_exec"},
        severity="critical",
        steps=[
            ChainStep(
                name="probe_debug_endpoint",
                description="Access debug/actuator endpoint to confirm exposure",
                input_keys=["debug_endpoint"],
                output_keys=["debug_response", "exec_capability"],
            ),
            ChainStep(
                name="execute_command",
                description="Execute system command via debug endpoint",
                input_keys=["debug_endpoint", "exec_capability"],
                output_keys=["command_output", "rce_confirmed"],
            ),
        ],
    ),

    # ── CORS + Auth ───────────────────────────────────────────────────────────

    ChainPattern(
        name="cors_open_credential_steal",
        description="CORS wildcard + auth endpoint → steal credentials from victim browser",
        requires={"cors_open", "auth_endpoint"},
        severity="high",
        steps=[
            ChainStep(
                name="confirm_cors_bypass",
                description="Confirm CORS allows arbitrary origin with credentials",
                input_keys=["auth_endpoint"],
                output_keys=["cors_bypass_confirmed", "allowed_origin"],
            ),
            ChainStep(
                name="build_cors_poc",
                description="Build JavaScript PoC that steals auth tokens via CORS",
                input_keys=["auth_endpoint", "cors_bypass_confirmed"],
                output_keys=["poc_js", "steal_response"],
            ),
        ],
    ),

    # ── SQLi + Data ───────────────────────────────────────────────────────────

    ChainPattern(
        name="sqli_credential_dump",
        description="SQLi confirmed → dump credentials table → crack → account access",
        requires={"sqli_confirmed", "auth_endpoint"},
        severity="critical",
        steps=[
            ChainStep(
                name="enumerate_tables",
                description="Use SQLi to list database tables",
                input_keys=["sqli_endpoint", "sqli_param"],
                output_keys=["table_names"],
            ),
            ChainStep(
                name="dump_credentials",
                description="Extract username/password from users/accounts table",
                input_keys=["sqli_endpoint", "sqli_param", "table_names"],
                output_keys=["credential_dump"],
            ),
            ChainStep(
                name="authenticate_with_dumped_creds",
                description="Use dumped credentials to authenticate",
                input_keys=["credential_dump", "auth_endpoint"],
                output_keys=["admin_session"],
            ),
        ],
    ),

    # ── GraphQL ───────────────────────────────────────────────────────────────

    ChainPattern(
        name="graphql_introspection_to_idor",
        description="GraphQL introspection enabled → find hidden mutations → IDOR/auth bypass",
        requires={"graphql_endpoint"},
        severity="high",
        steps=[
            ChainStep(
                name="run_introspection",
                description="Run full GraphQL introspection to get all queries/mutations",
                input_keys=["graphql_endpoint"],
                output_keys=["schema_queries", "schema_mutations"],
            ),
            ChainStep(
                name="test_hidden_mutations",
                description="Test privileged mutations not exposed in UI",
                input_keys=["graphql_endpoint", "schema_mutations"],
                output_keys=["accessible_mutations", "mutation_response"],
            ),
        ],
    ),

]
