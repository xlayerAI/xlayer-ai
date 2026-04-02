# Mutation Engine — के के थप्नुपर्छ (What to Add)

यो फाइलमा `mutation_engine.py` मा थप्नुपर्ने र सुधार गर्नुपर्ने कुराहरू सूचीबद्ध छन्।

---

## 1. पहिले नै रहेका limitation हरू fix गर्ने

### 1.1 Context (ctx) पूरै use गर्ने
- **`ctx.waf`** अहिले कहीं पनि use भएको छैन।  
  - WAF type अनुसार strategy: जस्तै `mod_security` भए space_sub/comment_sandwich priority बढाउने, `cloudflare` भए hex/unicode जस्ता encoding जोड्ने।
- **XSS मा `filtered_chars`** use गर्ने: जस्तै `'<'` filter भएको भए HTML entity वा unicode variant मात्र suggest गर्ने।
- **Auth मा `filtered_chars`** use गर्ने: quote filter भए sqli_no_quote/hex मात्र priority बढाउने।

### 1.2 Auth: username payload बाट लिने
- **Case variation** र **Unicode bypass** मा हार्डकोडेड `"admin"` नराखी **payload बाट username extract** गर्ने (वा ctx मा `username_hint` जोड्ने र त्यो use गर्ने)。
- जस्तै: `_auth_case_variations(payload or "admin")` वा ctx.username_candidate।

### 1.3 SSRF: input URL लाई base बनाउने
- दिइएको `payload` (URL) लाई **mutate** गर्ने:
  - Payload मा host part पत्ता लगाएर त्यसलाई IPv6/decimal/octal/hex/localhost/metadata मा replace गर्ने।
  - Path र query preserve गर्दै scheme/host variants generate गर्ने।
- Static list साथै **payload-based variants** पनि return गर्ने।

### 1.4 Deduplication र limit
- **`mutate_to_strings(..., limit=30)`**: default 30 को सट्टा 50–100 वा configurable (settings बाट) बनाउने; वा `limit=None` मा सबै दिने option।
- **Near-duplicate** (जस्तै URL-encoded र raw एउटै meaning) लाई एकै group मा राख्ने optional step — जटिल भए skip पनि सकिन्छ।

---

## 2. नयाँ vulnerability types थप्ने (16 hunters संग match)

प्रोजेक्टमा **16 hunters** छन् तर mutation engine मा **5 मात्र** (sqli, xss, lfi, ssrf, auth)। अरू hunters को लागि mutation support थप्नुपर्छ।

### 2.1 SSTI (Server-Side Template Injection)
- **Dispatch मा थप्ने**: `"ssti": self._ssti_mutations`
- **Techniques**:  
  - `{{7*7}}`, `{{config}}`, `${7*7}`, `<%= 7*7 %>`, `#{(7*7)}`, `{{''.__class__}}`,  
  - Jinja2 / Twig / Freemarker / Pebble / Velocity / Smarty / Mako bypass (filter/escape bypass),  
  - Unicode, tag split, newline/comment variants।

### 2.2 RCE (Remote Code Execution) / Command Injection
- **Dispatch मा थप्ने**: `"rce": self._rce_mutations` (वा `"cmd_injection"`)
- **Techniques**:  
  - Separator variants: `;`, `|`, `` ` ``, `$()`, `&&`, `||`, `\n`, `%0a`  
  - Encoding: base64, hex, octal  
  - Variable/brace expansion: `${IFS}`, `{cat,/etc/passwd}`  
  - Space bypass: `$IFS`, `<`, `<>`, `%09`  
  - Windows: `%COMSPEC%`, `powershell -enc`, `cmd /c`

### 2.3 XXE (XML External Entity)
- **Dispatch मा थप्ने**: `"xxe": self._xxe_mutations`
- **Techniques**:  
  - External entity, parameter entity,  
  - Local file: `file:///etc/passwd`, `php://filter/...`,  
  - SSRF/out-of-band: `http://`, `expect://`,  
  - DOCTYPE/encoding bypass (UTF-8, UTF-16, etc.)

### 2.4 Open Redirect
- **Dispatch मा थप्ने**: `"open_redirect": self._open_redirect_mutations`
- **Techniques**:  
  - Payload (URL) लाई: double encode, `//evil.com`, `\/\/evil.com`, `https:evil.com`,  
  - Subdomain: `https://target.com.evil.com`,  
  - Null byte, `@evil.com`, `?url=...`, `#...`,  
  - JavaScript/data URI जहाँ supported।

### 2.5 (Optional) अरू types — जसको payload mutation फाइदाजनक छ
- **CORS**: origin header variants (null, subdomain, suffix, scheme) — यदि hunter ले payload send गर्छ भने।
- **GraphQL**: alias overflow, batch, persisted query bypass — mutation list जोड्न सकिन्छ।
- **Deserialization**: Java/Python/PHP gadget chain hints वा magic method names — payload shape अनुसार।

---

## 3. SQLi मा अरू DB support

- **PostgreSQL**: `CHR()` encoding, `$$` dollar quote, `:name` placeholder bypass, versioned-comment जस्तो PostgreSQL-style।
- **MSSQL**: `WAITFOR DELAY`, bracket quote `[ ]`, `CHAR()` + concatenation।
- **Oracle**: `CHR()` + `||`, dual, DBMS_XMLGEN।
- **ctx.database** (अगाडि payload_generator मा छ) use गरेर DB-specific mutations मात्र जोड्ने वा priority दिने।

---

## 4. LFI मा non-PHP

- **Java** (जस्तै `file://`, jar:, netdoc:): यदि ctx.language / ctx.framework मा java आउँछ भने यी wrapper को list।
- **.NET**: `file://`, UNC path।
- **Python**: `file://` र framework-specific include patterns।  
(Scope ठूलो भएमा phase 2 मा पनि राख्न सकिन्छ।)

---

## 5. Combination / chaining (optional, phase 2)

- एउटै payload मा **दुई वा बढी technique** लगाउने: जस्तै SQLi मा "hex_strings + versioned_comment + space_sub"।  
- Priority र explosion (संख्या नियन्त्रण) सावधानीपूर्वक राख्नुपर्छ।

---

## 6. Priority र config

- **Priority** अहिले hardcoded।  
  - Optional: `ctx` वा config बाट per-technique priority override (जस्तै WAF name अनुसार)।  
- **Config**: `settings.py` वा env बाट `mutation_limit_default`, `mutation_skip_failed` (already in ctx) जस्ता option।

---

## 7. Implementation order (सिफारिश)

| Priority | Item | Effort |
|----------|------|--------|
| 1 | Auth: username payload/ctx बाट लिने | S |
| 2 | SSRF: payload-based URL mutations | M |
| 3 | ctx.waf र filtered_chars use (SQLi/XSS/Auth) | M |
| 4 | mutate_to_strings limit configurable / बढाउने | S |
| 5 | SSTI mutations + dispatch | M |
| 6 | RCE/Command injection mutations + dispatch | M |
| 7 | XXE mutations + dispatch | M |
| 8 | Open Redirect mutations + dispatch | S–M |
| 9 | SQLi: PostgreSQL/MSSQL/Oracle (ctx.database) | M |
| 10 | LFI: Java/.NET (ctx.language) | M |
| 11 | Combination mutations (optional) | L |
| 12 | Adaptive/override priority (optional) | S |

---

## 8. Summary

- **Fix**: ctx पूरै use (waf, filtered_chars), auth मा dynamic username, SSRF मा payload-based mutations, limit config।
- **Add vuln types**: ssti, rce, xxe, open_redirect (र optional: cors/graphql/deserialization)।
- **Add DB/stack**: SQLi मा अरू DB; LFI मा non-PHP (Java/.NET)।
- **Optional**: combination mutations, adaptive priority।

यो सबै गरेपछि mutation engine 16 hunters संग align हुने र limitation घट्ने छ।
