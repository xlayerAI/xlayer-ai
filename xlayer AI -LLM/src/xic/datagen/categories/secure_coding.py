"""
Secure Coding generator.
Produces insecure-to-secure code transformation entries across multiple languages.
Topics: input validation, output encoding, parameterized queries, password hashing,
secure session management, error handling, file I/O, deserialization, least privilege.
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

SECURE_CODE_INSTRUCTIONS = [
    "Review the following code for security vulnerabilities. Identify the issue and provide a secure alternative with explanation.",
    "Analyze this code snippet for security anti-patterns. Explain why it is insecure and rewrite it using secure coding best practices.",
    "As a security code reviewer, identify the vulnerability in this code. Provide the secure version and explain the fix.",
    "Examine this code for common security weaknesses. Classify the vulnerability, explain the risk, and demonstrate the secure implementation.",
    "Perform a secure code review on the following snippet. Identify CWE violations and provide remediated code.",
    "Identify the security flaw in this code and explain how an attacker could exploit it. Then provide a hardened version.",
    "Review this code for OWASP Top 10 compliance. Point out violations and rewrite using defense-in-depth principles.",
    "Analyze this code snippet from a security perspective. Explain the vulnerability class, provide a proof-of-concept attack, and show the fix.",
    "As a senior security engineer, review this code. Identify insecure patterns, explain the threat model, and provide production-ready secure code.",
    "Evaluate this code against secure coding standards (CERT, OWASP). Identify weaknesses and provide compliant alternatives.",
    "This code contains a security vulnerability. Identify it, explain the potential impact, and refactor it to be secure.",
    "Assess the following code for input validation, output encoding, and access control weaknesses. Provide secure replacements.",
    "Review this code for injection vulnerabilities. Explain the attack surface and demonstrate proper parameterization.",
    "Identify the cryptographic weakness in this code. Explain why the current approach is insecure and provide a modern secure alternative.",
    "Analyze this authentication/authorization code for security flaws. Provide a hardened implementation following current best practices.",
    "Review this error handling code for information disclosure risks. Show how to handle errors securely without leaking sensitive data.",
]

# ── Topic definitions ─────────────────────────────────────────────────────

TOPICS = [
    "sql_injection", "xss_output", "command_injection", "path_traversal",
    "password_hashing", "session_management", "error_handling", "file_io",
    "deserialization", "input_validation", "crypto_weakness", "auth_bypass",
    "xxe_parsing", "ldap_injection", "log_injection",
]

LANGUAGES = ["python", "javascript", "java", "go"]

# ── SQL Injection ─────────────────────────────────────────────────────────

SQL_INJECTION_PAIRS = {
    "python": [
        {
            "insecure": 'def get_user(username):\n    query = f"SELECT * FROM users WHERE username = \'{username}\'"\n    cursor.execute(query)\n    return cursor.fetchone()',
            "secure": 'def get_user(username):\n    query = "SELECT * FROM users WHERE username = %s"\n    cursor.execute(query, (username,))\n    return cursor.fetchone()',
            "explanation": "String interpolation in SQL queries allows attackers to inject arbitrary SQL. Parameterized queries ensure user input is always treated as data, never as SQL code.",
        },
        {
            "insecure": 'def search_products(name, category):\n    sql = "SELECT * FROM products WHERE name LIKE \'%" + name + "%\' AND category = \'" + category + "\'"\n    return db.execute(sql)',
            "secure": 'def search_products(name, category):\n    sql = "SELECT * FROM products WHERE name LIKE %s AND category = %s"\n    return db.execute(sql, (f"%{name}%", category))',
            "explanation": "String concatenation with user input enables SQL injection. Using parameterized queries with LIKE requires wrapping the wildcard characters around the parameter value, not in the query string.",
        },
        {
            "insecure": 'def delete_order(order_id):\n    db.execute(f"DELETE FROM orders WHERE id = {order_id}")\n    db.commit()',
            "secure": 'def delete_order(order_id):\n    if not isinstance(order_id, int):\n        raise ValueError("order_id must be integer")\n    db.execute("DELETE FROM orders WHERE id = %s", (order_id,))\n    db.commit()',
            "explanation": "Even numeric inputs should use parameterized queries. Adding type validation provides defense-in-depth against injection via unexpected input types.",
        },
    ],
    "javascript": [
        {
            "insecure": 'app.get("/user", (req, res) => {\n  const query = `SELECT * FROM users WHERE id = ${req.query.id}`;\n  db.query(query, (err, result) => res.json(result));\n});',
            "secure": 'app.get("/user", (req, res) => {\n  const query = "SELECT * FROM users WHERE id = ?";\n  db.query(query, [req.query.id], (err, result) => res.json(result));\n});',
            "explanation": "Template literals interpolate user input directly into SQL. Use parameterized queries with placeholder markers to prevent injection.",
        },
        {
            "insecure": 'const getOrders = async (userId, status) => {\n  const sql = "SELECT * FROM orders WHERE user_id = " + userId + " AND status = \'" + status + "\'";\n  return await pool.query(sql);\n};',
            "secure": 'const getOrders = async (userId, status) => {\n  const sql = "SELECT * FROM orders WHERE user_id = $1 AND status = $2";\n  return await pool.query(sql, [userId, status]);\n};',
            "explanation": "String concatenation builds exploitable queries. PostgreSQL uses numbered placeholders ($1, $2) for parameterized queries.",
        },
    ],
    "java": [
        {
            "insecure": 'public User findUser(String username) {\n    String sql = "SELECT * FROM users WHERE username = \'" + username + "\'";\n    Statement stmt = conn.createStatement();\n    ResultSet rs = stmt.executeQuery(sql);\n    return mapUser(rs);\n}',
            "secure": 'public User findUser(String username) {\n    String sql = "SELECT * FROM users WHERE username = ?";\n    PreparedStatement pstmt = conn.prepareStatement(sql);\n    pstmt.setString(1, username);\n    ResultSet rs = pstmt.executeQuery();\n    return mapUser(rs);\n}',
            "explanation": "Statement with string concatenation is vulnerable to SQL injection. PreparedStatement separates SQL logic from data, preventing injection attacks.",
        },
        {
            "insecure": 'public List<Product> search(String term, String sort) {\n    String sql = "SELECT * FROM products WHERE name LIKE \'%" + term + "%\' ORDER BY " + sort;\n    return jdbcTemplate.query(sql, new ProductMapper());\n}',
            "secure": 'private static final Set<String> ALLOWED_SORTS = Set.of("name", "price", "date");\n\npublic List<Product> search(String term, String sort) {\n    if (!ALLOWED_SORTS.contains(sort)) sort = "name";\n    String sql = "SELECT * FROM products WHERE name LIKE ? ORDER BY " + sort;\n    return jdbcTemplate.query(sql, new ProductMapper(), "%" + term + "%");\n}',
            "explanation": "Column names cannot be parameterized, so ORDER BY requires allowlist validation. The search term uses a parameterized LIKE query.",
        },
    ],
    "go": [
        {
            "insecure": 'func GetUser(db *sql.DB, username string) (*User, error) {\n    query := fmt.Sprintf("SELECT * FROM users WHERE username = \'%s\'", username)\n    row := db.QueryRow(query)\n    var u User\n    err := row.Scan(&u.ID, &u.Name, &u.Email)\n    return &u, err\n}',
            "secure": 'func GetUser(db *sql.DB, username string) (*User, error) {\n    query := "SELECT id, name, email FROM users WHERE username = $1"\n    row := db.QueryRow(query, username)\n    var u User\n    err := row.Scan(&u.ID, &u.Name, &u.Email)\n    return &u, err\n}',
            "explanation": "fmt.Sprintf with user input creates SQL injection. Go database/sql uses positional placeholders ($1) with separate parameter arguments.",
        },
    ],
}

# ── XSS / Output Encoding ────────────────────────────────────────────────

XSS_PAIRS = {
    "python": [
        {
            "insecure": 'from flask import request\n\n@app.route("/greet")\ndef greet():\n    name = request.args.get("name", "")\n    return f"<h1>Hello, {name}!</h1>"',
            "secure": 'from flask import request\nfrom markupsafe import escape\n\n@app.route("/greet")\ndef greet():\n    name = escape(request.args.get("name", ""))\n    return f"<h1>Hello, {name}!</h1>"',
            "explanation": "Directly embedding user input in HTML without escaping enables XSS. The markupsafe.escape function HTML-encodes special characters (<, >, &, quotes).",
        },
    ],
    "javascript": [
        {
            "insecure": 'app.get("/search", (req, res) => {\n  res.send(`<p>Results for: ${req.query.q}</p>`);\n});',
            "secure": 'const escapeHtml = (str) => str.replace(/[&<>"\']/g, (m) => ({\n  "&": "&amp;", "<": "&lt;", ">": "&gt;", \'"\': "&quot;", "\'": "&#x27;"\n})[m]);\n\napp.get("/search", (req, res) => {\n  res.send(`<p>Results for: ${escapeHtml(req.query.q)}</p>`);\n});',
            "explanation": "Reflecting user input in HTML without encoding allows script injection. HTML entity encoding neutralizes special characters. Prefer template engines with auto-escaping.",
        },
        {
            "insecure": 'document.getElementById("output").innerHTML = userInput;',
            "secure": 'document.getElementById("output").textContent = userInput;',
            "explanation": "innerHTML parses and executes HTML/JavaScript in user input. textContent safely inserts text without HTML interpretation.",
        },
    ],
    "java": [
        {
            "insecure": 'protected void doGet(HttpServletRequest req, HttpServletResponse resp) {\n    String name = req.getParameter("name");\n    resp.getWriter().println("<div>Welcome, " + name + "</div>");\n}',
            "secure": 'import org.owasp.encoder.Encode;\n\nprotected void doGet(HttpServletRequest req, HttpServletResponse resp) {\n    String name = req.getParameter("name");\n    resp.getWriter().println("<div>Welcome, " + Encode.forHtml(name) + "</div>");\n}',
            "explanation": "Directly writing user input to response enables XSS. OWASP Java Encoder provides context-aware encoding for HTML, JavaScript, URL, and CSS contexts.",
        },
    ],
    "go": [
        {
            "insecure": 'func handler(w http.ResponseWriter, r *http.Request) {\n    name := r.URL.Query().Get("name")\n    fmt.Fprintf(w, "<h1>Hello, %s</h1>", name)\n}',
            "secure": 'func handler(w http.ResponseWriter, r *http.Request) {\n    name := r.URL.Query().Get("name")\n    tmpl := template.Must(template.New("").Parse("<h1>Hello, {{.}}</h1>"))\n    tmpl.Execute(w, name)\n}',
            "explanation": "fmt.Fprintf does no escaping. Go html/template auto-escapes values based on context, preventing XSS.",
        },
    ],
}

# ── Command Injection ─────────────────────────────────────────────────────

CMD_INJECTION_PAIRS = {
    "python": [
        {
            "insecure": 'import os\n\ndef ping_host(hostname):\n    result = os.system(f"ping -c 4 {hostname}")\n    return result',
            "secure": 'import subprocess\nimport re\n\ndef ping_host(hostname):\n    if not re.match(r"^[a-zA-Z0-9.-]+$", hostname):\n        raise ValueError("Invalid hostname")\n    result = subprocess.run(\n        ["ping", "-c", "4", hostname],\n        capture_output=True, text=True, timeout=30\n    )\n    return result.stdout',
            "explanation": "os.system passes input to a shell, allowing command chaining (;, &&, |). subprocess.run with a list argument avoids shell interpretation. Input validation adds defense-in-depth.",
        },
    ],
    "javascript": [
        {
            "insecure": 'const { exec } = require("child_process");\n\napp.post("/convert", (req, res) => {\n  exec(`ffmpeg -i ${req.body.filename} output.mp4`, (err, stdout) => {\n    res.send(stdout);\n  });\n});',
            "secure": 'const { execFile } = require("child_process");\nconst path = require("path");\n\napp.post("/convert", (req, res) => {\n  const safeName = path.basename(req.body.filename);\n  if (!/^[\\w.-]+$/.test(safeName)) return res.status(400).send("Invalid filename");\n  execFile("ffmpeg", ["-i", safeName, "output.mp4"], (err, stdout) => {\n    res.send(stdout);\n  });\n});',
            "explanation": "exec() passes the command string to a shell. execFile() bypasses the shell entirely, treating each argument as a literal. Path.basename and regex validation prevent path traversal and injection.",
        },
    ],
    "java": [
        {
            "insecure": 'public String runDiag(String host) throws Exception {\n    Process p = Runtime.getRuntime().exec("nslookup " + host);\n    return new String(p.getInputStream().readAllBytes());\n}',
            "secure": 'public String runDiag(String host) throws Exception {\n    if (!host.matches("^[a-zA-Z0-9.\\\\-]+$")) {\n        throw new IllegalArgumentException("Invalid hostname");\n    }\n    ProcessBuilder pb = new ProcessBuilder("nslookup", host);\n    pb.redirectErrorStream(true);\n    Process p = pb.start();\n    return new String(p.getInputStream().readAllBytes());\n}',
            "explanation": "Runtime.exec with a single string can invoke a shell. ProcessBuilder with separate arguments avoids shell interpretation. Input validation ensures only valid hostnames are accepted.",
        },
    ],
    "go": [
        {
            "insecure": 'func lookupDNS(host string) (string, error) {\n    cmd := exec.Command("sh", "-c", "dig "+host)\n    out, err := cmd.Output()\n    return string(out), err\n}',
            "secure": 'func lookupDNS(host string) (string, error) {\n    matched, _ := regexp.MatchString(`^[a-zA-Z0-9.-]+$`, host)\n    if !matched {\n        return "", fmt.Errorf("invalid hostname")\n    }\n    cmd := exec.Command("dig", host)\n    out, err := cmd.Output()\n    return string(out), err\n}',
            "explanation": "Using sh -c passes the command through a shell, enabling injection. Passing the command and arguments separately to exec.Command avoids shell interpretation.",
        },
    ],
}

# ── Path Traversal ────────────────────────────────────────────────────────

PATH_TRAVERSAL_PAIRS = {
    "python": [
        {
            "insecure": 'from flask import request, send_file\n\n@app.route("/download")\ndef download():\n    filename = request.args.get("file")\n    return send_file(f"/uploads/{filename}")',
            "secure": 'import os\nfrom flask import request, send_file, abort\n\nUPLOAD_DIR = "/uploads"\n\n@app.route("/download")\ndef download():\n    filename = request.args.get("file")\n    safe_path = os.path.realpath(os.path.join(UPLOAD_DIR, filename))\n    if not safe_path.startswith(os.path.realpath(UPLOAD_DIR)):\n        abort(403)\n    if not os.path.isfile(safe_path):\n        abort(404)\n    return send_file(safe_path)',
            "explanation": "Direct path concatenation allows ../../etc/passwd traversal. os.path.realpath resolves symlinks and relative paths, then the startswith check ensures the resolved path stays within the upload directory.",
        },
    ],
    "javascript": [
        {
            "insecure": 'app.get("/files/:name", (req, res) => {\n  res.sendFile(`/data/files/${req.params.name}`);\n});',
            "secure": 'const path = require("path");\n\nconst SAFE_DIR = "/data/files";\n\napp.get("/files/:name", (req, res) => {\n  const safePath = path.resolve(SAFE_DIR, req.params.name);\n  if (!safePath.startsWith(path.resolve(SAFE_DIR))) {\n    return res.status(403).send("Forbidden");\n  }\n  res.sendFile(safePath);\n});',
            "explanation": "Template literal path allows directory traversal. path.resolve normalizes the path, and the startswith check prevents breakout from the intended directory.",
        },
    ],
    "java": [
        {
            "insecure": 'public void serveFile(HttpServletRequest req, HttpServletResponse resp) {\n    String filename = req.getParameter("file");\n    File f = new File("/uploads/" + filename);\n    Files.copy(f.toPath(), resp.getOutputStream());\n}',
            "secure": 'public void serveFile(HttpServletRequest req, HttpServletResponse resp) {\n    String filename = req.getParameter("file");\n    Path basePath = Paths.get("/uploads").toRealPath();\n    Path resolved = basePath.resolve(filename).normalize().toRealPath();\n    if (!resolved.startsWith(basePath)) {\n        resp.sendError(403);\n        return;\n    }\n    Files.copy(resolved, resp.getOutputStream());\n}',
            "explanation": "Direct file path concatenation is vulnerable to traversal. Using toRealPath() and normalize() resolves the actual filesystem path, and startsWith validates containment within the base directory.",
        },
    ],
    "go": [
        {
            "insecure": 'func serveFile(w http.ResponseWriter, r *http.Request) {\n    filename := r.URL.Query().Get("file")\n    http.ServeFile(w, r, "/uploads/"+filename)\n}',
            "secure": 'func serveFile(w http.ResponseWriter, r *http.Request) {\n    filename := r.URL.Query().Get("file")\n    cleanPath := filepath.Clean(filename)\n    fullPath := filepath.Join("/uploads", cleanPath)\n    absPath, _ := filepath.Abs(fullPath)\n    if !strings.HasPrefix(absPath, "/uploads") {\n        http.Error(w, "Forbidden", http.StatusForbidden)\n        return\n    }\n    http.ServeFile(w, r, absPath)\n}',
            "explanation": "Direct concatenation allows traversal. filepath.Clean removes .. components, filepath.Abs resolves to absolute path, and HasPrefix ensures the path stays within /uploads.",
        },
    ],
}

# ── Password Hashing ─────────────────────────────────────────────────────

PASSWORD_PAIRS = {
    "python": [
        {
            "insecure": 'import hashlib\n\ndef store_password(password):\n    hashed = hashlib.md5(password.encode()).hexdigest()\n    db.execute("INSERT INTO users (password_hash) VALUES (%s)", (hashed,))',
            "secure": 'import bcrypt\n\ndef store_password(password):\n    salt = bcrypt.gensalt(rounds=12)\n    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)\n    db.execute("INSERT INTO users (password_hash) VALUES (%s)", (hashed,))\n\ndef verify_password(password, stored_hash):\n    return bcrypt.checkpw(password.encode("utf-8"), stored_hash)',
            "explanation": "MD5 is cryptographically broken and has no salt, making it vulnerable to rainbow tables and brute force. bcrypt is designed for password hashing: it includes a salt, is computationally expensive, and has a configurable work factor.",
        },
    ],
    "javascript": [
        {
            "insecure": 'const crypto = require("crypto");\n\nfunction hashPassword(password) {\n  return crypto.createHash("sha256").update(password).digest("hex");\n}',
            "secure": 'const bcrypt = require("bcrypt");\nconst SALT_ROUNDS = 12;\n\nasync function hashPassword(password) {\n  return await bcrypt.hash(password, SALT_ROUNDS);\n}\n\nasync function verifyPassword(password, hash) {\n  return await bcrypt.compare(password, hash);\n}',
            "explanation": "SHA-256 is a fast hash not designed for passwords. Without a salt, identical passwords produce identical hashes. bcrypt provides adaptive cost, built-in salt, and timing-safe comparison.",
        },
    ],
    "java": [
        {
            "insecure": 'import java.security.MessageDigest;\n\npublic String hashPassword(String password) {\n    MessageDigest md = MessageDigest.getInstance("SHA-1");\n    byte[] hash = md.digest(password.getBytes());\n    return Base64.getEncoder().encodeToString(hash);\n}',
            "secure": 'import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;\n\nprivate final Argon2PasswordEncoder encoder = \n    new Argon2PasswordEncoder(16, 32, 1, 65536, 3);\n\npublic String hashPassword(String password) {\n    return encoder.encode(password);\n}\n\npublic boolean verifyPassword(String password, String hash) {\n    return encoder.matches(password, hash);\n}',
            "explanation": "SHA-1 is deprecated and unsuitable for password hashing. Argon2 is the winner of the Password Hashing Competition, providing memory-hard computation that resists GPU and ASIC attacks.",
        },
    ],
    "go": [
        {
            "insecure": 'func hashPassword(password string) string {\n    h := sha256.Sum256([]byte(password))\n    return hex.EncodeToString(h[:])\n}',
            "secure": 'func hashPassword(password string) (string, error) {\n    hash, err := bcrypt.GenerateFromPassword(\n        []byte(password), bcrypt.DefaultCost,\n    )\n    return string(hash), err\n}\n\nfunc verifyPassword(password, hash string) bool {\n    err := bcrypt.CompareHashAndPassword(\n        []byte(hash), []byte(password),\n    )\n    return err == nil\n}',
            "explanation": "SHA-256 is a fast general-purpose hash. golang.org/x/crypto/bcrypt provides adaptive password hashing with built-in salt and constant-time comparison.",
        },
    ],
}

# ── Error Handling ────────────────────────────────────────────────────────

ERROR_HANDLING_PAIRS = {
    "python": [
        {
            "insecure": 'from flask import request\nimport traceback\n\n@app.route("/api/data")\ndef get_data():\n    try:\n        result = db.query(request.args["id"])\n        return jsonify(result)\n    except Exception as e:\n        return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500',
            "secure": 'import logging\nfrom flask import request\n\nlogger = logging.getLogger(__name__)\n\n@app.route("/api/data")\ndef get_data():\n    try:\n        data_id = request.args.get("id")\n        if not data_id:\n            return jsonify({"error": "Missing required parameter"}), 400\n        result = db.query(data_id)\n        return jsonify(result)\n    except ValueError:\n        return jsonify({"error": "Invalid parameter format"}), 400\n    except Exception as e:\n        logger.exception("Unexpected error in get_data")\n        return jsonify({"error": "An internal error occurred"}), 500',
            "explanation": "Returning exception messages and stack traces to clients exposes internal implementation details (database structure, file paths, library versions). Log details server-side; return generic messages to users.",
        },
    ],
    "javascript": [
        {
            "insecure": 'app.get("/api/user/:id", async (req, res) => {\n  try {\n    const user = await db.findUser(req.params.id);\n    res.json(user);\n  } catch (err) {\n    res.status(500).json({ error: err.message, stack: err.stack });\n  }\n});',
            "secure": 'const logger = require("./logger");\n\napp.get("/api/user/:id", async (req, res) => {\n  try {\n    const user = await db.findUser(req.params.id);\n    if (!user) return res.status(404).json({ error: "Resource not found" });\n    res.json(user);\n  } catch (err) {\n    const errorId = crypto.randomUUID();\n    logger.error({ errorId, err, params: req.params });\n    res.status(500).json({ error: "Internal server error", reference: errorId });\n  }\n});',
            "explanation": "Exposing err.message and err.stack reveals internal details. A unique error reference ID lets support teams correlate user reports with server logs without exposing internals.",
        },
    ],
    "java": [
        {
            "insecure": '@GetMapping("/api/account/{id}")\npublic ResponseEntity<?> getAccount(@PathVariable String id) {\n    try {\n        return ResponseEntity.ok(accountService.findById(id));\n    } catch (Exception e) {\n        return ResponseEntity.status(500)\n            .body(Map.of("error", e.getMessage(), "class", e.getClass().getName()));\n    }\n}',
            "secure": '@GetMapping("/api/account/{id}")\npublic ResponseEntity<?> getAccount(@PathVariable String id) {\n    try {\n        Account account = accountService.findById(id);\n        if (account == null) {\n            return ResponseEntity.notFound().build();\n        }\n        return ResponseEntity.ok(account);\n    } catch (IllegalArgumentException e) {\n        return ResponseEntity.badRequest()\n            .body(Map.of("error", "Invalid account identifier"));\n    } catch (Exception e) {\n        String refId = UUID.randomUUID().toString();\n        log.error("Error ref={}: {}", refId, e.getMessage(), e);\n        return ResponseEntity.status(500)\n            .body(Map.of("error", "Internal error", "reference", refId));\n    }\n}',
            "explanation": "Returning exception class names and messages helps attackers map internal architecture. Use typed exception handling with generic user messages and server-side logging with correlation IDs.",
        },
    ],
    "go": [
        {
            "insecure": 'func handler(w http.ResponseWriter, r *http.Request) {\n    data, err := fetchData(r.URL.Query().Get("id"))\n    if err != nil {\n        http.Error(w, fmt.Sprintf("Error: %v", err), 500)\n        return\n    }\n    json.NewEncoder(w).Encode(data)\n}',
            "secure": 'func handler(w http.ResponseWriter, r *http.Request) {\n    data, err := fetchData(r.URL.Query().Get("id"))\n    if err != nil {\n        refID := uuid.New().String()\n        log.Printf("error ref=%s: %v", refID, err)\n        w.Header().Set("Content-Type", "application/json")\n        w.WriteHeader(http.StatusInternalServerError)\n        json.NewEncoder(w).Encode(map[string]string{\n            "error": "internal server error",\n            "reference": refID,\n        })\n        return\n    }\n    json.NewEncoder(w).Encode(data)\n}',
            "explanation": "Sending err.Error() to clients leaks internal details. Log the full error server-side with a reference ID, return only a generic message to the client.",
        },
    ],
}

# ── Deserialization ───────────────────────────────────────────────────────

DESER_PAIRS = {
    "python": [
        {
            "insecure": 'import pickle\n\ndef load_session(data):\n    return pickle.loads(data)',
            "secure": 'import json\nimport hmac\nimport hashlib\n\nSECRET = os.environ["SESSION_SECRET"]\n\ndef load_session(data, signature):\n    expected = hmac.new(SECRET.encode(), data, hashlib.sha256).hexdigest()\n    if not hmac.compare_digest(expected, signature):\n        raise ValueError("Invalid session signature")\n    return json.loads(data)',
            "explanation": "pickle.loads executes arbitrary code during deserialization. Use safe formats like JSON and add HMAC signatures to verify data integrity and authenticity.",
        },
    ],
    "javascript": [
        {
            "insecure": 'const yaml = require("js-yaml");\n\napp.post("/config", (req, res) => {\n  const config = yaml.load(req.body.data);\n  applyConfig(config);\n});',
            "secure": 'const yaml = require("js-yaml");\n\napp.post("/config", (req, res) => {\n  const config = yaml.load(req.body.data, { schema: yaml.JSON_SCHEMA });\n  const validated = validateConfig(config);\n  applyConfig(validated);\n});',
            "explanation": "YAML's default schema supports language-specific types that can trigger code execution. Using JSON_SCHEMA restricts parsing to safe JSON-compatible types. Always validate deserialized data against an expected schema.",
        },
    ],
    "java": [
        {
            "insecure": 'public Object deserialize(byte[] data) {\n    ObjectInputStream ois = new ObjectInputStream(\n        new ByteArrayInputStream(data)\n    );\n    return ois.readObject();\n}',
            "secure": 'public Object deserialize(byte[] data) {\n    ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(\n        "com.myapp.model.*;!*"\n    );\n    ObjectInputStream ois = new ObjectInputStream(\n        new ByteArrayInputStream(data)\n    );\n    ois.setObjectInputFilter(filter);\n    return ois.readObject();\n}',
            "explanation": "Unrestricted Java deserialization allows arbitrary code execution via gadget chains. ObjectInputFilter (Java 9+) restricts which classes can be deserialized. Prefer JSON/protobuf over native serialization.",
        },
    ],
    "go": [
        {
            "insecure": 'func handleData(w http.ResponseWriter, r *http.Request) {\n    var data interface{}\n    json.NewDecoder(r.Body).Decode(&data)\n    processData(data)\n}',
            "secure": 'type SafeInput struct {\n    Name  string `json:"name" validate:"required,max=100"`\n    Value int    `json:"value" validate:"min=0,max=1000"`\n}\n\nfunc handleData(w http.ResponseWriter, r *http.Request) {\n    var data SafeInput\n    decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))\n    decoder.DisallowUnknownFields()\n    if err := decoder.Decode(&data); err != nil {\n        http.Error(w, "Invalid input", 400)\n        return\n    }\n    if err := validate.Struct(data); err != nil {\n        http.Error(w, "Validation failed", 400)\n        return\n    }\n    processData(data)\n}',
            "explanation": "Decoding into interface{} accepts any shape of data. Use typed structs with DisallowUnknownFields and struct validation to enforce expected schemas. LimitReader prevents denial-of-service via oversized payloads.",
        },
    ],
}

# ── Secure Session Management ─────────────────────────────────────────────

SESSION_PAIRS = {
    "python": [
        {
            "insecure": 'import hashlib, time\n\ndef create_session(user_id):\n    token = hashlib.md5(f"{user_id}{time.time()}".encode()).hexdigest()\n    sessions[token] = {"user_id": user_id}\n    response.set_cookie("session", token)\n    return token',
            "secure": 'import secrets\n\ndef create_session(user_id):\n    token = secrets.token_urlsafe(32)\n    sessions[token] = {\n        "user_id": user_id,\n        "created_at": time.time(),\n        "ip": request.remote_addr,\n    }\n    response.set_cookie(\n        "session", token,\n        httponly=True, secure=True, samesite="Strict",\n        max_age=3600\n    )\n    return token',
            "explanation": "MD5-hashed timestamps are predictable. secrets.token_urlsafe generates cryptographically random tokens. Cookie flags prevent XSS theft (HttpOnly), MITM (Secure), and CSRF (SameSite).",
        },
    ],
    "javascript": [
        {
            "insecure": 'function login(req, res) {\n  const sessionId = Math.random().toString(36).substr(2);\n  req.session = { id: sessionId, userId: req.body.userId };\n  res.cookie("sid", sessionId);\n  res.json({ success: true });\n}',
            "secure": 'const crypto = require("crypto");\n\nfunction login(req, res) {\n  const sessionId = crypto.randomBytes(32).toString("hex");\n  req.session.regenerate(() => {\n    req.session.userId = req.body.userId;\n    res.cookie("sid", sessionId, {\n      httpOnly: true,\n      secure: true,\n      sameSite: "strict",\n      maxAge: 3600000,\n    });\n    res.json({ success: true });\n  });\n}',
            "explanation": "Math.random() is not cryptographically secure. crypto.randomBytes provides sufficient entropy. Session regeneration after login prevents session fixation attacks.",
        },
    ],
    "java": [
        {
            "insecure": 'protected void doPost(HttpServletRequest req, HttpServletResponse resp) {\n    if (authenticate(req.getParameter("user"), req.getParameter("pass"))) {\n        HttpSession session = req.getSession();\n        session.setAttribute("authenticated", true);\n    }\n}',
            "secure": 'protected void doPost(HttpServletRequest req, HttpServletResponse resp) {\n    if (authenticate(req.getParameter("user"), req.getParameter("pass"))) {\n        req.getSession().invalidate();\n        HttpSession session = req.getSession(true);\n        session.setAttribute("authenticated", true);\n        session.setMaxInactiveInterval(1800);\n    }\n}',
            "explanation": "Reusing the existing session after authentication enables session fixation. Invalidating the old session and creating a new one ensures a fresh, unpredictable session ID post-login.",
        },
    ],
    "go": [
        {
            "insecure": 'func loginHandler(w http.ResponseWriter, r *http.Request) {\n    if authenticate(r.FormValue("user"), r.FormValue("pass")) {\n        http.SetCookie(w, &http.Cookie{\n            Name:  "session",\n            Value: r.FormValue("user"),\n        })\n    }\n}',
            "secure": 'func loginHandler(w http.ResponseWriter, r *http.Request) {\n    if authenticate(r.FormValue("user"), r.FormValue("pass")) {\n        b := make([]byte, 32)\n        if _, err := rand.Read(b); err != nil {\n            http.Error(w, "Internal error", 500)\n            return\n        }\n        token := base64.URLEncoding.EncodeToString(b)\n        store.Set(token, r.FormValue("user"), 30*time.Minute)\n        http.SetCookie(w, &http.Cookie{\n            Name:     "session",\n            Value:    token,\n            HttpOnly: true,\n            Secure:   true,\n            SameSite: http.SameSiteStrictMode,\n            MaxAge:   1800,\n        })\n    }\n}',
            "explanation": "Using the username as a session token is predictable and trivially forgeable. crypto/rand generates a secure random token that maps to user data server-side.",
        },
    ],
}

# ── Input Validation ──────────────────────────────────────────────────────

INPUT_VALIDATION_PAIRS = {
    "python": [
        {
            "insecure": 'from flask import request\n\n@app.route("/api/users/<user_id>")\ndef get_user(user_id):\n    return db.query(f"SELECT * FROM users WHERE id = {user_id}")',
            "secure": 'from flask import request, abort\nimport re\n\n@app.route("/api/users/<user_id>")\ndef get_user(user_id):\n    if not re.match(r"^[0-9]+$", user_id):\n        abort(400, "Invalid user ID format")\n    user_id_int = int(user_id)\n    if user_id_int <= 0 or user_id_int > 2**31:\n        abort(400, "User ID out of range")\n    return db.execute("SELECT * FROM users WHERE id = %s", (user_id_int,)).fetchone()',
            "explanation": "No validation allows any input including SQL injection payloads. Proper validation includes format checking (regex), type coercion, range validation, and parameterized queries as defense-in-depth.",
        },
    ],
    "javascript": [
        {
            "insecure": 'app.post("/api/register", (req, res) => {\n  const { email, age, role } = req.body;\n  db.query("INSERT INTO users (email, age, role) VALUES ($1, $2, $3)",\n    [email, age, role]);\n  res.json({ success: true });\n});',
            "secure": 'const Joi = require("joi");\n\nconst registerSchema = Joi.object({\n  email: Joi.string().email().max(254).required(),\n  age: Joi.number().integer().min(13).max(120).required(),\n  role: Joi.string().valid("user", "viewer").default("user"),\n});\n\napp.post("/api/register", (req, res) => {\n  const { error, value } = registerSchema.validate(req.body);\n  if (error) return res.status(400).json({ error: error.details[0].message });\n  db.query("INSERT INTO users (email, age, role) VALUES ($1, $2, $3)",\n    [value.email, value.age, value.role]);\n  res.json({ success: true });\n});',
            "explanation": "Accepting raw body parameters without validation allows invalid data, type confusion, and mass assignment (e.g., setting role to admin). Schema validation ensures type safety, bounds checking, and allowlisted values.",
        },
    ],
    "java": [
        {
            "insecure": '@PostMapping("/api/product")\npublic ResponseEntity<?> createProduct(@RequestBody Map<String, Object> body) {\n    String name = (String) body.get("name");\n    double price = (double) body.get("price");\n    productRepo.save(new Product(name, price));\n    return ResponseEntity.ok("Created");\n}',
            "secure": 'public class ProductDTO {\n    @NotBlank @Size(max = 200)\n    private String name;\n\n    @NotNull @DecimalMin("0.01") @DecimalMax("999999.99")\n    private BigDecimal price;\n}\n\n@PostMapping("/api/product")\npublic ResponseEntity<?> createProduct(\n        @Valid @RequestBody ProductDTO dto, BindingResult result) {\n    if (result.hasErrors()) {\n        return ResponseEntity.badRequest()\n            .body(result.getFieldErrors().stream()\n                .map(e -> e.getField() + ": " + e.getDefaultMessage())\n                .toList());\n    }\n    productRepo.save(new Product(dto.getName(), dto.getPrice()));\n    return ResponseEntity.ok("Created");\n}',
            "explanation": "Using raw Map accepts any fields including unexpected ones. A typed DTO with Bean Validation annotations enforces field presence, type, format, and range constraints at the framework level.",
        },
    ],
    "go": [
        {
            "insecure": 'func createUser(w http.ResponseWriter, r *http.Request) {\n    var input map[string]interface{}\n    json.NewDecoder(r.Body).Decode(&input)\n    db.Exec("INSERT INTO users (name, email) VALUES ($1, $2)",\n        input["name"], input["email"])\n}',
            "secure": 'type CreateUserInput struct {\n    Name  string `json:"name" validate:"required,min=1,max=100"`\n    Email string `json:"email" validate:"required,email,max=254"`\n}\n\nfunc createUser(w http.ResponseWriter, r *http.Request) {\n    var input CreateUserInput\n    decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<16))\n    decoder.DisallowUnknownFields()\n    if err := decoder.Decode(&input); err != nil {\n        http.Error(w, "Invalid JSON", 400)\n        return\n    }\n    if err := validate.Struct(input); err != nil {\n        http.Error(w, "Validation failed", 400)\n        return\n    }\n    db.Exec("INSERT INTO users (name, email) VALUES ($1, $2)",\n        input.Name, input.Email)\n}',
            "explanation": "map[string]interface{} provides no type safety or validation. Typed structs with validation tags enforce schema constraints. DisallowUnknownFields rejects unexpected fields, preventing mass assignment.",
        },
    ],
}

# ── Crypto Weakness ───────────────────────────────────────────────────────

CRYPTO_PAIRS = {
    "python": [
        {
            "insecure": 'import random\nimport string\n\ndef generate_token():\n    return "".join(random.choices(string.ascii_letters + string.digits, k=16))',
            "secure": 'import secrets\n\ndef generate_token():\n    return secrets.token_urlsafe(32)',
            "explanation": "random.choices uses a Mersenne Twister PRNG which is predictable. secrets module uses the OS cryptographic random source, providing tokens suitable for authentication and authorization.",
        },
    ],
    "javascript": [
        {
            "insecure": 'const crypto = require("crypto");\n\nfunction encrypt(text, key) {\n  const cipher = crypto.createCipher("aes-128-ecb", key);\n  return cipher.update(text, "utf8", "hex") + cipher.final("hex");\n}',
            "secure": 'const crypto = require("crypto");\n\nfunction encrypt(text, key) {\n  const iv = crypto.randomBytes(16);\n  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);\n  const encrypted = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);\n  const tag = cipher.getAuthTag();\n  return Buffer.concat([iv, tag, encrypted]).toString("base64");\n}',
            "explanation": "AES-ECB mode leaks patterns and provides no authentication. AES-256-GCM provides confidentiality, integrity, and authenticity. Random IVs prevent identical plaintext from producing identical ciphertext.",
        },
    ],
    "java": [
        {
            "insecure": 'public String encrypt(String data, String key) throws Exception {\n    Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");\n    SecretKey secretKey = new SecretKeySpec(key.getBytes(), "DES");\n    cipher.init(Cipher.ENCRYPT_MODE, secretKey);\n    return Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes()));\n}',
            "secure": 'public String encrypt(String data, SecretKey key) throws Exception {\n    byte[] iv = new byte[12];\n    SecureRandom.getInstanceStrong().nextBytes(iv);\n    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");\n    cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));\n    byte[] ciphertext = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));\n    ByteBuffer buf = ByteBuffer.allocate(iv.length + ciphertext.length);\n    buf.put(iv).put(ciphertext);\n    return Base64.getEncoder().encodeToString(buf.array());\n}',
            "explanation": "DES has a 56-bit key (brute-forceable) and ECB mode leaks patterns. AES-256-GCM with random IVs provides strong confidentiality and authentication. Always prepend the IV to the ciphertext for decryption.",
        },
    ],
    "go": [
        {
            "insecure": 'func encrypt(data, key []byte) []byte {\n    block, _ := aes.NewCipher(key)\n    encrypted := make([]byte, len(data))\n    block.Encrypt(encrypted, data)\n    return encrypted\n}',
            "secure": 'func encrypt(data, key []byte) ([]byte, error) {\n    block, err := aes.NewCipher(key)\n    if err != nil {\n        return nil, err\n    }\n    aesGCM, err := cipher.NewGCM(block)\n    if err != nil {\n        return nil, err\n    }\n    nonce := make([]byte, aesGCM.NonceSize())\n    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {\n        return nil, err\n    }\n    return aesGCM.Seal(nonce, nonce, data, nil), nil\n}',
            "explanation": "Direct block cipher encryption only encrypts one block with no IV, integrity, or padding. AES-GCM provides authenticated encryption with random nonces, protecting confidentiality and detecting tampering.",
        },
    ],
}

# ── Log Injection ─────────────────────────────────────────────────────────

LOG_INJECTION_PAIRS = {
    "python": [
        {
            "insecure": 'import logging\n\ndef handle_login(username, success):\n    logging.info(f"Login attempt: user={username} success={success}")',
            "secure": 'import logging\nimport re\n\ndef sanitize_log(value):\n    return re.sub(r"[\\n\\r\\t]", "_", str(value))[:200]\n\ndef handle_login(username, success):\n    logging.info("Login attempt: user=%s success=%s",\n                 sanitize_log(username), sanitize_log(success))',
            "explanation": "Unsanitized log input allows log injection via newline characters, forging log entries. Stripping control characters and using parameterized logging prevents log forging and potential log-based injection attacks (e.g., JNDI in Log4j).",
        },
    ],
    "javascript": [
        {
            "insecure": 'function logAction(userId, action) {\n  console.log(`User ${userId} performed ${action}`);\n}',
            "secure": 'const logger = require("pino")();\n\nfunction logAction(userId, action) {\n  const safeUserId = String(userId).replace(/[\\n\\r]/g, "").slice(0, 100);\n  const safeAction = String(action).replace(/[\\n\\r]/g, "").slice(0, 100);\n  logger.info({ userId: safeUserId, action: safeAction }, "User action");\n}',
            "explanation": "Template literal logging allows log injection via control characters. Structured logging (JSON) with sanitized fields prevents log forging and enables safer log analysis.",
        },
    ],
    "java": [
        {
            "insecure": 'private static final Logger log = LoggerFactory.getLogger(MyApp.class);\n\npublic void audit(String username, String action) {\n    log.info("User " + username + " performed " + action);\n}',
            "secure": 'private static final Logger log = LoggerFactory.getLogger(MyApp.class);\n\npublic void audit(String username, String action) {\n    String safeUser = username.replaceAll("[\\\\n\\\\r\\\\t]", "_");\n    String safeAction = action.replaceAll("[\\\\n\\\\r\\\\t]", "_");\n    log.info("User {} performed {}", safeUser, safeAction);\n}',
            "explanation": "String concatenation in log statements combined with unsanitized input enables CRLF injection for log forging. Parameterized logging with SLF4J and input sanitization prevents injection.",
        },
    ],
    "go": [
        {
            "insecure": 'func logRequest(user, path string) {\n    log.Printf("Request from %s to %s", user, path)\n}',
            "secure": 'func sanitizeLogField(s string) string {\n    s = strings.ReplaceAll(s, "\\n", "_")\n    s = strings.ReplaceAll(s, "\\r", "_")\n    if len(s) > 200 {\n        s = s[:200]\n    }\n    return s\n}\n\nfunc logRequest(user, path string) {\n    slog.Info("request",\n        "user", sanitizeLogField(user),\n        "path", sanitizeLogField(path))\n}',
            "explanation": "Printf-style logging with unsanitized input allows log injection. Structured logging with slog and field sanitization prevents log forging and enables machine-parseable log analysis.",
        },
    ],
}

# Map topic names to pair dictionaries
TOPIC_PAIRS = {
    "sql_injection": SQL_INJECTION_PAIRS,
    "xss_output": XSS_PAIRS,
    "command_injection": CMD_INJECTION_PAIRS,
    "path_traversal": PATH_TRAVERSAL_PAIRS,
    "password_hashing": PASSWORD_PAIRS,
    "session_management": SESSION_PAIRS,
    "error_handling": ERROR_HANDLING_PAIRS,
    "deserialization": DESER_PAIRS,
    "input_validation": INPUT_VALIDATION_PAIRS,
    "crypto_weakness": CRYPTO_PAIRS,
    "log_injection": LOG_INJECTION_PAIRS,
}

TOPIC_CWE_MAP = {
    "sql_injection": "CWE-89",
    "xss_output": "CWE-79",
    "command_injection": "CWE-78",
    "path_traversal": "CWE-22",
    "password_hashing": "CWE-916",
    "session_management": "CWE-384",
    "error_handling": "CWE-209",
    "deserialization": "CWE-502",
    "input_validation": "CWE-20",
    "crypto_weakness": "CWE-327",
    "auth_bypass": "CWE-287",
    "xxe_parsing": "CWE-611",
    "ldap_injection": "CWE-90",
    "log_injection": "CWE-117",
}

TOPIC_LABELS = {
    "sql_injection": "SQL Injection",
    "xss_output": "Cross-Site Scripting (Output Encoding)",
    "command_injection": "OS Command Injection",
    "path_traversal": "Path Traversal",
    "password_hashing": "Password Hashing",
    "session_management": "Secure Session Management",
    "error_handling": "Secure Error Handling",
    "deserialization": "Safe Deserialization",
    "input_validation": "Input Validation",
    "crypto_weakness": "Cryptographic Weakness",
    "auth_bypass": "Authentication Bypass",
    "xxe_parsing": "XXE Prevention",
    "ldap_injection": "LDAP Injection",
    "log_injection": "Log Injection",
}


def _generate_entry(rng, complexity, idx, prefix):
    """Generate a single secure coding entry."""
    topic = rng.choice(list(TOPIC_PAIRS.keys()))
    pairs = TOPIC_PAIRS[topic]
    lang = rng.choice(list(pairs.keys()))
    pair = rng.choice(pairs[lang])

    cwe = TOPIC_CWE_MAP.get(topic, "CWE-20")
    cwe_info = CWE_DB.get(cwe, {"name": topic, "severity": ["medium"], "owasp": "N/A"})
    severity = pick_severity(rng, complexity)
    app = rng.choice(APP_CONTEXTS)
    framework = rng.choice(FRAMEWORKS.get(lang, [lang.title()]))
    label = TOPIC_LABELS.get(topic, topic.replace("_", " ").title())

    input_text = f"**Language:** {lang.title()}\n"
    input_text += f"**Framework:** {framework}\n"
    input_text += f"**Application Context:** {app}\n"
    input_text += f"**Topic:** {label}\n\n"
    input_text += f"Review the following code for security issues:\n"
    input_text += f"```{lang}\n{pair['insecure']}\n```"

    output = f"## Secure Code Review: {label}\n\n"
    output += f"**CWE:** {cwe} ({cwe_info['name']})\n"
    output += f"**OWASP:** {cwe_info.get('owasp', 'N/A')} - {OWASP_TOP10.get(cwe_info.get('owasp', ''), 'N/A')}\n"
    output += f"**Severity:** {severity.upper()}\n"
    output += f"**Language:** {lang.title()} ({framework})\n\n"

    output += "### Vulnerability Identified\n"
    output += f"The code contains a **{label}** vulnerability. "
    output += f"{pair['explanation']}\n\n"

    output += "### Insecure Code\n"
    output += f"```{lang}\n{pair['insecure']}\n```\n\n"

    output += "### Secure Alternative\n"
    output += f"```{lang}\n{pair['secure']}\n```\n\n"

    output += "### Key Changes\n"
    changes = _derive_changes(topic)
    for c in changes:
        output += f"- {c}\n"
    output += "\n"

    if complexity in ("advanced", "expert"):
        output += "### Defense-in-Depth Recommendations\n"
        recs = _defense_in_depth(topic)
        for r in recs:
            output += f"- {r}\n"
        output += "\n"

    output += "### Testing Checklist\n"
    tests = _test_checklist(topic)
    for t in tests:
        output += f"- [ ] {t}\n"

    return format_entry(
        entry_id=f"{prefix}-{idx:05d}",
        title=f"Secure Coding: {label} in {lang.title()} ({framework})",
        severity=severity, cwe=cwe,
        instruction=rng.choice(SECURE_CODE_INSTRUCTIONS),
        input_text=input_text, output_text=output,
    )


def _derive_changes(topic):
    changes_map = {
        "sql_injection": [
            "Replaced string concatenation/interpolation with parameterized queries",
            "User input is passed as query parameters, never part of the SQL string",
            "Added input type validation as defense-in-depth",
        ],
        "xss_output": [
            "Applied context-aware output encoding before rendering user input",
            "Used framework's built-in escaping mechanisms",
            "Set appropriate Content-Type headers to prevent MIME sniffing",
        ],
        "command_injection": [
            "Replaced shell-based execution with direct process execution (no shell)",
            "Arguments passed as array/list, not concatenated into a command string",
            "Added input validation with allowlist pattern matching",
        ],
        "path_traversal": [
            "Resolved the full path and validated it stays within the allowed directory",
            "Used path canonicalization to resolve symlinks and relative components",
            "Added file existence check to prevent information disclosure via error messages",
        ],
        "password_hashing": [
            "Replaced fast hash (MD5/SHA) with adaptive password hash (bcrypt/argon2)",
            "Built-in salt generation eliminates rainbow table attacks",
            "Added constant-time comparison for password verification",
        ],
        "session_management": [
            "Used cryptographically secure random number generator for tokens",
            "Set HttpOnly, Secure, and SameSite flags on session cookies",
            "Added session regeneration to prevent session fixation",
        ],
        "error_handling": [
            "Replaced detailed error messages with generic user-facing messages",
            "Added server-side logging with correlation IDs for debugging",
            "Implemented specific exception handling instead of catching all exceptions",
        ],
        "deserialization": [
            "Replaced unsafe deserialization with safe data formats (JSON)",
            "Added integrity verification (HMAC/signature) for serialized data",
            "Implemented schema validation on deserialized objects",
        ],
        "input_validation": [
            "Added schema-based validation with type, format, and range constraints",
            "Rejected unexpected fields to prevent mass assignment",
            "Limited input size to prevent denial-of-service",
        ],
        "crypto_weakness": [
            "Upgraded from weak/broken algorithm to modern authenticated encryption",
            "Added random IV/nonce generation for each encryption operation",
            "Used authenticated encryption mode (GCM) for integrity protection",
        ],
        "log_injection": [
            "Sanitized user input to remove control characters before logging",
            "Switched to structured (JSON) logging format",
            "Added field length limits to prevent log flooding",
        ],
    }
    return changes_map.get(topic, ["Applied secure coding best practices"])


def _defense_in_depth(topic):
    recs_map = {
        "sql_injection": [
            "Deploy a Web Application Firewall (WAF) with SQL injection rules",
            "Use an ORM with built-in parameterization as primary data access layer",
            "Apply least privilege to database accounts (no DROP, GRANT permissions)",
            "Enable database query logging and anomaly detection",
        ],
        "xss_output": [
            "Deploy Content Security Policy headers to restrict script execution",
            "Implement Trusted Types API to prevent DOM XSS sinks",
            "Use DOMPurify for user-generated rich HTML content",
            "Enable CSP reporting to monitor for XSS attempts",
        ],
        "command_injection": [
            "Use language-native libraries instead of shell commands where possible",
            "Run processes in sandboxed environments with restricted permissions",
            "Implement allowlists for acceptable command arguments",
            "Monitor process execution with security auditing tools",
        ],
        "path_traversal": [
            "Use chroot or container isolation to restrict filesystem access",
            "Implement file access through an abstraction layer with ACLs",
            "Use random filenames for uploaded content (no user-controlled names)",
            "Enable filesystem-level auditing for sensitive directories",
        ],
        "password_hashing": [
            "Implement password complexity requirements and length minimums",
            "Check passwords against known-breached password databases (HaveIBeenPwned)",
            "Implement rate limiting on authentication endpoints",
            "Support multi-factor authentication as additional security layer",
        ],
        "session_management": [
            "Implement session timeout (idle and absolute)",
            "Bind sessions to client properties (IP, User-Agent fingerprint)",
            "Store sessions server-side (Redis/database) rather than client-side",
            "Implement concurrent session limits per user",
        ],
        "error_handling": [
            "Implement centralized exception handling middleware",
            "Use structured logging with security event categorization",
            "Set up alerting for unusual error patterns",
            "Conduct regular log reviews for security events",
        ],
        "deserialization": [
            "Prefer stateless tokens (JWT with signature verification) over serialized sessions",
            "Implement content-type validation before deserialization",
            "Use schema registries for structured data formats",
            "Monitor for deserialization-related gadget chain patterns",
        ],
        "input_validation": [
            "Implement validation at multiple layers (client, API gateway, service)",
            "Use OpenAPI/JSON Schema specifications for API contract enforcement",
            "Deploy API gateways with request validation capabilities",
            "Conduct fuzz testing to discover validation bypasses",
        ],
        "crypto_weakness": [
            "Use a key management service (KMS) for key storage and rotation",
            "Implement automatic key rotation policies",
            "Use envelope encryption for data-at-rest protection",
            "Conduct periodic cryptographic algorithm reviews",
        ],
        "log_injection": [
            "Use centralized log management with immutable storage",
            "Implement log integrity verification (signed log entries)",
            "Deploy SIEM with correlation rules for log-based attacks",
            "Regular audit of logging configurations and output",
        ],
    }
    return recs_map.get(topic, ["Follow industry secure coding standards"])


def _test_checklist(topic):
    tests_map = {
        "sql_injection": [
            "Test with single quotes, double quotes, and SQL keywords in all inputs",
            "Verify parameterized queries are used in all database interactions",
            "Run SAST tool to detect string-concatenated SQL queries",
            "Test with sqlmap or similar tool against all endpoints",
        ],
        "xss_output": [
            "Test with <script>alert(1)</script> in all input fields",
            "Verify output encoding is applied in HTML, attribute, JS, and URL contexts",
            "Check that CSP headers are present and restrictive",
            "Run DOM XSS scanner against client-side JavaScript",
        ],
        "command_injection": [
            "Test with ; && | ` $() in all inputs that may reach command execution",
            "Verify no shell-based execution functions are used with user input",
            "Confirm process execution uses array-based arguments",
            "Review all exec/system/popen calls in the codebase",
        ],
        "path_traversal": [
            "Test with ../../../etc/passwd and URL-encoded variants",
            "Verify path canonicalization and containment checks",
            "Test with symbolic links and null bytes in filenames",
            "Confirm uploaded file storage uses random names",
        ],
        "password_hashing": [
            "Verify bcrypt/argon2/scrypt is used (not MD5/SHA)",
            "Confirm work factor/cost parameter meets current recommendations",
            "Test that password verification uses constant-time comparison",
            "Verify no plaintext passwords in logs, errors, or responses",
        ],
        "session_management": [
            "Verify session tokens have sufficient entropy (128+ bits)",
            "Test for session fixation by checking token regeneration on login",
            "Confirm HttpOnly, Secure, SameSite flags on session cookies",
            "Test session timeout and invalidation on logout",
        ],
        "error_handling": [
            "Verify no stack traces, SQL queries, or file paths in error responses",
            "Confirm server-side error logging includes correlation IDs",
            "Test error responses for information leakage under various failure modes",
            "Verify custom error pages for all HTTP error codes",
        ],
        "deserialization": [
            "Verify no native serialization (pickle, ObjectInputStream) on untrusted data",
            "Test with crafted payloads against deserialization endpoints",
            "Confirm integrity checks (HMAC) on serialized data",
            "Review all data parsing for type confusion vulnerabilities",
        ],
        "input_validation": [
            "Test boundary values, null inputs, and oversized inputs",
            "Verify server-side validation (do not rely on client-side only)",
            "Test with unexpected types (string where int expected, arrays where string)",
            "Confirm allowlisting for enumerated fields (roles, statuses)",
        ],
        "crypto_weakness": [
            "Verify AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption",
            "Confirm random IV/nonce generation for each operation",
            "Test that crypto keys are not hardcoded in source code",
            "Review key storage and rotation mechanisms",
        ],
        "log_injection": [
            "Test with newline characters in all logged inputs",
            "Verify structured logging format is used throughout",
            "Confirm log field sanitization removes control characters",
            "Test log output for JNDI/format string injection patterns",
        ],
    }
    return tests_map.get(topic, ["Conduct security testing for this vulnerability class"])


# ── Main generator ────────────────────────────────────────────────────────

class SecureCodingGenerator(CategoryGenerator):
    category = "secure_coding"
    id_prefix = "xld-secure"

    def generate_entries(self, rng: random.Random, count: int, start_id: int,
                         complexity_weights: Dict[str, float]) -> List[Dict[str, Any]]:
        entries = []
        idx = start_id

        for i in range(count):
            complexity = pick_complexity(rng, complexity_weights)
            entries.append(_generate_entry(rng, complexity, idx, self.id_prefix))
            idx += 1

        return entries
