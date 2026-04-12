"""
Parameterized vulnerable code snippet generators.
Each function returns (vulnerable_code, fixed_code, vuln_info) with
randomized variable/function/table names for diversity.
"""

import random
from typing import Tuple, Dict


def _names(rng: random.Random):
    """Generate randomized names for variables, tables, functions."""
    tables = ["users", "accounts", "customers", "employees", "orders", "products", "sessions", "payments"]
    id_cols = ["user_id", "account_id", "customer_id", "emp_id", "order_id", "product_id"]
    funcs = ["get_data", "fetch_record", "load_item", "find_entry", "retrieve_info", "lookup_record"]
    params = ["user_input", "query_param", "request_data", "form_value", "search_term", "filter_text"]
    return {
        "table": rng.choice(tables),
        "id_col": rng.choice(id_cols),
        "func": rng.choice(funcs),
        "param": rng.choice(params),
        "var": rng.choice(["result", "data", "record", "rows", "output", "response"]),
    }


# ── SQL Injection ────────────────────────────────────────────────────────────

def sqli_python(rng: random.Random) -> Tuple[str, str, Dict]:
    n = _names(rng)
    vuln = f'''def {n["func"]}({n["param"]}):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM {n["table"]} WHERE {n["id_col"]} = '{{{n["param"]}}}'"
    cursor.execute(query)
    {n["var"]} = cursor.fetchall()
    conn.close()
    return {n["var"]}'''

    fix = f'''def {n["func"]}({n["param"]}):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM {n["table"]} WHERE {n["id_col"]} = ?"
    cursor.execute(query, ({n["param"]},))
    {n["var"]} = cursor.fetchall()
    conn.close()
    return {n["var"]}'''

    info = {"cwe": "CWE-89", "name": "SQL Injection", "language": "python",
            "severity": "critical", "line": 4,
            "root_cause": f"User input '{n['param']}' is directly interpolated into the SQL query via f-string",
            "fix_desc": "Use parameterized queries with placeholder '?' and pass input as a tuple"}
    return vuln, fix, info


def sqli_javascript(rng: random.Random) -> Tuple[str, str, Dict]:
    n = _names(rng)
    routes = ["/api/search", "/api/lookup", "/api/find", "/api/query", "/api/filter"]
    route = rng.choice(routes)
    vuln = f'''app.get("{route}", (req, res) => {{
    const {n["param"]} = req.query.q;
    const query = `SELECT * FROM {n["table"]} WHERE {n["id_col"]} = '${{{n["param"]}}}'`;
    db.query(query, (err, {n["var"]}) => {{
        if (err) return res.status(500).json({{ error: err.message }});
        res.json({n["var"]});
    }});
}});'''

    fix = f'''app.get("{route}", (req, res) => {{
    const {n["param"]} = req.query.q;
    const query = "SELECT * FROM {n["table"]} WHERE {n["id_col"]} = ?";
    db.query(query, [{n["param"]}], (err, {n["var"]}) => {{
        if (err) return res.status(500).json({{ error: "Database error" }});
        res.json({n["var"]});
    }});
}});'''

    info = {"cwe": "CWE-89", "name": "SQL Injection", "language": "javascript",
            "severity": "critical", "line": 3,
            "root_cause": f"Template literal injects '{n['param']}' directly into SQL query",
            "fix_desc": "Use parameterized queries with '?' placeholders and pass input as array"}
    return vuln, fix, info


def sqli_java(rng: random.Random) -> Tuple[str, str, Dict]:
    n = _names(rng)
    vuln = f'''public List<Map<String, Object>> {n["func"]}(String {n["param"]}) {{
    String sql = "SELECT * FROM {n["table"]} WHERE {n["id_col"]} = '" + {n["param"]} + "'";
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(sql);
    return mapResults(rs);
}}'''

    fix = f'''public List<Map<String, Object>> {n["func"]}(String {n["param"]}) {{
    String sql = "SELECT * FROM {n["table"]} WHERE {n["id_col"]} = ?";
    PreparedStatement pstmt = connection.prepareStatement(sql);
    pstmt.setString(1, {n["param"]});
    ResultSet rs = pstmt.executeQuery();
    return mapResults(rs);
}}'''

    info = {"cwe": "CWE-89", "name": "SQL Injection", "language": "java",
            "severity": "critical", "line": 2,
            "root_cause": f"String concatenation injects '{n['param']}' into SQL query",
            "fix_desc": "Use PreparedStatement with parameter binding via setString()"}
    return vuln, fix, info


def sqli_php(rng: random.Random) -> Tuple[str, str, Dict]:
    n = _names(rng)
    vuln = f'''function {n["func"]}(${n["param"]}) {{
    $query = "SELECT * FROM {n["table"]} WHERE {n["id_col"]} = '${n["param"]}'";
    ${n["var"]} = mysqli_query($conn, $query);
    return mysqli_fetch_all(${n["var"]}, MYSQLI_ASSOC);
}}'''

    fix = f'''function {n["func"]}(${n["param"]}) {{
    $stmt = $conn->prepare("SELECT * FROM {n["table"]} WHERE {n["id_col"]} = ?");
    $stmt->bind_param("s", ${n["param"]});
    $stmt->execute();
    return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
}}'''

    info = {"cwe": "CWE-89", "name": "SQL Injection", "language": "php",
            "severity": "critical", "line": 2,
            "root_cause": f"Direct variable interpolation of ${n['param']} into SQL string",
            "fix_desc": "Use prepared statements with bind_param()"}
    return vuln, fix, info


# ── XSS (Cross-Site Scripting) ───────────────────────────────────────────────

def xss_reflected_python(rng: random.Random) -> Tuple[str, str, Dict]:
    n = _names(rng)
    routes = ["/search", "/profile", "/results", "/display", "/view"]
    route = rng.choice(routes)
    vuln = f'''@app.route("{route}")
def {n["func"]}():
    {n["param"]} = request.args.get("q", "")
    return f"<h1>Results for: {{{n['param']}}}</h1><div id='content'></div>"'''

    fix = f'''from markupsafe import escape

@app.route("{route}")
def {n["func"]}():
    {n["param"]} = request.args.get("q", "")
    return f"<h1>Results for: {{escape({n['param']})}}</h1><div id='content'></div>"'''

    info = {"cwe": "CWE-79", "name": "Reflected XSS", "language": "python",
            "severity": "medium", "line": 4,
            "root_cause": f"User input '{n['param']}' rendered in HTML without escaping",
            "fix_desc": "Use markupsafe.escape() to sanitize user input before rendering"}
    return vuln, fix, info


def xss_stored_javascript(rng: random.Random) -> Tuple[str, str, Dict]:
    n = _names(rng)
    vuln = f'''app.post("/api/comment", async (req, res) => {{
    const {{ content, author }} = req.body;
    await db.collection("comments").insertOne({{ content, author, createdAt: new Date() }});
    res.json({{ success: true }});
}});

app.get("/api/comments", async (req, res) => {{
    const comments = await db.collection("comments").find().toArray();
    let html = comments.map(c => `<div class="comment"><b>${{c.author}}</b>: ${{c.content}}</div>`).join("");
    res.send(html);
}});'''

    fix = f'''const sanitizeHtml = require("sanitize-html");

app.post("/api/comment", async (req, res) => {{
    const content = sanitizeHtml(req.body.content, {{ allowedTags: [], allowedAttributes: {{}} }});
    const author = sanitizeHtml(req.body.author, {{ allowedTags: [], allowedAttributes: {{}} }});
    await db.collection("comments").insertOne({{ content, author, createdAt: new Date() }});
    res.json({{ success: true }});
}});

app.get("/api/comments", async (req, res) => {{
    const comments = await db.collection("comments").find().toArray();
    res.json(comments);  // Let frontend handle rendering safely
}});'''

    info = {"cwe": "CWE-79", "name": "Stored XSS", "language": "javascript",
            "severity": "high", "line": 9,
            "root_cause": "User-supplied comment content stored and rendered as raw HTML without sanitization",
            "fix_desc": "Sanitize input on storage, return JSON and render safely on frontend"}
    return vuln, fix, info


# ── Command Injection ────────────────────────────────────────────────────────

def cmdi_python(rng: random.Random) -> Tuple[str, str, Dict]:
    n = _names(rng)
    tools = [("ping", "hostname"), ("nslookup", "domain"), ("dig", "domain"), ("whois", "target")]
    tool, pname = rng.choice(tools)
    vuln = f'''import os

def {n["func"]}({pname}):
    result = os.popen(f"{tool} {{{pname}}}").read()
    return result'''

    fix = f'''import subprocess

def {n["func"]}({pname}):
    result = subprocess.run(["{tool}", {pname}], capture_output=True, text=True, timeout=10)
    return result.stdout'''

    info = {"cwe": "CWE-78", "name": "OS Command Injection", "language": "python",
            "severity": "critical", "line": 4,
            "root_cause": f"os.popen() with f-string allows shell metacharacter injection via '{pname}'",
            "fix_desc": "Use subprocess.run() with argument list (no shell=True) to prevent injection"}
    return vuln, fix, info


def cmdi_javascript(rng: random.Random) -> Tuple[str, str, Dict]:
    n = _names(rng)
    vuln = f'''const {{ exec }} = require("child_process");

app.get("/api/dns", (req, res) => {{
    const domain = req.query.domain;
    exec(`nslookup ${{domain}}`, (error, stdout, stderr) => {{
        res.json({{ result: stdout }});
    }});
}});'''

    fix = f'''const {{ execFile }} = require("child_process");

app.get("/api/dns", (req, res) => {{
    const domain = req.query.domain;
    if (!/^[a-zA-Z0-9.-]+$/.test(domain)) {{
        return res.status(400).json({{ error: "Invalid domain" }});
    }}
    execFile("nslookup", [domain], (error, stdout, stderr) => {{
        res.json({{ result: stdout }});
    }});
}});'''

    info = {"cwe": "CWE-78", "name": "OS Command Injection", "language": "javascript",
            "severity": "critical", "line": 5,
            "root_cause": "exec() with template literal allows shell metacharacter injection via 'domain'",
            "fix_desc": "Use execFile() with argument array and validate input with allowlist regex"}
    return vuln, fix, info


# ── Path Traversal ───────────────────────────────────────────────────────────

def path_traversal_python(rng: random.Random) -> Tuple[str, str, Dict]:
    n = _names(rng)
    vuln = f'''@app.route("/download")
def {n["func"]}():
    filename = request.args.get("file")
    filepath = os.path.join("uploads", filename)
    return send_file(filepath)'''

    fix = f'''@app.route("/download")
def {n["func"]}():
    filename = request.args.get("file")
    safe_name = os.path.basename(filename)
    filepath = os.path.join("uploads", safe_name)
    if not os.path.abspath(filepath).startswith(os.path.abspath("uploads")):
        abort(403)
    return send_file(filepath)'''

    info = {"cwe": "CWE-22", "name": "Path Traversal", "language": "python",
            "severity": "high", "line": 4,
            "root_cause": "Filename from user input joined to path without sanitization; '../' sequences escape uploads dir",
            "fix_desc": "Use os.path.basename() and verify resolved path starts with the intended directory"}
    return vuln, fix, info


def path_traversal_javascript(rng: random.Random) -> Tuple[str, str, Dict]:
    n = _names(rng)
    vuln = f'''app.get("/files/:name", (req, res) => {{
    const filePath = path.join(__dirname, "uploads", req.params.name);
    res.sendFile(filePath);
}});'''

    fix = f'''app.get("/files/:name", (req, res) => {{
    const safeName = path.basename(req.params.name);
    const filePath = path.join(__dirname, "uploads", safeName);
    const uploadsDir = path.resolve(__dirname, "uploads");
    if (!path.resolve(filePath).startsWith(uploadsDir)) {{
        return res.status(403).send("Forbidden");
    }}
    res.sendFile(filePath);
}});'''

    info = {"cwe": "CWE-22", "name": "Path Traversal", "language": "javascript",
            "severity": "high", "line": 2,
            "root_cause": "req.params.name used directly in path.join() without sanitization",
            "fix_desc": "Use path.basename() and validate resolved path stays within uploads directory"}
    return vuln, fix, info


# ── Buffer Overflow (C) ──────────────────────────────────────────────────────

def buffer_overflow_strcpy(rng: random.Random) -> Tuple[str, str, Dict]:
    buf_size = rng.choice([64, 128, 256, 512])
    funcs = ["parse_header", "process_input", "handle_request", "read_field", "copy_payload"]
    func = rng.choice(funcs)
    params = ["raw_data", "input", "payload", "header", "user_data"]
    param = rng.choice(params)

    vuln = f'''void {func}(char *{param}) {{
    char buf[{buf_size}];
    strcpy(buf, {param});
    process(buf);
}}'''

    fix = f'''void {func}(const char *{param}) {{
    char buf[{buf_size}];
    strncpy(buf, {param}, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\\0';
    process(buf);
}}'''

    info = {"cwe": "CWE-120", "name": "Stack-based Buffer Overflow", "language": "c",
            "severity": "critical", "line": 3,
            "root_cause": f"strcpy() copies '{param}' into buf[{buf_size}] without bounds checking",
            "fix_desc": f"Use strncpy() with sizeof(buf)-1 limit and explicit null-termination"}
    return vuln, fix, info


def buffer_overflow_sprintf(rng: random.Random) -> Tuple[str, str, Dict]:
    buf_size = rng.choice([128, 256, 512])
    func = rng.choice(["format_log", "build_response", "create_message", "format_output"])
    vuln = f'''void {func}(const char *username, const char *action) {{
    char log_entry[{buf_size}];
    sprintf(log_entry, "[%s] User %s performed: %s", timestamp(), username, action);
    write_log(log_entry);
}}'''

    fix = f'''void {func}(const char *username, const char *action) {{
    char log_entry[{buf_size}];
    snprintf(log_entry, sizeof(log_entry), "[%s] User %s performed: %s", timestamp(), username, action);
    write_log(log_entry);
}}'''

    info = {"cwe": "CWE-120", "name": "Stack-based Buffer Overflow", "language": "c",
            "severity": "critical", "line": 3,
            "root_cause": f"sprintf() writes to log_entry[{buf_size}] without size limit; long username/action overflows",
            "fix_desc": "Use snprintf() with sizeof(log_entry) to enforce buffer bounds"}
    return vuln, fix, info


def format_string_vuln(rng: random.Random) -> Tuple[str, str, Dict]:
    func = rng.choice(["log_message", "print_status", "display_error", "show_info"])
    param = rng.choice(["msg", "user_input", "error_text", "status_msg"])

    vuln = f'''void {func}(const char *{param}) {{
    printf({param});
}}'''

    fix = f'''void {func}(const char *{param}) {{
    printf("%s", {param});
}}'''

    info = {"cwe": "CWE-134", "name": "Uncontrolled Format String", "language": "c",
            "severity": "critical", "line": 2,
            "root_cause": f"printf() called with '{param}' as format string; attacker controls format specifiers",
            "fix_desc": "Always use a format specifier: printf(\"%s\", input)"}
    return vuln, fix, info


# ── Deserialization ──────────────────────────────────────────────────────────

def deserialization_python(rng: random.Random) -> Tuple[str, str, Dict]:
    n = _names(rng)
    vuln = f'''import pickle
import base64

@app.route("/api/load-session", methods=["POST"])
def {n["func"]}():
    encoded = request.form.get("session_data")
    {n["var"]} = pickle.loads(base64.b64decode(encoded))
    return jsonify({n["var"]})'''

    fix = f'''import json
import base64

@app.route("/api/load-session", methods=["POST"])
def {n["func"]}():
    encoded = request.form.get("session_data")
    try:
        {n["var"]} = json.loads(base64.b64decode(encoded))
    except (json.JSONDecodeError, Exception):
        return jsonify({{"error": "Invalid session data"}}), 400
    return jsonify({n["var"]})'''

    info = {"cwe": "CWE-502", "name": "Insecure Deserialization", "language": "python",
            "severity": "critical", "line": 7,
            "root_cause": "pickle.loads() on user-supplied data allows arbitrary code execution via crafted payloads",
            "fix_desc": "Replace pickle with JSON for untrusted data; never deserialize untrusted binary formats"}
    return vuln, fix, info


def deserialization_java(rng: random.Random) -> Tuple[str, str, Dict]:
    n = _names(rng)
    vuln = f'''public Object {n["func"]}(HttpServletRequest request) throws Exception {{
    String encoded = request.getParameter("data");
    byte[] bytes = Base64.getDecoder().decode(encoded);
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
    return ois.readObject();
}}'''

    fix = f'''public Map<String, Object> {n["func"]}(HttpServletRequest request) throws Exception {{
    String encoded = request.getParameter("data");
    byte[] bytes = Base64.getDecoder().decode(encoded);
    ObjectMapper mapper = new ObjectMapper();
    mapper.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.NON_FINAL);
    return mapper.readValue(bytes, new TypeReference<Map<String, Object>>() {{}});
}}'''

    info = {"cwe": "CWE-502", "name": "Insecure Deserialization", "language": "java",
            "severity": "critical", "line": 4,
            "root_cause": "ObjectInputStream.readObject() on user-supplied data enables gadget chain attacks",
            "fix_desc": "Use JSON deserialization with type restrictions instead of Java native serialization"}
    return vuln, fix, info


# ── SSRF ─────────────────────────────────────────────────────────────────────

def ssrf_python(rng: random.Random) -> Tuple[str, str, Dict]:
    n = _names(rng)
    routes = ["/api/preview", "/api/fetch", "/api/proxy", "/api/check-url", "/api/screenshot"]
    route = rng.choice(routes)
    vuln = f'''@app.route("{route}")
def {n["func"]}():
    url = request.args.get("url")
    response = requests.get(url)
    return jsonify({{"status": response.status_code, "body": response.text[:1000]}})'''

    fix = f'''from urllib.parse import urlparse
import ipaddress

BLOCKED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

@app.route("{route}")
def {n["func"]}():
    url = request.args.get("url")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return jsonify({{"error": "Invalid scheme"}}), 400
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        if any(ip in net for net in BLOCKED_RANGES):
            return jsonify({{"error": "Blocked address"}}), 403
    except (socket.gaierror, ValueError):
        return jsonify({{"error": "Invalid host"}}), 400
    response = requests.get(url, timeout=5, allow_redirects=False)
    return jsonify({{"status": response.status_code, "body": response.text[:1000]}})'''

    info = {"cwe": "CWE-918", "name": "Server-Side Request Forgery (SSRF)", "language": "python",
            "severity": "high", "line": 4,
            "root_cause": "User-supplied URL passed directly to requests.get() without validation",
            "fix_desc": "Validate URL scheme, resolve hostname, block internal/private IP ranges, disable redirects"}
    return vuln, fix, info


# ── IDOR ─────────────────────────────────────────────────────────────────────

def idor_python(rng: random.Random) -> Tuple[str, str, Dict]:
    n = _names(rng)
    resources = ["invoice", "document", "report", "profile", "order"]
    resource = rng.choice(resources)
    vuln = f'''@app.route("/api/{resource}/<int:{resource}_id>")
def {n["func"]}({resource}_id):
    {n["var"]} = db.session.query({resource.title()}).get({resource}_id)
    if not {n["var"]}:
        return jsonify({{"error": "Not found"}}), 404
    return jsonify({n["var"]}.to_dict())'''

    fix = f'''@app.route("/api/{resource}/<int:{resource}_id>")
@login_required
def {n["func"]}({resource}_id):
    {n["var"]} = db.session.query({resource.title()}).get({resource}_id)
    if not {n["var"]}:
        return jsonify({{"error": "Not found"}}), 404
    if {n["var"]}.owner_id != current_user.id:
        return jsonify({{"error": "Forbidden"}}), 403
    return jsonify({n["var"]}.to_dict())'''

    info = {"cwe": "CWE-639", "name": "Insecure Direct Object Reference (IDOR)", "language": "python",
            "severity": "high", "line": 3,
            "root_cause": f"{resource.title()} retrieved by user-supplied ID without ownership verification",
            "fix_desc": "Verify the authenticated user owns the requested resource before returning it"}
    return vuln, fix, info


# ── Authentication Bypass ────────────────────────────────────────────────────

def auth_bypass_javascript(rng: random.Random) -> Tuple[str, str, Dict]:
    vuln = '''app.use("/api/admin", (req, res, next) => {
    const isAdmin = req.headers["x-admin"] || req.cookies.isAdmin;
    if (isAdmin === "true") {
        next();
    } else {
        res.status(403).json({ error: "Forbidden" });
    }
});'''

    fix = '''app.use("/api/admin", authenticateToken, (req, res, next) => {
    if (req.user && req.user.role === "admin") {
        next();
    } else {
        res.status(403).json({ error: "Forbidden" });
    }
});'''

    info = {"cwe": "CWE-287", "name": "Authentication Bypass", "language": "javascript",
            "severity": "critical", "line": 2,
            "root_cause": "Admin check relies on client-controllable header/cookie instead of server-side auth",
            "fix_desc": "Use JWT/session-based auth with server-verified role claims"}
    return vuln, fix, info


# ── CSRF ─────────────────────────────────────────────────────────────────────

def csrf_python(rng: random.Random) -> Tuple[str, str, Dict]:
    actions = [("change_email", "email"), ("change_password", "password"),
               ("transfer_funds", "amount"), ("delete_account", "confirm")]
    action, param = rng.choice(actions)
    vuln = f'''@app.route("/api/{action}", methods=["POST"])
@login_required
def {action}():
    new_{param} = request.form.get("{param}")
    current_user.{param} = new_{param}
    db.session.commit()
    return jsonify({{"success": True}})'''

    fix = f'''from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

@app.route("/api/{action}", methods=["POST"])
@login_required
def {action}():
    new_{param} = request.form.get("{param}")
    current_user.{param} = new_{param}
    db.session.commit()
    return jsonify({{"success": True}})'''

    info = {"cwe": "CWE-352", "name": "Cross-Site Request Forgery (CSRF)", "language": "python",
            "severity": "high", "line": 1,
            "root_cause": f"State-changing POST endpoint /{action} has no CSRF token validation",
            "fix_desc": "Enable CSRF protection via Flask-WTF CSRFProtect; validate tokens on all state-changing requests"}
    return vuln, fix, info


# ── Race Condition ───────────────────────────────────────────────────────────

def race_condition_python(rng: random.Random) -> Tuple[str, str, Dict]:
    vuln = '''@app.route("/api/redeem", methods=["POST"])
@login_required
def redeem_coupon():
    code = request.form.get("code")
    coupon = db.session.query(Coupon).filter_by(code=code, used=False).first()
    if not coupon:
        return jsonify({"error": "Invalid or used coupon"}), 400
    # TOCTOU: another request can use the coupon between check and update
    current_user.balance += coupon.value
    coupon.used = True
    db.session.commit()
    return jsonify({"success": True, "new_balance": current_user.balance})'''

    fix = '''@app.route("/api/redeem", methods=["POST"])
@login_required
def redeem_coupon():
    code = request.form.get("code")
    # Atomic update prevents TOCTOU race condition
    result = db.session.execute(
        text("UPDATE coupons SET used = TRUE WHERE code = :code AND used = FALSE RETURNING value"),
        {"code": code}
    )
    row = result.fetchone()
    if not row:
        return jsonify({"error": "Invalid or used coupon"}), 400
    current_user.balance += row.value
    db.session.commit()
    return jsonify({"success": True, "new_balance": current_user.balance})'''

    info = {"cwe": "CWE-362", "name": "Race Condition (TOCTOU)", "language": "python",
            "severity": "high", "line": 5,
            "root_cause": "Time-of-check-to-time-of-use gap between querying coupon and marking it used",
            "fix_desc": "Use atomic UPDATE ... WHERE used=FALSE to eliminate the race window"}
    return vuln, fix, info


# ── XXE ──────────────────────────────────────────────────────────────────────

def xxe_python(rng: random.Random) -> Tuple[str, str, Dict]:
    n = _names(rng)
    vuln = f'''from lxml import etree

@app.route("/api/parse-xml", methods=["POST"])
def {n["func"]}():
    xml_data = request.data
    parser = etree.XMLParser()
    doc = etree.fromstring(xml_data, parser)
    return jsonify({{"root_tag": doc.tag, "text": doc.text}})'''

    fix = f'''from lxml import etree

@app.route("/api/parse-xml", methods=["POST"])
def {n["func"]}():
    xml_data = request.data
    parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False)
    doc = etree.fromstring(xml_data, parser)
    return jsonify({{"root_tag": doc.tag, "text": doc.text}})'''

    info = {"cwe": "CWE-611", "name": "XML External Entity (XXE)", "language": "python",
            "severity": "high", "line": 7,
            "root_cause": "XML parser with default settings resolves external entities, enabling file read/SSRF",
            "fix_desc": "Disable entity resolution: resolve_entities=False, no_network=True"}
    return vuln, fix, info


# ── Hardcoded Credentials ───────────────────────────────────────────────────

def hardcoded_creds_python(rng: random.Random) -> Tuple[str, str, Dict]:
    services = [("database", "DB_PASSWORD", "db_pass123!"), ("API", "API_SECRET", "sk_live_abc123"),
                ("SMTP", "SMTP_PASSWORD", "mailpass456"), ("Redis", "REDIS_AUTH", "r3dis_s3cret")]
    service, env_var, pwd = rng.choice(services)

    vuln = f'''# {service} configuration
{env_var} = "{pwd}"
connection = create_connection(host="localhost", password={env_var})'''

    fix = f'''import os

# {service} configuration
{env_var} = os.environ.get("{env_var}")
if not {env_var}:
    raise EnvironmentError("{env_var} not set")
connection = create_connection(host="localhost", password={env_var})'''

    info = {"cwe": "CWE-798", "name": "Hard-coded Credentials", "language": "python",
            "severity": "critical", "line": 2,
            "root_cause": f"{service} password hardcoded in source code; exposed in version control",
            "fix_desc": f"Load {env_var} from environment variables; never commit secrets to code"}
    return vuln, fix, info


def hardcoded_creds_javascript(rng: random.Random) -> Tuple[str, str, Dict]:
    vuln = '''const config = {
    database: {
        host: "db.internal.prod",
        user: "admin",
        password: "Pr0d_P@ssw0rd!",
        database: "app_production"
    },
    jwt: {
        secret: "my-super-secret-jwt-key-2024"
    }
};'''

    fix = '''const config = {
    database: {
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME
    },
    jwt: {
        secret: process.env.JWT_SECRET
    }
};

for (const [key, val] of Object.entries(config.database)) {
    if (!val) throw new Error(`Missing env var for database.${key}`);
}'''

    info = {"cwe": "CWE-798", "name": "Hard-coded Credentials", "language": "javascript",
            "severity": "critical", "line": 5,
            "root_cause": "Database password and JWT secret hardcoded in config object",
            "fix_desc": "Load all secrets from environment variables via process.env"}
    return vuln, fix, info


# ── File Upload ──────────────────────────────────────────────────────────────

def unrestricted_upload_python(rng: random.Random) -> Tuple[str, str, Dict]:
    n = _names(rng)
    vuln = f'''@app.route("/upload", methods=["POST"])
def {n["func"]}():
    file = request.files.get("file")
    if file:
        file.save(os.path.join("uploads", file.filename))
        return jsonify({{"message": "File uploaded", "path": file.filename}})
    return jsonify({{"error": "No file"}}), 400'''

    fix = f'''import uuid
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {{"png", "jpg", "jpeg", "gif", "pdf"}}

@app.route("/upload", methods=["POST"])
def {n["func"]}():
    file = request.files.get("file")
    if not file:
        return jsonify({{"error": "No file"}}), 400
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        return jsonify({{"error": "File type not allowed"}}), 400
    safe_name = f"{{uuid.uuid4().hex}}.{{ext}}"
    file.save(os.path.join("uploads", safe_name))
    return jsonify({{"message": "File uploaded", "path": safe_name}})'''

    info = {"cwe": "CWE-434", "name": "Unrestricted File Upload", "language": "python",
            "severity": "high", "line": 5,
            "root_cause": "No validation of file type or name; attacker can upload .php/.py/.exe files",
            "fix_desc": "Validate extension against allowlist, use random filenames, store outside webroot"}
    return vuln, fix, info


# ── Mass Assignment ──────────────────────────────────────────────────────────

def mass_assignment_python(rng: random.Random) -> Tuple[str, str, Dict]:
    vuln = '''@app.route("/api/profile", methods=["PUT"])
@login_required
def update_profile():
    data = request.get_json()
    for key, value in data.items():
        setattr(current_user, key, value)  # Sets ANY attribute including is_admin, role
    db.session.commit()
    return jsonify(current_user.to_dict())'''

    fix = '''ALLOWED_FIELDS = {"display_name", "email", "bio", "avatar_url"}

@app.route("/api/profile", methods=["PUT"])
@login_required
def update_profile():
    data = request.get_json()
    for key, value in data.items():
        if key in ALLOWED_FIELDS:
            setattr(current_user, key, value)
    db.session.commit()
    return jsonify(current_user.to_dict())'''

    info = {"cwe": "CWE-915", "name": "Mass Assignment", "language": "python",
            "severity": "high", "line": 5,
            "root_cause": "setattr() applies all user-supplied fields including privileged ones (is_admin, role)",
            "fix_desc": "Allowlist specific updatable fields; reject any field not in ALLOWED_FIELDS"}
    return vuln, fix, info


# ── Registry of all snippet generators ───────────────────────────────────────

SNIPPET_GENERATORS = {
    "sqli_python": sqli_python,
    "sqli_javascript": sqli_javascript,
    "sqli_java": sqli_java,
    "sqli_php": sqli_php,
    "xss_reflected_python": xss_reflected_python,
    "xss_stored_javascript": xss_stored_javascript,
    "cmdi_python": cmdi_python,
    "cmdi_javascript": cmdi_javascript,
    "path_traversal_python": path_traversal_python,
    "path_traversal_javascript": path_traversal_javascript,
    "buffer_overflow_strcpy": buffer_overflow_strcpy,
    "buffer_overflow_sprintf": buffer_overflow_sprintf,
    "format_string_vuln": format_string_vuln,
    "deserialization_python": deserialization_python,
    "deserialization_java": deserialization_java,
    "ssrf_python": ssrf_python,
    "idor_python": idor_python,
    "auth_bypass_javascript": auth_bypass_javascript,
    "csrf_python": csrf_python,
    "race_condition_python": race_condition_python,
    "xxe_python": xxe_python,
    "hardcoded_creds_python": hardcoded_creds_python,
    "hardcoded_creds_javascript": hardcoded_creds_javascript,
    "unrestricted_upload_python": unrestricted_upload_python,
    "mass_assignment_python": mass_assignment_python,
}


def generate_random_snippet(rng: random.Random, vuln_type: str = None):
    """Generate a random vulnerable code snippet.
    If vuln_type is None, picks randomly from all generators.
    Returns (vulnerable_code, fixed_code, vuln_info).
    """
    if vuln_type and vuln_type in SNIPPET_GENERATORS:
        return SNIPPET_GENERATORS[vuln_type](rng)
    name = rng.choice(list(SNIPPET_GENERATORS.keys()))
    return SNIPPET_GENERATORS[name](rng)
