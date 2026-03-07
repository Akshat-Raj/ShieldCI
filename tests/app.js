const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { execSync } = require('child_process');
const fs = require('fs');
const http = require('http');
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ═══════════════════════════════════════════════════════
//  🎯 INTENTIONALLY VULNERABLE APPLICATION
//  Built for testing ShieldCI's security scanning tools
//  DO NOT deploy this anywhere near production!
// ═══════════════════════════════════════════════════════

// ── Hardcoded credentials (CWE-798) ──────────────────
const ADMIN_PASSWORD = "admin123";
const DB_SECRET = "supersecretdbpassword";
const API_KEY = "sk-1234567890abcdef";

// ── Database setup ───────────────────────────────────
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, email TEXT)");
    db.run("INSERT INTO users VALUES (1, 'admin', 'admin123', 'administrator', 'admin@corp.local')");
    db.run("INSERT INTO users VALUES (2, 'guest', 'guest',    'viewer',        'guest@corp.local')");
    db.run("INSERT INTO users VALUES (3, 'john',  'password1','editor',        'john@corp.local')");

    db.run("CREATE TABLE secrets (id INTEGER PRIMARY KEY, key TEXT, value TEXT)");
    db.run("INSERT INTO secrets VALUES (1, 'aws_key', 'AKIAIOSFODNN7EXAMPLE')");
    db.run("INSERT INTO secrets VALUES (2, 'stripe',  'sk_live_abc123xyz')");
});


// ═══════════════════════════════════════════════════════
//  VULN 1 — Health check (clean, so ShieldCI knows it's alive)
// ═══════════════════════════════════════════════════════
app.get('/', (req, res) => res.status(200).send('Alive!'));


// ═══════════════════════════════════════════════════════
//  VULN 2 — SQL Injection (CWE-89)
//  Raw string concatenation in query
// ═══════════════════════════════════════════════════════
app.get('/login', (req, res) => {
    const user = req.query.username || '';
    const pass = req.query.password || '';
    // 🚨 Classic SQLi — string concatenation
    const query = "SELECT * FROM users WHERE username = '" + user + "' AND password = '" + pass + "'";

    db.get(query, (err, row) => {
        if (err) return res.status(500).send("DB Error: " + err.message);
        if (row) res.send(`Welcome ${row.username}! Role: ${row.role}`);
        else res.status(401).send("Invalid credentials");
    });
});


// ═══════════════════════════════════════════════════════
//  VULN 3 — Reflected XSS (CWE-79)
//  User input rendered directly into HTML without escaping
// ═══════════════════════════════════════════════════════
app.get('/search', (req, res) => {
    const query = req.query.q || '';
    // 🚨 Reflected XSS — unescaped user input in HTML
    res.send(`
        <html>
        <body>
            <h1>Search Results</h1>
            <p>You searched for: ${query}</p>
            <p>No results found.</p>
        </body>
        </html>
    `);
});


// ═══════════════════════════════════════════════════════
//  VULN 4 — Command Injection (CWE-78)
//  User input passed directly to shell command
// ═══════════════════════════════════════════════════════
app.get('/ping', (req, res) => {
    const host = req.query.host || '127.0.0.1';
    try {
        // 🚨 OS Command Injection — unsanitized input to execSync
        const result = execSync(`ping -c 1 ${host}`, { timeout: 5000 });
        res.send(`<pre>${result.toString()}</pre>`);
    } catch (e) {
        res.status(500).send(`Ping failed: ${e.message}`);
    }
});


// ═══════════════════════════════════════════════════════
//  VULN 5 — Path Traversal / LFI (CWE-22)
//  User-controlled file path with no sanitization
// ═══════════════════════════════════════════════════════
app.get('/file', (req, res) => {
    const filename = req.query.name || 'index.html';
    // 🚨 Path traversal — no sanitization on filename
    const filepath = __dirname + '/public/' + filename;
    try {
        const content = fs.readFileSync(filepath, 'utf8');
        res.send(content);
    } catch (e) {
        res.status(404).send("File not found: " + filename);
    }
});


// ═══════════════════════════════════════════════════════
//  VULN 6 — IDOR / Insecure Direct Object Reference (CWE-639)
//  No authorization check — any user can access any profile
// ═══════════════════════════════════════════════════════
app.get('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    // 🚨 IDOR — no auth check, returns password + email
    db.get("SELECT * FROM users WHERE id = " + userId, (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (row) res.json({ id: row.id, username: row.username, password: row.password, email: row.email, role: row.role });
        else res.status(404).json({ error: "User not found" });
    });
});


// ═══════════════════════════════════════════════════════
//  VULN 7 — SSRF / Server-Side Request Forgery (CWE-918)
//  Fetches arbitrary URLs provided by the user
// ═══════════════════════════════════════════════════════
app.get('/api/fetch', (req, res) => {
    const url = req.query.url || '';
    if (!url) return res.status(400).send("Missing url parameter");
    // 🚨 SSRF — no URL validation, can hit internal services
    http.get(url, (proxyRes) => {
        let data = '';
        proxyRes.on('data', chunk => data += chunk);
        proxyRes.on('end', () => res.send(data));
    }).on('error', (e) => {
        res.status(500).send("Fetch error: " + e.message);
    });
});


// ═══════════════════════════════════════════════════════
//  VULN 8 — Open Redirect (CWE-601)
//  Redirects to any URL the user provides
// ═══════════════════════════════════════════════════════
app.get('/redirect', (req, res) => {
    const target = req.query.url || '/';
    // 🚨 Open redirect — no validation of target URL
    res.redirect(target);
});


// ═══════════════════════════════════════════════════════
//  VULN 9 — Sensitive Data Exposure (CWE-200)
//  Debug endpoint leaks env vars, secrets, stack info
// ═══════════════════════════════════════════════════════
app.get('/debug', (req, res) => {
    // 🚨 Exposes environment variables, DB creds, secrets
    res.json({
        env: process.env,
        admin_password: ADMIN_PASSWORD,
        db_secret: DB_SECRET,
        api_key: API_KEY,
        node_version: process.version,
        cwd: process.cwd(),
        uptime: process.uptime(),
        memory: process.memoryUsage()
    });
});


// ═══════════════════════════════════════════════════════
//  VULN 10 — Mass Assignment / Insecure Deserialization
//  Accepts arbitrary JSON fields for user creation
// ═══════════════════════════════════════════════════════
app.post('/api/users', (req, res) => {
    const { username, password, email, role } = req.body;
    // 🚨 Mass assignment — user can set their own role to 'administrator'
    const query = `INSERT INTO users (username, password, role, email) VALUES ('${username}', '${password}', '${role || 'viewer'}', '${email}')`;
    db.run(query, function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, username, role: role || 'viewer' });
    });
});


// ═══════════════════════════════════════════════════════
//  VULN 11 — SQL Injection in search (CWE-89, second instance)
//  Demonstrates LIKE-based injection
// ═══════════════════════════════════════════════════════
app.get('/api/search', (req, res) => {
    const term = req.query.query || '';
    // 🚨 SQLi via LIKE clause
    const query = "SELECT id, username, email FROM users WHERE username LIKE '%" + term + "%' OR email LIKE '%" + term + "%'";
    db.all(query, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows || []);
    });
});


// ═══════════════════════════════════════════════════════
//  VULN 12 — Secrets endpoint with no auth (CWE-306)
//  Exposes internal secrets table without any authentication
// ═══════════════════════════════════════════════════════
app.get('/api/secrets', (req, res) => {
    // 🚨 No authentication — anyone can read all secrets
    db.all("SELECT * FROM secrets", (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});


// ── No security headers set (CWE-693) ───────────────
// Missing: X-Content-Type-Options, X-Frame-Options,
//          Content-Security-Policy, Strict-Transport-Security

// Force IPv4 binding to match Rust's 127.0.0.1
app.listen(3000, '127.0.0.1', () => {
    console.log("🎯 Vulnerable target up on http://127.0.0.1:3000");
    console.log("   Endpoints: /, /login, /search, /ping, /file, /api/users/:id,");
    console.log("              /api/fetch, /redirect, /debug, /api/users, /api/search, /api/secrets");
});
