/**
 * VulnBank — Deliberately Insecure Express App
 *
 * PURPOSE: Demo target for the AuthTrack / Secura SAST scanner.
 * Every vulnerability here is INTENTIONAL so the scanner has real targets to find.
 *
 * DO NOT deploy this to production.
 */

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');  // pinned to 8.5.1 — known CVE for OSV-Scanner to catch
const { exec } = require('child_process');
const crypto = require('crypto');

const app = express();
const PORT = 4000;

// ─────────────────────────────────────────────────────────────────────────────
// VULN-1: Hardcoded secrets (Gitleaks will flag these)
// ─────────────────────────────────────────────────────────────────────────────
const JWT_SECRET        = 'hardcoded_jwt_secret_do_not_use';   // gitleaks: jwt-secret
const DB_PASSWORD       = 'S3cr3tP@ssw0rd!';                  // gitleaks: password
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';             // gitleaks: aws-access-key-id
const STRIPE_KEY        = 'sk_live_DEMO_FAKE_KEY_DO_NOT_USE_1234567890'; // gitleaks: stripe-secret-key

// ─────────────────────────────────────────────────────────────────────────────
// VULN-2: Intentionally weak HTTP response headers (Header Audit will flag these)
// ─────────────────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
    res.setHeader('X-Powered-By', 'Express 1.0 Vulnerable');
    // Missing: Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy
    // Weak CSP: allows everything
    res.setHeader('Content-Security-Policy', "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:");
    // X-Frame-Options missing — clickjacking possible
    // Set-Cookie without HttpOnly or Secure
    res.setHeader('Set-Cookie', `sessionid=${crypto.randomBytes(4).toString('hex')}; Path=/`);
    next();
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────────────────────────────────────
// Database setup
// ─────────────────────────────────────────────────────────────────────────────
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run(`CREATE TABLE users (
        id       INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        role     TEXT,
        email    TEXT,
        balance  REAL DEFAULT 0
    )`);
    db.run(`INSERT INTO users VALUES (1, 'admin',   'supersecret123', 'admin', 'admin@vulnbank.local', 99999)`);
    db.run(`INSERT INTO users VALUES (2, 'alice',   'alice1234',      'user',  'alice@vulnbank.local',  1500)`);
    db.run(`INSERT INTO users VALUES (3, 'bob',     'password123',   'user',  'bob@vulnbank.local',    250)`);

    db.run(`CREATE TABLE transactions (
        id      INTEGER PRIMARY KEY,
        from_id INTEGER,
        to_id   INTEGER,
        amount  REAL,
        note    TEXT
    )`);
    db.run(`INSERT INTO transactions VALUES (1, 2, 3, 100, 'Lunch')`);
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-3: SQL Injection — Login (Semgrep: javascript.express.security.injection.tainted-sql-string)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    // INTENTIONALLY VULNERABLE: string concatenation into SQL
    const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    db.get(sql, (err, row) => {
        if (err) {
            // VULN: leaks internal DB error to the client
            return res.status(500).json({ error: 'Database error', details: err.message, query: sql });
        }
        if (row) {
            // VULN: algorithm not specified — vulnerable to algorithm confusion attack
            const token = jwt.sign({ id: row.id, role: row.role }, JWT_SECRET);
            res.json({ success: true, token, user: row });
        } else {
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-4: SQL Injection — User search GET (Semgrep)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/users', (req, res) => {
    const q = req.query.q || '';

    // INTENTIONALLY VULNERABLE
    db.all(`SELECT id, username, role, email, balance FROM users WHERE username LIKE '%${q}%'`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ users: rows });
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-5: SQL Injection — Transaction lookup by ID
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/transactions/:id', (req, res) => {
    const id = req.params.id;

    // INTENTIONALLY VULNERABLE: param goes straight into SQL
    db.all(`SELECT * FROM transactions WHERE from_id = ` + id, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ transactions: rows });
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-6: Command Injection (Semgrep: javascript.lang.security.detect-child-process)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/ping', (req, res) => {
    const { host } = req.body;

    // INTENTIONALLY VULNERABLE: unsanitised user input in exec()
    exec(`ping -n 1 ${host}`, (error, stdout, stderr) => {
        if (error) return res.status(500).send(error.message);
        res.send(stdout || stderr);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-7: Path Traversal (Semgrep: detect-non-literal-fs-filename)
// ─────────────────────────────────────────────────────────────────────────────
app.get('/api/file', (req, res) => {
    const { name } = req.query;
    const fs = require('fs');

    // INTENTIONALLY VULNERABLE: no path sanitisation
    const filePath = path.join(__dirname, 'uploads', name);
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) return res.status(404).send('Not found');
        res.send(data);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-8: Weak cryptography — MD5 password hashing (Semgrep)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;

    // INTENTIONALLY VULNERABLE: MD5 is cryptographically broken
    const hashed = crypto.createHash('md5').update(password).digest('hex');

    db.run(`INSERT INTO users (username, password, role) VALUES ('${username}', '${hashed}', 'user')`, (err) => {
        if (err) return res.status(400).json({ error: err.message });
        res.json({ success: true, hashed_password: hashed });
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// VULN-9: Insecure Eval (Semgrep: detect-eval-with-expression)
// ─────────────────────────────────────────────────────────────────────────────
app.post('/api/calculate', (req, res) => {
    const { expression } = req.body;

    // INTENTIONALLY VULNERABLE: eval() on user input = RCE
    try {
        const result = eval(expression); // eslint-disable-line no-eval
        res.json({ result });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

// ─────────────────────────────────────────────────────────────────────────────
// Recon targets — sensitive paths the crawler should discover
// ─────────────────────────────────────────────────────────────────────────────
app.get('/.env', (req, res) => {
    res.type('text/plain').send([
        `DB_HOST=localhost`,
        `DB_USER=root`,
        `DB_PASS=${DB_PASSWORD}`,
        `JWT_SECRET=${JWT_SECRET}`,
        `AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}`,
        `STRIPE_SECRET_KEY=${STRIPE_KEY}`,
    ].join('\n'));
});

app.get('/admin', (req, res) => {
    res.json({ message: 'Admin panel — no auth required!', users: ['admin', 'alice', 'bob'] });
});

app.get('/admin/backup.sql', (req, res) => {
    res.type('text/plain').send(`INSERT INTO users VALUES (1,'admin','supersecret123','admin','admin@vulnbank.local',99999);`);
});

app.get('/api/internal/metrics', (req, res) => {
    res.json({ requests_per_second: 120, error_rate: 0.02, db_connections: 5 });
});

app.get('/api/v1/health', (req, res) => res.json({ status: 'ok' }));

// ─────────────────────────────────────────────────────────────────────────────
// Fallback
// ─────────────────────────────────────────────────────────────────────────────
app.use((req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`\n  VulnBank Demo Target`);
    console.log(`  ─────────────────────────────────────────`);
    console.log(`  Running at  http://localhost:${PORT}`);
    console.log(`  ⚠  Intentionally insecure — demo only!\n`);
});
