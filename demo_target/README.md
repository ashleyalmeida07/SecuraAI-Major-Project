# VulnBank — AuthTrack SAST Demo Target

> ⚠️ **Intentionally Insecure** — Do NOT deploy to production.

This is a deliberately vulnerable Node.js/Express web application built to demonstrate the
[AuthTrack](https://github.com/ashleyalmeida07/Authtrack-Major-Project) security scanner.

## Vulnerabilities (by design)

| # | Type | Location | Scanner that flags it |
|---|------|----------|----------------------|
| 1 | **Hardcoded secrets** (JWT, AWS key, Stripe key) | `server.js`, `src/auth.js` | Gitleaks |
| 2 | **SQL Injection** (string concat + template literals) | `server.js`, `src/db.js` | Semgrep |
| 3 | **Command Injection** (`exec()` with unsanitised input) | `server.js /api/ping` | Semgrep |
| 4 | **Path Traversal** (`fs.readFile` with user-controlled path) | `server.js /api/file` | Semgrep |
| 5 | **Insecure `eval()`** on user input (RCE) | `server.js /api/calculate` | Semgrep |
| 6 | **Weak crypto** — MD5 password hashing | `server.js`, `src/auth.js` | Semgrep |
| 7 | **Insecure randomness** — `Math.random()` for tokens | `src/auth.js` | Semgrep |
| 8 | **Vulnerable dependency** — `jsonwebtoken@8.5.1` (CVE-2022-23529) | `package.json` | OSV-Scanner |
| 9 | **Missing security headers** (CSP weak, no HSTS, no X-Frame-Options) | `server.js` middleware | Header Audit |
| 10 | **Sensitive routes** exposed without auth (`/.env`, `/admin`, `/admin/backup.sql`) | `server.js` | Recon Flow |

## Run the demo server

```bash
npm install
npm start
# → http://localhost:4000
```

## Scan with AuthTrack CLI

```bash
# Backend must be running at localhost:8000
node path/to/cli/bin/secura.mjs scan .
```
