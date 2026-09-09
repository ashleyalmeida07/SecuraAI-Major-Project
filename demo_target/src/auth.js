/**
 * auth.js — Intentionally insecure auth helpers.
 * VULN: All of these are anti-patterns that Semgrep will flag.
 */

const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// VULN-1: Hardcoded secret in code (Gitleaks + Semgrep)
const SECRET = 'my_super_weak_secret_1234';

/**
 * VULN-2: JWT verification with algorithm:none bypass allowed.
 * Real apps should pin algorithm to 'HS256' — omitting it enables spoofing.
 */
function verifyToken(token) {
    // Missing: { algorithms: ['HS256'] }
    return jwt.verify(token, SECRET);
}

/**
 * VULN-3: MD5 used for password hashing (Semgrep: insecure-hash-algorithm)
 */
function hashPassword(password) {
    return crypto.createHash('md5').update(password).digest('hex');
}

/**
 * VULN-4: Timing-attack-vulnerable string comparison
 */
function checkToken(a, b) {
    return a === b; // should use crypto.timingSafeEqual
}

/**
 * VULN-5: Random token using Math.random() — not cryptographically secure
 */
function generateSessionId() {
    return Math.random().toString(36).substring(2);
}

module.exports = { verifyToken, hashPassword, checkToken, generateSessionId };
