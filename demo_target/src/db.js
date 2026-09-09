/**
 * db.js — Intentionally insecure database helpers.
 * VULN: Direct SQL string concatenation — classic SQLi patterns Semgrep flags.
 */

const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(':memory:');

/**
 * VULN-1: Raw SQL concatenation with user input (Semgrep: tainted-sql-string)
 */
function getUserByUsername(username, cb) {
    const sql = "SELECT * FROM users WHERE username = '" + username + "'";
    db.get(sql, cb);
}

/**
 * VULN-2: Template literal SQL (Semgrep)
 */
function searchUsers(query, cb) {
    db.all(`SELECT * FROM users WHERE email LIKE '%${query}%'`, cb);
}

/**
 * VULN-3: SQL built from req.params with no sanitisation (Semgrep)
 */
function getTransactionById(id, cb) {
    db.all('SELECT * FROM transactions WHERE id = ' + id, cb);
}

module.exports = { getUserByUsername, searchUsers, getTransactionById };
