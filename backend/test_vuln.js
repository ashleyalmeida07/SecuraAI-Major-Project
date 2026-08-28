const express = require('express');
const app = express();
const db = require('./db');

// Vulnerable to SQL Injection
app.get('/user/:id', (req, res) => {
    // Known bad pattern
    db.query("SELECT * FROM users WHERE id = " + req.params.id, (err, result) => {
        if (err) throw err;
        res.json(result);
    });
});

// Vulnerable to Command Injection
const { exec } = require('child_process');
app.post('/ping', (req, res) => {
    exec('ping -c 1 ' + req.body.ip, (err, stdout, stderr) => {
        res.send(stdout);
    });
});

app.listen(3000);
