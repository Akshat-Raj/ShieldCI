const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const app = express();

const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (username TEXT, role TEXT)");
    db.run("INSERT INTO users VALUES ('admin', 'administrator')");
});

// 1. The Health Check Route (So Rust knows it's alive)
app.get('/', (req, res) => res.status(200).send('Alive!'));

// 2. 🚨 THE SQL INJECTION VULNERABILITY 🚨
app.get('/login', (req, res) => {
    const user = req.query.username || '';
    const query = "SELECT * FROM users WHERE username = '" + user + "'";
    
    db.get(query, (err, row) => {
        if (row) res.send(`Welcome ${row.username}!`);
        else res.status(401).send("Invalid");
    });
});

// 3. Force IPv4 binding to match Rust's 127.0.0.1
app.listen(3000, '127.0.0.1', () => console.log("Target up on 3000"));
