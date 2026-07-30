// ====================================================================
// DATABASE CONNECTION MODULE
// Uses Node.js built-in `node:sqlite` (no external DB driver needed).
// All queries elsewhere in the app use parameterised statements
// (prepared statements) — never raw string concatenation — to
// prevent SQL Injection (OWASP A03:2021).
// ====================================================================

const { DatabaseSync } = require('node:sqlite');
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'app.db');
const SCHEMA_PATH = path.join(__dirname, 'schema.sql');

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA foreign_keys = ON;');
db.exec(fs.readFileSync(SCHEMA_PATH, 'utf8'));

module.exports = db;
