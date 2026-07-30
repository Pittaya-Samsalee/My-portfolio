-- ====================================================================
-- DATABASE DEFINITION LANGUAGE (DDL)
-- Secure Web Application - Database Schema
-- Engine: SQLite (relational)
-- ====================================================================

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------
-- Table: users
-- Stores authentication credentials and MFA state.
-- Passwords are NEVER stored in plaintext (see lib/auth.js - PBKDF2).
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    email           TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,              -- format: pbkdf2$iterations$salt$hash
    mfa_secret      TEXT,                       -- base32 TOTP secret, NULL until MFA enabled
    mfa_enabled     INTEGER NOT NULL DEFAULT 0 CHECK (mfa_enabled IN (0,1)),
    role            TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_at   TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- ---------------------------------------------------------------
-- Table: messages
-- Contact-form submissions. Linked to a user only if the sender
-- was authenticated (nullable FK = anonymous visitors allowed).
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER,
    sender_name     TEXT NOT NULL,
    sender_email    TEXT NOT NULL,
    message_text    TEXT NOT NULL,
    submitted_at    TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_submitted_at ON messages(submitted_at);
CREATE INDEX IF NOT EXISTS idx_messages_user_id ON messages(user_id);

-- ---------------------------------------------------------------
-- Table: password_reset_tokens
-- One-time, short-lived tokens for account recovery (per Baker 2022:
-- must be user-bound, unguessable, expiring, single-use).
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    token_hash      TEXT NOT NULL UNIQUE,
    expires_at      TEXT NOT NULL,
    used            INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0,1)),
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_reset_tokens_user_id ON password_reset_tokens(user_id);

-- ---------------------------------------------------------------
-- Table: login_audit
-- Basic logging for OWASP A09 (Security Logging & Monitoring Failures).
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS login_audit (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email_attempted TEXT NOT NULL,
    success         INTEGER NOT NULL CHECK (success IN (0,1)),
    ip_address      TEXT,
    attempted_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_login_audit_attempted_at ON login_audit(attempted_at);
