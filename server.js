// ====================================================================
// SECURE WEB APPLICATION — BACKEND SERVER
// Student ID: 12700064
//
// Stack: Express + Node built-in `node:sqlite` + Node built-in `crypto`
// (PBKDF2 password hashing, RFC 6238 TOTP for MFA).
//
// Security measures implemented (see accompanying report for full
// OWASP Top 10 discussion and justification):
//   - Parameterised SQL everywhere (A03: Injection)
//   - HTML-entity sanitisation of all rendered user input (A03/XSS)
//   - PBKDF2-SHA256, 310,000 iterations, per-user salt (password storage)
//   - App-based MFA via TOTP (RFC 6238)
//   - Session cookies: HttpOnly, SameSite=Lax, Secure in production
//   - X-Content-Type-Options: nosniff on all responses
//   - Role-based access control on admin-only routes (A01)
//   - Login attempt auditing + basic rate limiting (A07/A09)
// ====================================================================

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const crypto = require('crypto');

const q = require('./db/queries.js');
const { hashPassword, verifyPassword, validatePasswordPolicy, generateResetToken } = require('./lib/auth.js');
const { generateSecret, buildOtpauthUri, verifyTOTP } = require('./lib/totp.js');

const app = express();

// --------------------------------------------------------------
// Global middleware
// --------------------------------------------------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Content-sniffing protection (OWASP: Baker, 2022) on every response.
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    next();
});

// Session cookie configuration.
// SESSION_SECRET must live in .env / environment variables — never
// hardcoded and never committed to version control (Baker, 2022).
if (!process.env.SESSION_SECRET) {
    console.warn('[WARNING] SESSION_SECRET not set in .env — using an insecure default for local dev only.');
}
app.use(session({
    name: 'sessionid',
    secret: process.env.SESSION_SECRET || 'dev-only-insecure-secret-change-me',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,                                  // JS cannot read the cookie
        sameSite: 'lax',                                  // CSRF mitigation
        secure: process.env.NODE_ENV === 'production',    // HTTPS-only in production
        maxAge: 1000 * 60 * 60 * 2,                        // 2 hours
    },
}));

app.use(express.static('.')); // serves the existing portfolio pages + new admin pages

// --------------------------------------------------------------
// Helpers
// --------------------------------------------------------------

function sanitizeInput(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;');
}

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Very small in-memory rate limiter for login attempts (per email).
// Mitigates brute-force credential guessing (OWASP A07).
const loginAttempts = new Map(); // email -> { count, firstAttemptAt }
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes

function isRateLimited(email) {
    const record = loginAttempts.get(email);
    if (!record) return false;
    if (Date.now() - record.firstAttemptAt > WINDOW_MS) {
        loginAttempts.delete(email);
        return false;
    }
    return record.count >= MAX_ATTEMPTS;
}
function recordFailedAttempt(email) {
    const record = loginAttempts.get(email) || { count: 0, firstAttemptAt: Date.now() };
    record.count += 1;
    loginAttempts.set(email, record);
}
function clearAttempts(email) {
    loginAttempts.delete(email);
}

function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Authentication required.' });
    }
    next();
}

function requireAdmin(req, res, next) {
    const user = q.findUserById(req.session.userId);
    if (!user || user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin privileges required.' });
    }
    next();
}

// ================================================================
// AUTH ROUTES
// ================================================================

// ---- Register ----
app.post('/api/register', (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: 'All fields are required.' });
        }
        if (!EMAIL_REGEX.test(email)) {
            return res.status(400).json({ error: 'Invalid email format.' });
        }
        const policy = validatePasswordPolicy(password);
        if (!policy.valid) {
            return res.status(400).json({ error: 'Weak password.', details: policy.errors });
        }
        if (q.findUserByEmail(email)) {
            return res.status(409).json({ error: 'An account with this email already exists.' });
        }

        const passwordHash = hashPassword(password);
        const userId = q.createUser({
            username: sanitizeInput(username.trim()),
            email: email.trim().toLowerCase(),
            passwordHash,
        });

        req.session.userId = userId;
        res.status(201).json({ success: 'Account created.', userId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ---- Login step 1: email + password ----
app.post('/api/login', (req, res) => {
    try {
        const { email, password } = req.body;
        const ip = req.ip;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required.' });
        }
        if (isRateLimited(email)) {
            q.recordLoginAttempt(email, false, ip);
            return res.status(429).json({ error: 'Too many failed attempts. Try again later.' });
        }

        const user = q.findUserByEmail(email.trim().toLowerCase());
        if (!user || !verifyPassword(password, user.password_hash)) {
            recordFailedAttempt(email);
            q.recordLoginAttempt(email, false, ip);
            // Deliberately vague error — do not reveal whether the email exists.
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        clearAttempts(email);

        if (user.mfa_enabled) {
            // Password correct, but MFA challenge still required.
            req.session.pendingMfaUserId = user.id;
            return res.status(200).json({ mfaRequired: true });
        }

        q.recordLoginAttempt(email, true, ip);
        q.touchLastLogin(user.id);
        req.session.userId = user.id;
        res.status(200).json({ success: 'Logged in.', mfaRequired: false });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ---- Login step 2: MFA code ----
app.post('/api/login/mfa', (req, res) => {
    try {
        const { code } = req.body;
        const pendingUserId = req.session.pendingMfaUserId;

        if (!pendingUserId) {
            return res.status(400).json({ error: 'No pending MFA challenge.' });
        }
        const user = q.findUserById(pendingUserId);
        if (!user || !user.mfa_secret) {
            return res.status(400).json({ error: 'MFA not configured for this account.' });
        }
        if (!code || !verifyTOTP(user.mfa_secret, String(code))) {
            return res.status(401).json({ error: 'Invalid or expired MFA code.' });
        }

        delete req.session.pendingMfaUserId;
        req.session.userId = user.id;
        q.touchLastLogin(user.id);
        q.recordLoginAttempt(user.email, true, req.ip);

        res.status(200).json({ success: 'Logged in.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ---- Logout ----
app.post('/api/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('sessionid');
        res.status(200).json({ success: 'Logged out.' });
    });
});

// ---- Current session info ----
app.get('/api/me', requireAuth, (req, res) => {
    const user = q.findUserById(req.session.userId);
    res.json({
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        mfaEnabled: !!user.mfa_enabled,
    });
});

// ================================================================
// MFA SETUP ROUTES (must be logged in)
// ================================================================

app.post('/api/mfa/setup', requireAuth, (req, res) => {
    const user = q.findUserById(req.session.userId);
    const secret = generateSecret();
    q.setMfaSecret(user.id, secret); // stored but mfa_enabled stays 0 until confirmed
    const otpauthUri = buildOtpauthUri(secret, user.email);
    res.json({ secret, otpauthUri });
});

app.post('/api/mfa/enable', requireAuth, (req, res) => {
    const { code } = req.body;
    const user = q.findUserById(req.session.userId);
    if (!user.mfa_secret) {
        return res.status(400).json({ error: 'Call /api/mfa/setup first.' });
    }
    if (!code || !verifyTOTP(user.mfa_secret, String(code))) {
        return res.status(401).json({ error: 'Invalid MFA code — setup not confirmed.' });
    }
    q.enableMfa(user.id);
    res.json({ success: 'MFA enabled.' });
});

app.post('/api/mfa/disable', requireAuth, (req, res) => {
    q.disableMfa(req.session.userId);
    res.json({ success: 'MFA disabled.' });
});

// ================================================================
// CONTACT FORM (public — INSERT only, existing feature retained)
// ================================================================

app.post('/api/contact', (req, res) => {
    try {
        const { name, email, message } = req.body;

        if (!name || !email || !message) {
            return res.status(400).json({ error: 'All fields are required.' });
        }
        if (!EMAIL_REGEX.test(email)) {
            return res.status(400).json({ error: 'Invalid email format detected!' });
        }

        const safeName = sanitizeInput(name.trim());
        const safeEmail = sanitizeInput(email.trim());
        const safeMessage = sanitizeInput(message);

        const userId = req.session && req.session.userId ? req.session.userId : null;

        const id = q.createMessage({
            userId,
            senderName: safeName,
            senderEmail: safeEmail,
            messageText: safeMessage,
        });

        res.status(201).json({ success: 'Message stored securely.', id });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ================================================================
// ADMIN CRUD ROUTES — SELECT / UPDATE / DELETE on messages
// (INSERT is covered by the public /api/contact route above)
// ================================================================

app.get('/api/messages', requireAuth, requireAdmin, (req, res) => {
    res.json(q.listMessages());
});

app.get('/api/messages/:id', requireAuth, requireAdmin, (req, res) => {
    const msg = q.getMessageById(req.params.id);
    if (!msg) return res.status(404).json({ error: 'Message not found.' });
    res.json(msg);
});

app.put('/api/messages/:id', requireAuth, requireAdmin, (req, res) => {
    const { senderName, senderEmail, messageText } = req.body;
    if (!senderName || !senderEmail || !messageText) {
        return res.status(400).json({ error: 'All fields are required.' });
    }
    if (!EMAIL_REGEX.test(senderEmail)) {
        return res.status(400).json({ error: 'Invalid email format.' });
    }
    const updated = q.updateMessage(req.params.id, {
        senderName: sanitizeInput(senderName.trim()),
        senderEmail: sanitizeInput(senderEmail.trim()),
        messageText: sanitizeInput(messageText),
    });
    if (!updated) return res.status(404).json({ error: 'Message not found.' });
    res.json({ success: 'Message updated.' });
});

app.delete('/api/messages/:id', requireAuth, requireAdmin, (req, res) => {
    const deleted = q.deleteMessage(req.params.id);
    if (!deleted) return res.status(404).json({ error: 'Message not found.' });
    res.json({ success: 'Message deleted.' });
});

// ================================================================
// SERVER START
// ================================================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`\n====================================================================`);
    console.log(`Secure backend server active on http://localhost:${PORT}`);
    console.log(`====================================================================\n`);
});
