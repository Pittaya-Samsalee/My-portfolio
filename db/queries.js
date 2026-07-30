// ====================================================================
// DATA ACCESS LAYER — all SQL lives here, all queries are parameterised
// (prepared statements) so user input is always bound as a literal
// value, never concatenated into the SQL string (OWASP A03:2021).
// ====================================================================

const db = require('./index.js');

// ---------------- USERS ----------------

const insertUserStmt = db.prepare(`
    INSERT INTO users (username, email, password_hash)
    VALUES (?, ?, ?)
`);
function createUser({ username, email, passwordHash }) {
    const result = insertUserStmt.run(username, email, passwordHash);
    return result.lastInsertRowid;
}

const findUserByEmailStmt = db.prepare(`SELECT * FROM users WHERE email = ?`);
function findUserByEmail(email) {
    return findUserByEmailStmt.get(email);
}

const findUserByIdStmt = db.prepare(`SELECT * FROM users WHERE id = ?`);
function findUserById(id) {
    return findUserByIdStmt.get(id);
}

const updateLastLoginStmt = db.prepare(`
    UPDATE users SET last_login_at = datetime('now') WHERE id = ?
`);
function touchLastLogin(userId) {
    updateLastLoginStmt.run(userId);
}

const setMfaSecretStmt = db.prepare(`
    UPDATE users SET mfa_secret = ?, mfa_enabled = 0 WHERE id = ?
`);
function setMfaSecret(userId, secret) {
    setMfaSecretStmt.run(secret, userId);
}

const enableMfaStmt = db.prepare(`UPDATE users SET mfa_enabled = 1 WHERE id = ?`);
function enableMfa(userId) {
    enableMfaStmt.run(userId);
}

const disableMfaStmt = db.prepare(`
    UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE id = ?
`);
function disableMfa(userId) {
    disableMfaStmt.run(userId);
}

// ---------------- MESSAGES (contact form + admin CRUD) ----------------

const insertMessageStmt = db.prepare(`
    INSERT INTO messages (user_id, sender_name, sender_email, message_text)
    VALUES (?, ?, ?, ?)
`);
function createMessage({ userId = null, senderName, senderEmail, messageText }) {
    const result = insertMessageStmt.run(userId, senderName, senderEmail, messageText);
    return result.lastInsertRowid;
}

const listMessagesStmt = db.prepare(`
    SELECT id, user_id, sender_name, sender_email, message_text, submitted_at
    FROM messages
    ORDER BY submitted_at DESC
`);
function listMessages() {
    return listMessagesStmt.all();
}

const getMessageByIdStmt = db.prepare(`SELECT * FROM messages WHERE id = ?`);
function getMessageById(id) {
    return getMessageByIdStmt.get(id);
}

const updateMessageStmt = db.prepare(`
    UPDATE messages
    SET sender_name = ?, sender_email = ?, message_text = ?
    WHERE id = ?
`);
function updateMessage(id, { senderName, senderEmail, messageText }) {
    const result = updateMessageStmt.run(senderName, senderEmail, messageText, id);
    return result.changes > 0;
}

const deleteMessageStmt = db.prepare(`DELETE FROM messages WHERE id = ?`);
function deleteMessage(id) {
    const result = deleteMessageStmt.run(id);
    return result.changes > 0;
}

// ---------------- PASSWORD RESET TOKENS ----------------

const insertResetTokenStmt = db.prepare(`
    INSERT INTO password_reset_tokens (user_id, token_hash, expires_at)
    VALUES (?, ?, ?)
`);
function createResetToken(userId, tokenHash, expiresAt) {
    insertResetTokenStmt.run(userId, tokenHash, expiresAt);
}

const findResetTokenStmt = db.prepare(`
    SELECT * FROM password_reset_tokens
    WHERE token_hash = ? AND used = 0 AND expires_at > datetime('now')
`);
function findValidResetToken(tokenHash) {
    return findResetTokenStmt.get(tokenHash);
}

const consumeResetTokenStmt = db.prepare(`
    UPDATE password_reset_tokens SET used = 1 WHERE id = ?
`);
function consumeResetToken(id) {
    consumeResetTokenStmt.run(id);
}

const updatePasswordStmt = db.prepare(`
    UPDATE users SET password_hash = ? WHERE id = ?
`);
function updateUserPassword(userId, passwordHash) {
    updatePasswordStmt.run(passwordHash, userId);
}

// ---------------- LOGIN AUDIT (OWASP A09 logging) ----------------

const insertAuditStmt = db.prepare(`
    INSERT INTO login_audit (email_attempted, success, ip_address)
    VALUES (?, ?, ?)
`);
function recordLoginAttempt(emailAttempted, success, ipAddress) {
    insertAuditStmt.run(emailAttempted, success ? 1 : 0, ipAddress);
}

const promoteToAdminStmt = db.prepare(`UPDATE users SET role = 'admin' WHERE email = ?`);
function promoteToAdmin(email) {
    const result = promoteToAdminStmt.run(email);
    return result.changes > 0;
}

module.exports = {
    createUser,
    promoteToAdmin,
    findUserByEmail,
    findUserById,
    touchLastLogin,
    setMfaSecret,
    enableMfa,
    disableMfa,
    createMessage,
    listMessages,
    getMessageById,
    updateMessage,
    deleteMessage,
    createResetToken,
    findValidResetToken,
    consumeResetToken,
    updateUserPassword,
    recordLoginAttempt,
};
