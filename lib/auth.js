// ====================================================================
// PASSWORD HASHING — PBKDF2 with per-user salt
// Follows OWASP Password Storage Cheat Sheet recommendation cited in
// the accompanying report (Baker, 2022): SHA-256, minimum 310,000
// iterations, unique random salt per user, one-way (never reversible).
// ====================================================================

const crypto = require('crypto');

const ITERATIONS = 310000; // OWASP-recommended minimum for PBKDF2-HMAC-SHA256
const KEY_LENGTH = 64;
const DIGEST = 'sha256';

/**
 * Hash a plaintext password. Returns a self-describing string:
 * "pbkdf2$<iterations>$<salt-hex>$<hash-hex>"
 * Storing the parameters alongside the hash allows the iteration
 * count to be safely increased in future without breaking old hashes.
 */
function hashPassword(plainPassword) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto
        .pbkdf2Sync(plainPassword, salt, ITERATIONS, KEY_LENGTH, DIGEST)
        .toString('hex');
    return `pbkdf2$${ITERATIONS}$${salt}$${hash}`;
}

/**
 * Verify a plaintext password against a stored PBKDF2 hash string.
 * Uses crypto.timingSafeEqual to avoid timing-attack side channels.
 */
function verifyPassword(plainPassword, storedHash) {
    try {
        const [scheme, iterStr, salt, hash] = storedHash.split('$');
        if (scheme !== 'pbkdf2') return false;

        const iterations = parseInt(iterStr, 10);
        const testHash = crypto.pbkdf2Sync(
            plainPassword, salt, iterations, KEY_LENGTH, DIGEST
        );
        const storedHashBuf = Buffer.from(hash, 'hex');

        if (testHash.length !== storedHashBuf.length) return false;
        return crypto.timingSafeEqual(testHash, storedHashBuf);
    } catch (err) {
        return false; // malformed hash -> treat as verification failure
    }
}

/**
 * Basic password complexity policy.
 * Per Baker (2022): length is the dominant factor in search-space size;
 * modern guidance favours a longer minimum length over forced periodic
 * rotation. Minimum 9 characters, mixed character classes recommended.
 */
function validatePasswordPolicy(password) {
    const errors = [];
    if (!password || password.length < 9) {
        errors.push('Password must be at least 9 characters long.');
    }
    if (!/[a-z]/.test(password)) errors.push('Include at least one lowercase letter.');
    if (!/[A-Z]/.test(password)) errors.push('Include at least one uppercase letter.');
    if (!/[0-9]/.test(password)) errors.push('Include at least one number.');
    if (!/[^A-Za-z0-9]/.test(password)) errors.push('Include at least one special character.');
    return { valid: errors.length === 0, errors };
}

/**
 * Generate a cryptographically secure, single-use, expiring token for
 * password resets. The raw token is sent to the user (e.g. via a link);
 * only its hash is stored server-side, so a leaked database cannot be
 * used to forge valid reset links (per Baker, 2022).
 */
function generateResetToken() {
    const raw = crypto.randomBytes(32).toString('base64url');
    const tokenHash = crypto.createHash('sha256').update(raw).digest('hex');
    return { raw, tokenHash };
}

module.exports = {
    hashPassword,
    verifyPassword,
    validatePasswordPolicy,
    generateResetToken,
};
