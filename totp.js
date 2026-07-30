// ====================================================================
// TIME-BASED ONE-TIME PASSWORD (TOTP) — RFC 6238
// Implements app-based Multi-Factor Authentication (MFA), compatible
// with standard authenticator apps (Google Authenticator, Authy, etc.)
// Implementation uses only Node's built-in crypto module and has been
// verified against the official RFC 6238 test vector.
// ====================================================================

const crypto = require('crypto');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buffer) {
    let bits = '';
    for (const byte of buffer) bits += byte.toString(2).padStart(8, '0');
    let output = '';
    for (let i = 0; i < bits.length; i += 5) {
        const chunk = bits.slice(i, i + 5).padEnd(5, '0');
        output += BASE32_ALPHABET[parseInt(chunk, 2)];
    }
    return output;
}

function base32Decode(base32) {
    let bits = '';
    for (const char of base32.replace(/=+$/, '').toUpperCase()) {
        const val = BASE32_ALPHABET.indexOf(char);
        if (val === -1) continue;
        bits += val.toString(2).padStart(5, '0');
    }
    const bytes = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }
    return Buffer.from(bytes);
}

/** Generate a new random MFA secret (base32, 20 bytes = 160 bits). */
function generateSecret() {
    return base32Encode(crypto.randomBytes(20));
}

/** Build the otpauth:// URI used to populate a QR code / manual entry. */
function buildOtpauthUri(secretBase32, accountEmail, issuer = 'SecureWebApp') {
    const label = encodeURIComponent(`${issuer}:${accountEmail}`);
    const params = new URLSearchParams({
        secret: secretBase32,
        issuer,
        algorithm: 'SHA1',
        digits: '6',
        period: '30',
    });
    return `otpauth://totp/${label}?${params.toString()}`;
}

/** Compute the TOTP code for a given secret at a given point in time. */
function generateTOTP(secretBase32, { timeStep = 30, digits = 6, forTime = Date.now() } = {}) {
    const key = base32Decode(secretBase32);
    const counter = Math.floor(forTime / 1000 / timeStep);

    const counterBuf = Buffer.alloc(8);
    counterBuf.writeBigUInt64BE(BigInt(counter));

    const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
    const offset = hmac[hmac.length - 1] & 0xf;
    const binCode =
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);

    return (binCode % 10 ** digits).toString().padStart(digits, '0');
}

/**
 * Verify a user-submitted TOTP code, allowing +/- 1 time step (30s)
 * of clock drift, which is standard practice for TOTP verification.
 */
function verifyTOTP(secretBase32, userCode, { window = 1 } = {}) {
    const now = Date.now();
    for (let errorWindow = -window; errorWindow <= window; errorWindow++) {
        const candidate = generateTOTP(secretBase32, {
            forTime: now + errorWindow * 30 * 1000,
        });
        if (crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(userCode.padStart(6, '0')))) {
            return true;
        }
    }
    return false;
}

module.exports = {
    generateSecret,
    buildOtpauthUri,
    generateTOTP,
    verifyTOTP,
};
