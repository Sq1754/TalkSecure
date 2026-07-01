/**
 * Talk-Secure — Server-Side Crypto Utilities
 * AES-256-GCM encryption for at-rest database storage
 * Uses only Node.js native crypto module
 */
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96-bit IV for GCM (recommended)
const KEY_LENGTH = 32;
const AUTH_TAG_LENGTH = 16;

let _derivedKey = null;

/**
 * Derive encryption key from the master DB_ENCRYPTION_KEY using PBKDF2
 */
function getDerivedKey() {
    if (_derivedKey) return _derivedKey;

    const masterKey = process.env.DB_ENCRYPTION_KEY;
    if (!masterKey) {
        throw new Error('DB_ENCRYPTION_KEY not set. Run: npm run setup');
    }

    // PBKDF2 with 100,000 iterations for key stretching
    _derivedKey = crypto.pbkdf2Sync(
        Buffer.from(masterKey, 'hex'),
        'vaultchat-db-salt-v1', // Fixed salt — the master key is already random (kept for backward compat)
        100000,
        KEY_LENGTH,
        'sha512'
    );

    return _derivedKey;
}

/**
 * Encrypt plaintext for database storage (AES-256-GCM)
 * Returns: iv:authTag:ciphertext (hex encoded)
 * Provides both confidentiality AND integrity/authentication
 */
function encryptForStorage(plaintext) {
    if (!plaintext) return null;

    const key = getDerivedKey();
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });

    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag().toString('hex');

    return iv.toString('hex') + ':' + authTag + ':' + encrypted;
}

/**
 * Decrypt ciphertext from database storage (AES-256-GCM)
 * Input: iv:authTag:ciphertext (hex encoded) — new format
 *    or: iv:ciphertext (hex encoded) — legacy CBC format
 */
function decryptFromStorage(encryptedData) {
    if (!encryptedData) return null;

    const key = getDerivedKey();
    const parts = encryptedData.split(':');

    if (parts.length === 3) {
        // New GCM format: iv:authTag:ciphertext
        const iv = Buffer.from(parts[0], 'hex');
        const authTag = Buffer.from(parts[1], 'hex');
        const encrypted = parts[2];

        const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
        decipher.setAuthTag(authTag);
        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        return decrypted;
    } else if (parts.length === 2) {
        // Legacy CBC format detected — no longer supported due to padding oracle risk
        throw new Error('Legacy CBC-encrypted data detected. Data migration required. Please contact support.');
    }

    throw new Error('Unknown encryption format');
}

/**
 * Generate a cryptographically secure random token
 */
function generateToken(bytes = 32) {
    return crypto.randomBytes(bytes).toString('hex');
}

/**
 * Hash data with SHA-256
 */
function sha256(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

module.exports = {
    encryptForStorage,
    decryptFromStorage,
    generateToken,
    sha256
};
