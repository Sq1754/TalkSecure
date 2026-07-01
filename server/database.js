/**
 * Talk-Secure — Database Module
 * SQLite with encrypted-at-rest message storage
 * Auto-cleanup of messages older than retention period
 * Multi-user support with targeted messaging
 */
const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');
const { encryptForStorage, decryptFromStorage } = require('./crypto');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'vault.db');
const UPLOADS_PATH = process.env.UPLOADS_PATH || path.join(__dirname, '..', 'data', 'uploads');
let db = null;

function getDb() {
    if (db) return db;

    // Ensure parent directories exist
    const dbDir = path.dirname(DB_PATH);
    if (!fs.existsSync(dbDir)) {
        fs.mkdirSync(dbDir, { recursive: true });
    }
    if (!fs.existsSync(UPLOADS_PATH)) {
        fs.mkdirSync(UPLOADS_PATH, { recursive: true });
    }

    db = new Database(DB_PATH);

    // Security: WAL mode for better concurrent access, foreign keys on
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');

    initializeTables();

    // Migration: verify if email, phone, and is_admin columns exist in the users table
    try {
        db.prepare('SELECT email FROM users LIMIT 1').get();
    } catch (e) {
        try { db.exec('ALTER TABLE users ADD COLUMN email TEXT'); } catch(err){}
        try { db.exec('ALTER TABLE users ADD COLUMN phone TEXT'); } catch(err){}
        try { db.exec('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0'); } catch(err){}
        console.log('✅ SQLite users table successfully migrated with Email, Phone, and Admin columns');
    }

    return db;
}

function initializeTables() {
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            failed_attempts INTEGER DEFAULT 0,
            locked_until TEXT DEFAULT NULL
        );

        CREATE TABLE IF NOT EXISTS public_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            public_key_jwk TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            session_id TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            encrypted_content TEXT NOT NULL,
            iv TEXT NOT NULL,
            auth_tag TEXT,
            timestamp TEXT DEFAULT (datetime('now')),
            delivered INTEGER DEFAULT 0,
            read_at TEXT DEFAULT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS contacts (
            user_id INTEGER NOT NULL,
            contact_user_id INTEGER NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            PRIMARY KEY (user_id, contact_user_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (contact_user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            rating INTEGER DEFAULT 5,
            timestamp TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            timestamp TEXT DEFAULT (datetime('now')),
            details TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            created_by INTEGER NOT NULL,
            used_by INTEGER DEFAULT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            used_at TEXT DEFAULT NULL,
            status TEXT DEFAULT 'pending',
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (used_by) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS support_tickets (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            category TEXT NOT NULL,
            status TEXT DEFAULT 'open',
            created_at TEXT DEFAULT (datetime('now')),
            resolved_at TEXT DEFAULT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS diagnostic_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            metric_type TEXT NOT NULL,
            metric_value REAL NOT NULL,
            timestamp TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS pending_registrations (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            invite_token TEXT,
            otp TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            expires_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id, delivered);
        CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at);
        CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, receiver_id);
        CREATE INDEX IF NOT EXISTS idx_public_keys_user ON public_keys(user_id);
        CREATE INDEX IF NOT EXISTS idx_contacts_user ON contacts(user_id);
        CREATE INDEX IF NOT EXISTS idx_invites_token ON invites(token);
        CREATE INDEX IF NOT EXISTS idx_support_tickets_user ON support_tickets(user_id);
        CREATE INDEX IF NOT EXISTS idx_diagnostic_metrics_type ON diagnostic_metrics(metric_type);
    `);
}

// ═══════════════════════════════════════
// User Operations
// ═══════════════════════════════════════

function getUserCount() {
    const row = getDb().prepare('SELECT COUNT(*) as count FROM users').get();
    return row.count;
}

function createUser(username, passwordHash, email, phone) {
    const countRow = getDb().prepare('SELECT COUNT(*) as count FROM users').get();
    const isAdmin = countRow.count === 0 ? 1 : 0;

    const stmt = getDb().prepare('INSERT INTO users (username, password_hash, email, phone, is_admin) VALUES (?, ?, ?, ?, ?)');
    return stmt.run(username, passwordHash, email || null, phone || null, isAdmin);
}

function getUserByUsername(username) {
    return getDb().prepare('SELECT * FROM users WHERE username = ?').get(username);
}

function getUserById(id) {
    return getDb().prepare('SELECT id, username, created_at FROM users WHERE id = ?').get(id);
}

function getAllUsersExcept(userId) {
    return getDb().prepare('SELECT id, username, created_at FROM users WHERE id != ? ORDER BY username ASC').all(userId);
}

function incrementFailedAttempts(userId) {
    const lockThreshold = 5;
    const lockMinutes = 15;

    const user = getDb().prepare('SELECT failed_attempts FROM users WHERE id = ?').get(userId);
    const newCount = (user.failed_attempts || 0) + 1;

    if (newCount >= lockThreshold) {
        const lockUntil = new Date(Date.now() + lockMinutes * 60 * 1000).toISOString();
        getDb().prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?')
            .run(newCount, lockUntil, userId);
    } else {
        getDb().prepare('UPDATE users SET failed_attempts = ? WHERE id = ?')
            .run(newCount, userId);
    }
}

function resetFailedAttempts(userId) {
    getDb().prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?')
        .run(userId);
}

function isUserLocked(userId) {
    const user = getDb().prepare('SELECT locked_until FROM users WHERE id = ?').get(userId);
    if (!user || !user.locked_until) return false;

    if (new Date(user.locked_until) > new Date()) {
        return true;
    }

    // Lock expired, reset
    resetFailedAttempts(userId);
    return false;
}

function deleteUser(userId) {
    const stmt = getDb().prepare('DELETE FROM users WHERE id = ?');
    return stmt.run(userId);
}

// ═══════════════════════════════════════
// Public Key Operations
// ═══════════════════════════════════════

function storePublicKey(userId, publicKeyJwk, fingerprint, sessionId) {
    // Remove old keys for this user
    getDb().prepare('DELETE FROM public_keys WHERE user_id = ?').run(userId);

    const stmt = getDb().prepare(
        'INSERT INTO public_keys (user_id, public_key_jwk, fingerprint, session_id) VALUES (?, ?, ?, ?)'
    );
    return stmt.run(userId, publicKeyJwk, fingerprint, sessionId);
}

function getPublicKey(userId) {
    return getDb().prepare(
        'SELECT public_key_jwk, fingerprint, session_id, created_at FROM public_keys WHERE user_id = ? ORDER BY created_at DESC LIMIT 1'
    ).get(userId);
}

function getLatestGlobalForceRotationTime() {
    const row = getDb().prepare("SELECT timestamp FROM activity_logs WHERE action = 'global_key_rotation_forced' ORDER BY timestamp DESC LIMIT 1").get();
    return row ? row.timestamp : null;
}

// ═══════════════════════════════════════
// Message Operations (encrypted at rest)
// ═══════════════════════════════════════

function storeMessage(id, senderId, receiverId, encryptedContent, iv, authTag) {
    const retentionDays = parseInt(process.env.MESSAGE_RETENTION_DAYS) || 14;
    const expiresAt = new Date(Date.now() + retentionDays * 24 * 60 * 60 * 1000).toISOString();
    const timestamp = new Date().toISOString();

    // Double-encrypt: client already encrypted the message, we encrypt again for at-rest storage
    const doubleEncrypted = encryptForStorage(encryptedContent);

    const stmt = getDb().prepare(
        `INSERT INTO messages (id, sender_id, receiver_id, encrypted_content, iv, auth_tag, timestamp, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    );
    return stmt.run(id, senderId, receiverId, doubleEncrypted, iv, authTag || null, timestamp, expiresAt);
}

function getUndeliveredMessages(receiverId) {
    const rows = getDb().prepare(
        `SELECT id, sender_id, encrypted_content, iv, auth_tag, timestamp
         FROM messages WHERE receiver_id = ? AND delivered = 0
         ORDER BY timestamp ASC`
    ).all(receiverId);

    // Decrypt the at-rest layer
    return rows.map(row => ({
        ...row,
        encrypted_content: decryptFromStorage(row.encrypted_content)
    }));
}

function getMessageHistory(userId1, userId2, limit = 100) {
    const rows = getDb().prepare(
        `SELECT id, sender_id, receiver_id, encrypted_content, iv, auth_tag, timestamp, read_at
         FROM messages
         WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
         ORDER BY timestamp DESC LIMIT ?`
    ).all(userId1, userId2, userId2, userId1, limit);

    return rows.map(row => ({
        ...row,
        encrypted_content: decryptFromStorage(row.encrypted_content)
    })).reverse();
}

function markAsDelivered(messageId) {
    getDb().prepare('UPDATE messages SET delivered = 1 WHERE id = ?').run(messageId);
}

function markAsRead(messageId) {
    getDb().prepare('UPDATE messages SET read_at = datetime(\'now\') WHERE id = ?').run(messageId);
}

/**
 * Delete expired messages (older than MESSAGE_RETENTION_DAYS)
 */
function cleanupExpiredMessages() {
    const result = getDb().prepare(
        "DELETE FROM messages WHERE expires_at < datetime('now')"
    ).run();

    if (result.changes > 0) {
        console.log(`🗑️  Auto-deleted ${result.changes} expired message(s)`);
    }
    return result.changes;
}

/**
 * Cleanup expired uploaded files (older than MESSAGE_RETENTION_DAYS)
 */
function cleanupExpiredUploads() {
    try {
        if (!fs.existsSync(UPLOADS_PATH)) return 0;

        const retentionDays = parseInt(process.env.MESSAGE_RETENTION_DAYS) || 14;
        const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
        const files = fs.readdirSync(UPLOADS_PATH);
        let cleaned = 0;

        for (const file of files) {
            const filePath = path.join(UPLOADS_PATH, file);
            try {
                const stats = fs.statSync(filePath);
                if (stats.mtimeMs < cutoff) {
                    fs.unlinkSync(filePath);
                    cleaned++;
                }
            } catch (err) {
                // Skip files we can't stat
            }
        }

        if (cleaned > 0) {
            console.log(`🗑️  Auto-deleted ${cleaned} expired upload(s)`);
        }
        return cleaned;
    } catch (err) {
        console.error('Failed to clean uploads directory:', err);
        return 0;
    }
}

function clearMessagesForPair(userId1, userId2) {
    const result = getDb().prepare(
        "DELETE FROM messages WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)"
    ).run(userId1, userId2, userId2, userId1);

    if (result.changes > 0) {
        console.log(`🗑️  Cleared ${result.changes} messages for key rotation between users ${userId1} and ${userId2}`);
    }
    return result.changes;
}

function searchUsers(query, userId) {
    const stmt = getDb().prepare(`
        SELECT id, username FROM users 
        WHERE (username LIKE ? OR phone LIKE ?) AND id != ?
        LIMIT 20
    `);
    const term = '%' + query + '%';
    return stmt.all(term, term, userId);
}

function addContact(userId, contactId) {
    const stmt = getDb().prepare('INSERT OR IGNORE INTO contacts (user_id, contact_user_id) VALUES (?, ?)');
    stmt.run(userId, contactId);
    stmt.run(contactId, userId);
}

function getContacts(userId) {
    return getDb().prepare(`
        SELECT u.id, u.username, u.created_at, u.is_admin 
        FROM contacts c
        JOIN users u ON c.contact_user_id = u.id
        WHERE c.user_id = ?
        ORDER BY u.username ASC
    `).all(userId);
}

function logActivity(userId, action, details) {
    try {
        const detailsStr = details ? JSON.stringify(details) : null;
        const stmt = getDb().prepare('INSERT INTO activity_logs (user_id, action, details) VALUES (?, ?, ?)');
        return stmt.run(userId || null, action, detailsStr);
    } catch (err) {
        console.error('Failed to log activity:', err);
    }
}

function submitFeedback(userId, message, rating) {
    const stmt = getDb().prepare('INSERT INTO feedback (user_id, message, rating) VALUES (?, ?, ?)');
    return stmt.run(userId, message, rating || 5);
}

function getAdminMetrics() {
    const db = getDb();
    
    const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
    const totalMessages = db.prepare('SELECT COUNT(*) as count FROM messages').get().count;
    const totalFeedbacks = db.prepare('SELECT COUNT(*) as count FROM feedback').get().count;
    const averageRatingRow = db.prepare('SELECT AVG(rating) as avgRating FROM feedback').get();
    const avgRating = averageRatingRow.avgRating ? parseFloat(averageRatingRow.avgRating).toFixed(1) : '5.0';
    
    const activeUsers24h = db.prepare(`
        SELECT COUNT(DISTINCT user_id) as count 
        FROM activity_logs 
        WHERE timestamp > datetime('now', '-1 day') AND user_id IS NOT NULL
    `).get().count;
    
    const usersList = db.prepare(`
        SELECT u.id, u.username, u.email, u.phone, u.is_admin, u.created_at, u.locked_until,
               (SELECT COUNT(*) FROM public_keys pk WHERE pk.user_id = u.id) as has_key
        FROM users u
        ORDER BY u.created_at DESC
    `).all();

    return {
        totalUsers,
        totalMessages,
        totalFeedbacks,
        avgRating,
        activeUsers24h,
        usersList
    };
}

function getFeedbackList() {
    return getDb().prepare(`
        SELECT f.id, f.message, f.rating, f.timestamp, u.username 
        FROM feedback f
        JOIN users u ON f.user_id = u.id
        ORDER BY f.timestamp DESC
    `).all();
}

function getActivityLogs() {
    return getDb().prepare(`
        SELECT al.id, al.action, al.timestamp, al.details, u.username 
        FROM activity_logs al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.timestamp DESC LIMIT 100
    `).all();
}

function getSecurityAuditSummary() {
    const db = getDb();
    
    // 1. Key Age Statistics: avg key age in days, count of expired/aged keys (> 30 days)
    // We compute julianday('now') - julianday(created_at) for all users' active public keys
    const keyMetrics = db.prepare(`
        SELECT 
            AVG(julianday('now') - julianday(created_at)) as avgAgeDays,
            COUNT(*) as totalKeys,
            SUM(CASE WHEN (julianday('now') - julianday(created_at)) > 30 THEN 1 ELSE 0 END) as expiredKeys
        FROM public_keys
    `).get();

    const avgKeyAge = keyMetrics.avgAgeDays != null ? parseFloat(keyMetrics.avgAgeDays).toFixed(1) : '0.0';
    const totalKeys = keyMetrics.totalKeys || 0;
    const expiredKeys = keyMetrics.expiredKeys || 0;

    // 2. Lockout and Access attempt metrics
    const activeLockouts = db.prepare(`
        SELECT COUNT(*) as count FROM users 
        WHERE locked_until IS NOT NULL AND datetime(locked_until) > datetime('now')
    `).get().count;

    const failedLoginsWeek = db.prepare(`
        SELECT COUNT(*) as count FROM activity_logs
        WHERE action = 'login_failed' AND timestamp > datetime('now', '-7 days')
    `).get().count;

    // 3. Security events timeline: last 30 logs from activity_logs containing security events
    const securityLogs = db.prepare(`
        SELECT al.id, al.action, al.timestamp, al.details, u.username 
        FROM activity_logs al
        LEFT JOIN users u ON al.user_id = u.id
        WHERE al.action IN ('login_failed', 'account_locked', 'admin_change_role', 'admin_delete_user', 'admin_toggle_lock', 'register', 'login_success', 'global_key_rotation_forced')
        ORDER BY al.timestamp DESC LIMIT 30
    `).all();

    // 4. Compute composite Security Health Score (1-100) and letter grade
    let score = 100;
    // Deduct 15 points per active lockout
    score -= (activeLockouts * 15);
    // Deduct 5 points per expired key
    score -= (expiredKeys * 5);
    // Deduct 2 points per failed login in the last week
    score -= (failedLoginsWeek * 2);

    // Clamp score
    score = Math.max(10, Math.min(100, score));

    // Grade mapping
    let grade = 'A+';
    if (score >= 95) grade = 'A+';
    else if (score >= 90) grade = 'A';
    else if (score >= 80) grade = 'B';
    else if (score >= 70) grade = 'C';
    else if (score >= 50) grade = 'D';
    else grade = 'F';

    return {
        avgKeyAge,
        totalKeys,
        expiredKeys,
        activeLockouts,
        failedLoginsWeek,
        securityLogs,
        score,
        grade
    };
}

function setUserRole(userId, isAdmin) {
    const stmt = getDb().prepare('UPDATE users SET is_admin = ? WHERE id = ?');
    return stmt.run(isAdmin ? 1 : 0, userId);
}

function toggleUserLock(userId) {
    const db = getDb();
    const user = db.prepare('SELECT locked_until FROM users WHERE id = ?').get(userId);
    if (user && user.locked_until) {
        return db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?').run(userId);
    } else {
        const lockTime = new Date(Date.now() + 99 * 365 * 24 * 60 * 60 * 1000).toISOString();
        return db.prepare('UPDATE users SET locked_until = ? WHERE id = ?').run(lockTime, userId);
    }
}

function createInvite(adminUserId, token) {
    const stmt = getDb().prepare('INSERT INTO invites (token, created_by) VALUES (?, ?)');
    return stmt.run(token, adminUserId);
}

function verifyInviteToken(token) {
    const invite = getDb().prepare("SELECT * FROM invites WHERE token = ? AND status = 'pending'").get(token);
    return invite || null;
}

function redeemInviteToken(token, newUserId) {
    const timestamp = new Date().toISOString();
    const db = getDb();
    
    // Mark token as used
    db.prepare("UPDATE invites SET used_by = ?, used_at = ?, status = 'used' WHERE token = ?")
      .run(newUserId, timestamp, token);
      
    // Find who invited the user
    const invite = db.prepare("SELECT created_by FROM invites WHERE token = ?").get(token);
    if (invite) {
        const referrerId = invite.created_by;
        const stmt = db.prepare('INSERT OR IGNORE INTO contacts (user_id, contact_user_id) VALUES (?, ?)');
        stmt.run(newUserId, referrerId);
        stmt.run(referrerId, newUserId);
    }
}

function getInvitesList() {
    return getDb().prepare(`
        SELECT i.id, i.token, i.created_at, i.used_at, i.status, 
               u_creator.username as creator_username,
               u_redeemer.username as redeemer_username
        FROM invites i
        JOIN users u_creator ON i.created_by = u_creator.id
        LEFT JOIN users u_redeemer ON i.used_by = u_redeemer.id
        ORDER BY i.created_at DESC
    `).all();
}

function getAllUsersPublicKeys() {
    return getDb().prepare(`
        SELECT u.id, u.username, pk.public_key_jwk 
        FROM users u
        JOIN public_keys pk ON pk.user_id = u.id
    `).all();
}

function createSupportTicket(userId, ticketId, category) {
    const stmt = getDb().prepare('INSERT INTO support_tickets (id, user_id, category) VALUES (?, ?, ?)');
    return stmt.run(ticketId, userId, category);
}

function resolveSupportTicket(ticketId) {
    const timestamp = new Date().toISOString();
    const stmt = getDb().prepare("UPDATE support_tickets SET status = 'resolved', resolved_at = ? WHERE id = ?");
    return stmt.run(timestamp, ticketId);
}

function getSupportTicketsList() {
    return getDb().prepare(`
        SELECT t.id, t.category, t.status, t.created_at, t.resolved_at, u.username 
        FROM support_tickets t
        JOIN users u ON t.user_id = u.id
        ORDER BY t.created_at DESC
    `).all();
}

function getUserSupportTickets(userId) {
    return getDb().prepare(`
        SELECT id, category, status, created_at, resolved_at 
        FROM support_tickets 
        WHERE user_id = ?
        ORDER BY created_at DESC
    `).all(userId);
}

function logDiagnosticMetric(userId, type, value) {
    const stmt = getDb().prepare('INSERT INTO diagnostic_metrics (user_id, metric_type, metric_value) VALUES (?, ?, ?)');
    return stmt.run(userId || null, type, parseFloat(value));
}

function getDiagnosticsSummary() {
    const db = getDb();
    
    // Average values
    const avgWsRow = db.prepare("SELECT AVG(metric_value) as avgVal FROM diagnostic_metrics WHERE metric_type = 'ws_latency'").get();
    const avgWebRtcRow = db.prepare("SELECT AVG(metric_value) as avgVal FROM diagnostic_metrics WHERE metric_type = 'webrtc_latency'").get();
    
    const avgWsLatency = avgWsRow.avgVal ? parseFloat(avgWsRow.avgVal).toFixed(1) : '0.0';
    const avgWebRtcLatency = avgWebRtcRow.avgVal ? parseFloat(avgWebRtcRow.avgVal).toFixed(1) : '0.0';
    
    // Last 30 metrics for sparkline charting
    const sparklinePoints = db.prepare(`
        SELECT metric_type, metric_value, timestamp 
        FROM diagnostic_metrics 
        ORDER BY timestamp DESC LIMIT 30
    `).all().reverse(); // reverse so chronologically sorted (left-to-right)

    // Last 10 raw logs for dashboard logs listing
    const rawLogs = db.prepare(`
        SELECT dm.id, dm.metric_type, dm.metric_value, dm.timestamp, u.username 
        FROM diagnostic_metrics dm
        LEFT JOIN users u ON dm.user_id = u.id
        ORDER BY dm.timestamp DESC LIMIT 10
    `).all();

    return {
        avgWsLatency,
        avgWebRtcLatency,
        sparklinePoints,
        rawLogs
    };
}

function createPendingRegistration(id, username, passwordHash, email, phone, inviteToken, otp, expiresAt) {
    const db = getDb();
    // Delete any existing pending registrations for this username to overwrite/retry
    db.prepare('DELETE FROM pending_registrations WHERE username = ?').run(username);
    
    const stmt = db.prepare(
        `INSERT INTO pending_registrations (id, username, password_hash, email, phone, invite_token, otp, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    );
    return stmt.run(id, username, passwordHash, email, phone, inviteToken || null, otp, expiresAt);
}

function getPendingRegistration(id) {
    return getDb().prepare('SELECT * FROM pending_registrations WHERE id = ?').get(id);
}

function deletePendingRegistration(id) {
    return getDb().prepare('DELETE FROM pending_registrations WHERE id = ?').run(id);
}

function closeDb() {
    if (db) {
        db.close();
        db = null;
    }
}

module.exports = {
    getDb,
    getUserCount,
    createUser,
    createPendingRegistration,
    getPendingRegistration,
    deletePendingRegistration,
    getUserByUsername,
    getUserById,
    getAllUsersExcept,
    incrementFailedAttempts,
    resetFailedAttempts,
    isUserLocked,
    storePublicKey,
    getPublicKey,
    getLatestGlobalForceRotationTime,
    storeMessage,
    getUndeliveredMessages,
    getMessageHistory,
    markAsDelivered,
    markAsRead,
    cleanupExpiredMessages,
    cleanupExpiredUploads,
    clearMessagesForPair,
    searchUsers,
    addContact,
    getContacts,
    logActivity,
    submitFeedback,
    getAdminMetrics,
    getFeedbackList,
    getActivityLogs,
    getSecurityAuditSummary,
    setUserRole,
    toggleUserLock,
    deleteUser,
    createInvite,
    verifyInviteToken,
    redeemInviteToken,
    getInvitesList,
    getAllUsersPublicKeys,
    createSupportTicket,
    resolveSupportTicket,
    getSupportTicketsList,
    getUserSupportTickets,
    logDiagnosticMetric,
    getDiagnosticsSummary,
    closeDb
};
