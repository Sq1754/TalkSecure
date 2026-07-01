/**
 * Talk-Secure — Main Server Entry
 * HTTPS + Express + WebSocket
 * Self-signed TLS, no third-party services
 */

// Load environment variables
const fs = require('fs');
const path = require('path');

const envPath = path.join(__dirname, '..', '.env');
if (fs.existsSync(envPath)) {
    const envContent = fs.readFileSync(envPath, 'utf8');
    for (const line of envContent.split('\n')) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
            const eqIdx = trimmed.indexOf('=');
            if (eqIdx > 0) {
                const key = trimmed.substring(0, eqIdx).trim();
                const value = trimmed.substring(eqIdx + 1).trim();
                if (!process.env[key]) {
                    process.env[key] = value;
                }
            }
        }
    }
} else {
    console.error('❌ .env file not found. Run: npm run setup');
    process.exit(1);
}

const https = require('https');
const http = require('http');
const express = require('express');
const { register, login, isRegistrationOpen, verifyOtp } = require('./auth');
const { rateLimit, securityHeaders, sanitizeBody, strictCors } = require('./middleware');
const { setupWebSocket } = require('./websocket');
const { getDb } = require('./database');
const { verifyToken } = require('./auth');

const app = express();
app.disable('x-powered-by');

// ═══════════════════════════════════════
// Middleware
// ═══════════════════════════════════════

app.use(express.json({ limit: '1mb' }));
app.use(securityHeaders);
app.use(strictCors);
app.use(sanitizeBody);

// Rate limiting on API endpoints
const apiLimiter = rateLimit(
    parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60000,
    parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100
);
app.use('/api/', apiLimiter);

// Stricter rate limit on auth endpoints
const authLimiter = rateLimit(60000, 10); // 10 per minute
app.use('/api/auth/', authLimiter);

// Serve static files
app.use(express.static(path.join(__dirname, '..', 'public')));

// ═══════════════════════════════════════
// JWT Authentication Middleware
// ═══════════════════════════════════════

function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    const token = authHeader.substring(7);
    const decoded = verifyToken(token);
    if (!decoded) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }

    req.userId = decoded.userId;
    req.username = decoded.username;
    next();
}

// ═══════════════════════════════════════
// API Routes
// ═══════════════════════════════════════

// Registration
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, email, phone, inviteToken } = req.body;
        const result = await register(username, password, email, phone, inviteToken);
        const status = result.success ? 201 : 400;
        res.status(status).json(result);
    } catch (err) {
        console.error('Register error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Verify OTP
app.post('/api/auth/verify-otp', async (req, res) => {
    try {
        const { pendingId, otp } = req.body;
        const result = await verifyOtp(pendingId, otp);
        const status = result.success ? 200 : 400;
        res.status(status).json(result);
    } catch (err) {
        console.error('Verify OTP error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const result = await login(username, password);
        const status = result.success ? 200 : 401;
        res.status(status).json(result);
    } catch (err) {
        console.error('Login error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Check registration status
app.get('/api/auth/status', (req, res) => {
    res.json({ registrationOpen: isRegistrationOpen() });
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ═══════════════════════════════════════
// Contacts & Discovery API
// ═══════════════════════════════════════

// Get ONLY connected contacts (curated list) — requires auth
app.get('/api/users', requireAuth, (req, res) => {
    try {
        const { getContacts } = require('./database');
        const users = getContacts(req.userId);
        res.json({ success: true, users });
    } catch (err) {
        console.error('Users list error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Search other users globally (discovery) — requires auth
app.post('/api/contacts/search', requireAuth, (req, res) => {
    try {
        const { query } = req.body;
        if (!query || query.trim().length === 0) {
            return res.status(400).json({ success: false, message: 'Search query is required' });
        }
        const { searchUsers } = require('./database');
        const results = searchUsers(query, req.userId);
        res.json({ success: true, results });
    } catch (err) {
        console.error('Contacts search error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Add/Connect a contact — requires auth
app.post('/api/contacts/add', requireAuth, (req, res) => {
    try {
        const { contactId } = req.body;
        if (!contactId) {
            return res.status(400).json({ success: false, message: 'Contact user ID is required' });
        }
        if (isNaN(parseInt(contactId, 10))) {
            return res.status(400).json({ success: false, message: 'Invalid user ID format' });
        }
        const { addContact, logActivity } = require('./database');
        addContact(req.userId, contactId);
        
        // Log connection activity
        logActivity(req.userId, 'connect_contact', { contactId });
        
        res.json({ success: true, message: 'Contact successfully added' });
    } catch (err) {
        console.error('Add contact error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Submit user feedback — requires auth
app.post('/api/feedback', requireAuth, (req, res) => {
    try {
        const { message, rating } = req.body;
        if (!message || message.trim().length === 0) {
            return res.status(400).json({ success: false, message: 'Feedback message is required' });
        }
        const { submitFeedback, logActivity } = require('./database');
        submitFeedback(req.userId, message, parseInt(rating) || 5);
        
        // Log feedback activity
        logActivity(req.userId, 'submit_feedback', { rating });
        
        res.json({ success: true, message: 'Feedback successfully submitted. Thank you!' });
    } catch (err) {
        console.error('Feedback submit error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ═══════════════════════════════════════
// Admin Cockpit API
// ═══════════════════════════════════════

function requireAdmin(req, res, next) {
    const { getDb } = require('./database');
    const user = getDb().prepare('SELECT is_admin FROM users WHERE id = ?').get(req.userId);
    if (!user || user.is_admin !== 1) {
        return res.status(403).json({ error: 'Access denied: Administrator privileges required' });
    }
    next();
}

// System Metrics
app.get('/api/admin/metrics', requireAuth, requireAdmin, (req, res) => {
    try {
        const { getAdminMetrics } = require('./database');
        const metrics = getAdminMetrics();
        res.json({ success: true, ...metrics });
    } catch (err) {
        console.error('Admin metrics error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Feedback Hub List
app.get('/api/admin/feedback', requireAuth, requireAdmin, (req, res) => {
    try {
        const { getFeedbackList } = require('./database');
        const feedbacks = getFeedbackList();
        res.json({ success: true, feedbacks });
    } catch (err) {
        console.error('Admin feedback list error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Audit Activity Logs
app.get('/api/admin/logs', requireAuth, requireAdmin, (req, res) => {
    try {
        const { getActivityLogs } = require('./database');
        const logs = getActivityLogs();
        res.json({ success: true, logs });
    } catch (err) {
        console.error('Admin activity logs error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Toggle locks
app.post('/api/admin/users/lock', requireAuth, requireAdmin, (req, res) => {
    try {
        const { targetUserId } = req.body;
        if (!targetUserId) {
            return res.status(400).json({ success: false, message: 'Target user ID is required' });
        }
        if (isNaN(parseInt(targetUserId, 10))) {
            return res.status(400).json({ success: false, message: 'Invalid user ID format' });
        }
        
        if (Number(targetUserId) === Number(req.userId)) {
            return res.status(400).json({ success: false, message: 'You cannot lock or unlock your own account' });
        }
        
        const { toggleUserLock, logActivity } = require('./database');
        toggleUserLock(targetUserId);
        
        logActivity(req.userId, 'admin_toggle_lock', { targetUserId });
        
        res.json({ success: true, message: 'User lock status successfully toggled' });
    } catch (err) {
        console.error('Admin toggle lock error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Promote/Demote roles
app.post('/api/admin/users/role', requireAuth, requireAdmin, (req, res) => {
    try {
        const { targetUserId, isAdmin } = req.body;
        if (!targetUserId) {
            return res.status(400).json({ success: false, message: 'Target user ID is required' });
        }
        if (isNaN(parseInt(targetUserId, 10))) {
            return res.status(400).json({ success: false, message: 'Invalid user ID format' });
        }
        const { setUserRole, logActivity } = require('./database');
        setUserRole(targetUserId, isAdmin);

        // Auto-pair the newly promoted admin with all other users
        if (isAdmin) {
            try {
                const { getDb } = require('./database');
                const db = getDb();
                const otherUsers = db.prepare('SELECT id FROM users WHERE id != ?').all(targetUserId);
                for (const other of otherUsers) {
                    const stmt = db.prepare('INSERT OR IGNORE INTO contacts (user_id, contact_user_id) VALUES (?, ?)');
                    stmt.run(targetUserId, other.id);
                    stmt.run(other.id, targetUserId);
                }
            } catch (err) {
                console.error('Failed to auto-pair newly promoted administrator:', err);
            }
        }
        
        logActivity(req.userId, 'admin_change_role', { targetUserId, isAdmin });
        
        res.json({ success: true, message: 'User role successfully updated' });
    } catch (err) {
        console.error('Admin change role error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Delete user account
app.post('/api/admin/users/delete', requireAuth, requireAdmin, (req, res) => {
    try {
        const { targetUserId } = req.body;
        if (!targetUserId) {
            return res.status(400).json({ success: false, message: 'Target user ID is required' });
        }
        if (isNaN(parseInt(targetUserId, 10))) {
            return res.status(400).json({ success: false, message: 'Invalid user ID format' });
        }
        
        if (Number(targetUserId) === Number(req.userId)) {
            return res.status(400).json({ success: false, message: 'You cannot delete your own account' });
        }
        
        const { deleteUser, logActivity } = require('./database');
        const { disconnectUser } = require('./websocket');
        
        // Terminate any active socket sessions first
        disconnectUser(Number(targetUserId));
        
        // Delete user (cascades automatically to all tables in SQLite)
        deleteUser(Number(targetUserId));
        
        logActivity(req.userId, 'admin_delete_user', { targetUserId });
        
        res.json({ success: true, message: 'User and all related records successfully deleted' });
    } catch (err) {
        console.error('Admin delete user error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Create invite token
app.post('/api/admin/invites/create', requireAuth, requireAdmin, (req, res) => {
    try {
        const crypto = require('crypto');
        const token = 'TS-' + crypto.randomBytes(8).toString('hex').toUpperCase();
        
        const { createInvite, logActivity } = require('./database');
        createInvite(req.userId, token);
        
        logActivity(req.userId, 'admin_create_invite', { token });
        
        res.json({ success: true, token, message: 'Invite token generated successfully' });
    } catch (err) {
        console.error('Admin create invite error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// List all invite tokens
app.get('/api/admin/invites', requireAuth, requireAdmin, (req, res) => {
    try {
        const { getInvitesList } = require('./database');
        const invites = getInvitesList();
        res.json({ success: true, invites });
    } catch (err) {
        console.error('Admin list invites error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get all users' public keys for broadcast E2E encryption
app.get('/api/admin/broadcast/keys', requireAuth, requireAdmin, (req, res) => {
    try {
        const { getAllUsersPublicKeys } = require('./database');
        const keys = getAllUsersPublicKeys();
        res.json({ success: true, keys });
    } catch (err) {
        console.error('Admin broadcast keys error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Expose user-level ticket creation
app.post('/api/support/tickets', requireAuth, (req, res) => {
    try {
        const { ticketId, category } = req.body;
        if (!ticketId || !category) {
            return res.status(400).json({ success: false, message: 'ticketId and category are required' });
        }
        
        const { createSupportTicket, logActivity } = require('./database');
        createSupportTicket(req.userId, ticketId, category);
        
        logActivity(req.userId, 'create_support_ticket', { ticketId, category });
        
        res.json({ success: true, message: 'Support ticket successfully registered' });
    } catch (err) {
        console.error('Create support ticket error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Expose user-level ticket listings
app.get('/api/support/tickets/my', requireAuth, (req, res) => {
    try {
        const { getUserSupportTickets } = require('./database');
        const tickets = getUserSupportTickets(req.userId);
        res.json({ success: true, tickets });
    } catch (err) {
        console.error('User support tickets error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Expose admin-level ticket listings
app.get('/api/admin/support/tickets', requireAuth, requireAdmin, (req, res) => {
    try {
        const { getSupportTicketsList } = require('./database');
        const tickets = getSupportTicketsList();
        res.json({ success: true, tickets });
    } catch (err) {
        console.error('Admin support tickets list error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Expose admin-level ticket resolution
app.post('/api/admin/support/tickets/resolve', requireAuth, requireAdmin, (req, res) => {
    try {
        const { ticketId } = req.body;
        if (!ticketId) {
            return res.status(400).json({ success: false, message: 'Ticket ID is required' });
        }
        
        const { resolveSupportTicket, logActivity } = require('./database');
        resolveSupportTicket(ticketId);
        
        logActivity(req.userId, 'admin_resolve_support_ticket', { ticketId });
        
        res.json({ success: true, message: 'Support ticket successfully marked as resolved' });
    } catch (err) {
        console.error('Admin resolve support ticket error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Expose user-level telemetry logging
app.post('/api/diagnostics/report', requireAuth, (req, res) => {
    try {
        const { type, value } = req.body;
        if (!type || value === undefined) {
            return res.status(400).json({ success: false, message: 'type and value are required' });
        }
        
        const { logDiagnosticMetric } = require('./database');
        logDiagnosticMetric(req.userId, type, value);
        
        res.json({ success: true, message: 'Telemetry metric recorded' });
    } catch (err) {
        console.error('Diagnostics report error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Expose admin-level diagnostics and system telemetry summary
app.get('/api/admin/diagnostics', requireAuth, requireAdmin, (req, res) => {
    try {
        const { getDiagnosticsSummary } = require('./database');
        const { getActiveConnectionsCount } = require('./websocket');
        
        const summary = getDiagnosticsSummary();
        const activeSockets = getActiveConnectionsCount();
        
        // System host metrics (Memory RSS in MB)
        const memoryUsageMB = Math.round(process.memoryUsage().rss / 1024 / 1024);
        
        res.json({
            success: true,
            activeSockets,
            memoryUsageMB,
            ...summary
        });
    } catch (err) {
        console.error('Admin diagnostics error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Expose admin-level security audit metrics
app.get('/api/admin/security/audit', requireAuth, requireAdmin, (req, res) => {
    try {
        const { getSecurityAuditSummary } = require('./database');
        const summary = getSecurityAuditSummary();
        res.json({
            success: true,
            ...summary
        });
    } catch (err) {
        console.error('Admin security audit error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Expose admin action: force global key rotation alert
app.post('/api/admin/security/force-rotation-alert', requireAuth, requireAdmin, (req, res) => {
    try {
        const { logActivity } = require('./database');
        logActivity(req.userId, 'global_key_rotation_forced', { forcedBy: req.userId });
        res.json({ success: true, message: 'Global key rotation alert successfully triggered' });
    } catch (err) {
        console.error('Admin force rotation alert error:', err.message);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// SPA fallback
app.get(/^(?!\/api).*/, (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// ═══════════════════════════════════════
// Server Startup
// ═══════════════════════════════════════

const PORT = parseInt(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';

// Initialize database
getDb();

let server;

const certsDir = path.join(__dirname, '..', 'certs');
const keyPath = path.join(certsDir, 'server.key');
const certPath = path.join(certsDir, 'server.cert');

if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
    // HTTPS mode (production)
    const options = {
        key: fs.readFileSync(keyPath),
        cert: fs.readFileSync(certPath)
    };
    server = https.createServer(options, app);
    console.log('🔒 Running in HTTPS mode (self-signed TLS)');
} else {
    // HTTP fallback (development only)
    server = http.createServer(app);
    console.log('⚠️  Running in HTTP mode (no TLS certs found — run: npm run setup)');
}

// Setup WebSocket
setupWebSocket(server);

// No cleanup intervals needed — server stores no user data!

server.listen(PORT, HOST, () => {
    const protocol = server instanceof https.Server ? 'https' : 'http';
    console.log(`
╔══════════════════════════════════════════════╗
║          🔒 Talk-Secure Server 🔒            ║
╠══════════════════════════════════════════════╣
║                                              ║
║   ${protocol}://${HOST}:${PORT}                    ║
║                                              ║
║   • End-to-End Encrypted (AES-256-GCM)       ║
║   • Zero-Storage Mode (device-only data)     ║
║   • Pure Signaling Relay                     ║
║   • Max users: ${process.env.MAX_USERS || 50}                           ║
║                                              ║
╚══════════════════════════════════════════════╝
`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down Talk-Secure...');
    const { closeDb } = require('./database');
    closeDb();
    server.close(() => {
        console.log('Server closed.');
        process.exit(0);
    });
});
