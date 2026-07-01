/**
 * Talk-Secure — Authentication Module
 * bcrypt password hashing + JWT tokens
 * Registration locks after MAX_USERS accounts
 * Brute-force protection with account lockout
 */
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const {
    getUserCount,
    createUser,
    createPendingRegistration,
    getPendingRegistration,
    deletePendingRegistration,
    getUserByUsername,
    incrementFailedAttempts,
    resetFailedAttempts,
    isUserLocked,
    getDb,
    logActivity,
    verifyInviteToken,
    redeemInviteToken
} = require('./database');

const BCRYPT_ROUNDS = 12;

/**
 * Register a new user with email and phone validations
 * Returns: { success, message, userId? }
 */
async function register(username, password, email, phone, inviteToken) {
    // Validate input
    if (!username || !password || !email || !phone) {
        return { success: false, message: 'All fields (username, password, email, phone) are required' };
    }

    if (username.length < 3 || username.length > 20) {
        return { success: false, message: 'Username must be 3-20 characters' };
    }

    if (password.length < 8) {
        return { success: false, message: 'Password must be at least 8 characters' };
    }

    // Enforce password complexity
    if (!/[A-Z]/.test(password)) {
        return { success: false, message: 'Password must contain at least one uppercase letter' };
    }
    if (!/[a-z]/.test(password)) {
        return { success: false, message: 'Password must contain at least one lowercase letter' };
    }
    if (!/[0-9]/.test(password)) {
        return { success: false, message: 'Password must contain at least one digit' };
    }
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
        return { success: false, message: 'Password must contain at least one special character' };
    }

    // Check username format (alphanumeric + underscore only)
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        return { success: false, message: 'Username must contain only letters, numbers, and underscores' };
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return { success: false, message: 'Please provide a valid email address' };
    }

    // Validate phone format
    const phoneRegex = /^\+?[0-9\s\-()]{7,20}$/;
    if (!phoneRegex.test(phone)) {
        return { success: false, message: 'Please provide a valid phone number (7-20 digits)' };
    }

    const currentUsersCount = getUserCount();
    let usedInvite = false;

    // Invite token is optional. If provided, validate it.
    if (inviteToken && inviteToken.trim().length > 0) {
        const activeInvite = verifyInviteToken(inviteToken.trim());
        if (!activeInvite) {
            return { success: false, message: 'Invalid or already redeemed invite token' };
        }
        usedInvite = true;
    }

    const db = getDb();

    // Check if email already registered
    const existingEmail = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existingEmail) {
        return { success: false, message: 'Email address is already registered' };
    }

    // Check if phone already registered
    const existingPhone = db.prepare('SELECT id FROM users WHERE phone = ?').get(phone);
    if (existingPhone) {
        return { success: false, message: 'Phone number is already registered' };
    }

    // Enforce max user limit
    const maxUsers = parseInt(process.env.MAX_USERS) || 50;
    if (currentUsersCount >= maxUsers) {
        return { success: false, message: 'Registration is closed. Maximum users reached.' };
    }

    // Check if username exists
    if (getUserByUsername(username)) {
        return { success: false, message: 'Username already taken' };
    }

    // Hash password with bcrypt (cost factor 12)
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    // If verification is disabled, register immediately
    if (process.env.DISABLE_OTP === 'true') {
        const result = createUser(username, passwordHash, email, phone);
        const newUserId = result.lastInsertRowid;
        logActivity(newUserId, 'register', { username, usedInvite: usedInvite });
        if (inviteToken && usedInvite) {
            redeemInviteToken(inviteToken.trim(), newUserId);
        }
        // Auto-pair with admins
        try {
            const admins = db.prepare('SELECT id FROM users WHERE is_admin = 1').all();
            for (const admin of admins) {
                const stmt = db.prepare('INSERT OR IGNORE INTO contacts (user_id, contact_user_id) VALUES (?, ?)');
                stmt.run(newUserId, admin.id);
                stmt.run(admin.id, newUserId);
            }
        } catch (err) {
            console.error('Failed to auto-pair new user with administrators:', err);
        }
        return {
            success: true,
            message: 'Account created successfully'
        };
    }

    // Generate 6-digit verification OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const pendingId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 minutes expiration

    // Store in pending registrations
    createPendingRegistration(pendingId, username, passwordHash, email, phone, inviteToken || null, otp, expiresAt);

    // Send the verification code
    await sendVerificationOTP(email, phone, otp);

    return {
        success: true,
        pending: true,
        pendingId: pendingId,
        message: 'A 6-digit verification code has been sent to your email/phone'
    };
}

let transporter = null;

function getMailTransporter() {
    if (transporter) return transporter;
    if (process.env.SMTP_HOST) {
        try {
            const nodemailer = require('nodemailer');
            transporter = nodemailer.createTransport({
                host: process.env.SMTP_HOST,
                port: parseInt(process.env.SMTP_PORT) || 587,
                secure: process.env.SMTP_SECURE === 'true',
                auth: {
                    user: process.env.SMTP_USER,
                    pass: process.env.SMTP_PASS
                }
            });
        } catch (e) {
            console.error('Failed to initialize nodemailer:', e.message);
        }
    }
    return transporter;
}

async function sendVerificationOTP(email, phone, otp) {
    console.log(`
╔══════════════════════════════════════════════╗
║        ✉️  TALK-SECURE VERIFICATION CODE      ║
╠══════════════════════════════════════════════╣
║                                              ║
║   Email: ${email}
║   Phone: ${phone}
║                                              ║
║   OTP:   ${otp}
║                                              ║
╚══════════════════════════════════════════════╝
`);

    const mailTransporter = getMailTransporter();
    if (mailTransporter) {
        try {
            await mailTransporter.sendMail({
                from: process.env.SMTP_FROM || 'noreply@talksecure.local',
                to: email,
                subject: 'Talk-Secure — Verification Code',
                text: `Your verification code is: ${otp}\n\nPlease enter this code in the app to complete your registration.`,
                html: `<p>Your verification code is: <strong>${otp}</strong></p><p>Please enter this code in the app to complete your registration.</p>`
            });
            console.log(`✅ Verification email successfully sent to ${email}`);
        } catch (mailErr) {
            console.error(`❌ Failed to send verification email to ${email}:`, mailErr.message);
        }
    } else {
        console.log(`ℹ️ SMTP is not configured. OTP printed above to console for development.`);
    }
}

async function verifyOtp(pendingId, otp) {
    if (!pendingId || !otp) {
        return { success: false, message: 'Pending registration ID and verification code are required' };
    }

    const pending = getPendingRegistration(pendingId);
    if (!pending) {
        return { success: false, message: 'Invalid or expired registration session. Please register again.' };
    }

    // Check expiration
    if (new Date(pending.expires_at).getTime() < Date.now()) {
        deletePendingRegistration(pendingId);
        return { success: false, message: 'Verification code has expired. Please register again.' };
    }

    // Verify OTP
    if (pending.otp !== otp.trim()) {
        return { success: false, message: 'Invalid verification code. Please try again.' };
    }

    const db = getDb();
    
    // Check again if username/email/phone got taken in the meantime
    if (getUserByUsername(pending.username)) {
        deletePendingRegistration(pendingId);
        return { success: false, message: 'Username is already taken' };
    }
    const existingEmail = db.prepare('SELECT id FROM users WHERE email = ?').get(pending.email);
    if (existingEmail) {
        deletePendingRegistration(pendingId);
        return { success: false, message: 'Email address is already registered' };
    }
    const existingPhone = db.prepare('SELECT id FROM users WHERE phone = ?').get(pending.phone);
    if (existingPhone) {
        deletePendingRegistration(pendingId);
        return { success: false, message: 'Phone number is already registered' };
    }

    // Create user
    const result = createUser(pending.username, pending.password_hash, pending.email, pending.phone);
    const newUserId = result.lastInsertRowid;

    // Log the user registration
    logActivity(newUserId, 'register', { username: pending.username, usedInvite: !!pending.invite_token });

    // Redeem invite
    if (pending.invite_token) {
        redeemInviteToken(pending.invite_token, newUserId);
    }

    // Auto-pair with admins
    try {
        const admins = db.prepare('SELECT id FROM users WHERE is_admin = 1').all();
        for (const admin of admins) {
            const stmt = db.prepare('INSERT OR IGNORE INTO contacts (user_id, contact_user_id) VALUES (?, ?)');
            stmt.run(newUserId, admin.id);
            stmt.run(admin.id, newUserId);
        }
    } catch (err) {
        console.error('Failed to auto-pair new user with administrators:', err);
    }

    // Delete pending registration
    deletePendingRegistration(pendingId);

    return {
        success: true,
        message: 'Account created successfully'
    };
}

/**
 * Login user
 * Returns: { success, message, token?, userId?, username?, isAdmin? }
 */
async function login(username, password) {
    if (!username || !password) {
        return { success: false, message: 'Username and password are required' };
    }

    const user = getUserByUsername(username);
    if (!user) {
        // Log failed attempt with null user id
        logActivity(null, 'login_failed', { username, reason: 'Username not found' });
        return { success: false, message: 'Invalid credentials' };
    }

    // Check if account is locked
    if (isUserLocked(user.id)) {
        logActivity(user.id, 'login_failed', { username, reason: 'Account locked' });
        return { success: false, message: 'Account temporarily locked. Try again in 15 minutes.' };
    }

    // Verify password
    const isValid = await bcrypt.compare(password, user.password_hash);
    if (!isValid) {
        incrementFailedAttempts(user.id);
        
        // Log locked event if just locked
        if (isUserLocked(user.id)) {
            logActivity(user.id, 'account_locked', { username });
        } else {
            logActivity(user.id, 'login_failed', { username, reason: 'Incorrect password' });
        }
        
        return { success: false, message: 'Invalid credentials' };
    }

    // Reset failed attempts on successful login
    resetFailedAttempts(user.id);

    // Generate JWT (include isAdmin)
    const token = jwt.sign(
        { userId: user.id, username: user.username },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRY || '24h', algorithm: 'HS256' }
    );

    // Log successful login
    logActivity(user.id, 'login_success', { username });

    return {
        success: true,
        message: 'Login successful',
        token,
        userId: user.id,
        username: user.username,
        isAdmin: user.is_admin === 1
    };
}

/**
 * Verify JWT token
 * Returns decoded payload or null
 */
function verifyToken(token) {
    try {
        return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    } catch (err) {
        return null;
    }
}

/**
 * Check if registration is still open
 */
function isRegistrationOpen() {
    const maxUsers = parseInt(process.env.MAX_USERS) || 50;
    return getUserCount() < maxUsers;
}

module.exports = {
    register,
    login,
    verifyOtp,
    verifyToken,
    isRegistrationOpen
};
