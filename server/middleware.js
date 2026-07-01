/**
 * Talk-Secure — Security Middleware
 * Rate limiting, input sanitization, security headers
 * No third-party middleware dependencies
 */

// ═══════════════════════════════════════
// Rate Limiter (in-memory, no dependencies)
// ═══════════════════════════════════════

const rateLimitStore = new Map();

function rateLimit(windowMs, maxRequests) {
    // Cleanup stale entries every 5 minutes
    setInterval(() => {
        const now = Date.now();
        for (const [key, data] of rateLimitStore.entries()) {
            if (now - data.windowStart > windowMs * 2) {
                rateLimitStore.delete(key);
            }
        }
    }, 5 * 60 * 1000);

    return (req, res, next) => {
        const ip = req.ip || req.connection.remoteAddress;
        const now = Date.now();

        let clientData = rateLimitStore.get(ip);

        if (!clientData || now - clientData.windowStart > windowMs) {
            clientData = { windowStart: now, count: 0 };
            rateLimitStore.set(ip, clientData);
        }

        clientData.count++;

        // Set rate limit headers
        res.set('X-RateLimit-Limit', String(maxRequests));
        res.set('X-RateLimit-Remaining', String(Math.max(0, maxRequests - clientData.count)));

        if (clientData.count > maxRequests) {
            return res.status(429).json({
                success: false,
                message: 'Too many requests. Slow down.'
            });
        }

        next();
    };
}

// ═══════════════════════════════════════
// Security Headers
// ═══════════════════════════════════════

function securityHeaders(req, res, next) {
    // Content Security Policy — strict, allow Google Fonts
    res.set('Content-Security-Policy', [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data: blob:",
        "media-src 'self' blob:",
        "connect-src 'self' wss: ws:",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'"
    ].join('; '));

    // Prevent clickjacking
    res.set('X-Frame-Options', 'DENY');

    // Prevent MIME sniffing
    res.set('X-Content-Type-Options', 'nosniff');

    // XSS filter
    res.set('X-XSS-Protection', '1; mode=block');

    // Referrer policy
    res.set('Referrer-Policy', 'no-referrer');

    // Permissions policy — allow camera/mic for video calls (wildcard needed for ngrok/proxy)
    res.set('Permissions-Policy', 'camera=(self), microphone=(self), geolocation=(), payment=()');

    // HSTS (1 year)
    res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');

    next();
}

// ═══════════════════════════════════════
// Input Sanitization
// ═══════════════════════════════════════

function sanitizeInput(str) {
    if (typeof str !== 'string') return str;
    // Recursively strip angle brackets until stable
    let prev;
    do {
        prev = str;
        str = str
            .replace(/[<>]/g, '')           // Strip angle brackets
            .replace(/javascript\s*:/gi, '')  // No JS URIs (with optional whitespace)
            .replace(/vbscript\s*:/gi, '')    // No VBScript URIs
            .replace(/on\w+\s*=/gi, '')       // No event handlers
            .replace(/data\s*:\s*text\/html/gi, ''); // No data: HTML URIs
    } while (str !== prev);
    return str.trim();
}

function sanitizeBody(req, res, next) {
    if (req.body && typeof req.body === 'object') {
        for (const key of Object.keys(req.body)) {
            if (typeof req.body[key] === 'string') {
                req.body[key] = sanitizeInput(req.body[key]);
            }
        }
    }
    next();
}

// ═══════════════════════════════════════
// CORS — Strict origin check
// ═══════════════════════════════════════

function strictCors(req, res, next) {
    const origin = req.get('origin');
    const host = req.get('host');

    // Build expected origins from the host header
    if (!origin) {
        // Direct navigation / same-origin — allow
        res.set('Access-Control-Allow-Origin', `https://${host}`);
    } else {
        // Strict check: origin must exactly match the host
        const expectedOrigins = [
            `https://${host}`,
            `http://${host}`
        ];

        if (expectedOrigins.includes(origin)) {
            res.set('Access-Control-Allow-Origin', origin);
        }
        // If origin doesn't match, no CORS header is set — browser blocks the request
    }

    res.set('Access-Control-Allow-Methods', 'GET, POST');
    res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
    }

    next();
}

module.exports = {
    rateLimit,
    securityHeaders,
    sanitizeBody,
    strictCors
};
