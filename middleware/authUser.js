const firebaseAdmin = require('../config/firebase');
const jwt = require('jsonwebtoken');

/**
 * Combined Authentication Middleware.
 *
 * Tries to verify the Bearer token in this order:
 *   1. Firebase ID token  (for regular users authenticated via Firebase Auth)
 *   2. Local JWT           (for admin users authenticated via /api/admin/login)
 *
 * On success, attaches the decoded payload to req.user and calls next().
 */
const authenticateUser = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    const token = authHeader.split(' ')[1];

    // ── 1. Try Firebase ID token ────────────────────────────────────
    try {
        const decoded = await firebaseAdmin.auth().verifyIdToken(token);
        req.user = {
            uid: decoded.uid,
            email: decoded.email,
            emailVerified: decoded.email_verified,
            role: 'user',
        };
        return next();
    } catch (_firebaseErr) {
        // Not a valid Firebase token — fall through to JWT
    }

    // ── 2. Try local JWT (admin tokens) ─────────────────────────────
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        return next();
    } catch (_jwtErr) {
        return res.status(401).json({ error: 'Invalid or expired token.' });
    }
};

module.exports = { authenticateUser };
