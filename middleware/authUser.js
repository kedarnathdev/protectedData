const jwt = require('jsonwebtoken');

/**
 * JWT Authentication Middleware for regular Users.
 * Expects `Authorization: Bearer <token>` header.
 * Attaches decoded user payload to req.user on success.
 *
 * Also accepts admin tokens (role check is flexible) so that
 * admins can call user-protected endpoints like /api/shorten.
 */
const authenticateUser = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        // Accept both 'user' role tokens and admin tokens (admin tokens have no role field)
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token.' });
    }
};

module.exports = { authenticateUser };
