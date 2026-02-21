const rateLimit = require('express-rate-limit');

/**
 * General rate limiter — applied to all routes.
 * Allows 100 requests per 15-minute window per IP.
 */
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Too many requests from this IP. Please try again after 15 minutes.',
    },
});

/**
 * Sensitive route rate limiter — applied to login, shorten, and verify routes.
 * Allows only 10 requests per 15-minute window per IP to prevent brute-force attacks.
 */
const sensitiveLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        error: 'Too many attempts. Please try again after 15 minutes.',
    },
});

module.exports = { generalLimiter, sensitiveLimiter };
