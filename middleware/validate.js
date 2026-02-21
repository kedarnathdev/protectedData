const path = require('path');

// Allowed file extensions for uploads
const ALLOWED_EXTENSIONS = ['.pdf', '.png', '.jpg', '.jpeg', '.gif', '.zip', '.txt', '.docx', '.xlsx', '.csv'];
const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB

/**
 * Validate the POST /api/shorten request body.
 * Ensures password and textContent are present and within limits.
 * Sanitizes optional label field.
 */
const validateShortenInput = (req, res, next) => {
    const { password, textContent, label } = req.body;

    if (!password || typeof password !== 'string' || password.trim().length === 0) {
        return res.status(400).json({ error: 'Password is required.' });
    }

    if (password.trim().length < 4) {
        return res.status(400).json({ error: 'Password must be at least 4 characters.' });
    }

    if (password.trim().length > 128) {
        return res.status(400).json({ error: 'Password must not exceed 128 characters.' });
    }

    if (!textContent || typeof textContent !== 'string' || textContent.trim().length === 0) {
        return res.status(400).json({ error: 'Text content is required.' });
    }

    if (textContent.trim().length > 10000) {
        return res.status(400).json({ error: 'Text content must not exceed 10,000 characters.' });
    }

    // Validate optional label
    if (label && typeof label === 'string' && label.trim().length > 100) {
        return res.status(400).json({ error: 'Label must not exceed 100 characters.' });
    }

    // Sanitize: trim whitespace
    req.body.password = password.trim();
    req.body.textContent = textContent.trim();
    req.body.label = (label && typeof label === 'string') ? label.trim() : '';

    next();
};

/**
 * Validate uploaded file (used as multer fileFilter).
 * Checks file extension against the allowed list.
 */
const fileFilter = (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (ALLOWED_EXTENSIONS.includes(ext)) {
        cb(null, true);
    } else {
        cb(new Error(`File type '${ext}' is not allowed. Allowed types: ${ALLOWED_EXTENSIONS.join(', ')}`), false);
    }
};

/**
 * Validate the verify password request body.
 */
const validateVerifyInput = (req, res, next) => {
    const { password } = req.body;

    if (!password || typeof password !== 'string' || password.trim().length === 0) {
        return res.status(400).json({ error: 'Password is required.' });
    }

    req.body.password = password.trim();
    next();
};

/**
 * Validate admin login input.
 */
const validateAdminLogin = (req, res, next) => {
    const { username, password } = req.body;

    if (!username || typeof username !== 'string' || username.trim().length === 0) {
        return res.status(400).json({ error: 'Username is required.' });
    }

    if (!password || typeof password !== 'string' || password.trim().length === 0) {
        return res.status(400).json({ error: 'Password is required.' });
    }

    req.body.username = username.trim();
    req.body.password = password.trim();
    next();
};

module.exports = {
    validateShortenInput,
    validateVerifyInput,
    validateAdminLogin,
    fileFilter,
    MAX_FILE_SIZE,
    ALLOWED_EXTENSIONS,
};
