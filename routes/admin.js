const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');

const Admin = require('../models/Admin');
const Url = require('../models/Url');
const { sensitiveLimiter } = require('../middleware/rateLimiter');
const { validateAdminLogin } = require('../middleware/validate');

// ─── JWT Auth Middleware ─────────────────────────────────────────────
// Verifies the JWT token from the Authorization header
const authenticateAdmin = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.admin = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Invalid or expired token.' });
    }
};

// ─── POST /api/admin/login ──────────────────────────────────────────
// Authenticate admin and return JWT
router.post('/api/admin/login', sensitiveLimiter, validateAdminLogin, async (req, res) => {
    try {
        const { username, password } = req.body;

        const admin = await Admin.findOne({ username });
        if (!admin) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        const isMatch = await bcrypt.compare(password, admin.passwordHash);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }

        // Generate JWT valid for 24 hours
        const token = jwt.sign(
            { id: admin._id, username: admin.username },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ success: true, token });
    } catch (err) {
        console.error('Admin login error:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ─── GET /api/admin/urls ────────────────────────────────────────────
// List all short URLs with metadata (protected)
router.get('/api/admin/urls', authenticateAdmin, async (req, res) => {
    try {
        const urls = await Url.find()
            .select('-passwordHash') // Never expose password hashes
            .sort({ createdAt: -1 });

        res.json({ success: true, urls });
    } catch (err) {
        console.error('Error fetching URLs:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ─── PUT /api/admin/urls/:id ────────────────────────────────────────
// Edit label and/or textContent of a URL (protected)
router.put('/api/admin/urls/:id', authenticateAdmin, async (req, res) => {
    try {
        const { label, textContent } = req.body;
        const updates = {};

        if (label !== undefined) {
            if (typeof label !== 'string' || label.length > 100) {
                return res.status(400).json({ error: 'Label must be a string of 100 characters or fewer.' });
            }
            updates.label = label.trim();
        }

        if (textContent !== undefined) {
            if (typeof textContent !== 'string' || textContent.trim().length === 0 || textContent.length > 10000) {
                return res.status(400).json({ error: 'Text content must be 1–10,000 characters.' });
            }
            updates.textContent = textContent.trim();
        }

        if (Object.keys(updates).length === 0) {
            return res.status(400).json({ error: 'No valid fields to update.' });
        }

        const urlDoc = await Url.findByIdAndUpdate(req.params.id, updates, { new: true }).select('-passwordHash');
        if (!urlDoc) {
            return res.status(404).json({ error: 'URL not found.' });
        }

        res.json({ success: true, url: urlDoc });
    } catch (err) {
        console.error('Error updating URL:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ─── DELETE /api/admin/urls/:id ─────────────────────────────────────
// Delete a URL and its associated file (protected)
router.delete('/api/admin/urls/:id', authenticateAdmin, async (req, res) => {
    try {
        const urlDoc = await Url.findById(req.params.id);
        if (!urlDoc) {
            return res.status(404).json({ error: 'URL not found.' });
        }

        // Delete the associated file from disk if it exists
        if (urlDoc.filePath && fs.existsSync(urlDoc.filePath)) {
            fs.unlinkSync(urlDoc.filePath);
        }

        await Url.findByIdAndDelete(req.params.id);

        res.json({ success: true, message: 'URL deleted successfully.' });
    } catch (err) {
        console.error('Error deleting URL:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

module.exports = router;
