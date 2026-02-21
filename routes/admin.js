const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const { nanoid } = require('nanoid');

const Admin = require('../models/Admin');
const Url = require('../models/Url');
const { validateAdminLogin, fileFilter, MAX_FILE_SIZE } = require('../middleware/validate');

// ─── Multer Configuration (shared with url.js pattern) ───────────────
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, '..', 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = `${nanoid(16)}${path.extname(file.originalname).toLowerCase()}`;
        cb(null, uniqueName);
    },
});

const upload = multer({
    storage,
    fileFilter,
    limits: { fileSize: MAX_FILE_SIZE },
});

// ─── JWT Auth Middleware ─────────────────────────────────────────────
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
router.post('/api/admin/login', validateAdminLogin, async (req, res) => {
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
router.get('/api/admin/urls', authenticateAdmin, async (req, res) => {
    try {
        const urls = await Url.find()
            .select('-passwordHash')
            .sort({ createdAt: -1 });

        res.json({ success: true, urls });
    } catch (err) {
        console.error('Error fetching URLs:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ─── PUT /api/admin/urls/:id ────────────────────────────────────────
// Edit label, textContent, file (replace or delete) — protected
router.put('/api/admin/urls/:id', authenticateAdmin, upload.single('file'), async (req, res) => {
    try {
        const { label, textContent, deleteFile } = req.body;
        const urlDoc = await Url.findById(req.params.id);

        if (!urlDoc) {
            return res.status(404).json({ error: 'URL not found.' });
        }

        // Update label
        if (label !== undefined) {
            if (typeof label !== 'string' || label.length > 100) {
                return res.status(400).json({ error: 'Label must be a string of 100 characters or fewer.' });
            }
            urlDoc.label = label.trim();
        }

        // Update text content
        if (textContent !== undefined) {
            if (typeof textContent !== 'string' || textContent.trim().length === 0 || textContent.length > 10000) {
                return res.status(400).json({ error: 'Text content must be 1–10,000 characters.' });
            }
            urlDoc.textContent = textContent.trim();
        }

        // Delete existing file (either because user wants to remove it, or replacing it)
        if (deleteFile === 'true' || req.file) {
            if (urlDoc.filePath && fs.existsSync(urlDoc.filePath)) {
                fs.unlinkSync(urlDoc.filePath);
            }
            urlDoc.fileName = null;
            urlDoc.filePath = null;
        }

        // Attach new file (replacement)
        if (req.file) {
            urlDoc.fileName = req.file.originalname;
            urlDoc.filePath = req.file.path;
        }

        await urlDoc.save();

        // Return without passwordHash
        const result = urlDoc.toObject();
        delete result.passwordHash;

        res.json({ success: true, url: result });
    } catch (err) {
        console.error('Error updating URL:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ─── DELETE /api/admin/urls/:id ─────────────────────────────────────
router.delete('/api/admin/urls/:id', authenticateAdmin, async (req, res) => {
    try {
        const urlDoc = await Url.findById(req.params.id);
        if (!urlDoc) {
            return res.status(404).json({ error: 'URL not found.' });
        }

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
