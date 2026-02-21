const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
const { nanoid } = require('nanoid');
const fs = require('fs');

const Url = require('../models/Url');
const { validateShortenInput, validateVerifyInput, fileFilter, MAX_FILE_SIZE } = require('../middleware/validate');

// ─── Multer Configuration ────────────────────────────────────────────
// Files are stored with randomized names to prevent conflicts and path traversal
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

// ─── Helper: Generate next serial number ─────────────────────────────
async function getNextSerialNumber() {
    const last = await Url.findOne().sort({ serialNumber: -1 }).select('serialNumber');
    return last ? last.serialNumber + 1 : 1001; // Start from 1001
}

// ─── POST /api/shorten ───────────────────────────────────────────────
// Create a new short URL with password, text content, label, and optional file
router.post(
    '/api/shorten',
    upload.single('file'),
    validateShortenInput,
    async (req, res) => {
        try {
            const { password, textContent, label } = req.body;

            const passwordHash = await bcrypt.hash(password, 12);
            const shortId = nanoid(8);
            const serialNumber = await getNextSerialNumber();

            const urlDoc = new Url({
                serialNumber,
                shortId,
                passwordHash,
                textContent,
                label: label || '',
                fileName: req.file ? req.file.originalname : null,
                filePath: req.file ? req.file.path : null,
            });

            await urlDoc.save();

            const baseUrl = `${req.protocol}://${req.get('host')}`;
            res.status(201).json({
                success: true,
                shortUrl: `${baseUrl}/${shortId}`,
                shortId,
                serialNumber,
            });
        } catch (err) {
            console.error('Error creating short URL:', err);
            res.status(500).json({ error: 'Internal server error.' });
        }
    }
);

// ─── GET /api/search ─────────────────────────────────────────────────
// Search for a URL by serial number (returns shortId if found, requires password next)
router.get('/api/search', async (req, res) => {
    try {
        const serial = parseInt(req.query.serial, 10);
        if (!serial || isNaN(serial)) {
            return res.status(400).json({ error: 'A valid serial number is required.' });
        }

        const urlDoc = await Url.findOne({ serialNumber: serial }).select('shortId serialNumber label');
        if (!urlDoc) {
            return res.status(404).json({ error: 'No URL found with that serial number.' });
        }

        res.json({
            success: true,
            shortId: urlDoc.shortId,
            serialNumber: urlDoc.serialNumber,
            label: urlDoc.label,
        });
    } catch (err) {
        console.error('Error searching URL:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ─── POST /api/:shortId/verify ───────────────────────────────────────
// Verify password and return the protected content
router.post(
    '/api/:shortId/verify',
    validateVerifyInput,
    async (req, res) => {
        try {
            const { shortId } = req.params;
            const { password } = req.body;

            const urlDoc = await Url.findOne({ shortId });
            if (!urlDoc) {
                return res.status(404).json({ error: 'Short URL not found.' });
            }

            const isMatch = await bcrypt.compare(password, urlDoc.passwordHash);
            if (!isMatch) {
                return res.status(401).json({ error: 'Incorrect password.' });
            }

            res.json({
                success: true,
                textContent: urlDoc.textContent,
                hasFile: !!urlDoc.fileName,
                fileName: urlDoc.fileName,
                downloadUrl: urlDoc.fileName ? `/api/${shortId}/download?token=${encodeURIComponent(password)}` : null,
            });
        } catch (err) {
            console.error('Error verifying password:', err);
            res.status(500).json({ error: 'Internal server error.' });
        }
    }
);

// ─── GET /api/:shortId/download ──────────────────────────────────────
// Download the attached file (requires password as query param for verification)
router.get('/api/:shortId/download', async (req, res) => {
    try {
        const { shortId } = req.params;
        const { token } = req.query;

        if (!token) {
            return res.status(401).json({ error: 'Authentication required.' });
        }

        const urlDoc = await Url.findOne({ shortId });
        if (!urlDoc) {
            return res.status(404).json({ error: 'Short URL not found.' });
        }

        const isMatch = await bcrypt.compare(token, urlDoc.passwordHash);
        if (!isMatch) {
            return res.status(401).json({ error: 'Incorrect password.' });
        }

        if (!urlDoc.filePath || !fs.existsSync(urlDoc.filePath)) {
            return res.status(404).json({ error: 'No file attached to this URL.' });
        }

        urlDoc.downloadCount += 1;
        await urlDoc.save();

        res.download(urlDoc.filePath, urlDoc.fileName);
    } catch (err) {
        console.error('Error downloading file:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ─── GET /:shortId ──────────────────────────────────────────────────
// Serve the password verification page
router.get('/:shortId', async (req, res) => {
    try {
        const { shortId } = req.params;

        const urlDoc = await Url.findOne({ shortId });
        if (!urlDoc) {
            return res.status(404).send(`
        <!DOCTYPE html>
        <html><head><title>Not Found</title></head>
        <body style="display:flex;justify-content:center;align-items:center;height:100vh;background:#0f0f1a;color:#fff;font-family:sans-serif;">
          <h1>404 — Short URL not found</h1>
        </body></html>
      `);
        }

        res.sendFile(path.join(__dirname, '..', 'public', 'view.html'));
    } catch (err) {
        console.error('Error serving short URL page:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

module.exports = router;
