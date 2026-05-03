require('dotenv').config();

const express = require('express');
const path = require('path');
const cors = require('cors');
const connectDB = require('./config/db');

const app = express();

// ─── Global Middleware ───────────────────────────────────────────────
app.use(cors());                                  // Enable CORS for all origins
app.use(express.json());                          // Parse JSON request bodies
app.use(express.urlencoded({ extended: true }));  // Parse URL-encoded form data


// ─── Static Files ────────────────────────────────────────────────────
// Serve frontend files from the /public directory
app.use(express.static(path.join(__dirname, 'public')));

// ─── Routes ──────────────────────────────────────────────────────────
// User auth routes must be mounted first for /api/user/* endpoints
app.use('/', require('./routes/user'));
// Admin routes must be mounted BEFORE URL routes to prevent /:shortId
// from matching /admin.html or /api/admin/* paths
app.use('/', require('./routes/admin'));
app.use('/', require('./routes/url'));

// ─── Multer Error Handler ────────────────────────────────────────────
// Catches file upload errors (size limit, file type) and returns clean messages
app.use((err, req, res, next) => {
    if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'File size exceeds the 10 MB limit.' });
    }
    if (err.message && err.message.includes('File type')) {
        return res.status(400).json({ error: err.message });
    }
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error.' });
});

// ─── Start Server ────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;

connectDB().then(() => {
    app.listen(PORT, () => {
        console.log(`🚀 Server running on http://localhost:${PORT}`);
    });
});
