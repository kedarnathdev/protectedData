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


// ─── Dynamic JS ──────────────────────────────────────────────────────
// Serve firebase config dynamically so we can inject environment variables
app.get('/js/firebase-config.js', (req, res) => {
    res.type('application/javascript');
    res.send(`
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js";
import { getAuth } from "https://www.gstatic.com/firebasejs/10.14.1/firebase-auth.js";

const firebaseConfig = {
    apiKey: "${process.env.FIREBASE_API_KEY}",
    authDomain: "${process.env.FIREBASE_AUTH_DOMAIN}",
    projectId: "${process.env.FIREBASE_PROJECT_ID}",
    storageBucket: "${process.env.FIREBASE_STORAGE_BUCKET}",
    messagingSenderId: "${process.env.FIREBASE_MESSAGING_SENDER_ID}",
    appId: "${process.env.FIREBASE_APP_ID}",
    measurementId: "${process.env.FIREBASE_MEASUREMENT_ID}"
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
    `);
});

// ─── Static Files ────────────────────────────────────────────────────
// Serve frontend files from the /public directory
app.use(express.static(path.join(__dirname, 'public')));

// ─── Routes ──────────────────────────────────────────────────────────
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
