const admin = require('firebase-admin');

/**
 * Initialize Firebase Admin SDK.
 * Uses project ID for token verification against Google's public keys.
 * No service account key is required for basic ID token verification.
 */
admin.initializeApp({
    projectId: process.env.FIREBASE_PROJECT_ID,
});

module.exports = admin;
