const mongoose = require('mongoose');

/**
 * Url Schema
 * Represents a password-protected short URL with optional file attachment.
 *
 * Fields:
 *  - shortId:       Unique nanoid-generated identifier (used in the URL path)
 *  - passwordHash:  bcrypt-hashed password required to view content
 *  - textContent:   Text displayed after password verification
 *  - fileName:      Original name of the uploaded file (null if no file)
 *  - filePath:      Server-side path to the stored file (null if no file)
 *  - label:         Admin-assigned tag for organization
 *  - downloadCount: Number of times the attached file has been downloaded
 */
const urlSchema = new mongoose.Schema(
    {
        shortId: {
            type: String,
            required: true,
            unique: true,
            index: true,
        },
        passwordHash: {
            type: String,
            required: true,
        },
        textContent: {
            type: String,
            required: true,
            maxlength: 10000,
        },
        fileName: {
            type: String,
            default: null,
        },
        filePath: {
            type: String,
            default: null,
        },
        label: {
            type: String,
            default: '',
            maxlength: 100,
        },
        downloadCount: {
            type: Number,
            default: 0,
        },
    },
    {
        timestamps: true, // Adds createdAt and updatedAt
    }
);

module.exports = mongoose.model('Url', urlSchema);
