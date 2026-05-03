const mongoose = require('mongoose');
const crypto = require('crypto');

/**
 * User Schema
 * Stores user credentials for homepage access (search & create link).
 * Passwords are stored as bcrypt hashes — never in plain text.
 * Includes fields for password-reset token flow.
 */
const userSchema = new mongoose.Schema(
    {
        email: {
            type: String,
            required: true,
            unique: true,
            trim: true,
            lowercase: true,
        },
        passwordHash: {
            type: String,
            required: true,
        },
        resetToken: {
            type: String,
            default: null,
        },
        resetTokenExpiry: {
            type: Date,
            default: null,
        },
    },
    {
        timestamps: true,
    }
);

/**
 * Generate a random hex token for password reset.
 * Stores its SHA-256 hash in the DB (so the raw token is never persisted).
 * Returns the raw token to be sent to the user via email.
 */
userSchema.methods.createResetToken = function () {
    const rawToken = crypto.randomBytes(32).toString('hex');

    // Store hashed version in DB
    this.resetToken = crypto.createHash('sha256').update(rawToken).digest('hex');
    this.resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    return rawToken;
};

module.exports = mongoose.model('User', userSchema);
