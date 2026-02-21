const mongoose = require('mongoose');

/**
 * Admin Schema
 * Stores admin credentials for the management dashboard.
 * Passwords are stored as bcrypt hashes — never in plain text.
 */
const adminSchema = new mongoose.Schema(
    {
        username: {
            type: String,
            required: true,
            unique: true,
            trim: true,
        },
        passwordHash: {
            type: String,
            required: true,
        },
    },
    {
        timestamps: true,
    }
);

module.exports = mongoose.model('Admin', adminSchema);
