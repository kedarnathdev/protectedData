const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const User = require('../models/User');

// ─── Email Transporter ──────────────────────────────────────────────
// Uses SMTP credentials from .env for sending password-reset emails.
// Falls back to a no-op if not configured.
let transporter = null;

function getTransporter() {
    if (transporter) return transporter;

    if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
        transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: parseInt(process.env.SMTP_PORT, 10) || 587,
            secure: process.env.SMTP_SECURE === 'true',
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS,
            },
        });
    }

    return transporter;
}

// ─── POST /api/user/register ────────────────────────────────────────
router.post('/api/user/register', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate
        if (!email || typeof email !== 'string' || !email.trim()) {
            return res.status(400).json({ error: 'Email is required.' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email.trim())) {
            return res.status(400).json({ error: 'Please enter a valid email address.' });
        }

        if (!password || typeof password !== 'string' || password.trim().length === 0) {
            return res.status(400).json({ error: 'Password is required.' });
        }

        if (password.trim().length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters.' });
        }

        if (password.trim().length > 128) {
            return res.status(400).json({ error: 'Password must not exceed 128 characters.' });
        }

        // Check duplicate
        const existing = await User.findOne({ email: email.trim().toLowerCase() });
        if (existing) {
            return res.status(409).json({ error: 'An account with this email already exists.' });
        }

        const passwordHash = await bcrypt.hash(password.trim(), 12);

        const user = new User({
            email: email.trim().toLowerCase(),
            passwordHash,
        });

        await user.save();

        // Generate token immediately so user is logged in after registration
        const token = jwt.sign(
            { id: user._id, email: user.email, role: 'user' },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.status(201).json({ success: true, token, email: user.email });
    } catch (err) {
        console.error('User registration error:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ─── POST /api/user/login ───────────────────────────────────────────
router.post('/api/user/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || typeof email !== 'string' || !email.trim()) {
            return res.status(400).json({ error: 'Email is required.' });
        }

        if (!password || typeof password !== 'string' || password.trim().length === 0) {
            return res.status(400).json({ error: 'Password is required.' });
        }

        const user = await User.findOne({ email: email.trim().toLowerCase() });
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        const isMatch = await bcrypt.compare(password.trim(), user.passwordHash);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        const token = jwt.sign(
            { id: user._id, email: user.email, role: 'user' },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ success: true, token, email: user.email });
    } catch (err) {
        console.error('User login error:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ─── POST /api/user/forgot-password ─────────────────────────────────
router.post('/api/user/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email || typeof email !== 'string' || !email.trim()) {
            return res.status(400).json({ error: 'Email is required.' });
        }

        const user = await User.findOne({ email: email.trim().toLowerCase() });

        // Always return success to prevent email enumeration
        if (!user) {
            return res.json({ success: true, message: 'If that email exists, a reset link has been sent.' });
        }

        // Generate reset token
        const rawToken = user.createResetToken();
        await user.save();

        // Build reset URL
        const resetUrl = `${req.protocol}://${req.get('host')}/reset-password.html?token=${rawToken}&email=${encodeURIComponent(user.email)}`;

        // Try to send email
        const transport = getTransporter();
        if (transport) {
            await transport.sendMail({
                from: process.env.SMTP_FROM || process.env.SMTP_USER,
                to: user.email,
                subject: 'Fly Nexus LLP — Password Reset',
                html: `
                    <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 500px; margin: 0 auto; background: #0f0f1a; padding: 40px; border-radius: 12px; color: #e8e8f0;">
                        <h1 style="color: #6c5ce7; margin-bottom: 16px; font-size: 1.4rem;">Password Reset</h1>
                        <p style="color: #9090a8; margin-bottom: 24px;">You requested a password reset for your Fly Nexus LLP account. Click the button below to create a new password:</p>
                        <a href="${resetUrl}" style="display: inline-block; background: linear-gradient(135deg, #6c5ce7, #8b7cf7); color: #fff; text-decoration: none; padding: 14px 28px; border-radius: 8px; font-weight: 600; font-size: 0.95rem;">Reset My Password</a>
                        <p style="color: #606078; margin-top: 24px; font-size: 0.85rem;">This link expires in 1 hour. If you didn't request this, you can safely ignore this email.</p>
                    </div>
                `,
            });
            console.log(`Password reset email sent to ${user.email}`);
        } else {
            // No SMTP configured — log the reset URL for development
            console.log('─────────────────────────────────────────────');
            console.log('📧 SMTP not configured. Password reset link:');
            console.log(resetUrl);
            console.log('─────────────────────────────────────────────');
        }

        res.json({ success: true, message: 'If that email exists, a reset link has been sent.' });
    } catch (err) {
        console.error('Forgot password error:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// ─── POST /api/user/reset-password ──────────────────────────────────
router.post('/api/user/reset-password', async (req, res) => {
    try {
        const { email, token, newPassword } = req.body;

        if (!email || !token || !newPassword) {
            return res.status(400).json({ error: 'Email, token, and new password are required.' });
        }

        if (newPassword.trim().length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters.' });
        }

        // Hash the incoming token and compare with stored hash
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

        const user = await User.findOne({
            email: email.trim().toLowerCase(),
            resetToken: hashedToken,
            resetTokenExpiry: { $gt: new Date() },
        });

        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired reset token.' });
        }

        // Update password
        user.passwordHash = await bcrypt.hash(newPassword.trim(), 12);
        user.resetToken = null;
        user.resetTokenExpiry = null;
        await user.save();

        res.json({ success: true, message: 'Password has been reset successfully. You can now log in.' });
    } catch (err) {
        console.error('Reset password error:', err);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

module.exports = router;
