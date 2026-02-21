/**
 * Admin Seed Script
 * Creates or updates the admin user in the database.
 * Reads credentials from ADMIN_USERNAME and ADMIN_PASSWORD in .env.
 *
 * Usage: node scripts/seedAdmin.js
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const Admin = require('../models/Admin');

const seed = async () => {
    const { MONGO_URI, ADMIN_USERNAME, ADMIN_PASSWORD } = process.env;

    if (!MONGO_URI || !ADMIN_USERNAME || !ADMIN_PASSWORD) {
        console.error('❌ Missing required environment variables: MONGO_URI, ADMIN_USERNAME, ADMIN_PASSWORD');
        process.exit(1);
    }

    try {
        await mongoose.connect(MONGO_URI);
        console.log('✅ Connected to MongoDB');

        const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);

        // Upsert: create if not exists, update if exists
        await Admin.findOneAndUpdate(
            { username: ADMIN_USERNAME },
            { username: ADMIN_USERNAME, passwordHash },
            { upsert: true, new: true }
        );

        console.log(`✅ Admin user "${ADMIN_USERNAME}" created/updated successfully.`);
    } catch (err) {
        console.error('❌ Seed error:', err.message);
    } finally {
        await mongoose.disconnect();
        process.exit(0);
    }
};

seed();
