const mongoose = require('mongoose');

/**
 * Connect to MongoDB Atlas.
 * Uses MONGO_URI from environment variables.
 * Exits the process on connection failure to avoid running in a broken state.
 */
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`✅ MongoDB connected: ${conn.connection.host}`);
  } catch (err) {
    console.error(`❌ MongoDB connection error: ${err.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;
