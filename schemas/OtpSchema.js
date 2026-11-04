const { Schema } = require("mongoose");

const OtpSchema = new Schema({
  email: {
    type: String,
    required: true,
    index: true,
    lowercase: true,
    trim: true,
  },
  otp: {
    type: String,
    required: true,
  },
  attempts: {
    type: Number,
    default: 0,
  },
  expiresAt: {
    type: Date,
    required: true,
    expires: 0, // MongoDB TTL index: expires automatically when expiresAt timestamp arrives
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = { OtpSchema };
