const { Schema } = require("mongoose");

const UserSchema = new Schema({
  userId: { 
    type: String, 
    required: true, 
    unique: true 
  },
  email: { 
    type: String, 
    required: true, 
    unique: true, 
    lowercase: true, 
    trim: true 
  },
  fullName: { 
    type: String, 
    default: "Trader" 
  },
  phone: {
    type: String,
    trim: true,
  },
  pan: {
    type: String,
    uppercase: true,
    trim: true,
  },
  dob: {
    type: String,
  },
  demat: {
    type: String,
    default: () => "12081600" + Math.floor(10000000 + Math.random() * 90000000),
  },
  annualIncome: {
    type: String,
    default: "₹1L - ₹5L",
  },
  tradingExp: {
    type: String,
    default: "1-3 Years",
  },
  broker: {
    type: String,
    default: "Zerodha Broking Ltd.",
  },
  password: {
    type: String,
  },
  role: { 
    type: String, 
    enum: ["user", "admin"], 
    default: "user" 
  },
  avatarText: { 
    type: String, 
    default: "TR" 
  },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  lastLogin: { 
    type: Date, 
    default: Date.now 
  }
});

module.exports = { UserSchema };
