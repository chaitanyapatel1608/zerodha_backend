const { Schema } = require("mongoose");

const NomineeSubSchema = new Schema(
  {
    fullName: { type: String, default: "" },
    relationship: { type: String, default: "Spouse" },
    dob: { type: String, default: "" },
    isMinor: { type: Boolean, default: false },
    guardian: {
      fullName: { type: String, default: "" },
      relationship: { type: String, default: "Father" },
      idType: { type: String, default: "PAN" },
      idNumber: { type: String, default: "" },
      phone: { type: String, default: "" },
      address: { type: String, default: "" },
    },
    idType: {
      type: String,
      default: "PAN",
    },
    idNumber: { type: String, default: "" },
    pan: { type: String, default: "" },
    email: { type: String, default: "" },
    phone: { type: String, default: "" },
    address: { type: String, default: "" },
    allocation: { type: Number, default: 100 },
    submittedAt: { type: Date, default: Date.now },
  },
  { _id: false }
);

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
  address: {
    type: String,
    default: "",
  },
  password: {
    type: String,
  },
  nomineeStatus: {
    type: String,
    enum: ['PENDING', 'VERIFIED', 'OPTED_OUT'],
    default: 'PENDING',
  },
  nominees: {
    type: [NomineeSubSchema],
    default: [],
  },
  nominee: {
    type: NomineeSubSchema,
    default: null,
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
