const { Schema } = require("mongoose");
const crypto = require("crypto");
const { encryptField, isEncrypted } = require("../utils/encryption");

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
    index: true,
  },
  pan: {
    type: String,
    // uppercase handled before encryption in pre-save hook
    trim: true,
  },
  dob: {
    type: String,
  },
  demat: {
    type: String,
    default: () => "12081600" + crypto.randomInt(10000000, 100000000),
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
  segments: {
    type: Object,
    default: () => ({
      equity: {
        name: "NSE & BSE Equity (Cash)",
        exchange: "NSE, BSE",
        active: true,
        deactivatedAt: null,
        activatedAt: new Date(),
      },
      futuresAndOptions: {
        name: "Futures & Options (F&O)",
        exchange: "NFO, BFO",
        active: true,
        deactivatedAt: null,
        activatedAt: new Date(),
      },
      currency: {
        name: "Currency Derivatives (CDS)",
        exchange: "CDS, BCD",
        active: false,
        deactivatedAt: null,
        activatedAt: null,
      },
      commodity: {
        name: "Commodity Derivatives",
        exchange: "MCX",
        active: false,
        deactivatedAt: null,
        activatedAt: null,
      },
    }),
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
  cdslTpin: {
    type: String,
    default: "",
  },
  cdslAttempts: { type: Number, default: 0 },
  cdslLockedUntil: { type: Date, default: null },
  cdslAuthorizedUntil: { type: Date, default: null },
  tokenVersion: { type: Number, default: 0 },
  cdslAuthorizedUntil: { type: Date, default: null },
  createdAt: { 
    type: Date, 
    default: Date.now 
  },
  lastLogin: { 
    type: Date, 
    default: Date.now 
  }
});

function encryptNomineeFields(nom) {
  if (!nom) return;
  if (nom.idNumber) nom.idNumber = encryptField(nom.idNumber);
  if (nom.pan) nom.pan = encryptField(nom.pan);
  if (nom.phone) nom.phone = encryptField(nom.phone);
  if (nom.address) nom.address = encryptField(nom.address);
  if (nom.guardian?.idNumber) nom.guardian.idNumber = encryptField(nom.guardian.idNumber);
  if (nom.guardian?.phone) nom.guardian.phone = encryptField(nom.guardian.phone);
  if (nom.guardian?.address) nom.guardian.address = encryptField(nom.guardian.address);
}

UserSchema.pre("save", async function () {
  if (this.pan && !isEncrypted(this.pan)) this.pan = encryptField(String(this.pan).trim().toUpperCase());
  if (this.dob && !isEncrypted(this.dob)) this.dob = encryptField(this.dob);
  if (this.phone && !isEncrypted(this.phone)) this.phone = encryptField(this.phone);
  if (this.address && !isEncrypted(this.address)) this.address = encryptField(this.address);
  if (Array.isArray(this.nominees)) {
    this.nominees.forEach(encryptNomineeFields);
  }
  if (this.nominee) {
    encryptNomineeFields(this.nominee);
  }
});

module.exports = { UserSchema };
