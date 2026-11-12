const { Schema } = require("mongoose");
const { encryptField } = require("../utils/encryption");

const BankAccountSchema = new Schema({
  userId: { type: String, required: true },
  bankName: { type: String, required: true },
  accountNumber: { type: String, required: true }, // Full or masked
  maskedAccountNumber: { type: String, required: true }, // e.g. "····4821"
  ifscCode: { type: String, required: true },
  branch: { type: String, default: "Main Branch" },
  accountType: { type: String, enum: ["SAVINGS", "CURRENT"], default: "SAVINGS" },
  isPrimary: { type: Boolean, default: false },
  status: { type: String, enum: ["VERIFIED", "PENDING_VERIFICATION"], default: "VERIFIED" },
  pennyDropRef: { type: String },
  createdAt: { type: Date, default: Date.now },
});

BankAccountSchema.pre("save", async function () {
  if (this.accountNumber) {
    this.accountNumber = encryptField(this.accountNumber);
  }
});

module.exports = { BankAccountSchema };
