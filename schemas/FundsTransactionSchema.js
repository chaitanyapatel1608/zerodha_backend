const { Schema } = require("mongoose");

const FundsTransactionSchema = new Schema({
  userId: { type: String, required: true, index: true },
  type: {
    type: String,
    enum: ["PAYIN", "PAYOUT", "PLEDGE_MARGIN", "UNPLEDGE_MARGIN"],
    required: true,
  },
  amount: { type: Number, required: true },
  paymentMethod: { type: String, default: "UPI" },
  upiId: { type: String },
  bankAccount: { type: String, default: "HDFC Bank ····4821" },
  status: {
    type: String,
    enum: ["PENDING_APPROVAL", "COMPLETED", "REJECTED"],
    default: "PENDING_APPROVAL",
  },
  referenceId: { type: String, required: true, unique: true },
  approvalToken: { type: String, index: true },
  approvalExpiresAt: { type: Date },
  idempotencyKey: { type: String, index: true, sparse: true },
  remarks: { type: String },
  createdAt: { type: Date, default: Date.now },
  completedAt: { type: Date },
});

module.exports = { FundsTransactionSchema };
