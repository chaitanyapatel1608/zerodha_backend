const { Schema } = require("mongoose");

const SseApplicationSchema = new Schema({
  userId: { type: String, required: true },
  symbol: { type: String, required: true },
  orgName: { type: String, required: true },
  units: { type: Number, required: true },
  unitPrice: { type: Number, default: 100 },
  totalAmount: { type: Number, required: true },
  panNumber: { type: String, required: true },
  taxReceiptRequested: { type: Boolean, default: true },
  taxCertificateNo: { type: String },
  upiId: { type: String, required: true },
  status: { type: String, default: "APPLIED" },
  mandateStatus: { type: String, default: "ACCEPTED" },
  asbaReference: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
});

module.exports = { SseApplicationSchema };
