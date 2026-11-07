const { Schema } = require("mongoose");

const SseIpoSchema = new Schema({
  symbol: { type: String, required: true, unique: true },
  orgName: { type: String, required: true },
  focusArea: { type: String, required: true },
  issueDates: { type: String, required: true },
  targetAmount: { type: String, required: true },
  unitPrice: { type: Number, default: 100 },
  minUnits: { type: Number, default: 100 }, // Min lot: 100 units = ₹10,000
  minInvestment: { type: Number, default: 10000 },
  taxExemption: { type: String, default: "100% Tax Exempt u/s 80G" },
  impactGoal: { type: String, required: true },
  socialAuditor: { type: String, default: "ICAI Certified Social Auditor" },
  sebiRegNo: { type: String, required: true },
  status: { type: String, default: "Apply" }, // Apply, Closed
  rhpUrl: { type: String, default: "https://www.bseindia.com/markets/social-stock-exchange" },
});

module.exports = { SseIpoSchema };
