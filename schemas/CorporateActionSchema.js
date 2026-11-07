const { Schema } = require("mongoose");

const CorporateActionSchema = new Schema(
  {
    userId: { type: String, required: true, index: true },
    symbol: { type: String, required: true },
    companyName: { type: String, required: true },
    actionType: { type: String, default: "BUYBACK" }, // "BUYBACK", "TAKEOVER", "DELISTING"
    tenderPrice: { type: Number, required: true },
    tenderedQty: { type: Number, required: true, min: 1 },
    totalAmount: { type: Number, required: true },
    status: {
      type: String,
      enum: ["TENDERED", "ACCEPTED", "SETTLED", "REJECTED"],
      default: "TENDERED",
    },
    tenderRef: { type: String, required: true, unique: true },
    tenderedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

module.exports = { CorporateActionSchema };
