const { Schema } = require("mongoose");

const GsecBidSchema = new Schema(
  {
    userId: { type: String, required: true, index: true },
    symbol: { type: String, required: true },
    instrumentName: { type: String, required: true },
    category: { type: String, default: "T-BILL" }, // "T-BILL", "G-SEC", "SGB", "SDL"
    units: { type: Number, required: true, min: 1 },
    indicativeYield: { type: String, default: "7.05%" },
    pricePerUnit: { type: Number, required: true },
    totalAmount: { type: Number, required: true },
    status: {
      type: String,
      enum: ["BID_PLACED", "ALLOTTED", "SETTLED", "CANCELLED"],
      default: "BID_PLACED",
    },
    bidNumber: { type: String, required: true, unique: true },
    biddedAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

module.exports = { GsecBidSchema };
