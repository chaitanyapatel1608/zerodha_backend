const { Schema } = require("mongoose");

const PledgedCollateralSchema = new Schema({
  userId: { type: String, required: true },
  symbol: { type: String, required: true },
  companyName: { type: String, required: true },
  pledgedQty: { type: Number, required: true },
  marketPrice: { type: Number, required: true },
  haircutPercent: { type: Number, default: 15 }, // e.g. 15%
  collateralValue: { type: Number, required: true }, // pledgedQty * marketPrice * (1 - haircut/100)
  status: { type: String, enum: ["PLEDGED", "RELEASED"], default: "PLEDGED" },
  pledgeRef: { type: String, required: true },
  pledgedAt: { type: Date, default: Date.now },
  releasedAt: { type: Date },
});

module.exports = { PledgedCollateralSchema };
