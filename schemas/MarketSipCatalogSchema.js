const { Schema } = require("mongoose");

const MarketSipCatalogSchema = new Schema(
  {
    code: { type: String, required: true, unique: true, index: true },
    symbol: { type: String, required: true },
    name: { type: String, required: true },
    category: { type: String, required: true },
    tag: { type: String, default: "Equity" },
    minAmount: { type: Number, required: true },
    cagr3Yr: { type: String, default: "+15.0%" },
    risk: { type: String, default: "Moderate" },
    description: { type: String, default: "" },
    instruments: [
      {
        symbol: { type: String, required: true },
        name: { type: String, default: "" },
        qty: { type: Number, default: 1 },
        price: { type: Number, default: 0 },
        product: { type: String, default: "CNC" },
        mode: { type: String, default: "BUY" },
      },
    ],
  },
  { timestamps: true }
);

module.exports = { MarketSipCatalogSchema };
