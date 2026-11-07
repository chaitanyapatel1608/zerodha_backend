const { Schema } = require("mongoose");

const InstrumentSchema = new Schema(
  {
    symbol: { type: String, required: true, index: true },
    name: { type: String, required: true },
    exchange: { type: String, default: "NSE" },
    sector: { type: String, default: "Equity" },
    price: { type: Number, required: true },
    change: { type: Number, default: 0 },
    percent: { type: String, default: "0.00%" },
    isDown: { type: Boolean, default: false },
  },
  { timestamps: true }
);

module.exports = { InstrumentSchema };
