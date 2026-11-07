const { Schema } = require("mongoose");

const AuctionSchema = new Schema({
  symbol: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  exchange: { type: String, default: "NSE" },
  settlementType: { type: String, default: "T+1 Short Delivery" },
  shortQtyRequired: { type: Number, required: true },
  basePrice: { type: Number, required: true },
  maxAllowedPrice: { type: Number, required: true }, // +20% upper penalty circuit
  auctionWindow: { type: String, default: "14:00 - 14:45 IST" },
  status: { type: String, default: "OPEN" }, // OPEN, CLOSED
  settlementDate: { type: String, default: "Tomorrow (T+1)" },
});

module.exports = { AuctionSchema };
