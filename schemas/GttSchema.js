const { Schema } = require("mongoose");

const GttSchema = new Schema({
  userId: {
    type: String,
    required: true,
    index: true,
  },
  gttId: {
    type: String,
    default: () => "GTT" + Date.now().toString().slice(-8),
  },
  symbol: {
    type: String,
    required: true,
  },
  exchange: {
    type: String,
    default: "NSE",
  },
  type: {
    type: String,
    enum: ["SINGLE", "OCO"],
    default: "SINGLE",
  },
  transactionType: {
    type: String,
    enum: ["BUY", "SELL"],
    default: "BUY",
  },
  product: {
    type: String,
    default: "CNC",
  },
  qty: {
    type: Number,
    required: true,
    min: 1,
  },
  triggerPrice: Number,
  orderPrice: Number,
  stoplossTrigger: Number,
  stoplossPrice: Number,
  targetTrigger: Number,
  targetPrice: Number,
  status: {
    type: String,
    enum: ["ACTIVE", "TRIGGERED", "CANCELLED", "REJECTED"],
    default: "ACTIVE",
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  triggeredAt: Date,
});

module.exports = { GttSchema };
