const { Schema } = require("mongoose");

const BasketItemSchema = new Schema({
  symbol: { type: String, required: true },
  mode: { type: String, enum: ["BUY", "SELL"], default: "BUY" },
  product: { type: String, default: "CNC" },
  qty: { type: Number, required: true, min: 1 },
  price: { type: Number, required: true },
  orderType: { type: String, default: "LIMIT" },
});

const BasketSchema = new Schema({
  userId: {
    type: String,
    default: "ZU9344",
  },
  name: {
    type: String,
    required: true,
  },
  items: [BasketItemSchema],
  marginRequired: {
    type: Number,
    default: 0,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = { BasketSchema };
