const mongoose = require("mongoose");
const { Schema } = mongoose;

const NotificationSchema = new Schema(
  {
    userId: {
      type: String,
      required: true,
      index: true,
      default: "ZU9344",
    },
    type: {
      type: String,
      enum: ["ORDER", "FUNDS", "COMPLIANCE", "GTT", "MARKET_ALERT", "SYSTEM"],
      required: true,
      default: "ORDER",
    },
    category: {
      type: String,
      default: "EXECUTION",
    },
    title: {
      type: String,
      required: true,
    },
    description: {
      type: String,
      required: true,
    },
    metadata: {
      orderId: { type: String, default: "" },
      symbol: { type: String, default: "" },
      qty: { type: Number },
      price: { type: Number },
      mode: { type: String }, // "BUY" | "SELL"
      product: { type: String }, // "CNC" | "MIS"
      amount: { type: Number },
      referenceId: { type: String, default: "" },
      actionUrl: { type: String, default: "/orders" },
    },
    unread: {
      type: Boolean,
      default: true,
      index: true,
    },
    priority: {
      type: String,
      enum: ["LOW", "NORMAL", "HIGH", "CRITICAL"],
      default: "NORMAL",
    },
    createdAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
  },
  { timestamps: true }
);

// Compound index for high-speed user queries and unread count aggregation
NotificationSchema.index({ userId: 1, createdAt: -1 });
NotificationSchema.index({ userId: 1, unread: 1 });

module.exports = { NotificationSchema };
