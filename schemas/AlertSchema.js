const mongoose = require("mongoose");
const { Schema } = mongoose;

const AlertSchema = new Schema(
  {
    userId: {
      type: String,
      required: true,
      index: true,
    },
    symbol: {
      type: String,
      required: true,
      uppercase: true,
      trim: true,
      index: true,
    },
    name: {
      type: String,
      default: "",
    },
    exchange: {
      type: String,
      default: "NSE",
    },
    // Condition Type:
    // GTE: Last Traded Price >= Target Price
    // LTE: Last Traded Price <= Target Price
    // PCT_UP: Day Change % >= Target Percentage
    // PCT_DOWN: Day Change % <= -Target Percentage
    conditionType: {
      type: String,
      enum: ["GTE", "LTE", "PCT_UP", "PCT_DOWN"],
      required: true,
      default: "GTE",
    },
    targetPrice: {
      type: Number,
      default: 0,
    },
    targetPercentage: {
      type: Number,
      default: 0,
    },
    initialLtp: {
      type: Number,
      default: 0,
    },
    notes: {
      type: String,
      default: "",
      trim: true,
    },
    status: {
      type: String,
      enum: ["ACTIVE", "TRIGGERED", "DISABLED"],
      default: "ACTIVE",
      index: true,
    },
    triggeredAt: {
      type: Date,
    },
    triggeredPrice: {
      type: Number,
    },
    notificationChannels: {
      type: [String],
      default: ["IN_APP", "EMAIL"],
    },
  },
  { timestamps: true }
);

module.exports = AlertSchema;
