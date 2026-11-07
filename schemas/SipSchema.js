const mongoose = require("mongoose");
const { Schema } = mongoose;

const ExecutionLogSchema = new Schema({
  executedAt: { type: Date, default: Date.now },
  ordersCount: { type: Number, default: 0 },
  amountDebited: { type: Number, default: 0 },
  status: { type: String, enum: ["SUCCESS", "FAILED_INSUFFICIENT_FUNDS"], required: true },
  failureReason: { type: String },
});

const SipInstrumentSchema = new Schema({
  symbol: { type: String, required: true },
  name: { type: String },
  qty: { type: Number, required: true, default: 1 },
  price: { type: Number, required: true },
  product: { type: String, default: "CNC" },
  mode: { type: String, default: "BUY" },
});

const SipSchema = new Schema(
  {
    userId: {
      type: String,
      required: true,
      index: true,
    },
    name: {
      type: String,
      required: true,
      trim: true,
    },
    sipType: {
      type: String,
      enum: ["STOCK", "ETF", "THEMATIC", "BASKET"],
      default: "STOCK",
    },
    symbol: {
      type: String, // e.g. "RELIANCE", "NIFTYBEES"
    },
    basketId: {
      type: Schema.Types.ObjectId,
      ref: "basket",
      required: false,
    },
    basketName: {
      type: String,
      required: false,
    },
    instruments: [SipInstrumentSchema],
    minAmount: {
      type: Number,
      default: 0,
    },
    frequency: {
      type: String,
      enum: ["DAILY", "WEEKLY", "MONTHLY"],
      default: "MONTHLY",
    },
    scheduleDay: {
      type: Number,
      default: 5, // Day of Month (1-28) or Day of Week (1=Mon ... 5=Fri)
    },
    scheduleTime: {
      type: String,
      default: "09:30", // e.g. "09:30", "11:00", "14:30"
    },
    status: {
      type: String,
      enum: ["ACTIVE", "PAUSED", "COMPLETED", "FAILED_MARGIN"],
      default: "ACTIVE",
      index: true,
    },
    nextTriggerAt: {
      type: Date,
      required: true,
      index: true,
    },
    lastExecutedAt: {
      type: Date,
    },
    totalInstallmentsExecuted: {
      type: Number,
      default: 0,
    },
    totalCapitalInvested: {
      type: Number,
      default: 0,
    },
    executionLogs: [ExecutionLogSchema],
  },
  { timestamps: true }
);

module.exports = { SipSchema };
