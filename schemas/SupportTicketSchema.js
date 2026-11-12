const mongoose = require("mongoose");
const { Schema } = mongoose;

const SupportTicketSchema = new Schema(
  {
    ticketId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    userId: {
      type: String,
      required: true,
      index: true,
    },
    userName: {
      type: String,
      default: "Trader",
    },
    userEmail: {
      type: String,
      default: "",
    },
    category: {
      type: String,
      enum: ["FUNDS", "ORDERS", "DEMAT", "ACCOUNT", "TECH", "OTHER"],
      default: "ORDERS",
    },
    categoryLabel: {
      type: String,
      default: "Order Placement & Fills",
    },
    subject: {
      type: String,
      required: true,
      trim: true,
    },
    description: {
      type: String,
      required: true,
      trim: true,
    },
    priority: {
      type: String,
      enum: ["NORMAL", "HIGH", "URGENT"],
      default: "NORMAL",
    },
    status: {
      type: String,
      enum: ["OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"],
      default: "OPEN",
    },
    slaHours: {
      type: Number,
      default: 2,
    },
    assignedTo: {
      type: String,
      default: "Kite Helpdesk Team",
    },
    resolvedAt: {
      type: Date,
      default: null,
    },
    createdAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
  },
  { timestamps: true }
);

module.exports = { SupportTicketSchema };
