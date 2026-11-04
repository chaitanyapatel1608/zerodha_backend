const mongoose = require("mongoose");
const { Schema } = mongoose;

const IpoApplicationSchema = new Schema(
  {
    userId: {
      type: String,
      required: true,
      index: true,
      default: "ZU9344",
    },
    userEmail: {
      type: String,
      required: true,
    },
    ipoSymbol: {
      type: String,
      required: true,
      index: true,
    },
    companyName: {
      type: String,
      required: true,
    },
    applicationNumber: {
      type: String,
      required: true,
      unique: true,
    },
    investorCategory: {
      type: String,
      enum: ["INDIVIDUAL", "HNI", "EMPLOYEE", "SHAREHOLDER"],
      default: "INDIVIDUAL",
    },
    upiId: {
      type: String,
      required: true,
    },
    lots: {
      type: Number,
      required: true,
      min: 1,
      default: 1,
    },
    lotSize: {
      type: Number,
      required: true,
      default: 1,
    },
    totalQty: {
      type: Number,
      required: true,
    },
    bidPrice: {
      type: Number,
      required: true,
    },
    isCutOff: {
      type: Boolean,
      default: true,
    },
    totalAmount: {
      type: Number,
      required: true,
    },
    dematBoId: {
      type: String,
      required: true,
      default: "1208160081236464",
    },
    pan: {
      type: String,
      required: true,
      default: "ABCDE1234F",
    },
    mandateToken: {
      type: String,
      required: true,
      unique: true,
    },
    status: {
      type: String,
      enum: ["MANDATE_PENDING", "APPLIED", "ALLOTTED", "REFUNDED", "CANCELLED"],
      default: "MANDATE_PENDING",
      index: true,
    },
    mandateStatus: {
      type: String,
      enum: ["PENDING_APPROVAL", "ACCEPTED", "REJECTED"],
      default: "PENDING_APPROVAL",
      index: true,
    },
    appliedAt: {
      type: Date,
      default: Date.now,
      index: true,
    },
    mandateDecidedAt: {
      type: Date,
    },
  },
  { timestamps: true }
);

IpoApplicationSchema.index({ userId: 1, ipoSymbol: 1 });

module.exports = { IpoApplicationSchema };
