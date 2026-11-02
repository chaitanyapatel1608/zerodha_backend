const { Schema } = require("mongoose");

const FundsSchema = new Schema({
  userId: {
    type: String,
    default: "ZU8842",
    unique: true,
  },
  equity: {
    availableMargin: { type: String, default: "1,24,500.00" },
    usedMargin: { type: String, default: "42,180.00" },
    availableCash: { type: String, default: "1,24,500.00" },
    openingBalance: { type: String, default: "1,66,680.00" },
    payin: { type: String, default: "0.00" },
    span: { type: String, default: "28,450.00" },
    deliveryMargin: { type: String, default: "0.00" },
    exposure: { type: String, default: "13,730.00" },
    optionsPremium: { type: String, default: "0.00" },
    collateralLiquid: { type: String, default: "0.00" },
    collateralEquity: { type: String, default: "0.00" },
    totalCollateral: { type: String, default: "0.00" },
  },
  commodity: {
    availableMargin: { type: String, default: "55,000.00" },
    usedMargin: { type: String, default: "0.00" },
    availableCash: { type: String, default: "55,000.00" },
    openingBalance: { type: String, default: "55,000.00" },
    payin: { type: String, default: "0.00" },
    span: { type: String, default: "0.00" },
    deliveryMargin: { type: String, default: "0.00" },
    exposure: { type: String, default: "0.00" },
    optionsPremium: { type: String, default: "0.00" },
  },
});

module.exports = { FundsSchema };
