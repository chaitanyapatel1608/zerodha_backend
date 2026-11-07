const { Schema } = require("mongoose");

const AuctionOfferSchema = new Schema({
  userId: { type: String, required: true },
  symbol: { type: String, required: true },
  companyName: { type: String, required: true },
  exchange: { type: String, default: "NSE" },
  quantity: { type: Number, required: true },
  basePrice: { type: Number, required: true },
  offerPrice: { type: Number, required: true },
  totalAmount: { type: Number, required: true },
  premiumPercent: { type: String, default: "+0.00%" },
  status: { type: String, default: "OFFERED" }, // OFFERED, MATCHED, SETTLED, REJECTED
  orderId: { type: String, required: true },
  settlementDate: { type: String, default: "T+1" },
  createdAt: { type: Date, default: Date.now },
});

module.exports = { AuctionOfferSchema };
