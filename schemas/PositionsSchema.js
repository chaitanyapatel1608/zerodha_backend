const { Schema } = require("mongoose");

const PositionsSchema = new Schema({
    userId: {
        type: String,
        required: true,
        index: true,
    },
    product: { type: String, default: "MIS" },
    name: String,
    instrument: String,
    qty: { type: Number, default: 0 },
    avg: { type: Number, default: 0 },
    price: { type: Number, default: 0 },
    ltp: { type: Number, default: 0 },
    pnl: { type: Number, default: 0 },
    realizedPnl: { type: Number, default: 0 },
    unrealizedPnl: { type: Number, default: 0 },
    net: { type: String, default: "+0.00%" },
    day: { type: String, default: "+0.00%" },
    chg: { type: String, default: "+0.00%" },
    isLoss: { type: Boolean, default: false },
    isProfit: { type: Boolean, default: true },
    status: { type: String, enum: ["OPEN", "CLOSED"], default: "OPEN" },
    closedAt: { type: Date, default: null },
    convertedAt: { type: Date, default: null },
    updatedAt: { type: Date, default: Date.now },
});

module.exports = { PositionsSchema };
