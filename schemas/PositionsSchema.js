const { Schema } = require("mongoose");

const PositionsSchema = new Schema({
    userId: {
        type: String,
        default: "ZU9344",
    },
    product: String,
    name: String,
    instrument: String,
    qty: Number,
    avg: Number,
    price: Number,
    ltp: Number,
    pnl: Number,
    net: String,
    day: String,
    chg: String,
    isLoss: Boolean,
    isProfit: Boolean,
});

module.exports = { PositionsSchema };
