const { Schema } = require("mongoose");

const HoldingsSchema = new Schema({
    userId: {
        type: String,
        required: true,
        index: true,
    },
    name: String,
    instrument: String,
    qty: Number,
    avg: Number,
    avgCost: Number,
    price: Number,
    ltp: Number,
    curVal: Number,
    pnl: Number,
    net: String,
    netChg: String,
    day: String,
    dayChg: String,
    isProfit: Boolean,
    isDayProfit: Boolean,
});

module.exports = { HoldingsSchema };
