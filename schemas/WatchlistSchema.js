const { Schema } = require("mongoose");

const WatchlistSchema = new Schema({
  symbol: {
    type: String,
    required: true,
    unique: true,
  },
  name: String,
  exchange: {
    type: String,
    default: "NSE",
  },
  price: Number,
  change: Number,
  percent: String,
  isDown: Boolean,
});

module.exports = { WatchlistSchema };
