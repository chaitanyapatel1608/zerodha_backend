const { Schema } = require("mongoose");

const WatchlistStockSubSchema = new Schema(
  {
    symbol: { type: String, required: true },
    name: { type: String, default: "" },
    exchange: { type: String, default: "NSE" },
    price: { type: Number, default: 0 },
    change: { type: Number, default: 0 },
    percent: { type: String, default: "0.00%" },
    isDown: { type: Boolean, default: false },
    sector: { type: String, default: "Equity" },
  },
  { _id: false }
);

const UserWatchlistSchema = new Schema(
  {
    userId: {
      type: String,
      required: true,
      index: true,
    },
    tabId: {
      type: Number,
      required: true,
      min: 1,
      max: 7,
    },
    tabName: {
      type: String,
      default: function () {
        return `Watchlist ${this.tabId}`;
      },
      trim: true,
      maxlength: 30,
    },
    stocks: {
      type: [WatchlistStockSubSchema],
      default: [],
    },
  },
  { timestamps: true }
);

// Compound unique index so each user has at most one record per tab
UserWatchlistSchema.index({ userId: 1, tabId: 1 }, { unique: true });

module.exports = { UserWatchlistSchema };
