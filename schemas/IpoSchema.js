const { Schema } = require("mongoose");

const IpoSchema = new Schema({
  symbol: {
    type: String,
    required: true,
    unique: true,
  },
  name: String,
  dates: String,
  priceRange: String,
  minQty: Number,
  minAmount: String,
  status: {
    type: String,
    default: "Upcoming", // "Apply", "Pre-apply", "Closed", "Upcoming"
  },
  type: {
    type: String,
    default: "IPO",
  },
});

module.exports = { IpoSchema };
