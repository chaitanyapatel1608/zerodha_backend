const { model } = require("mongoose");
const { AuctionSchema } = require("../schemas/AuctionSchema");

const AuctionModel = model("auction", AuctionSchema);

module.exports = { AuctionModel };
