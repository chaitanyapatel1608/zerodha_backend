const { model } = require("mongoose");
const { AuctionOfferSchema } = require("../schemas/AuctionOfferSchema");

const AuctionOfferModel = model("auction_offer", AuctionOfferSchema);

module.exports = { AuctionOfferModel };
