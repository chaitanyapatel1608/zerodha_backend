const { model } = require("mongoose");
const { GsecBidSchema } = require("../schemas/GsecBidSchema");

const GsecBidModel = model("gsec_bid", GsecBidSchema);

module.exports = { GsecBidModel };
