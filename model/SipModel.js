const mongoose = require("mongoose");
const { SipSchema } = require("../schemas/SipSchema");

const SipModel = mongoose.model("sip", SipSchema);

module.exports = { SipModel };
