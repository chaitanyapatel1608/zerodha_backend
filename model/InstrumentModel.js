const { model } = require("mongoose");
const { InstrumentSchema } = require("../schemas/InstrumentSchema");

const InstrumentModel = model("instrument", InstrumentSchema);

module.exports = { InstrumentModel };
