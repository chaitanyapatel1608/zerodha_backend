const { model } = require("mongoose");
const { GttSchema } = require("../schemas/GttSchema");

const GttModel = new model("gtt", GttSchema);

module.exports = { GttModel };
