const { model } = require("mongoose");
const { IpoSchema } = require("../schemas/IpoSchema");

const IpoModel = new model("ipo", IpoSchema);

module.exports = { IpoModel };
