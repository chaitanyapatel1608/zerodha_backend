const { model } = require("mongoose");
const { IpoApplicationSchema } = require("../schemas/IpoApplicationSchema");

const IpoApplicationModel = new model("ipo_application", IpoApplicationSchema);

module.exports = { IpoApplicationModel };
