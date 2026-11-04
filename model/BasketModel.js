const { model } = require("mongoose");
const { BasketSchema } = require("../schemas/BasketSchema");

const BasketModel = new model("basket", BasketSchema);

module.exports = { BasketModel };
