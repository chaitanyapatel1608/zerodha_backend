const mongoose = require("mongoose");
const AlertSchema = require("../schemas/AlertSchema");

const AlertModel = mongoose.model("alert", AlertSchema);

module.exports = AlertModel;
