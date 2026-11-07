const { model } = require("mongoose");
const { CorporateActionSchema } = require("../schemas/CorporateActionSchema");

const CorporateActionModel = model("corporate_action_tender", CorporateActionSchema);

module.exports = { CorporateActionModel };
