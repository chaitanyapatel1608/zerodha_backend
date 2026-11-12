const { model } = require("mongoose");
const { PledgedCollateralSchema } = require("../schemas/PledgedCollateralSchema");

const PledgedCollateralModel = model("pledged_collateral", PledgedCollateralSchema);

module.exports = { PledgedCollateralModel };
