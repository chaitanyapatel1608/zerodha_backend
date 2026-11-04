const { model } = require("mongoose");
const { OtpSchema } = require("../schemas/OtpSchema");

const OtpModel = model("otp", OtpSchema);

module.exports = { OtpModel };
