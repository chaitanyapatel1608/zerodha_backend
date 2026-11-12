const { model } = require("mongoose");
const { BankAccountSchema } = require("../schemas/BankAccountSchema");

const BankAccountModel = model("bank_account", BankAccountSchema);

module.exports = { BankAccountModel };
