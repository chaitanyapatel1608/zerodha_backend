const { model } = require("mongoose");
const { FundsTransactionSchema } = require("../schemas/FundsTransactionSchema");

const FundsTransactionModel = model("funds_transaction", FundsTransactionSchema);

module.exports = { FundsTransactionModel };
