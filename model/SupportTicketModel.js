const { model } = require("mongoose");
const { SupportTicketSchema } = require("../schemas/SupportTicketSchema");

const SupportTicketModel = new model("support_ticket", SupportTicketSchema);

module.exports = { SupportTicketModel };
