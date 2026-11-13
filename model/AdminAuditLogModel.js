const { model } = require("mongoose");
const { AdminAuditLogSchema } = require("../schemas/AdminAuditLogSchema");

const AdminAuditLogModel = model("adminauditlog", AdminAuditLogSchema);

module.exports = { AdminAuditLogModel };
