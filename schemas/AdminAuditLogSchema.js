const { Schema } = require("mongoose");

const AdminAuditLogSchema = new Schema(
  {
    adminUserId: { type: String, required: true, index: true },
    adminEmail: { type: String, default: "" },
    action: { type: String, required: true, index: true },
    targetType: { type: String, default: "system", index: true },
    targetId: { type: String, default: "", index: true },
    reason: { type: String, default: "" },
    details: { type: Schema.Types.Mixed, default: {} },
    ipAddress: { type: String, default: "" },
    userAgent: { type: String, default: "" },
  },
  { timestamps: true }
);

AdminAuditLogSchema.index({ createdAt: -1 });

module.exports = { AdminAuditLogSchema };
