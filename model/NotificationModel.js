const { model } = require("mongoose");
const { NotificationSchema } = require("../schemas/NotificationSchema");

const NotificationModel = new model("notification", NotificationSchema);

module.exports = { NotificationModel };
