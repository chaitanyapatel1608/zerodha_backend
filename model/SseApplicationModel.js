const { model } = require("mongoose");
const { SseApplicationSchema } = require("../schemas/SseApplicationSchema");

const SseApplicationModel = model("sse_application", SseApplicationSchema);

module.exports = { SseApplicationModel };
