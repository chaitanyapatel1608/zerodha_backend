const { model } = require("mongoose");
const { SseIpoSchema } = require("../schemas/SseIpoSchema");

const SseIpoModel = model("sse_ipo", SseIpoSchema);

module.exports = { SseIpoModel };
