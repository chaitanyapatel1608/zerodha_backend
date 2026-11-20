const { ReservationModel } = require("../model/ReservationModel");
const { GttModel } = require("../model/GttModel");
const reservations = require("./reservations");
const gtt = require("./gttExecution");

// One quote publication evaluates both instruction kinds in a common priority order.
// Keep reads sequential: MongoDB sessions do not support parallel operations.
async function evaluateInstructions(execute, session) {
  const limits = await ReservationModel.find({ status: "PENDING", parentGtt: null }).select("_id createdAt userId").session(session).lean();
  const triggers = await GttModel.find({ status: "ACTIVE" }).select("_id createdAt userId").session(session).lean();
  const instructions = [...limits.map(row => ({ ...row, kind: "limit" })), ...triggers.map(row => ({ ...row, kind: "gtt" }))];
  instructions.sort((a, b) => (+a.createdAt || 0) - (+b.createdAt || 0) || String(a._id).localeCompare(String(b._id)));
  for (const row of instructions) {
    if (row.kind === "limit") await reservations.evaluatePending(execute, session, { _id: row._id });
    else await gtt.evaluate(row._id, row.userId, execute, session);
  }
}

module.exports = { evaluateInstructions };
