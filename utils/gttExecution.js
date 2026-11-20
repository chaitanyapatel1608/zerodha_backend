const { GttModel } = require("../model/GttModel");
const { runInTransaction } = require("./transactions");
const { executionQuote } = require("./executionQuote");
const reservations = require("./reservations");
const { ReservationModel } = require("../model/ReservationModel");

function branches(gtt) {
  const buy = gtt.transactionType === "BUY";
  if (gtt.type === "SINGLE") return [{
    key: "single", trigger: gtt.triggerPrice, limit: gtt.orderPrice,
    above: gtt.triggerDirection ? gtt.triggerDirection === "ABOVE" : !buy,
  }];
  return [
    { key: "stop", trigger: gtt.stoplossTrigger, limit: gtt.stoplossPrice, above: buy },
    { key: "target", trigger: gtt.targetTrigger, limit: gtt.targetPrice, above: !buy },
  ];
}

async function evaluate(id, userId, execute, existingSession = null) {
  const apply = async session => {
    const gtt = await GttModel.findOne({ _id: id, userId, status: "ACTIVE" }).session(session);
    if (!gtt) return { status: 404, message: "Active instruction unavailable." };
    const quote = await executionQuote(gtt.symbol, session);
    if (!quote) return { status: 409, message: "Server quote unavailable.", gtt };
    const latched = new Set(gtt.activatedBranches || []);
    for (const branch of branches(gtt)) {
      if (!(branch.trigger > 0 && branch.limit > 0)) continue;
      if (branch.above ? quote.price >= branch.trigger : quote.price <= branch.trigger) latched.add(branch.key);
    }
    const eligible = branches(gtt).find(b => latched.has(b.key) &&
      (gtt.transactionType === "BUY" ? quote.price <= b.limit : quote.price >= b.limit));
    let reserved = gtt.reservation ? await ReservationModel.findOne({ _id: gtt.reservation, status: "PENDING" }).session(session) : null;
    if (latched.size && !reserved) {
      // One worst-case reservation supports both OCO siblings until either fills.
      const result = await reservations.place({ userId, name: gtt.symbol, qty: gtt.qty,
        mode: gtt.transactionType, product: gtt.product, parentGtt: gtt._id,
        price: Math.max(...branches(gtt).map(branch => branch.limit)) }, execute, session, { reserveOnly: true });
      if (!result.success) {
        gtt.lastReason = result.message;
        gtt.activatedBranches = [];
        await gtt.save({ session });
        return { status: 200, gtt, message: result.message };
      }
      reserved = result.order;
      gtt.reservation = reserved._id;
    }
    if (eligible) {
      const result = await reservations.executeReserved(reserved, execute, session);
      if (result.success) {
        gtt.status = "TRIGGERED";
        gtt.triggeredAt = new Date();
        gtt.executedOrder = result.order._id;
        gtt.executedBranch = eligible.key;
        gtt.lastReason = undefined;
      } else {
        gtt.lastReason = result.message;
      }
    }
    gtt.activatedBranches = [...latched];
    await gtt.save({ session });
    return { status: 200, gtt, order: gtt.executedOrder, message: gtt.lastReason || gtt.status };
  };
  return existingSession ? apply(existingSession) : runInTransaction(apply);
}

async function cancel(id, userId) {
  return runInTransaction(async session => {
    const instruction = await GttModel.findOne({ _id: id, userId, status: "ACTIVE" }).session(session);
    if (!instruction) return null;
    if (instruction.reservation) await reservations.cancel(instruction.reservation, userId, session, true);
    instruction.status = "CANCELLED";
    await instruction.save({ session });
    return instruction;
  });
}

async function evaluateActive(execute, session) {
  const cursor = GttModel.find({ status: "ACTIVE" }).sort({ createdAt: 1, _id: 1 }).select("_id userId").session(session).lean().cursor();
  for await (const instruction of cursor) await evaluate(instruction._id, instruction.userId, execute, session);
}

module.exports = { evaluate, evaluateActive, cancel };
