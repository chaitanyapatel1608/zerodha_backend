const { SipModel } = require("../model/SipModel");
const { BasketModel } = require("../model/BasketModel");
const { NotificationModel } = require("../model/NotificationModel");
const { runInTransaction } = require("./transactions");
const { executionQuote, orderValuePaise } = require("./executionQuote");
const { toPaise } = require("./money");
const { nextSipDate, DAY } = require("./sipSchedule");

async function processInstallment(id, due, execute) {
  const filter = { _id: id, status: "ACTIVE", nextTriggerAt: due };
  const snapshot = await runInTransaction(async session => {
    const sip = await SipModel.findOne(filter).session(session);
    if (!sip) return null;
    if (!sip.installment) {
      const items = sip.instruments.length ? sip.instruments :
        (await BasketModel.findOne({ _id: sip.basketId, userId: sip.userId }).session(session))?.items || [];
      sip.installment = { legs: items.map(item => ({
        symbol: item.symbol || item.name, product: item.product || "CNC", mode: item.mode || "BUY",
        budget: item.budget ?? Number(item.price) * Number(item.qty), status: "WAITING", failures: 0
      })) };
      await sip.save({ session });
    }
    return sip.installment;
  });
  if (!snapshot) return { success: false, message: "Installment unavailable or already processed." };
  for (let i = 0; i < snapshot.legs.length; i++) {
    const key = "installment.legs." + i;
    const eligible = { ...filter, [key + ".status"]: "WAITING" };
    try {
      await runInTransaction(async session => {
        const sip = await SipModel.findOne(eligible).session(session);
        if (!sip) return;
        const leg = sip.installment.legs[i];
        const expired = Date.now() - +new Date(due) > DAY;
        if (!expired && leg.retryAt && new Date(leg.retryAt) > new Date()) return;
        const quote = expired ? null : await executionQuote(leg.symbol, session);
        const budget = toPaise(leg.budget);
        const units = quote ? Math.floor((budget - 2000) * 100 / Math.round(quote.price * 10000)) : 0;
        const validSize = Number.isSafeInteger(units) && units > 0 && units <= 10000 && orderValuePaise(units, quote?.price) !== null;
        const result = validSize && leg.mode === "BUY" ? await execute({
          name: leg.symbol, product: leg.product, mode: "BUY", qty: units, price: quote.price, userId: sip.userId
        }, session) : { success: false, message: expired ? "Catch-up window expired" : "No eligible purchase within budget" };
        leg.status = result.success ? "FILLED" : "SKIPPED";
        if (result.success) {
          leg.order = result.order._id;
          leg.debitPaise = orderValuePaise(units, quote.price) + 2000;
        } else leg.reason = result.message;
        sip.markModified("installment");
        await sip.save({ session });
      });
    } catch (error) {
      // A competing worker may already have committed this leg.
      await runInTransaction(async session => {
        const sip = await SipModel.findOne(eligible).session(session);
        if (!sip) return;
        const leg = sip.installment.legs[i];
        if (leg.retryAt && new Date(leg.retryAt) > new Date()) return;
        const delay = [1, 5, 15][leg.failures++];
        if (delay && Date.now() - +new Date(due) < DAY) leg.retryAt = new Date(Date.now() + delay * 60000);
        else { leg.status = "SKIPPED"; leg.reason = "Technical retries exhausted"; }
        sip.markModified("installment");
        await sip.save({ session });
      });
    }
  }
  return runInTransaction(async session => {
    const sip = await SipModel.findOne(filter).session(session);
    if (!sip) return { success: true, message: "Installment already processed." };
    const legs = sip.installment.legs;
    if (legs.some(leg => leg.status === "WAITING")) return { success: true, message: "Installment awaiting retry.", sip };
    const filled = legs.filter(leg => leg.status === "FILLED");
    const amount = filled.reduce((sum, leg) => sum + leg.debitPaise, 0) / 100;
    sip.executionLogs.push({ executedAt: new Date(), scheduledAt: due, legs, ordersCount: filled.length,
      amountDebited: amount, status: filled.length === legs.length && filled.length ? "SUCCESS" : filled.length ? "PARTIAL" : "SKIPPED" });
    sip.totalCapitalInvested += amount;
    sip.totalInstallmentsExecuted += filled.length ? 1 : 0;
    sip.lastExecutedAt = new Date();
    sip.nextTriggerAt = nextSipDate(sip.frequency, sip.scheduleDay, new Date(Math.max(Date.now(), +new Date(due))));
    sip.installment = undefined;
    await sip.save({ session });
    await new NotificationModel({ userId: sip.userId, type: "ORDER", category: "SIP", title: "SIP installment processed",
      description: filled.length + " of " + legs.length + " purchases completed." }).save({ session });
    return { success: true, sip, executedOrders: filled.map(leg => leg.order), message: "Installment processed." };
  });
}
module.exports = { processInstallment };
