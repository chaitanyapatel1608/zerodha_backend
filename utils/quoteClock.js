const { NotificationModel } = require("../model/NotificationModel");
const mongoose = require("mongoose");
const { InstrumentModel } = require("../model/InstrumentModel");
const { PledgedCollateralModel } = require("../model/PledgedCollateralModel");
const { FundsModel } = require("../model/FundsModel");
const { toPaise, formatPaiseINR } = require("./money");
const { runInTransaction } = require("./transactions");

const PERIOD = 10000;
const OFFSETS = [0, 1, 2, 1, 0, -1, -2, -1];
const clockId = "demo-v1";

async function revaluePledges(prices, session) {
  const byAccount = new Map();
  const pledges = await PledgedCollateralModel.find({ status: "PLEDGED", symbol: { $in: [...prices.keys()] } }).session(session);
  for (const pledge of pledges) {
    if (!byAccount.has(pledge.userId)) byAccount.set(pledge.userId, []);
    byAccount.get(pledge.userId).push(pledge);
  }
  for (const [userId, accountPledges] of byAccount) {
    const funds = await FundsModel.findOne({ userId }).session(session);
    if (!funds) {
      await mongoose.connection.db.collection("portfolio_reconciliation").updateOne(
        { _id: "missing-pledge-funds:" + userId },
        { $setOnInsert: { userId, reason: "ACTIVE_PLEDGE_WITHOUT_FUNDS", detectedAt: new Date() } },
        { upsert: true, session });
      continue;
    }
    let delta = 0;
    for (const pledge of accountPledges) {
      const price = prices.get(pledge.symbol);
      const value = Math.round(pledge.pledgedQty * price * (100 - pledge.haircutPercent));
      delta += value - toPaise(pledge.collateralValue);
      pledge.marketPrice = price;
      pledge.collateralValue = value / 100;
      await pledge.save({ session });
    }
    if (!delta) continue;
    const previous = toPaise(funds.equity.availableMargin);
    for (const field of ["collateralEquity", "totalCollateral", "availableMargin"]) {
      funds.equity[field] = formatPaiseINR(toPaise(funds.equity[field]) + delta);
    }
    await funds.save({ session });
    if (previous >= 0 && previous + delta < 0) {
      await new NotificationModel({ userId, type: "FUNDS", category: "MARGIN_SHORTFALL",
        title: "Collateral margin shortfall", description: "Your pledged collateral fell in value. Add demo funds or reduce exposure." }).save({ session });
    }
  }
}

async function advanceQuoteClock(now = new Date(), evaluateInstructions) {
  const clocks = mongoose.connection.db.collection("demo_quote_clocks");
  // Initialize outside the transaction so competing workers share the same clock.
  try {
    await clocks.updateOne({ _id: clockId }, { $setOnInsert: { step: 0, nextAt: now } }, { upsert: true });
  } catch (err) { if (err.code !== 11000) throw err; }
  return runInTransaction(async session => {
    const clock = await clocks.findOneAndUpdate({ _id: clockId, nextAt: { $lte: now } },
      { $inc: { step: 1 }, $set: { nextAt: new Date(now.getTime() + PERIOD) } },
      { session, returnDocument: "after", includeResultMetadata: false });
    if (!clock) return false;
    const instruments = await InstrumentModel.find({}).session(session).lean();
    const prices = new Map();
    const updates = instruments.map(item => {
      const base = item.sequenceBase ?? item.price;
      const tick = item.tickSize ?? (/currency/i.test(item.sector) || item.exchange === "CDS" ? 0.0001 : 0.01);
      if (!(base > 0) || !(tick > 0)) throw new Error("Invalid catalog quote settings");
      const ticks = Math.max(1, Math.round(base / tick) + OFFSETS[clock.step % OFFSETS.length]);
      const price = Number((ticks * tick).toFixed(4));
      const change = Number((price - base).toFixed(4));
      prices.set(item.symbol, price);
      return { updateOne: { filter: { _id: item._id }, update: { $set: {
        sequenceBase: base, price, change, percent: (100 * change / base).toFixed(2) + "%",
        isDown: change < 0, quoteVersion: clockId + ":" + clock.step
      } } } };
    });
    if (!updates.length) throw new Error("Quote catalog is empty");
    await InstrumentModel.bulkWrite(updates, { session });
    await revaluePledges(prices, session);
    if (evaluateInstructions) await evaluateInstructions(session);
    return true;
  });
}

module.exports = { advanceQuoteClock, PERIOD };
