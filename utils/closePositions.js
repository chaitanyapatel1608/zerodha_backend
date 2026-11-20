const { runInTransaction } = require("./transactions");
const { executionQuote } = require("./executionQuote");
const { toPaise, fromPaise, formatPaiseINR } = require("./money");
const { PositionsModel } = require("../model/PositionsModel");
const { FundsModel } = require("../model/FundsModel");
const { OrdersModel } = require("../model/OrdersModel");
const { HoldingsModel } = require("../model/HoldingsModel");
const { PledgedCollateralModel } = require("../model/PledgedCollateralModel");
const { NotificationModel } = require("../model/NotificationModel");

function reject(status, message) {
  throw Object.assign(new Error(message), { closeStatus: status });
}

async function closePositions(filter, { bulk = false, admin = false, audit } = {}) {
  return runInTransaction(async session => {
    const positions = await PositionsModel.find({ ...filter, status: { $ne: "CLOSED" }, qty: { $ne: 0 } }).session(session);
    if (!positions.length) reject(admin ? 404 : 400, "No open position found.");
    const userId = positions[0].userId;
    const funds = await FundsModel.findOne({ userId }).session(session);
    if (!funds) reject(409, "Account balance requires reconciliation.");
    const equity = funds.equity;
    const fee = 2000;
    if (toPaise(equity.availableCash) < fee * positions.length) reject(400, "Insufficient free cash for exit fees.");
    let total = 0;
    for (const position of positions) {
      const { qty, avg, product } = position;
      const symbol = position.instrument || position.name;
      const quote = await executionQuote(symbol, session);
      if (!quote) reject(409, "Server quote unavailable.");
      const tracked = position.cashMarginPaise != null;
      const margin = tracked ? position.cashMarginPaise + position.collateralMarginPaise : Math.round(Math.abs(qty) * avg * (product === "MIS" ? 20 : 100));
      // Historical shorts and collateral-backed rows lack per-position funding provenance.
      if (!Number.isSafeInteger(qty) || !(avg > 0) || (!tracked && (qty < 0 || toPaise(equity.totalCollateral) !== 0)) || margin > toPaise(equity.usedMargin)) {
        reject(409, "Position funding requires reconciliation before closing.");
      }
      if (product === "CNC") {
        const holdings = await HoldingsModel.find({ userId, $or: [{ name: symbol }, { instrument: symbol }] }).session(session);
        const pledged = await PledgedCollateralModel.exists({ userId, symbol, status: "PLEDGED" }).session(session);
        if (holdings.length !== 1 || holdings[0].qty !== qty || holdings[0].avg !== avg || pledged) {
          reject(409, "Converted holding requires reconciliation before closing.");
        }
        await holdings[0].deleteOne({ session });
      }
      const pnl = Math.round((quote.price - avg) * qty * 100);
      total += pnl;
      const credit = margin + pnl - fee;
      equity.availableMargin = formatPaiseINR(toPaise(equity.availableMargin) + credit);
      equity.availableCash = formatPaiseINR(toPaise(equity.availableCash) + credit - (position.collateralMarginPaise || 0));
      equity.usedMargin = formatPaiseINR(toPaise(equity.usedMargin) - margin);
      await new OrdersModel({ userId, name: symbol, qty: Math.abs(qty), price: quote.price,
        quoteVersion: quote.version, mode: qty > 0 ? "SELL" : "BUY", product, status: "COMPLETE",
        executionFee: fromPaise(fee) }).save({ session });
      position.cashMarginPaise = position.collateralMarginPaise = 0;
      position.realizedPnl = fromPaise(toPaise(position.realizedPnl) + pnl);
      Object.assign(position, { pnl: position.realizedPnl, unrealizedPnl: 0, qty: 0, ltp: quote.price,
        status: "CLOSED", closedAt: new Date(), isProfit: position.realizedPnl >= 0, isLoss: position.realizedPnl < 0 });
      await position.save({ session });
      await require("./linkedExits").capLinkedExits(position._id, 0, funds, session);
      await new NotificationModel({ userId, type: admin ? "COMPLIANCE" : "ORDER",
        category: admin ? "RMS_SQUARE_OFF" : "TRADE", title: "Position closed: " + symbol,
        description: "Closed " + Math.abs(qty) + " units at " + quote.price + ". Execution fee: INR 20." }).save({ session });
      if (audit) await audit(position, Math.abs(qty), quote.price, session);
    }
    await funds.save({ session });
    return bulk ? { count: positions.length, totalRealized: fromPaise(total), positions }
      : { position: positions[0], realizedPnl: fromPaise(total) };
  });
}

module.exports = { closePositions };
