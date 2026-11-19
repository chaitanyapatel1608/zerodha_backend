const { ReservationModel } = require("../model/ReservationModel");
const { FundsModel } = require("../model/FundsModel");
const { HoldingsModel } = require("../model/HoldingsModel");
const { PositionsModel } = require("../model/PositionsModel");
const { PledgedCollateralModel } = require("../model/PledgedCollateralModel");
const { runInTransaction } = require("./transactions");
const { executionQuote, orderValuePaise } = require("./executionQuote");
const { toPaise, formatPaiseINR } = require("./money");

async function reservedShares(userId, name, session) {
  const rows = await ReservationModel.find({ userId, name, status: "PENDING" }).select("shares").session(session);
  return rows.reduce((sum, row) => sum + row.shares, 0);
}
function balanceChange(funds, cash, collateral) {
  funds.equity.availableCash = formatPaiseINR(toPaise(funds.equity.availableCash) + cash);
  funds.equity.availableMargin = formatPaiseINR(toPaise(funds.equity.availableMargin) + cash + collateral);
}
async function place(input, execute) {
  return runInTransaction(async session => {
    const { userId, name, qty, price, mode, product } = input;
    const value = orderValuePaise(qty, price);
    if (!Number.isSafeInteger(qty) || qty < 1 || qty > 10000 || !(price > 0) || value == null ||
        !["BUY","SELL"].includes(mode) || !["CNC","MIS","NRML"].includes(product)) {
      return { success: false, message: "Invalid limit order." };
    }
    const quote = await executionQuote(name, session);
    if (!quote) return { success: false, message: "Quote unavailable." };
    if (mode === "BUY" ? quote.price <= price : quote.price >= price) return execute(input, session);
    const funds = await FundsModel.findOne({ userId }).session(session);
    if (!funds) return { success: false, message: "Fund the account first." };
    let shares = 0;
    let required = value * (product === "MIS" ? 0.2 : 1);
    if (product === "CNC" && mode === "SELL") {
      const holding = await HoldingsModel.findOne({ userId, name }).session(session);
      const pledges = await PledgedCollateralModel.find({ userId, symbol: name, status: "PLEDGED" }).session(session);
      const unavailable = pledges.reduce((sum, p) => sum + p.pledgedQty, 0) + await reservedShares(userId, name, session);
      if (!holding || holding.qty - unavailable < qty) return { success: false, message: "Insufficient unreserved holdings." };
      shares = qty;
      required = 0;
    } else if (product !== "CNC") {
      const position = await PositionsModel.findOne({ userId, name, product, qty: { $ne: 0 } }).session(session);
      if (position && position.qty * (mode === "BUY" ? 1 : -1) < 0) {
        return { success: false, message: "Pending position reductions require position reservation support." };
      }
    }
    required = Math.round(required);
    const cash = toPaise(funds.equity.availableCash);
    const available = toPaise(funds.equity.availableMargin);
    if (cash < 2000 || available < required + 2000 || (product === "CNC" && cash < required + 2000)) {
      return { success: false, code: "INSUFFICIENT_MARGIN", message: "Insufficient funds to reserve this order." };
    }
    const cashPaise = 2000 + Math.min(cash - 2000, required);
    const collateralPaise = required + 2000 - cashPaise;
    balanceChange(funds, -cashPaise, -collateralPaise);
    await funds.save({ session });
    const reservation = new ReservationModel({ ...input, cashPaise, collateralPaise, shares });
    await reservation.save({ session });
    return { success: true, order: reservation, funds: funds.equity };
  });
}
async function cancel(id, userId) {
  return runInTransaction(async session => {
    const reservation = await ReservationModel.findOne({ _id: id, userId, status: "PENDING" }).session(session);
    if (!reservation) return false;
    const funds = await FundsModel.findOne({ userId }).session(session);
    balanceChange(funds, reservation.cashPaise, reservation.collateralPaise);
    reservation.status = "CANCELLED";
    await funds.save({ session });
    await reservation.save({ session });
    return true;
  });
}
async function evaluatePending(execute, session) {
  const rows = await ReservationModel.find({ status: "PENDING" }).sort({ createdAt: 1, _id: 1 }).session(session);
  for (const row of rows) {
    const quote = await executionQuote(row.name, session);
    if (!quote || (row.mode === "BUY" ? quote.price > row.price : quote.price < row.price)) continue;
    const funds = await FundsModel.findOne({ userId: row.userId }).session(session);
    balanceChange(funds, row.cashPaise, row.collateralPaise);
    await funds.save({ session });
    row.status = "FILLED";
    await row.save({ session });
    const result = await execute({ userId: row.userId, name: row.name, qty: row.qty, price: row.price,
      mode: row.mode, product: row.product }, session);
    if (result.success) row.order = result.order._id;
    else {
      row.status = "PENDING";
      row.reason = result.message;
      balanceChange(funds, -row.cashPaise, -row.collateralPaise);
      await funds.save({ session });
    }
    await row.save({ session });
  }
}
module.exports = { place, cancel, reservedShares, evaluatePending };
