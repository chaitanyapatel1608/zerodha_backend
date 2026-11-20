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
async function place(input, execute, existingSession = null, { reserveOnly = false } = {}) {
  const apply = async session => {
    const { userId, name, qty, price, mode, product } = input;
    const value = orderValuePaise(qty, price);
    if (typeof name !== "string" || !name.trim() || !Number.isFinite(price) || !Number.isSafeInteger(qty) || qty < 1 || qty > 10000 || !(price > 0) || value == null || value <= 0 ||
        !["BUY","SELL"].includes(mode) || !["CNC","MIS","NRML"].includes(product)) {
      return { success: false, message: "Invalid limit order." };
    }
    const quote = await executionQuote(name, session);
    if (!quote) return { success: false, message: "Quote unavailable." };
    if (!reserveOnly && (mode === "BUY" ? quote.price <= price : quote.price >= price)) return execute(input, session);
    const funds = await FundsModel.findOne({ userId }).session(session);
    if (!funds) return { success: false, message: "Fund the account first." };
    let shares = 0;
    let linkedPosition;
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
        if (qty > Math.abs(position.qty)) return { success: false, message: "Separate a pending reversal into a reduction and a new entry." };
        linkedPosition = position._id;
        required = 0;
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
    const reservation = new ReservationModel({ ...input, cashPaise, collateralPaise, shares, linkedPosition });
    await reservation.save({ session });
    return { success: true, order: reservation, funds: funds.equity };
  };
  return existingSession ? apply(existingSession) : runInTransaction(apply);
}
async function cancel(id, userId, existingSession = null, allowManaged = false) {
  const apply = async session => {
    const reservation = await ReservationModel.findOne({ _id: id, userId, status: "PENDING", ...(allowManaged ? {} : { parentGtt: null }) }).session(session);
    if (!reservation) return false;
    const funds = await FundsModel.findOne({ userId }).session(session);
    balanceChange(funds, reservation.cashPaise, reservation.collateralPaise);
    reservation.status = "CANCELLED";
    await funds.save({ session });
    await reservation.save({ session });
    return true;
  };
  return existingSession ? apply(existingSession) : runInTransaction(apply);
}
class EditRejected extends Error {
  constructor(result) { super(result.message); this.result = result; }
}
async function edit(id, userId, changes, execute) {
  try {
    return await runInTransaction(async session => {
      const previous = await ReservationModel.findOne({ _id: id, userId, status: "PENDING", parentGtt: null }).session(session);
      if (!previous) return { success: false, message: "Pending order unavailable." };
      await cancel(id, userId, session);
      const result = await place({ userId, name: previous.name, mode: previous.mode, product: previous.product,
        qty: changes.qty === undefined ? previous.qty : changes.qty,
        price: changes.price === undefined ? previous.price : changes.price }, execute, session);
      // Aborting restores both the original reservation and its original priority.
      if (!result.success) throw new EditRejected(result);
      previous.status = "CANCELLED";
      previous.reason = `Replaced by ${result.order._id}`;
      await previous.save({ session });
      return result;
    });
  } catch (error) {
    if (error instanceof EditRejected) return error.result;
    throw error;
  }
}
async function executeReserved(row, execute, session) {
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
    return result;
}
async function evaluatePending(execute, session, filter = {}) {
  const rows = await ReservationModel.find({ ...filter, status: "PENDING", parentGtt: null }).sort({ createdAt: 1, _id: 1 }).session(session);
  for (const row of rows) {
    const quote = await executionQuote(row.name, session);
    if (!quote || (row.mode === "BUY" ? quote.price > row.price : quote.price < row.price)) continue;
    await executeReserved(row, execute, session);
  }
}
module.exports = { place, cancel, edit, reservedShares, evaluatePending, executeReserved };
