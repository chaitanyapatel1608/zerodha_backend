const { runInTransaction } = require("./transactions");
const { PositionsModel } = require("../model/PositionsModel");
const { HoldingsModel } = require("../model/HoldingsModel");
const { FundsModel } = require("../model/FundsModel");
const { PledgedCollateralModel } = require("../model/PledgedCollateralModel");
const { NotificationModel } = require("../model/NotificationModel");
const { reservedShares } = require("./reservations");
const { toPaise, formatPaiseINR } = require("./money");

function reject(message, status = 400) { throw Object.assign(new Error(message), { conversionStatus: status }); }
async function convertPosition(userId, id, product, requestedUnits) {
  return runInTransaction(async session => {
    const source = await PositionsModel.findOne({ _id: id, userId, qty: { $ne: 0 }, status: "OPEN" }).session(session);
    if (!source) reject("Active open position required to convert.");
    const target = product || (source.product === "MIS" ? "CNC" : "MIS");
    const units = requestedUnits === undefined ? Math.abs(source.qty) : requestedUnits;
    if (!["CNC", "MIS", "NRML"].includes(target) || target === source.product ||
        !Number.isSafeInteger(units) || units < 1 || units > Math.abs(source.qty)) reject("Invalid conversion product or whole-unit quantity.");
    if (target === "CNC" && source.qty < 0) reject("Short positions cannot convert to delivery.");
    if (source.cashMarginPaise == null || source.collateralMarginPaise == null) reject("Position funding requires reconciliation.", 409);
    const symbol = source.name || source.instrument;
    const destination = await PositionsModel.findOne({ userId, name: symbol, product: target, qty: { $ne: 0 } }).session(session);
    if (destination && (destination.qty * source.qty < 0 || destination.cashMarginPaise == null)) reject("Destination position is opposite or requires reconciliation.", 409);
    const funds = await FundsModel.findOne({ userId }).session(session);
    if (!funds) reject("Account balance requires reconciliation.", 409);
    const equity = funds.equity;
    const cashReleased = Math.round(source.cashMarginPaise * units / Math.abs(source.qty));
    const collateralReleased = Math.round(source.collateralMarginPaise * units / Math.abs(source.qty));
    const required = Math.round(units * source.avg * (target === "MIS" ? 20 : 100));
    const freeCash = toPaise(equity.availableCash) + cashReleased;
    const freeMargin = toPaise(equity.availableMargin) + cashReleased + collateralReleased;
    if (freeMargin < required || (target === "CNC" && freeCash < required)) reject("Insufficient funds for product conversion.");
    const cashAllocated = Math.min(required, Math.max(0, freeCash));
    const collateralAllocated = required - cashAllocated;
    if (source.product === "CNC") {
      const holding = await HoldingsModel.findOne({ userId, name: symbol }).session(session);
      const pledges = await PledgedCollateralModel.find({ userId, symbol, status: "PLEDGED" }).session(session);
      const reserved = await reservedShares(userId, symbol, session) + pledges.reduce((sum, row) => sum + row.pledgedQty, 0);
      if (!holding || holding.qty - reserved < units || holding.avg !== source.avg) reject("Delivery units are reserved or require reconciliation.", 409);
      holding.qty -= units;
      if (!holding.qty) await holding.deleteOne({ session });
      else await holding.save({ session });
    }
    if (target === "CNC") {
      const holding = await HoldingsModel.findOne({ userId, name: symbol }).session(session)
        || new HoldingsModel({ userId, name: symbol, instrument: symbol, qty: 0, avg: 0 });
      holding.avg = (holding.qty * holding.avg + units * source.avg) / (holding.qty + units);
      holding.avgCost = holding.avg;
      holding.qty += units;
      holding.price = holding.ltp = source.ltp || source.price;
      await holding.save({ session });
    }
    const signed = Math.sign(source.qty) * units;
    const remaining = Math.abs(source.qty) - units;
    let converted;
    if (units === Math.abs(source.qty) && !destination) {
      source.product = target;
      source.cashMarginPaise = cashAllocated;
      source.collateralMarginPaise = collateralAllocated;
      converted = source;
    } else {
      converted = destination || new PositionsModel({ userId, name: symbol, instrument: symbol, product: target, qty: 0,
        avg: source.avg, cashMarginPaise: 0, collateralMarginPaise: 0, price: source.price, ltp: source.ltp });
      converted.avg = (Math.abs(converted.qty) * converted.avg + units * source.avg) / (Math.abs(converted.qty) + units);
      converted.qty += signed;
      converted.cashMarginPaise += cashAllocated;
      converted.collateralMarginPaise += collateralAllocated;
      source.qty -= signed;
      source.cashMarginPaise -= cashReleased;
      source.collateralMarginPaise -= collateralReleased;
      if (!source.qty) { source.status = "CLOSED"; source.closedAt = new Date(); }
      await source.save({ session });
    }
    converted.convertedAt = new Date();
    await converted.save({ session });
    equity.availableCash = formatPaiseINR(freeCash - cashAllocated);
    equity.availableMargin = formatPaiseINR(freeMargin - required);
    equity.usedMargin = formatPaiseINR(toPaise(equity.usedMargin) - cashReleased - collateralReleased + required);
    await require("./linkedExits").capLinkedExits(source._id, remaining, funds, session);
    await funds.save({ session });
    await new NotificationModel({ userId, type: "ORDER", category: "TRADE", title: "Position converted: " + symbol,
      description: `${units} units converted to ${target} at their existing cost basis without an execution fee.` }).save({ session });
    return converted;
  });
}
module.exports = { convertPosition };
