const { PositionsModel } = require("../model/PositionsModel");
const { toPaise, formatPaiseINR } = require("./money");

async function tradePosition({ userId, name, product, side, units, price, funds, session }) {
  const position = await PositionsModel.findOne({ userId, name, product, qty: { $ne: 0 } }).session(session)
    || new PositionsModel({ userId, name, instrument: name, product });
  const old = position.qty;
  const signed = side === "BUY" ? units : -units;
  const closing = old * signed < 0 ? Math.min(Math.abs(old), units) : 0;
  const opening = units - closing;
  const equity = funds.equity;
  const available = toPaise(equity.availableMargin);
  const cash = toPaise(equity.availableCash);
  const used = toPaise(equity.usedMargin);
  if (old && position.cashMarginPaise == null) {
    return { success: false, code: "RECONCILIATION_REQUIRED", message: "Position funding requires reconciliation." };
  }
  const priorCash = position.cashMarginPaise || 0;
  const priorCollateral = position.collateralMarginPaise || 0;
  const release = amount => closing ? Math.round(amount * closing / Math.abs(old)) : 0;
  const cashReleased = release(priorCash);
  const collateralReleased = release(priorCollateral);
  const pnl = Math.round((price - position.avg) * closing * Math.sign(old) * 100);
  const margin = Math.round(opening * price * (product === "MIS" ? 20 : 100));
  const fee = 2000;
  if (cash < fee || (opening && available + cashReleased + collateralReleased + pnl - fee < margin)) {
    return { success: false, code: "INSUFFICIENT_MARGIN", message: "Insufficient cash for fees or buying power for margin." };
  }
  const cashAllocated = Math.min(margin, Math.max(0, cash + cashReleased + pnl - fee));
  const net = old + signed;
  if (opening) {
    position.avg = closing || !old ? price : (position.avg * Math.abs(old) + price * opening) / Math.abs(net);
  }
  position.cashMarginPaise = priorCash - cashReleased + cashAllocated;
  position.collateralMarginPaise = priorCollateral - collateralReleased + margin - cashAllocated;
  position.qty = net;
  position.price = position.ltp = price;
  position.realizedPnl = (toPaise(position.realizedPnl) + pnl) / 100;
  position.status = net ? "OPEN" : "CLOSED";
  position.closedAt = net ? null : new Date();
  equity.availableCash = formatPaiseINR(cash + cashReleased + pnl - fee - cashAllocated);
  equity.availableMargin = formatPaiseINR(available + cashReleased + collateralReleased + pnl - fee - margin);
  equity.usedMargin = formatPaiseINR(used - cashReleased - collateralReleased + margin);
  await position.save({ session });
  await funds.save({ session });
  return { success: true };
}
module.exports = { tradePosition };
