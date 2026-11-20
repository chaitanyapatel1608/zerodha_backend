const { ReservationModel } = require("../model/ReservationModel");
const { GttModel } = require("../model/GttModel");
const { toPaise, formatPaiseINR } = require("./money");

// Called inside the position mutation transaction with its current funds document.
async function capLinkedExits(positionId, remaining, funds, session) {
  const reservations = await ReservationModel.find({ linkedPosition: positionId, status: "PENDING" }).session(session);
  for (const row of reservations) {
    if (!remaining) {
      funds.equity.availableCash = formatPaiseINR(toPaise(funds.equity.availableCash) + row.cashPaise);
      funds.equity.availableMargin = formatPaiseINR(toPaise(funds.equity.availableMargin) + row.cashPaise + row.collateralPaise);
      row.status = "CANCELLED";
      row.reason = "Source position closed or converted.";
    } else row.qty = Math.min(row.qty, remaining);
    await row.save({ session });
  }
  const triggers = await GttModel.find({ linkedPosition: positionId, status: "ACTIVE" }).session(session);
  for (const row of triggers) {
    if (!remaining) row.status = "CANCELLED";
    else row.qty = Math.min(row.qty, remaining);
    await row.save({ session });
  }
}
module.exports = { capLinkedExits };
