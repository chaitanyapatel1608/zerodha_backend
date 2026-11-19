const { InstrumentModel } = require("../model/InstrumentModel");

// Read the same persisted catalog used by the instrument search and quote screens.
async function executionQuote(symbol, session = null) {
  const record = await InstrumentModel.findOne({ symbol }).select("symbol price quoteVersion updatedAt").session(session).lean();
  if (!record || !Number.isFinite(record.price) || record.price <= 0) return null;
  return { price: record.price, version: record.quoteVersion || record.updatedAt?.toISOString() || "initial" };
}

// Catalog prices support four decimal places. Round the extended amount once.
function orderValuePaise(quantity, price) {
  const scaled = Math.round(price * 10000);
  const extended = scaled * quantity;
  if (!Number.isSafeInteger(extended) || extended > 1000000 * 10000) return null;
  return Math.floor((extended + 50) / 100);
}

module.exports = { executionQuote, orderValuePaise };
