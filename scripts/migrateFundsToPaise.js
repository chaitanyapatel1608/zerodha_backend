/**
 * Reversible Monetary Migration Script: String INR -> Integer Paise Shadow Ledger
 *
 * Modes:
 *   node scripts/migrateFundsToPaise.js            (dry-run, default, read-only)
 *   node scripts/migrateFundsToPaise.js --apply    (adds equityPaise & commodityPaise fields)
 *   node scripts/migrateFundsToPaise.js --rollback (removes equityPaise & commodityPaise fields)
 */
const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "..", ".env") });
const mongoose = require("mongoose");
const { toPaise } = require("../utils/money");

async function main() {
  const args = new Set(process.argv.slice(2));
  const isApply = args.has("--apply");
  const isRollback = args.has("--rollback");
  const mode = isRollback ? "ROLLBACK" : isApply ? "APPLY" : "DRY_RUN";

  if (!process.env.MONGO_URL) {
    console.error("MONGO_URL is required in environment.");
    process.exit(1);
  }

  await mongoose.connect(process.env.MONGO_URL);
  const collection = mongoose.connection.db.collection("funds");
  const docs = await collection.find({}).toArray();

  console.log(`[MIGRATION] Mode=${mode}, Documents=${docs.length}`);

  let modified = 0;
  for (const doc of docs) {
    if (isRollback) {
      if (doc.equityPaise !== undefined || doc.commodityPaise !== undefined) {
        await collection.updateOne(
          { _id: doc._id },
          { $unset: { equityPaise: "", commodityPaise: "", migratedPaiseAt: "" } }
        );
        modified += 1;
      }
      continue;
    }

    const eq = doc.equity || {};
    const cmd = doc.commodity || {};
    const equityPaise = {
      availableMargin: toPaise(eq.availableMargin || "0"),
      usedMargin: toPaise(eq.usedMargin || "0"),
      availableCash: toPaise(eq.availableCash || "0"),
      openingBalance: toPaise(eq.openingBalance || "0"),
      payin: toPaise(eq.payin || "0"),
      payout: toPaise(eq.payout || "0"),
      collateralEquity: toPaise(eq.collateralEquity || "0"),
      totalCollateral: toPaise(eq.totalCollateral || "0"),
    };
    const commodityPaise = {
      availableMargin: toPaise(cmd.availableMargin || "0"),
      usedMargin: toPaise(cmd.usedMargin || "0"),
      availableCash: toPaise(cmd.availableCash || "0"),
    };

    if (isApply) {
      await collection.updateOne(
        { _id: doc._id },
        { $set: { equityPaise, commodityPaise, migratedPaiseAt: new Date() } }
      );
      modified += 1;
    } else {
      console.log(
        `[DRY_RUN] userId=${doc.userId} avail=${eq.availableMargin} -> availableMarginPaise=${equityPaise.availableMargin}`
      );
    }
  }

  console.log(`[MIGRATION COMPLETE] Mode=${mode}, Updated=${modified}`);
  await mongoose.disconnect();
}

main().catch((err) => {
  console.error("[MIGRATION ERROR]", err);
  process.exit(1);
});
