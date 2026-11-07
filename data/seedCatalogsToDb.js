const { InstrumentModel } = require("../model/InstrumentModel");
const { MarketSipCatalogModel } = require("../model/MarketSipCatalogModel");
const { masterInstruments } = require("./masterInstruments");
const { marketSips50 } = require("./marketSips50");

async function seedCatalogsToDb() {
  try {
    console.log("🌱 [DB SEEDER] Checking Master Instruments & 50 Market SIPs in MongoDB Atlas...");

    // 1. Seed / Upsert Master Instruments (Stocks & ETFs)
    const instrumentCount = await InstrumentModel.countDocuments();
    if (instrumentCount < masterInstruments.length) {
      console.log(`📥 Seeding ${masterInstruments.length} Master Instruments to MongoDB Atlas...`);
      for (const item of masterInstruments) {
        await InstrumentModel.findOneAndUpdate(
          { symbol: item.symbol },
          { $set: item },
          { upsert: true, new: true }
        );
      }
      const updatedCount = await InstrumentModel.countDocuments();
      console.log(`✅ [DB SEEDER] Master Instruments in MongoDB Atlas: ${updatedCount} stocks/ETFs.`);
    } else {
      console.log(`✅ [DB SEEDER] Master Instruments already seeded in MongoDB Atlas (${instrumentCount} stocks).`);
    }

    // 2. Seed / Upsert 50 Market SIPs Catalog
    const sipCatalogCount = await MarketSipCatalogModel.countDocuments();
    if (sipCatalogCount < marketSips50.length) {
      console.log(`📥 Seeding ${marketSips50.length} Market SIPs to MongoDB Atlas...`);
      for (const sip of marketSips50) {
        await MarketSipCatalogModel.findOneAndUpdate(
          { code: sip.code },
          { $set: sip },
          { upsert: true, new: true }
        );
      }
      const updatedSipCount = await MarketSipCatalogModel.countDocuments();
      console.log(`✅ [DB SEEDER] Market SIPs in MongoDB Atlas: ${updatedSipCount} strategies.`);
    } else {
      console.log(`✅ [DB SEEDER] Market SIPs already seeded in MongoDB Atlas (${sipCatalogCount} strategies).`);
    }
  } catch (err) {
    console.error("❌ [DB SEEDER ERROR]", err.message);
  }
}

module.exports = { seedCatalogsToDb };
