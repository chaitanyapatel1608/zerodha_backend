require("dotenv").config();
const mongoose = require("mongoose");

if (process.env.NODE_ENV === "production") {
  console.error("FATAL: Seed scripts are strictly prohibited in production.");
  process.exit(1);
}
if (!process.argv.includes("--confirm-seed") && process.env.ALLOW_DESTRUCTIVE_SEED !== "true") {
  console.error("ABORTED: Pass --confirm-seed or ALLOW_DESTRUCTIVE_SEED=true to run seed_extensions.js in non-production.");
  process.exit(1);
}
const { WatchlistModel } = require("./model/WatchlistModel");
const { FundsModel } = require("./model/FundsModel");
const { HoldingsModel } = require("./model/HoldingsModel");
const { PositionsModel } = require("./model/PositionsModel");

const initialWatchlist = [
  { symbol: "INFY", name: "Infosys Ltd.", exchange: "NSE", price: 1845.50, change: -18.25, percent: "-0.98%", isDown: true },
  { symbol: "RELIANCE", name: "Reliance Industries", exchange: "NSE", price: 2712.40, change: 24.30, percent: "+0.90%", isDown: false },
  { symbol: "HDFCBANK", name: "HDFC Bank Ltd.", exchange: "NSE", price: 1728.15, change: -6.40, percent: "-0.37%", isDown: true },
  { symbol: "TCS", name: "Tata Consultancy Services", exchange: "NSE", price: 3982.75, change: 15.60, percent: "+0.39%", isDown: false },
  { symbol: "TATAMOTORS", name: "Tata Motors Ltd.", exchange: "NSE", price: 884.20, change: -12.10, percent: "-1.35%", isDown: true },
  { symbol: "ICICIBANK", name: "ICICI Bank Ltd.", exchange: "NSE", price: 1242.00, change: 11.80, percent: "+0.96%", isDown: false },
  { symbol: "SBIN", name: "State Bank of India", exchange: "NSE", price: 814.65, change: -4.50, percent: "-0.55%", isDown: true },
  { symbol: "BHARTIARTL", name: "Bharti Airtel Ltd.", exchange: "NSE", price: 1684.90, change: 22.40, percent: "+1.35%", isDown: false },
  { symbol: "ITC", name: "ITC Ltd.", exchange: "NSE", price: 478.30, change: 1.15, percent: "+0.24%", isDown: false },
  { symbol: "WIPRO", name: "Wipro Ltd.", exchange: "NSE", price: 546.80, change: -5.20, percent: "-0.94%", isDown: true },
  { symbol: "LT", name: "Larsen & Toubro Ltd.", exchange: "NSE", price: 3560.10, change: -28.75, percent: "-0.80%", isDown: true },
  { symbol: "HINDUNILVR", name: "Hindustan Unilever Ltd.", exchange: "NSE", price: 2382.40, change: 8.90, percent: "+0.38%", isDown: false },
  { symbol: "BAJFINANCE", name: "Bajaj Finance Ltd.", exchange: "NSE", price: 6890.00, change: -45.50, percent: "-0.66%", isDown: true },
  { symbol: "MARUTI", name: "Maruti Suzuki India", exchange: "NSE", price: 11240.50, change: 85.00, percent: "+0.76%", isDown: false },
  { symbol: "SUNPHARMA", name: "Sun Pharmaceutical", exchange: "NSE", price: 1782.30, change: 14.20, percent: "+0.80%", isDown: false },
];

const initialFunds = {
  userId: "ZU8842",
  equity: {
    availableMargin: "1,24,500.00",
    usedMargin: "42,180.00",
    availableCash: "1,24,500.00",
    openingBalance: "1,66,680.00",
    payin: "0.00",
    span: "28,450.00",
    deliveryMargin: "0.00",
    exposure: "13,730.00",
    optionsPremium: "0.00",
    collateralLiquid: "0.00",
    collateralEquity: "0.00",
    totalCollateral: "0.00",
  },
  commodity: {
    availableMargin: "55,000.00",
    usedMargin: "0.00",
    availableCash: "55,000.00",
    openingBalance: "55,000.00",
    payin: "0.00",
    span: "0.00",
    deliveryMargin: "0.00",
    exposure: "0.00",
    optionsPremium: "0.00",
  },
};

async function seedExtensions() {
  try {
    console.log("Connecting to MongoDB Atlas...");
    await mongoose.connect(process.env.MONGO_URL, { serverSelectionTimeoutMS: 8000 });
    console.log("Connected successfully!");

    // Verify existing holdings and positions count (ensure no duplicates)
    const holdingsCount = await HoldingsModel.countDocuments();
    const positionsCount = await PositionsModel.countDocuments();
    console.log(`Current Holdings in DB: ${holdingsCount} (Preserved - NO duplicates pushed)`);
    console.log(`Current Positions in DB: ${positionsCount} (Preserved - NO duplicates pushed)`);

    // 1. Seed Watchlist idempotently
    const existingWatchlistCount = await WatchlistModel.countDocuments();
    if (existingWatchlistCount === 0) {
      console.log("Seeding Watchlist collection...");
      for (const item of initialWatchlist) {
        await WatchlistModel.updateOne(
          { symbol: item.symbol },
          { $setOnInsert: item },
          { upsert: true }
        );
      }
      console.log(`Seeded ${initialWatchlist.length} watchlist stocks without duplicates!`);
    } else {
      console.log(`Watchlist already contains ${existingWatchlistCount} records. Skipping to prevent duplicates.`);
    }

    // 2. Seed Funds idempotently
    const existingFunds = await FundsModel.findOne({ userId: "ZU8842" });
    if (!existingFunds) {
      console.log("Seeding User Funds collection...");
      await FundsModel.create(initialFunds);
      console.log("Seeded user funds record for ZU8842!");
    } else {
      console.log("Funds record already exists for ZU8842. Skipping to prevent duplicates.");
    }

    console.log("\nDatabase extension verification complete with zero duplicates!");
    process.exit(0);
  } catch (error) {
    console.error("Seeding error:", error);
    process.exit(1);
  }
}

seedExtensions();
