require("dotenv").config();
const mongoose = require("mongoose");

if (process.env.NODE_ENV === "production") {
  console.error("FATAL: Seed scripts are strictly prohibited in production.");
  process.exit(1);
}
if (!process.argv.includes("--confirm-seed") && process.env.ALLOW_DESTRUCTIVE_SEED !== "true") {
  console.error("ABORTED: Pass --confirm-seed or ALLOW_DESTRUCTIVE_SEED=true to run seed.js in non-production.");
  process.exit(1);
}
const { HoldingsModel } = require("./model/HoldingsModel");
const { PositionsModel } = require("./model/PositionsModel");
const { OrdersModel } = require("./model/OrdersModel");

const initialHoldings = [
  {
    name: "BHARTIARTL",
    instrument: "BHARTIARTL",
    qty: 15,
    avg: 1420.5,
    avgCost: 1420.5,
    price: 1684.9,
    ltp: 1684.9,
    curVal: 25273.5,
    pnl: 3966.0,
    net: "+18.61%",
    netChg: "+18.61%",
    day: "+1.35%",
    dayChg: "+1.35%",
    isProfit: true,
    isDayProfit: true,
  },
  {
    name: "HDFCBANK",
    instrument: "HDFCBANK",
    qty: 25,
    avg: 1610.0,
    avgCost: 1610.0,
    price: 1728.15,
    ltp: 1728.15,
    curVal: 43203.75,
    pnl: 2953.75,
    net: "+7.34%",
    netChg: "+7.34%",
    day: "-0.37%",
    dayChg: "-0.37%",
    isProfit: true,
    isDayProfit: false,
  },
  {
    name: "INFY",
    instrument: "INFY",
    qty: 20,
    avg: 1650.0,
    avgCost: 1650.0,
    price: 1845.5,
    ltp: 1845.5,
    curVal: 36910.0,
    pnl: 3910.0,
    net: "+11.85%",
    netChg: "+11.85%",
    day: "-0.98%",
    dayChg: "-0.98%",
    isProfit: true,
    isDayProfit: false,
  },
  {
    name: "ITC",
    instrument: "ITC",
    qty: 80,
    avg: 430.0,
    avgCost: 430.0,
    price: 478.3,
    ltp: 478.3,
    curVal: 38264.0,
    pnl: 3864.0,
    net: "+11.23%",
    netChg: "+11.23%",
    day: "+0.24%",
    dayChg: "+0.24%",
    isProfit: true,
    isDayProfit: true,
  },
  {
    name: "RELIANCE",
    instrument: "RELIANCE",
    qty: 12,
    avg: 2540.0,
    avgCost: 2540.0,
    price: 2712.4,
    ltp: 2712.4,
    curVal: 32548.8,
    pnl: 2068.8,
    net: "+6.79%",
    netChg: "+6.79%",
    day: "+0.90%",
    dayChg: "+0.90%",
    isProfit: true,
    isDayProfit: true,
  },
  {
    name: "SBIN",
    instrument: "SBIN",
    qty: 30,
    avg: 740.0,
    avgCost: 740.0,
    price: 814.65,
    ltp: 814.65,
    curVal: 24439.5,
    pnl: 2239.5,
    net: "+10.09%",
    netChg: "+10.09%",
    day: "-0.55%",
    dayChg: "-0.55%",
    isProfit: true,
    isDayProfit: false,
  },
  {
    name: "TATAMOTORS",
    instrument: "TATAMOTORS",
    qty: 35,
    avg: 940.0,
    avgCost: 940.0,
    price: 884.2,
    ltp: 884.2,
    curVal: 30947.0,
    pnl: -1953.0,
    net: "-5.94%",
    netChg: "-5.94%",
    day: "-1.35%",
    dayChg: "-1.35%",
    isProfit: false,
    isDayProfit: false,
  },
  {
    name: "TCS",
    instrument: "TCS",
    qty: 8,
    avg: 3820.0,
    avgCost: 3820.0,
    price: 3982.75,
    ltp: 3982.75,
    curVal: 31862.0,
    pnl: 1302.0,
    net: "+4.26%",
    netChg: "+4.26%",
    day: "+0.39%",
    dayChg: "+0.39%",
    isProfit: true,
    isDayProfit: true,
  },
];

const initialPositions = [
  {
    product: "MIS",
    name: "NIFTY 24400 CE",
    instrument: "NIFTY 24400 CE",
    qty: 50,
    avg: 112.5,
    price: 134.2,
    ltp: 134.2,
    pnl: 1085.0,
    net: "+19.29%",
    chg: "+19.29%",
    day: "+19.29%",
    isLoss: false,
    isProfit: true,
  },
  {
    product: "MIS",
    name: "BANKNIFTY 51200 PE",
    instrument: "BANKNIFTY 51200 PE",
    qty: -15,
    avg: 245.0,
    price: 210.8,
    ltp: 210.8,
    pnl: 513.0,
    net: "+13.96%",
    chg: "+13.96%",
    day: "+13.96%",
    isLoss: false,
    isProfit: true,
  },
  {
    product: "NRML",
    name: "INFY 1860 CE",
    instrument: "INFY 1860 CE",
    qty: 400,
    avg: 28.5,
    price: 22.1,
    ltp: 22.1,
    pnl: -2560.0,
    net: "-22.46%",
    chg: "-22.46%",
    day: "-22.46%",
    isLoss: true,
    isProfit: false,
  },
];

async function seedDatabase() {
  try {
    console.log("Connecting to MongoDB Atlas...");
    await mongoose.connect(process.env.MONGO_URL, { serverSelectionTimeoutMS: 8000 });
    console.log("Connected successfully!");

    // Clear existing collections and seed
    console.log("Clearing existing collections...");
    await HoldingsModel.deleteMany({});
    await PositionsModel.deleteMany({});
    
    console.log("Seeding Holdings...");
    await HoldingsModel.insertMany(initialHoldings);
    console.log(`Seeded ${initialHoldings.length} holdings documents successfully!`);

    console.log("Seeding Positions...");
    await PositionsModel.insertMany(initialPositions);
    console.log(`Seeded ${initialPositions.length} positions documents successfully!`);

    console.log("\nDatabase seeded successfully!");
    process.exit(0);
  } catch (error) {
    console.error("Seeding error:", error);
    process.exit(1);
  }
}

seedDatabase();
