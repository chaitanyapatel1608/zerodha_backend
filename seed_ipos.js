require("dotenv").config();
const mongoose = require("mongoose");

if (process.env.NODE_ENV === "production") {
  console.error("FATAL: Seed scripts are strictly prohibited in production.");
  process.exit(1);
}
if (!process.argv.includes("--confirm-seed") && process.env.ALLOW_DESTRUCTIVE_SEED !== "true") {
  console.error("ABORTED: Pass --confirm-seed or ALLOW_DESTRUCTIVE_SEED=true to run seed_ipos.js in non-production.");
  process.exit(1);
}
const { IpoModel } = require("./model/IpoModel");

const initialIpos = [
  {
    symbol: "HYUNDAI",
    name: "Hyundai Motor India Limited",
    dates: "15 Oct - 17 Oct 2024",
    priceRange: "₹1,865 - ₹1,960",
    minQty: 7,
    minAmount: "₹13,720",
    status: "Closed",
    type: "IPO",
  },
  {
    symbol: "WAARRE",
    name: "Waaree Energies Limited",
    dates: "21 Oct - 23 Oct 2024",
    priceRange: "₹1,427 - ₹1,503",
    minQty: 9,
    minAmount: "₹13,527",
    status: "Closed",
    type: "IPO",
  },
  {
    symbol: "AFCONS",
    name: "Afcons Infrastructure Limited",
    dates: "25 Oct - 29 Oct 2024",
    priceRange: "₹440 - ₹463",
    minQty: 32,
    minAmount: "₹14,816",
    status: "Closed",
    type: "IPO",
  },
  {
    symbol: "SWIGGY",
    name: "Swiggy Limited",
    dates: "06 Nov - 08 Nov 2024",
    priceRange: "₹371 - ₹390",
    minQty: 38,
    minAmount: "₹14,820",
    status: "Apply",
    type: "IPO",
  },
  {
    symbol: "ACME",
    name: "ACME Solar Holdings Limited",
    dates: "06 Nov - 08 Nov 2024",
    priceRange: "₹275 - ₹289",
    minQty: 51,
    minAmount: "₹14,739",
    status: "Apply",
    type: "IPO",
  },
  {
    symbol: "NTPCGREEN",
    name: "NTPC Green Energy Limited",
    dates: "19 Nov - 22 Nov 2024",
    priceRange: "₹102 - ₹108",
    minQty: 138,
    minAmount: "₹14,904",
    status: "Upcoming",
    type: "IPO",
  },
];

async function seedIpos() {
  try {
    console.log("Connecting to MongoDB Atlas...");
    await mongoose.connect(process.env.MONGO_URL, { serverSelectionTimeoutMS: 8000 });
    console.log("Connected successfully!");

    console.log("Seeding IPO collection idempotently...");
    for (const ipo of initialIpos) {
      await IpoModel.updateOne(
        { symbol: ipo.symbol },
        { $setOnInsert: ipo },
        { upsert: true }
      );
    }

    const totalCount = await IpoModel.countDocuments();
    console.log(`Total IPOs in database: ${totalCount} (Zero duplicates ensured)`);
    process.exit(0);
  } catch (err) {
    console.error("Seeding error:", err);
    process.exit(1);
  }
}

seedIpos();
