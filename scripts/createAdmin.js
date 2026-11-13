const mongoose = require("mongoose");
const { MONGO_URL } = require("../config/env");
const { UserModel } = require("../model/UserModel");
const { FundsModel } = require("../model/FundsModel");
const { hashPassword } = require("../utils/security");

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token.startsWith("--")) {
      const key = token.slice(2);
      const val = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[i + 1] : "true";
      args[key] = val;
      if (val !== "true") i += 1;
    }
  }
  return args;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const email = String(args.email || "").trim().toLowerCase();
  const password = args.password ? String(args.password) : "";
  const fullName = String(args.name || "CTO Administrator").trim();

  if (!email) {
    console.error("Usage: node scripts/createAdmin.js --email <admin@domain.com> [--password <secret>] [--name <Full Name>]");
    process.exit(1);
  }

  await mongoose.connect(MONGO_URL);
  try {
    let user = await UserModel.findOne({ email });
    if (user) {
      user.role = "admin";
      if (password) {
        user.password = hashPassword(password);
      }
      if (args.name) {
        user.fullName = fullName;
      }
      await user.save();
      console.log(`Promoted existing user ${user.userId} (${email}) to role=admin`);
    } else {
      if (!password || password.length < 8) {
        console.error("Password of at least 8 characters is required when creating a new admin account.");
        process.exit(1);
      }
      const userId = `ADM${Date.now().toString().slice(-6)}`;
      user = await UserModel.create({
        userId,
        email,
        fullName,
        password: hashPassword(password),
        role: "admin",
        segments: ["NSE", "BSE", "NFO", "MCX"],
      });
      await FundsModel.create({ userId });
      console.log(`Created new admin user ${user.userId} (${email})`);
    }
  } finally {
    await mongoose.disconnect();
  }
}

main().catch((err) => {
  console.error("createAdmin error:", err.message);
  process.exit(1);
});
