/**
 * Reversible Field-Level Encryption Migration Script
 * Usage:
 *   node scripts/encryptSensitiveFields.js --dry-run
 *   node scripts/encryptSensitiveFields.js --apply
 *   node scripts/encryptSensitiveFields.js --rollback
 */
const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "..", ".env") });
const mongoose = require("mongoose");
const { UserModel } = require("../model/UserModel");
const { BankAccountModel } = require("../model/BankAccountModel");
const { encryptField, decryptField, isEncrypted } = require("../utils/encryption");

const isApply = process.argv.includes("--apply");
const isRollback = process.argv.includes("--rollback");
const isDryRun = !isApply && !isRollback;

async function run() {
  if (!process.env.MONGO_URL) {
    throw new Error("MONGO_URL is required");
  }
  await mongoose.connect(process.env.MONGO_URL);

  let usersUpdated = 0;
  let banksUpdated = 0;

  const users = await UserModel.find({});
  for (const u of users) {
    let dirty = false;
    for (const field of ["pan", "dob", "phone", "address"]) {
      const val = u[field];
      if (!val) continue;
      if (isRollback && isEncrypted(val)) {
        u[field] = decryptField(val);
        dirty = true;
      } else if (!isRollback && !isEncrypted(val)) {
        u[field] = encryptField(val);
        dirty = true;
      }
    }
    if (dirty) {
      usersUpdated++;
      if (!isDryRun) {
        await UserModel.updateOne(
          { _id: u._id },
          { $set: { pan: u.pan, dob: u.dob, phone: u.phone, address: u.address } }
        );
      }
    }
  }

  const banks = await BankAccountModel.find({});
  for (const b of banks) {
    if (!b.accountNumber) continue;
    if (isRollback && isEncrypted(b.accountNumber)) {
      banksUpdated++;
      if (!isDryRun) {
        await BankAccountModel.updateOne(
          { _id: b._id },
          { $set: { accountNumber: decryptField(b.accountNumber) } }
        );
      }
    } else if (!isRollback && !isEncrypted(b.accountNumber)) {
      banksUpdated++;
      if (!isDryRun) {
        await BankAccountModel.updateOne(
          { _id: b._id },
          { $set: { accountNumber: encryptField(b.accountNumber) } }
        );
      }
    }
  }

  console.log(
    JSON.stringify({
      mode: isDryRun ? "dry-run" : isRollback ? "rollback" : "apply",
      usersAffected: usersUpdated,
      bankAccountsAffected: banksUpdated,
    })
  );
  await mongoose.disconnect();
}

run().catch((err) => {
  console.error("Migration error:", err.message);
  process.exit(1);
});
