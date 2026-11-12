const mongoose = require("mongoose");

/**
 * Executes multi-document DB mutations inside a MongoDB ACID transaction session
 * when backed by a Replica Set (MongoDB Atlas), with graceful fallback for
 * standalone local development servers.
 */
async function runInTransaction(workFn) {
  let session = null;
  try {
    session = await mongoose.startSession();
    let result;
    await session.withTransaction(async () => {
      result = await workFn(session);
    });
    return result;
  } catch (err) {
    const msg = String(err?.message || "");
    if (
      msg.includes("Transaction numbers are only allowed on a replica set") ||
      msg.includes("Sessions are not supported")
    ) {
      return await workFn(null);
    }
    throw err;
  } finally {
    if (session) {
      await session.endSession().catch(() => {});
    }
  }
}

module.exports = { runInTransaction };
