const mongoose = require("mongoose");

/**
 * Executes multi-document DB mutations inside a MongoDB ACID transaction session
 * on a replica set. Never retry a financial operation without a transaction:
 * standalone development databases must fail closed rather than partially commit.
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
  } finally {
    if (session) {
      await session.endSession().catch(() => {});
    }
  }
}

module.exports = { runInTransaction };
