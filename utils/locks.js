const mongoose = require("mongoose");
const crypto = require("crypto");

const activeLocks = new Set();

/**
 * Serializes per-user concurrent operations within an application instance to mitigate TOCTOU races.
 */
async function withUserLock(key, fn) {
  const lockKey = String(key);
  if (activeLocks.has(lockKey)) {
    const err = new Error("An operation is already in progress. Please wait.");
    err.status = 429;
    throw err;
  }
  activeLocks.add(lockKey);
  try {
    return await fn();
  } finally {
    activeLocks.delete(lockKey);
  }
}

const JobLockSchema = new mongoose.Schema({
  _id: { type: String },
  owner: { type: String, required: true },
  expiresAt: { type: Date, required: true },
});
const JobLockModel = mongoose.models.joblock || mongoose.model("joblock", JobLockSchema);

/**
 * Acquires a distributed MongoDB lease lock across clustered worker instances.
 */
async function acquireDistributedLock(lockName, ttlMs = 40000) {
  const now = new Date();
  const expiresAt = new Date(Date.now() + ttlMs);
  const owner = crypto.randomUUID();
  try {
    const doc = await JobLockModel.findOneAndUpdate(
      {
        _id: lockName,
        $or: [{ expiresAt: { $lte: now } }, { owner }],
      },
      { $set: { owner, expiresAt } },
      { upsert: true, new: true }
    );
    return doc && doc.owner === owner ? owner : null;
  } catch (err) {
    // Duplicate key error means another instance holds the active lease
    return null;
  }
}

async function releaseDistributedLock(lockName, owner) {
  if (!owner) return;
  try {
    await JobLockModel.deleteOne({ _id: lockName, owner });
  } catch (e) {}
}

module.exports = {
  withUserLock,
  acquireDistributedLock,
  releaseDistributedLock,
};
