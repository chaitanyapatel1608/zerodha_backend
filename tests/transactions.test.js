const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const { runInTransaction } = require('../utils/transactions');

test('unsupported transactions fail closed without a nontransactional replay', async () => {
  const original = mongoose.startSession;
  for (const message of ['Transaction numbers are only allowed on a replica set', 'Sessions are not supported']) {
    let attempts = 0;
    let ended = false;
    const session = {
      withTransaction: async callback => { await callback(); },
      endSession: async () => { ended = true; },
    };
    mongoose.startSession = async () => session;
    try {
      await assert.rejects(runInTransaction(async suppliedSession => {
        attempts++;
        assert.equal(suppliedSession, session);
        throw new Error(message);
      }), { message });
      assert.equal(attempts, 1);
      assert.equal(ended, true);
    } finally { mongoose.startSession = original; }
  }
});
