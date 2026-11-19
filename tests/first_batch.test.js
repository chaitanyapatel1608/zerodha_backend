const test = require("node:test");
const assert = require("node:assert/strict");
const jwt = require("jsonwebtoken");

process.env.NODE_ENV = "test";
delete process.env.MONGO_URL;
process.env.JWT_SECRET = "isolated-first-batch-test-key-not-for-deployment";
const email = require("../utils/emailService");
const dispatch = test.mock.method(email, "sendOtpEmail", async () => ({ delivered: true }));
const { app } = require("../index");
const { UserModel } = require("../model/UserModel");
const { GttModel } = require("../model/GttModel");
const { OtpModel } = require("../model/OtpModel");
let server, base;

test.before(async () => {
  server = await new Promise(resolve => {
    const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
  });
  base = `http://127.0.0.1:${server.address().port}`;
});
test.after(async () => {
  await new Promise(resolve => server.close(resolve));
  test.mock.restoreAll();
});

test("GTT HTTP creation uses the authenticated owner even when another account is supplied", async (t) => {
  const saved = [];
  t.mock.method(require("../utils/gttExecution"), "evaluate", async () => ({}));
  t.mock.method(UserModel, "findOne", ({ userId }) => ({
    select: () => ({ lean: async () => ["alice", "bob"].includes(userId) ? { tokenVersion: 0 } : null }),
  }));
  t.mock.method(GttModel.prototype, "save", async function () {
    await this.validate();
    saved.push(this.toObject());
    return this;
  });
  const body = { userId: "bob", symbol: "INFY", qty: 1, triggerPrice: 100, orderPrice: 101 };
  for (const owner of ["alice", "bob"]) {
    const token = jwt.sign({ userId: owner, tv: 0 }, process.env.JWT_SECRET);
    const response = await fetch(`${base}/newGtt`, {
      method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify(body),
    });
    assert.equal(response.status, 201);
    assert.equal((await response.json()).gtt.userId, owner);
  }
  const unauthenticated = await fetch(`${base}/newGtt`, {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  assert.equal(unauthenticated.status, 401);
  assert.deepEqual(saved.map(record => record.userId), ["alice", "bob"]);
});

test("login dispatch sends the generated OTP but does not log or return it outside test mode", async (t) => {
  let generated;
  const logs = [];
  t.mock.method(UserModel, "findOne", async () => ({ userId: "alice" }));
  t.mock.method(OtpModel, "findOneAndUpdate", async (_query, update) => { generated = update.otp; });
  for (const level of ["log", "warn", "error"]) t.mock.method(console, level, (...args) => logs.push(args.join(" ")));
  // Configuration was imported safely in test mode; exercise runtime logging/response policy.
  process.env.NODE_ENV = "development";
  try {
    const response = await fetch(`${base}/send-otp`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email: "alice@example.com", type: "login" }),
    });
    assert.equal(response.status, 200);
    const payload = await response.json();
    assert.match(generated, /^\d{6}$/);
    assert.equal(dispatch.mock.calls.at(-1).arguments[1], generated);
    assert.equal(payload.devOtp, undefined);
    assert.ok(!logs.join("\n").includes(generated));
  } finally { process.env.NODE_ENV = "test"; }
});
