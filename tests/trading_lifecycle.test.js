require("./helpers/integrationSetup");
const test = require("node:test");
const assert = require("node:assert/strict");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const path = require("path");

let API_BASE = process.env.TEST_API_BASE || "";
const JWT_SECRET = process.env.JWT_SECRET || "dev_only_ephemeral_jwt_key_change_in_env";
let isolatedServer = null;

test.before(async () => {
  await require("../index").databaseReady;
  // Fixed server quotes keep lifecycle expectations independent of display inputs.
  const { InstrumentModel } = require("../model/InstrumentModel");
  await InstrumentModel.updateMany({ symbol: { $in: ["INFY", "TCS", "RELIANCE"] } }, { $set: { price: 1000 } });
  if (!API_BASE) {
    process.env.NODE_ENV = "test";
    const { startServer } = require("../index");
    isolatedServer = startServer(0);
    await new Promise((resolve) => isolatedServer.once("listening", resolve));
    const addr = isolatedServer.address();
    API_BASE = `http://127.0.0.1:${addr.port}`;
    const deadline = Date.now() + 15000;
    while (mongoose.connection.readyState !== 1 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
});

test.after(async () => {
  if (isolatedServer) {
    await new Promise((resolve) => isolatedServer.close(resolve));
    isolatedServer = null;
  }
  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection.close().catch(() => {});
  }
});

function mintToken(userId) {
  return jwt.sign({ userId, email: `${userId.toLowerCase()}@test.local`, role: "USER", tv: 0 }, JWT_SECRET, {
    expiresIn: "1h",
  });
}

async function apiRequest(endpoint, { method = "GET", token = null, body = null } = {}) {
  const headers = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (body !== null) headers["Content-Type"] = "application/json";
  const res = await fetch(`${API_BASE}${endpoint}`, {
    method,
    headers,
    body: body !== null ? JSON.stringify(body) : undefined,
  });
  const contentType = res.headers.get("content-type") || "";
  const data = contentType.includes("application/json") ? await res.json() : await res.text();
  return { status: res.status, data };
}

async function seedUserWithFunds(db, userId, availableInr = "10,000.00") {
  await db.collection("users").insertOne({
    userId,
    email: `${userId.toLowerCase()}@test.local`,
    fullName: "Lifecycle Tester",
    tokenVersion: 0,
    segments: {
      equity: { name: "NSE Equity", active: true },
      futuresAndOptions: { name: "F&O", active: true },
      commodity: { name: "MCX", active: true },
      currency: { name: "CDS", active: true },
    },
  });
  await db.collection("funds").insertOne({
    userId,
    equity: {
      availableMargin: availableInr,
      usedMargin: "0.00",
      availableCash: availableInr,
      openingBalance: availableInr,
      payin: "0.00",
    },
  });
}

async function cleanupUser(db, userId) {
  await Promise.all([
    db.collection("users").deleteMany({ userId }),
    db.collection("funds").deleteMany({ userId }),
    db.collection("orders").deleteMany({ userId }),
    db.collection("holdings").deleteMany({ userId }),
    db.collection("positions").deleteMany({ userId }),
    db.collection("gtts").deleteMany({ userId }),
    db.collection("alerts").deleteMany({ userId }),
    db.collection("sips").deleteMany({ userId }),
    db.collection("ipoapplications").deleteMany({ userId }),
    db.collection("bankaccounts").deleteMany({ userId }),
    require("../model/PledgedCollateralModel").PledgedCollateralModel.collection.deleteMany({ userId }),
    db.collection("notifications").deleteMany({ userId }),
    db.collection("userwatchlists").deleteMany({ userId }),
  ]);
}

// ==========================================
// 1. Order Engine: Validation, Margin, Kill-Switch & Concurrency
// ==========================================

test("E2E-Orders: Validates inputs, blocks kill-switch & insufficient margin, and serializes concurrent BUYs", async () => {
  const uid = `__ORD_LIFE_${Date.now()}__`;
  const token = mintToken(uid);
  await mongoose.connect(process.env.MONGO_URL);
  const db = mongoose.connection.db;

  try {
    await seedUserWithFunds(db, uid, "10,000.00");

    // Invalid inputs
    for (const badBody of [
      { name: "", qty: 1, price: 100 },
      { name: "INFY", qty: 0, price: 100 },
      { name: "INFY", qty: -2, price: 100 },
      { name: "INFY", qty: 1, price: 0 },
      { name: "INFY", qty: 1, price: 100, mode: "HOLD" },
      { name: "INFY", qty: 1, price: 100, product: "INVALID" },
    ]) {
      const bad = await apiRequest("/newOrder", { method: "POST", token, body: badBody });
      assert.equal(bad.status, 400, `Expected 400 for ${JSON.stringify(badBody)}, got ${bad.status}`);
    }

    // Insufficient margin (10 * 1500 = 15000 > 10000)
    const insuf = await apiRequest("/newOrder", {
      method: "POST",
      token,
      body: { name: "INFY", qty: 15, price: 1500, mode: "BUY", product: "CNC" },
    });
    assert.equal(insuf.status, 400);
    assert.equal(insuf.data?.code, "INSUFFICIENT_MARGIN");

    // Valid BUY CNC (2 * 1000 = 2000 -> available becomes 8000)
    const buyCnc = await apiRequest("/newOrder", {
      method: "POST",
      token,
      body: { name: "INFY", qty: 2, price: 1, mode: "BUY", product: "CNC" },
    });
    assert.equal(buyCnc.status, 201);
    assert.equal(buyCnc.data.order.price, 1000);
    assert.equal(buyCnc.data.order.displayedPrice, 1);
    const holding = await db.collection("holdings").findOne({ userId: uid, name: "INFY" });
    assert.equal(holding?.qty, 2);

    // Concurrent BUY race: 2 parallel orders each costing 5000 when 8000 is available
    const [r1, r2] = await Promise.all([
      apiRequest("/newOrder", { method: "POST", token, body: { name: "TCS", qty: 5, price: 1000, mode: "BUY", product: "CNC" } }),
      apiRequest("/newOrder", { method: "POST", token, body: { name: "TCS", qty: 5, price: 1000, mode: "BUY", product: "CNC" } }),
    ]);
    const okCount = [r1, r2].filter((r) => r.status === 201).length;
    assert.equal(okCount, 1, "Only 1 of 2 concurrent 5000 INR orders may succeed with 8000 INR available");

    // Kill-switch test: disable equity segment and verify rejection
    await db.collection("users").updateOne({ userId: uid }, { $set: { "segments.equity.active": false } });
    const blocked = await apiRequest("/newOrder", {
      method: "POST",
      token,
      body: { name: "INFY", qty: 1, price: 100, mode: "BUY", product: "CNC" },
    });
    assert.equal(blocked.status, 400);
    assert.equal(blocked.data?.code, "SEGMENT_DISABLED");
  } finally {
    await cleanupUser(db, uid);
  }
});

// ==========================================
// 2. Positions: MIS BUY -> Convert MIS<->CNC -> SquareOff
// ==========================================

test("E2E-Positions: MIS margin (20%), convertPosition margin checks, and squareOff P&L + replay guard", async () => {
  const uidA = `__POS_A_${Date.now()}__`;
  const uidB = `__POS_B_${Date.now()}__`;
  const tokenA = mintToken(uidA);
  const tokenB = mintToken(uidB);
  await mongoose.connect(process.env.MONGO_URL);
  const db = mongoose.connection.db;

  try {
    await seedUserWithFunds(db, uidA, "10,000.00");
    await seedUserWithFunds(db, uidB, "10,000.00");

    // BUY MIS 5 * 1000 = 5000 order cost -> 20% margin = 1000 blocked -> 9000 available
    const buyMis = await apiRequest("/newOrder", {
      method: "POST",
      token: tokenA,
      body: { name: "RELIANCE", qty: 5, price: 1000, mode: "BUY", product: "MIS" },
    });
    assert.equal(buyMis.status, 201);

    const pos = await db.collection("positions").findOne({ userId: uidA, name: "RELIANCE" });
    assert.ok(pos, "MIS BUY must create a position");
    const posId = String(pos._id);

    // Same-product conversion rejected
    const sameProd = await apiRequest("/convertPosition", {
      method: "POST",
      token: tokenA,
      body: { positionId: posId, targetProduct: "MIS" },
    });
    assert.equal(sameProd.status, 400);

    // Convert MIS -> CNC (requires extra 80% = 4000; 9000 available -> succeeds, leaves 5000)
    const toCnc = await apiRequest("/convertPosition", {
      method: "POST",
      token: tokenA,
      body: { positionId: posId, targetProduct: "CNC" },
    });
    assert.equal(toCnc.status, 200);
    const holding = await db.collection("holdings").findOne({ userId: uidA, name: "RELIANCE" });
    assert.equal(holding?.qty, 5);

    // Cross-tenant square-off attempt by User B must fail with 400
    const crossSq = await apiRequest("/squareOffPosition", {
      method: "POST",
      token: tokenB,
      body: { positionId: posId, exitPrice: 1200 },
    });
    assert.equal(crossSq.status, 400);

    await db.collection("instruments").updateOne({ symbol: "RELIANCE" }, { $set: { price: 1200 } });
    // Owner square-off @ 1200 -> realized P&L = (1200 - 1000) * 5 = +1000
    const close = () => apiRequest("/squareOffPosition", {
      method: "POST", token: tokenA, body: { positionId: posId, exitPrice: 9000 },
    });
    const { NotificationModel } = require("../model/NotificationModel");
    const originalSave = NotificationModel.prototype.save;
    try {
      NotificationModel.prototype.save = async function () { throw new Error("Injected close failure"); };
      assert.equal((await close()).status, 500);
    } finally { NotificationModel.prototype.save = originalSave; }
    assert.equal((await db.collection("positions").findOne({ _id: pos._id })).qty, 5);
    assert.equal((await db.collection("holdings").findOne({ userId: uidA })).qty, 5);
    assert.equal(await db.collection("orders").countDocuments({ userId: uidA, mode: "SELL" }), 0);
    const attempts = await Promise.all([close(), close()]);
    assert.deepEqual(attempts.map(r => r.status).sort(), [200, 400]);
    assert.equal(attempts.find(r => r.status === 200).data.realizedPnl, 1000);
    const balance = await db.collection("funds").findOne({ userId: uidA });
    assert.equal(balance.equity.availableCash, "10,960.00");
    assert.equal(balance.equity.usedMargin, "0.00");
    assert.equal(await db.collection("holdings").countDocuments({ userId: uidA }), 0);
    const exits = await db.collection("orders").find({ userId: uidA, mode: "SELL" }).toArray();
    assert.equal(exits.length, 1);
    assert.equal(exits[0].executionFee, 20);

    // Re-squaring closed position must be rejected with 400
    const sqAgain = await apiRequest("/squareOffPosition", {
      method: "POST",
      token: tokenA,
      body: { positionId: posId, exitPrice: 9000 },
    });
    assert.equal(sqAgain.status, 400);
  } finally {
    await cleanupUser(db, uidA);
    await cleanupUser(db, uidB);
  }
});

// ==========================================
// 3. GTT, Alerts & Watchlist Lifecycle + Tenant Isolation
// ==========================================

test("E2E-GTT-Alerts-Watchlist: Full CRUD lifecycle, boundary checks, and cross-tenant isolation", async () => {
  const uidA = `__GAW_A_${Date.now()}__`;
  const uidB = `__GAW_B_${Date.now()}__`;
  const tokenA = mintToken(uidA);
  const tokenB = mintToken(uidB);
  await mongoose.connect(process.env.MONGO_URL);
  const db = mongoose.connection.db;

  try {
    await seedUserWithFunds(db, uidA, "10,000.00");
    await seedUserWithFunds(db, uidB, "10,000.00");

    // GTT validation & lifecycle
    const badGtt = await apiRequest("/newGtt", {
      method: "POST",
      token: tokenA,
      body: { symbol: "INFY", qty: 0, triggerPrice: 1500, orderPrice: 1505 },
    });
    assert.equal(badGtt.status, 400);

    const gttRes = await apiRequest("/newGtt", {
      method: "POST",
      token: tokenA,
      body: { symbol: "INFY", qty: 1, type: "SINGLE", triggerPrice: 900, orderPrice: 905 },
    });
    assert.equal(gttRes.status, 201);
    const gttId = String(gttRes.data?.gtt?._id);

    const crossCancel = await apiRequest("/cancelGtt", {
      method: "POST",
      token: tokenB,
      body: { id: gttId },
    });
    assert.equal(crossCancel.status, 404);

    const cancelRes = await apiRequest("/cancelGtt", {
      method: "POST",
      token: tokenA,
      body: { id: gttId },
    });
    assert.equal(cancelRes.status, 200);

    // Alerts lifecycle + invalid ObjectId + cross-tenant delete
    const alertRes = await apiRequest("/createAlert", {
      method: "POST",
      token: tokenA,
      body: { symbol: "TCS", targetPrice: 4000, conditionType: "GTE" },
    });
    assert.equal(alertRes.status, 201);
    const alertId = String(alertRes.data?.alert?._id);

    const badAlertId = await apiRequest("/deleteAlert/not-an-objectid", {
      method: "DELETE",
      token: tokenA,
    });
    assert.equal(badAlertId.status, 400);

    const crossDelAlert = await apiRequest(`/deleteAlert/${alertId}`, {
      method: "DELETE",
      token: tokenB,
    });
    assert.equal(crossDelAlert.status, 404);

    const toggleAlert = await apiRequest(`/toggleAlertStatus/${alertId}`, {
      method: "PATCH",
      token: tokenA,
    });
    assert.equal(toggleAlert.status, 200);

    const delAlert = await apiRequest(`/deleteAlert/${alertId}`, {
      method: "DELETE",
      token: tokenA,
    });
    assert.equal(delAlert.status, 200);

    // Watchlist add/remove on tabId 2
    const tabsRes = await apiRequest("/userWatchlistTabs", { token: tokenA });
    assert.equal(tabsRes.status, 200);
    const addWl = await apiRequest("/addWatchlistStock", {
      method: "POST",
      token: tokenA,
      body: { tabId: 2, stock: { symbol: "ZOMATO", name: "Zomato Ltd", price: 250 } },
    });
    assert.equal(addWl.status, 200);
    const remWl = await apiRequest("/removeWatchlistStock", {
      method: "POST",
      token: tokenA,
      body: { tabId: 2, symbol: "ZOMATO" },
    });
    assert.equal(remWl.status, 200);
  } finally {
    await cleanupUser(db, uidA);
    await cleanupUser(db, uidB);
  }
});

// ==========================================
// 4. IPO SEBI Limits, Mandate Replay, Bank Account & Pledge
// ==========================================

test("E2E-IPO-Bank-Pledge: Enforces SEBI IPO limits, mandate replay guard, bank IFSC validation, and pledge balance", async () => {
  const uid = `__IBP_${Date.now()}__`;
  const token = mintToken(uid);
  await mongoose.connect(process.env.MONGO_URL);
  const db = mongoose.connection.db;

  try {
    await seedUserWithFunds(db, uid, "50,000.00");

    // IPO: Invalid UPI & SEBI Retail > 2,00,000 & HNI > 5,00,000
    const badUpi = await apiRequest("/applyIpo", {
      method: "POST",
      token,
      body: { ipoSymbol: "TESTIPO", companyName: "Test Co", upiId: "invalid-upi", lots: 1, lotSize: 10, bidPrice: 100 },
    });
    assert.equal(badUpi.status, 400);

    const overRetail = await apiRequest("/applyIpo", {
      method: "POST",
      token,
      body: { ipoSymbol: "TESTIPO", companyName: "Test Co", upiId: "trader@okaxis", category: "INDIVIDUAL", lots: 100, lotSize: 10, bidPrice: 250 },
    });
    assert.equal(overRetail.status, 400);

    const validIpo = await apiRequest("/applyIpo", {
      method: "POST",
      token,
      body: { ipoSymbol: "TESTIPO", companyName: "Test Co", upiId: "trader@okaxis", category: "INDIVIDUAL", lots: 1, lotSize: 38, bidPrice: 390 },
    });
    assert.equal(validIpo.status, 201);

    // Duplicate IPO application blocked
    const dupIpo = await apiRequest("/applyIpo", {
      method: "POST",
      token,
      body: { ipoSymbol: "TESTIPO", companyName: "Test Co", upiId: "trader@okaxis", category: "INDIVIDUAL", lots: 1, lotSize: 38, bidPrice: 390 },
    });
    assert.equal(dupIpo.status, 400);

    // Bank Account: invalid IFSC rejected, valid created & deleted
    const badBank = await apiRequest("/addBankAccount", {
      method: "POST",
      token,
      body: { bankName: "HDFC", accountNumber: "1234567890", ifscCode: "BADIFSC" },
    });
    assert.equal(badBank.status, 400);

    const okBank = await apiRequest("/addBankAccount", {
      method: "POST",
      token,
      body: { bankName: "HDFC Bank", accountNumber: "123456789012", ifscCode: "HDFC0000060" },
    });
    assert.equal(okBank.status, 201);
    const primaryBankId = String(okBank.data?.account?._id);

    // Primary bank account cannot be deleted directly (400)
    const delPrimary = await apiRequest(`/deleteBankAccount/${primaryBankId}`, { method: "DELETE", token });
    assert.equal(delPrimary.status, 400);

    // Secondary non-primary bank account can be deleted (200)
    const secondBank = await apiRequest("/addBankAccount", {
      method: "POST",
      token,
      body: { bankName: "ICICI Bank", accountNumber: "987654321098", ifscCode: "ICIC0000001", isPrimary: false },
    });
    assert.equal(secondBank.status, 201);
    const secondBankId = String(secondBank.data?.account?._id);

    const delBank = await apiRequest(`/deleteBankAccount/${secondBankId}`, { method: "DELETE", token });
    assert.equal(delBank.status, 200);

    // Pledge: insufficient holdings rejected; after BUY CNC, pledge succeeds
    const noHoldPledge = await apiRequest("/pledgeHolding", {
      method: "POST",
      token,
      body: { symbol: "TCS", quantity: 2, marketPrice: 3000 },
    });
    assert.equal(noHoldPledge.status, 400);

    const buyTcs = await apiRequest("/newOrder", {
      method: "POST",
      token,
      body: { name: "TCS", qty: 2, price: 3000, mode: "BUY", product: "CNC" },
    });
    assert.equal(buyTcs.status, 201);

    const okPledge = await apiRequest("/pledgeHolding", {
      method: "POST",
      token,
      body: { symbol: "TCS", quantity: 2, marketPrice: 3000 },
    });
    assert.equal(okPledge.status, 201);
    const repeat = await apiRequest("/pledgeHolding", { method: "POST", token,
      body: { symbol: "TCS", quantity: 1 } });
    assert.equal(repeat.status, 400);
    assert.equal(okPledge.data.collateralValue, 1600);
    assert.equal(okPledge.data.pledge.marketPrice, 1000);
  } finally {
    await cleanupUser(db, uid);
  }
});

test("Gate B: execution failures roll back funds, holdings, positions, orders and notifications", async () => {
  const { OrdersModel } = require("../model/OrdersModel");
  const { NotificationModel } = require("../model/NotificationModel");
  const db = mongoose.connection.db;
  const collections = ["funds", "holdings", "positions", "orders", "notifications"];
  const scenarios = [
    { product: "CNC", mode: "BUY", initial: 0 },
    { product: "CNC", mode: "BUY", initial: 3 },
    { product: "CNC", mode: "SELL", initial: 3, qty: 1 },
    { product: "CNC", mode: "SELL", initial: 3, qty: 3 },
    { product: "MIS", mode: "BUY", initial: 0 },
    { product: "MIS", mode: "BUY", initial: 3 },
    { product: "MIS", mode: "SELL", initial: 0 },
    { product: "MIS", mode: "SELL", initial: 3, qty: 3 },
  ];
  for (const [index, scenario] of scenarios.entries()) {
    const uid = `__ATOMIC_${Date.now()}_${index}__`;
    const token = mintToken(uid);
    const snapshot = async () => {
      const result = {};
      for (const name of collections) result[name] = await db.collection(name).find({ userId: uid }).sort({ _id: 1 }).toArray();
      return JSON.stringify(result);
    };
    try {
      await seedUserWithFunds(db, uid);
      await db.collection("users").updateOne({ userId: uid }, { $set: { cdslAuthorizedUntil: new Date(Date.now() + 3600000) } });
      if (scenario.initial) {
        const seed = await apiRequest("/newOrder", { method: "POST", token, body: { name: "INFY", qty: scenario.initial, price: 100, mode: "BUY", product: scenario.product } });
        assert.equal(seed.status, 201);
      }
      const before = await snapshot();
      // Exercise failure both before the order persists and after it persists.
      for (const Model of [OrdersModel, NotificationModel]) {
        const original = Model.prototype.save;
        Model.prototype.save = async function (...args) {
          if (this.userId === uid) throw new Error("Injected Gate B persistence failure");
          return original.apply(this, args);
        };
        try {
          const result = await apiRequest("/newOrder", { method: "POST", token, body: { name: "INFY", qty: scenario.qty || 1, price: 100, mode: scenario.mode, product: scenario.product } });
          assert.equal(result.status, 500, JSON.stringify(scenario));
          assert.equal(await snapshot(), before, `Partial commit in ${JSON.stringify(scenario)} at ${Model.modelName}`);
        } finally {
          Model.prototype.save = original;
        }
      }
      const result = await apiRequest("/newOrder", { method: "POST", token, body: { name: "INFY", qty: scenario.qty || 1, price: 100, mode: scenario.mode, product: scenario.product } });
      assert.equal(result.status, 201, "A clean retry after rollback must succeed");
      const orderId = String(result.data.order._id);
      assert.equal(await db.collection("notifications").countDocuments({ userId: uid, "metadata.orderId": orderId }), 1);
    } finally {
      await cleanupUser(db, uid);
    }
  }
});

test("Short opened with cash and collateral releases each funding source exactly once", async () => {
  const db = mongoose.connection.db;
  const uid = "__SHORT_" + Date.now();
  const token = mintToken(uid);
  try {
    await seedUserWithFunds(db, uid, "150.00");
    await db.collection("funds").updateOne({ userId: uid }, { $set: {
      "equity.availableMargin": "350.00", "equity.totalCollateral": "200.00" } });
    const order = (mode, qty) => apiRequest("/newOrder", { method: "POST", token,
      body: { name: "INFY", price: 1000, product: "MIS", qty, mode } });
    assert.equal((await order("SELL", 1)).status, 201);
    const position = await db.collection("positions").findOne({ userId: uid });
    assert.equal(position.qty, -1);
    assert.equal(position.cashMarginPaise, 13000);
    assert.equal(position.collateralMarginPaise, 7000);
    const close = () => apiRequest("/squareOffPosition", { method: "POST", token, body: { positionId: position._id } });
    assert.equal((await close()).status, 400);
    await db.collection("funds").updateOne({ userId: uid }, { $set: {
      "equity.availableCash": "20.00", "equity.availableMargin": "150.00" } });
    assert.equal((await close()).status, 200);
    const { equity } = await db.collection("funds").findOne({ userId: uid });
    assert.equal(equity.availableCash, "130.00");
    assert.equal(equity.availableMargin, "330.00");
    assert.equal(equity.usedMargin, "0.00");
  } finally { await cleanupUser(db, uid); }
});

test("Competing quote workers publish one durable step; downtime advances only once", async () => {
  const { advanceQuoteClock, PERIOD } = require("../utils/quoteClock");
  const { executionQuote } = require("../utils/executionQuote");
  const now = new Date();
  const original = await executionQuote("INFY");
  const winners = await Promise.all([advanceQuoteClock(now), advanceQuoteClock(now)]);
  assert.deepEqual(winners.sort(), [false, true]);
  const first = await executionQuote("INFY");
  assert.equal(first.version, "demo-v1:1");
  assert.equal(first.price, original.price + 0.01);
  assert.equal(await advanceQuoteClock(new Date(+now + PERIOD - 1)), false);
  assert.equal(await advanceQuoteClock(new Date(+now + 86400000)), true);
  assert.equal((await executionQuote("INFY")).version, "demo-v1:2");
});

test("GTT evaluation enforces the server trigger and limit; competing evaluations create one fill", async () => {
  const uid = "__GTT_ENGINE_" + Date.now();
  const token = mintToken(uid);
  const db = mongoose.connection.db;
  const instrument = db.collection("instruments");
  const before = await instrument.findOne({ symbol: "INFY" });
  try {
    await seedUserWithFunds(db, uid);
    await instrument.updateOne({ symbol: "INFY" }, { $set: { price: 105 } });
    const created = await apiRequest("/newGtt", { method: "POST", token,
      body: { symbol: "INFY", qty: 1, triggerDirection: "BELOW", triggerPrice: 100, orderPrice: 98 } });
    assert.equal(created.status, 201);
    const id = created.data.gtt._id;
    const evaluate = () => apiRequest("/triggerGtt", { method: "POST", token, body: { id } });
    assert.equal((await evaluate()).data.gtt.status, "ACTIVE");
    await instrument.updateOne({ symbol: "INFY" }, { $set: { price: 99 } });
    assert.deepEqual((await evaluate()).data.gtt.activatedBranches, ["single"]);
    assert.equal(await db.collection("orders").countDocuments({ userId: uid }), 0);
    await instrument.updateOne({ symbol: "INFY" }, { $set: { price: 98 } });
    const outcomes = await Promise.all([evaluate(), evaluate()]);
    assert.deepEqual(outcomes.map(r => r.status).sort(), [200, 404]);
    const orders = await db.collection("orders").find({ userId: uid }).toArray();
    assert.equal(orders.length, 1);
    assert.equal(orders[0].price, 98);
    assert.equal(orders[0].executionFee, 20);
    assert.equal((await db.collection("funds").findOne({ userId: uid })).equity.availableCash, "9,882.00");
  } finally {
    await instrument.updateOne({ symbol: "INFY" }, { $set: { price: before.price } });
    await cleanupUser(db, uid);
  }
});

test("SIP retries a failed leg without repurchasing its completed sibling", async () => {
  const { SipModel } = require("../model/SipModel");
  const { OrdersModel } = require("../model/OrdersModel");
  const db = mongoose.connection.db;
  const uid = "__SIP_RETRY_" + Date.now();
  const token = mintToken(uid);
  const scheduledAt = new Date();
  await seedUserWithFunds(db, uid);
  const sip = await SipModel.create({ userId: uid, name: "Recovery test", nextTriggerAt: scheduledAt,
    instruments: ["INFY", "TCS"].map(symbol => ({ symbol, qty: 1, price: 1200, budget: 1200 })) });
  const run = () => apiRequest("/executeSipNow/" + sip._id, { method: "POST", token, body: { scheduledAt } });
  const original = OrdersModel.prototype.save;
  try {
    OrdersModel.prototype.save = async function (...args) {
      if (this.userId === uid && this.name === "TCS") throw new Error("simulated failure");
      return original.apply(this, args);
    };
    assert.equal((await run()).status, 200);
    const pending = await SipModel.findById(sip._id);
    assert.deepEqual(pending.installment.legs.map(l => l.status), ["FILLED","WAITING"]);
    assert.equal(pending.installment.legs[1].failures, 1);
    OrdersModel.prototype.save = original;
    await SipModel.updateOne({ _id: sip._id }, { $set: { "installment.legs.1.retryAt": new Date(0) } });
    await Promise.all([run(), run()]);
    const finished = await SipModel.findById(sip._id);
    assert.equal(finished.totalInstallmentsExecuted, 1);
    assert.equal(finished.executionLogs[0].ordersCount, 2);
    assert.equal(finished.executionLogs[0].status, "SUCCESS");
    assert.equal(await db.collection("orders").countDocuments({ userId: uid }), 2);
    const replay = await require("../utils/sipExecution").processInstallment(sip._id, scheduledAt,
      () => assert.fail("Completed installment attempted another order"));
    assert.equal(replay.success, false);
  } finally {
    OrdersModel.prototype.save = original;
    await cleanupUser(db, uid);
  }
});

test("Offering edits require fresh owner approval and cannot reopen allotted records", async () => {
  require("../middleware/rateLimiters").tradeFundsLimiter.resetKey("::/56");
  require("../middleware/rateLimiters").tradeFundsLimiter.resetKey("::ffff:127.0.0.1");
  require("../middleware/rateLimiters").tradeFundsLimiter.resetKey("127.0.0.1");
  const db = mongoose.connection.db;
  const uid = "__OFFER_" + Date.now();
  const token = mintToken(uid);
  await seedUserWithFunds(db, uid);
  const { IpoApplicationModel } = require("../model/IpoApplicationModel");
  const application = await IpoApplicationModel.create({ userId: uid, userEmail: uid + "@test.local",
    ipoSymbol: "TESTIPO", companyName: "Synthetic offering", applicationNumber: uid, upiId: "demo@upi",
    lots: 1, lotSize: 1, totalQty: 1, bidPrice: 100, totalAmount: 100, status: "APPLIED", mandateStatus: "ACCEPTED" });
  try {
    const edited = await apiRequest("/modifyIpoBid/" + application._id, { method: "PUT", token, body: { lots: 2 } });
    assert.equal(edited.status, 200);
    assert.equal(edited.data.application.status, "MANDATE_PENDING");
    assert.equal(edited.data.application.mandateToken, undefined);
    const approve = () => apiRequest("/approveIpoApplication/" + application._id, { method: "POST", token });
    assert.equal((await approve()).status, 200);
    assert.equal((await approve()).status, 409);
    await IpoApplicationModel.updateOne({ _id: application._id }, { $set: { status: "ALLOTTED" } });
    assert.equal((await apiRequest("/modifyIpoBid/" + application._id, { method: "PUT", token, body: { lots: 3 } })).status, 400);
    assert.equal((await apiRequest("/cancelIpoApplication/" + application._id, { method: "DELETE", token })).status, 404);
  } finally {
    await IpoApplicationModel.deleteMany({ userId: uid });
    await cleanupUser(db, uid);
  }
});

test("Pending delivery limits reserve cash and cancellation releases once", async () => {
  require("../middleware/rateLimiters").tradeFundsLimiter.resetKey("::/56");
  require("../middleware/rateLimiters").tradeFundsLimiter.resetKey("127.0.0.1");
  const db = mongoose.connection.db;
  const uid = "__RESERVE_" + Date.now();
  await seedUserWithFunds(db, uid, "1,000.00");
  const token = mintToken(uid);
  try {
    const place = () => apiRequest("/newOrder", { method: "POST", token,
      body: { name: "INFY", qty: 1, price: 800, mode: "BUY", product: "CNC", orderType: "LIMIT" } });
    const results = await Promise.all([place(), place()]);
    assert.deepEqual(results.map(r => r.status).sort(), [201, 400]);
    assert.equal((await db.collection("funds").findOne({ userId: uid })).equity.availableCash, "180.00");
    const id = results.find(r => r.status === 201).data.order._id;
    const cancel = () => apiRequest("/cancelOrder/" + id, { method: "POST", token });
    assert.deepEqual((await Promise.all([cancel(), cancel()])).map(r => r.status).sort(), [200, 409]);
    assert.equal((await db.collection("funds").findOne({ userId: uid })).equity.availableCash, "1,000.00");
    const second = await place();
    const quote = await db.collection("instruments").findOne({ symbol: "INFY" });
    try {
      await db.collection("instruments").updateOne({ symbol: "INFY" }, { $set: { price: 799 } });
      const execute = require("../index").executeOrderInternal;
      const evaluate = () => require("../utils/transactions").runInTransaction(session =>
        require("../utils/reservations").evaluatePending(execute, session));
      await Promise.all([evaluate(), evaluate()]);
      assert.equal(await db.collection("orders").countDocuments({ userId: uid }), 1);
      assert.equal((await db.collection("funds").findOne({ userId: uid })).equity.availableCash, "181.00");
      assert.equal((await require("../model/ReservationModel").ReservationModel.findById(second.data.order._id)).status, "FILLED");
    } finally { await db.collection("instruments").updateOne({ symbol: "INFY" }, { $set: { price: quote.price } }); }

  } finally {
    await require("../model/ReservationModel").ReservationModel.deleteMany({ userId: uid });
    await cleanupUser(db, uid);
  }
});

test("Limit edits preserve rejected reservations and arbitrate edit versus fill atomically", async () => {
  const db = mongoose.connection.db;
  const uid = "__EDIT_" + Date.now();
  await seedUserWithFunds(db, uid, "1,000.00");
  const reservations = require("../utils/reservations");
  const { ReservationModel } = require("../model/ReservationModel");
  const execute = require("../index").executeOrderInternal;
  const quote = await db.collection("instruments").findOne({ symbol: "INFY" });
  try {
    const placed = await reservations.place({ userId: uid, name: "INFY", qty: 1, price: 800, mode: "BUY", product: "CNC" }, execute);
    const id = placed.order._id;
    const rejected = await reservations.edit(id, uid, { qty: 2 }, execute);
    assert.equal(rejected.success, false);
    assert.equal((await ReservationModel.findById(id)).status, "PENDING");
    assert.equal((await ReservationModel.findById(id)).qty, 1);
    assert.equal((await db.collection("funds").findOne({ userId: uid })).equity.availableCash, "180.00");
    assert.equal((await reservations.edit(id, uid + "other", { price: 700 }, execute)).success, false);
    assert.equal((await reservations.edit(id, uid, { price: -1 }, execute)).success, false);
    await db.collection("instruments").updateOne({ symbol: "INFY" }, { $set: { price: 799 } });
    await Promise.all([
      reservations.edit(id, uid, { price: 800 }, execute),
      require("../utils/transactions").runInTransaction(session => reservations.evaluatePending(execute, session))
    ]);
    assert.equal(await db.collection("orders").countDocuments({ userId: uid }), 1);
    assert.equal(await ReservationModel.countDocuments({ userId: uid, status: "PENDING" }), 0);
    assert.equal((await db.collection("funds").findOne({ userId: uid })).equity.availableCash, "181.00");
  } finally {
    await db.collection("instruments").updateOne({ symbol: "INFY" }, { $set: { price: quote.price } });
    await ReservationModel.deleteMany({ userId: uid });
    await cleanupUser(db, uid);
  }
});

test("SIP expiry, retry exhaustion, pause and cancellation preserve completed purchases", async () => {
  const { SipModel } = require("../model/SipModel");
  const { processInstallment } = require("../utils/sipExecution");
  const db = mongoose.connection.db;
  const uid = "__SIP_BOUNDARY_" + Date.now();
  await seedUserWithFunds(db, uid);
  const create = (due, extra = {}) => SipModel.create({ userId: uid, name: "Boundary", nextTriggerAt: due,
    instruments: [{ symbol: "INFY", qty: 1, price: 1200, budget: 1200 }], ...extra });
  const neverExecute = () => assert.fail("Ineligible installment attempted a purchase");
  try {
    const expired = await create(new Date(Date.now() - 86400001));
    await processInstallment(expired._id, expired.nextTriggerAt, neverExecute);
    const expiredResult = await SipModel.findById(expired._id);
    assert.equal(expiredResult.executionLogs[0].status, "SKIPPED");
    assert.equal(expiredResult.executionLogs[0].legs[0].reason, "Catch-up window expired");
    const paused = await create(new Date(), { status: "PAUSED" });
    assert.equal((await processInstallment(paused._id, paused.nextTriggerAt, neverExecute)).success, false);
    const retry = await create(new Date());
    for (let attempt = 0; attempt < 4; attempt++) {
      await processInstallment(retry._id, retry.nextTriggerAt, async () => { throw new Error("Injected technical outage"); });
      const row = await SipModel.findById(retry._id);
      if (attempt < 3) {
        assert.equal(row.installment.legs[0].failures, attempt + 1);
        assert.ok(row.installment.legs[0].retryAt);
        await SipModel.updateOne({ _id: retry._id }, { $set: { "installment.legs.0.retryAt": new Date(0) } });
      } else {
        assert.equal(row.executionLogs[0].legs[0].reason, "Technical retries exhausted");
        assert.equal(row.installment, undefined);
      }
    }
    const oversized = await create(new Date(), { instruments: [{ symbol: "INFY", qty: 1, price: 1200, budget: 20000000 }] });
    await processInstallment(oversized._id, oversized.nextTriggerAt, neverExecute);
    assert.equal((await SipModel.findById(oversized._id)).executionLogs[0].status, "SKIPPED");
    const cancelled = await create(new Date());
    await SipModel.deleteOne({ _id: cancelled._id });
    assert.equal((await processInstallment(cancelled._id, cancelled.nextTriggerAt, neverExecute)).success, false);
    assert.equal(await db.collection("orders").countDocuments({ userId: uid }), 0);
    const partial = await create(new Date(), { instruments: ["INFY", "TCS"].map(symbol => ({ symbol, qty: 1, price: 1200, budget: 1200 })) });
    const execute = require("../index").executeOrderInternal;
    await processInstallment(partial._id, partial.nextTriggerAt, (input, session) => {
      if (input.name === "TCS") throw new Error("Injected second-leg outage");
      return execute(input, session);
    });
    assert.equal(await db.collection("orders").countDocuments({ userId: uid }), 1);
    await SipModel.deleteOne({ _id: partial._id });
    assert.equal((await processInstallment(partial._id, partial.nextTriggerAt, neverExecute)).success, false);
    assert.equal(await db.collection("orders").countDocuments({ userId: uid }), 1);
  } finally { await cleanupUser(db, uid); }
});

test("Disabled segments allow pure position reductions but reject reversals and cooldown bypass", async () => {
  const db = mongoose.connection.db;
  const uid = "__SEGMENT_EXIT_" + Date.now();
  await seedUserWithFunds(db, uid);
  const execute = require("../index").executeOrderInternal;
  const input = { userId: uid, name: "INFY", qty: 3, price: 1000, mode: "BUY", product: "MIS" };
  try {
    assert.equal((await execute(input)).success, true);
    await db.collection("users").updateOne({ userId: uid }, { $set: {
      "segments.equity.active": false, "segments.equity.deactivatedAt": new Date(Date.now() - 13 * 3600000)
    } });
    assert.equal((await execute({ ...input, qty: 1 })).code, "SEGMENT_DISABLED");
    assert.equal((await execute({ ...input, qty: 4, mode: "SELL" })).code, "SEGMENT_DISABLED");
    assert.equal((await execute({ ...input, qty: 1, mode: "SELL" })).success, true);
    assert.equal((await execute({ ...input, qty: 2, mode: "SELL" })).success, true);
    assert.equal(await db.collection("positions").countDocuments({ userId: uid, qty: { $ne: 0 } }), 0);
    const token = mintToken(uid);
    const reactivate = await apiRequest("/updateSegments", { method: "POST", token,
      body: { segmentKey: "equity", targetState: true } });
    assert.equal(reactivate.status, 403);
    assert.equal(reactivate.data.code, "KILL_SWITCH_ACTIVE");
    const otpBypass = await apiRequest("/verifySegmentOtp", { method: "POST", token,
      body: { segmentKey: "equity", otp: "000000" } });
    assert.equal(otpBypass.status, 403);
    assert.equal(otpBypass.data.code, "KILL_SWITCH_ACTIVE");
  } finally { await cleanupUser(db, uid); }
});

test("OCO shares one trigger-time reservation, cancels once, and fills one sibling", async () => {
  const db = mongoose.connection.db;
  const uid = "__OCO_RESERVE_" + Date.now();
  await seedUserWithFunds(db, uid, "1,000.00");
  const { GttModel } = require("../model/GttModel");
  const { ReservationModel } = require("../model/ReservationModel");
  const gtt = require("../utils/gttExecution");
  const execute = require("../index").executeOrderInternal;
  const quote = await db.collection("instruments").findOne({ symbol: "INFY" });
  const create = () => GttModel.create({ userId: uid, symbol: "INFY", qty: 1, type: "OCO", transactionType: "BUY", product: "CNC",
    stoplossTrigger: 1000, stoplossPrice: 900, targetTrigger: 800, targetPrice: 800 });
  try {
    const first = await create();
    await Promise.all([gtt.evaluate(first._id, uid, execute), gtt.evaluate(first._id, uid, execute)]);
    assert.equal(await ReservationModel.countDocuments({ userId: uid, status: "PENDING" }), 1);
    assert.equal((await db.collection("funds").findOne({ userId: uid })).equity.availableCash, "80.00");
    await Promise.all([gtt.cancel(first._id, uid), gtt.cancel(first._id, uid)]);
    assert.equal((await db.collection("funds").findOne({ userId: uid })).equity.availableCash, "1,000.00");
    const second = await create();
    await gtt.evaluate(second._id, uid, execute);
    await db.collection("instruments").updateOne({ symbol: "INFY" }, { $set: { price: 790 } });
    await Promise.all([gtt.evaluate(second._id, uid, execute), gtt.evaluate(second._id, uid, execute)]);
    assert.equal(await db.collection("orders").countDocuments({ userId: uid }), 1);
    assert.equal((await GttModel.findById(second._id)).status, "TRIGGERED");
    assert.equal(await ReservationModel.countDocuments({ userId: uid, status: "PENDING" }), 0);
    assert.equal((await db.collection("funds").findOne({ userId: uid })).equity.availableCash, "190.00");
  } finally {
    await db.collection("instruments").updateOne({ symbol: "INFY" }, { $set: { price: quote.price } });
    await ReservationModel.deleteMany({ userId: uid });
    await cleanupUser(db, uid);
  }
});

test("Quote evaluation honors common priority across limits and GTT instructions", async () => {
  const db = mongoose.connection.db;
  const uid = "__PRIORITY_" + Date.now();
  await seedUserWithFunds(db, uid);
  const { GttModel } = require("../model/GttModel");
  const { ReservationModel } = require("../model/ReservationModel");
  const execute = require("../index").executeOrderInternal;
  const quote = await db.collection("instruments").findOne({ symbol: "INFY" });
  try {
    const limit = await require("../utils/reservations").place({ userId: uid, name: "INFY", qty: 1, price: 900, product: "CNC", mode: "BUY" }, execute);
    const trigger = await GttModel.create({ userId: uid, symbol: "INFY", qty: 2, product: "CNC", transactionType: "BUY",
      type: "SINGLE", triggerPrice: 900, orderPrice: 900, createdAt: new Date(+limit.order.createdAt - 1000) });
    const listed = await apiRequest("/allOrders", { token: mintToken(uid) });
    assert.ok(listed.data.some(row => row._id === String(limit.order._id) && row.status === "PENDING"));
    await db.collection("instruments").updateOne({ symbol: "INFY" }, { $set: { price: 890 } });
    const evaluate = () => require("../utils/transactions").runInTransaction(session =>
      require("../utils/instructionExecution").evaluateInstructions(execute, session));
    await Promise.all([evaluate(), evaluate()]);
    const orders = await db.collection("orders").find({ userId: uid }).sort({ _id: 1 }).toArray();
    assert.deepEqual(orders.map(order => order.qty), [2, 1]);
    assert.equal(String((await GttModel.findById(trigger._id)).executedOrder), String(orders[0]._id));
    assert.equal(await ReservationModel.countDocuments({ userId: uid, status: "PENDING" }), 0);
  } finally {
    await db.collection("instruments").updateOne({ symbol: "INFY" }, { $set: { price: quote.price } });
    await ReservationModel.deleteMany({ userId: uid });
    await cleanupUser(db, uid);
  }
});

test("Partial conversion preserves basis and funding, and rolls back all writes on failure", async () => {
  const db = mongoose.connection.db;
  const uid = "__CONVERT_ATOMIC_" + Date.now();
  await seedUserWithFunds(db, uid);
  const execute = require("../index").executeOrderInternal;
  const { convertPosition } = require("../utils/convertPosition");
  const { NotificationModel } = require("../model/NotificationModel");
  const original = NotificationModel.prototype.save;
  const originalQuote = await db.collection("instruments").findOne({ symbol: "INFY" });
  await db.collection("instruments").updateOne({ symbol: "INFY" }, { $set: { price: 1000 } });
  try {
    await execute({ userId: uid, name: "INFY", qty: 5, price: 1000, mode: "BUY", product: "MIS" });
    const source = await db.collection("positions").findOne({ userId: uid });
    const before = await db.collection("funds").findOne({ userId: uid });
    NotificationModel.prototype.save = async function (...args) {
      if (this.userId === uid) throw new Error("Injected conversion receipt failure");
      return original.apply(this, args);
    };
    await assert.rejects(convertPosition(uid, source._id, "CNC", 2), /receipt failure/);
    NotificationModel.prototype.save = original;
    assert.equal((await db.collection("positions").findOne({ _id: source._id })).qty, 5);
    assert.equal(await db.collection("holdings").countDocuments({ userId: uid }), 0);
    assert.equal((await db.collection("funds").findOne({ userId: uid })).equity.availableCash, before.equity.availableCash);
    await convertPosition(uid, source._id, "NRML", 2);
    const positions = await db.collection("positions").find({ userId: uid }).toArray();
    assert.equal(positions.find(row => row.product === "MIS").qty, 3);
    assert.equal(positions.find(row => row.product === "MIS").cashMarginPaise, 60000);
    const converted = positions.find(row => row.product === "NRML");
    assert.equal(converted.qty, 2);
    assert.equal(converted.avg, 1000);
    assert.equal(converted.cashMarginPaise, 200000);
    assert.equal((await db.collection("funds").findOne({ userId: uid })).equity.availableCash, "7,380.00");
    assert.equal(await db.collection("orders").countDocuments({ userId: uid }), 1);
    await convertPosition(uid, converted._id, "MIS", 2);
    assert.equal((await db.collection("positions").findOne({ _id: source._id })).qty, 5);
    assert.equal((await db.collection("funds").findOne({ userId: uid })).equity.availableCash, before.equity.availableCash);
  } finally {
    NotificationModel.prototype.save = original;
    await db.collection("instruments").updateOne({ symbol: "INFY" }, { $set: { price: originalQuote.price } });
    await cleanupUser(db, uid);
  }
});

test("Pending reduction exits shrink with the source and release their fee on full close", async () => {
  const db = mongoose.connection.db;
  const uid = "__LINKED_EXIT_" + Date.now();
  await seedUserWithFunds(db, uid);
  const execute = require("../index").executeOrderInternal;
  const reservations = require("../utils/reservations");
  const { ReservationModel } = require("../model/ReservationModel");
  try {
    const input = { userId: uid, name: "INFY", qty: 5, price: 1000, mode: "BUY", product: "MIS" };
    await execute(input);
    const placed = await reservations.place({ ...input, mode: "SELL", price: 2000 }, execute);
    assert.equal(placed.success, true);
    assert.equal(placed.order.cashPaise, 2000);
    assert.ok(placed.order.linkedPosition);
    await execute({ ...input, mode: "SELL", qty: 2 });
    assert.equal((await ReservationModel.findById(placed.order._id)).qty, 3);
    await execute({ ...input, mode: "SELL", qty: 3 });
    assert.equal((await ReservationModel.findById(placed.order._id)).status, "CANCELLED");
    assert.equal((await db.collection("funds").findOne({ userId: uid })).equity.availableCash, "9,940.00");
    assert.equal(await db.collection("orders").countDocuments({ userId: uid }), 3);
  } finally { await ReservationModel.deleteMany({ userId: uid }); await cleanupUser(db, uid); }
});
