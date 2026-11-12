const test = require("node:test");
const assert = require("node:assert/strict");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "..", ".env") });

let API_BASE = process.env.TEST_API_BASE || "";
const JWT_SECRET = process.env.JWT_SECRET || "dev_only_ephemeral_jwt_key_change_in_env";
let isolatedServer = null;

test.before(async () => {
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
    db.collection("pledgedcollaterals").deleteMany({ userId }),
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
      body: { name: "INFY", qty: 10, price: 1500, mode: "BUY", product: "CNC" },
    });
    assert.equal(insuf.status, 400);
    assert.equal(insuf.data?.code, "INSUFFICIENT_MARGIN");

    // Valid BUY CNC (2 * 1000 = 2000 -> available becomes 8000)
    const buyCnc = await apiRequest("/newOrder", {
      method: "POST",
      token,
      body: { name: "INFY", qty: 2, price: 1000, mode: "BUY", product: "CNC" },
    });
    assert.equal(buyCnc.status, 201);
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

    // Owner square-off @ 1200 -> realized P&L = (1200 - 1000) * 5 = +1000
    const sq = await apiRequest("/squareOffPosition", {
      method: "POST",
      token: tokenA,
      body: { positionId: posId, exitPrice: 1200 },
    });
    assert.equal(sq.status, 200);
    assert.equal(sq.data?.realizedPnl, 1000);

    // Re-squaring closed position must be rejected with 400
    const sqAgain = await apiRequest("/squareOffPosition", {
      method: "POST",
      token: tokenA,
      body: { positionId: posId, exitPrice: 1200 },
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
      body: { symbol: "INFY", qty: 1, type: "SINGLE", triggerPrice: 1500, orderPrice: 1505 },
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
  } finally {
    await cleanupUser(db, uid);
  }
});
