const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "..", ".env") });
const test = require("node:test");
const assert = require("node:assert/strict");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const {
  hashPassword,
  verifyPassword,
  escapeRegex,
  resolveAuthenticatedUserId,
} = require("../utils/security");

let API_BASE = process.env.TEST_API_BASE || "";
let isolatedServer = null;
const JWT_SECRET = process.env.JWT_SECRET || "zerodha_jwt_super_secret_key_2026_finance_kite";

test.before(async () => {
  if (!API_BASE) {
    process.env.NODE_ENV = "test";
    const { app } = require("../index");
    await mongoose.connect(process.env.MONGO_URL);
    if (mongoose.connection.readyState !== 1) {
      await new Promise((resolve) => mongoose.connection.once("connected", resolve));
    }
    isolatedServer = await new Promise((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });
    API_BASE = `http://127.0.0.1:${isolatedServer.address().port}`;
  }
});

test.after(async () => {
  if (isolatedServer) {
    await new Promise((resolve) => isolatedServer.close(resolve));
    await mongoose.disconnect();
  }
});

function mintToken(userId) {
  return jwt.sign({ userId, email: `${userId.toLowerCase()}@test.local` }, JWT_SECRET, {
    expiresIn: "15m",
  });
}

async function apiRequest(route, { method = "GET", token, body } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${API_BASE}${route}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try {
    data = await res.json();
  } catch (e) {}
  return { status: res.status, headers: res.headers, data };
}

test("SEC-Crypt: Scrypt password hashing produces salted hashes and verifies in constant time", () => {
  const pw = "Zerodha@2026!Secure";
  const h1 = hashPassword(pw);
  const h2 = hashPassword(pw);

  assert.ok(h1.includes(":"), "Stored hash should contain salt:digest format");
  assert.notEqual(h1, h2, "Same password must produce distinct salted hashes");
  assert.equal(verifyPassword(pw, h1), true);
  assert.equal(verifyPassword("WrongPassword1!", h1), false);
  assert.equal(verifyPassword(pw, "malformed"), false);
});

test("SEC-ReDoS: escapeRegex neutralizes regex metacharacters cleanly", () => {
  const payload = "user+(admin)*?[test]^$|\\";
  const escaped = escapeRegex(payload);
  const start = Date.now();
  const re = new RegExp(`^${escaped}$`, "i");
  assert.equal(re.test(payload), true);
  assert.equal(re.test("useradmin"), false);
  assert.ok(Date.now() - start < 20, "Escaped regex must evaluate rapidly without backtracking");
});

test("SEC-Auth: Production resolver rejects query/body userId spoofing and invalid JWTs", () => {
  const validToken = mintToken("ZU9001");
  const reqValid = { headers: { authorization: `Bearer ${validToken}` }, query: { userId: "SPOOFED" } };
  assert.equal(resolveAuthenticatedUserId(reqValid, JWT_SECRET, "production"), "ZU9001");

  const reqSpoofNoAuth = { headers: {}, query: { userId: "ZU9999" }, body: { userId: "ZU9999" } };
  assert.equal(resolveAuthenticatedUserId(reqSpoofNoAuth, JWT_SECRET, "production"), null);

  const reqBadJwt = { headers: { authorization: "Bearer invalid.jwt.token" }, query: { userId: "ZU9999" } };
  assert.equal(resolveAuthenticatedUserId(reqBadJwt, JWT_SECRET, "production"), null);
});

test("SEC-Headers: Server strips X-Powered-By and sets Helmet security headers", async () => {
  const res = await apiRequest("/allWatchlist");
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("x-powered-by"), null, "X-Powered-By header must be suppressed");
  assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  assert.ok(res.headers.get("x-frame-options"), "X-Frame-Options should be set by helmet");
});

test("SEC-IDOR: Protected endpoints reject unauthenticated requests with 401", async () => {
  const unauthChecks = [
    ["DELETE", "/deleteBasket/000000000000000000000001"],
    ["PATCH", "/toggleSipStatus/000000000000000000000001"],
    ["PATCH", "/updateSipName/000000000000000000000001"],
    ["POST", "/executeSipNow/000000000000000000000001"],
    ["DELETE", "/deleteSip/000000000000000000000001"],
    ["PUT", "/updateAlert/000000000000000000000001"],
    ["PATCH", "/toggleAlertStatus/000000000000000000000001"],
    ["POST", "/resetAlert/000000000000000000000001"],
    ["DELETE", "/deleteAlert/000000000000000000000001"],
    ["DELETE", "/cancelIpoApplication/000000000000000000000001"],
    ["PUT", "/modifyIpoBid/000000000000000000000001"],
    ["POST", "/cancelGtt"],
    ["POST", "/triggerGtt"],
    ["GET", "/getNominee"],
    ["POST", "/addNominee"],
    ["POST", "/createSupportTicket"],
    ["GET", "/mySupportTickets"],
    ["POST", "/withdrawFunds"],
  ];

  for (const [method, route] of unauthChecks) {
    const res = await apiRequest(route, {
      method,
      body: method === "GET" || method === "DELETE" ? undefined : {},
    });
    assert.equal(res.status, 401, `${method} ${route} should return 401 without credentials (got ${res.status})`);
  }
});

test("SEC-IDOR-CrossTenant: User B cannot delete User A's basket; Owner User A can", async () => {
  const tokenA = mintToken("__SEC_TEST_USER_A__");
  const tokenB = mintToken("__SEC_TEST_USER_B__");
  await mongoose.connect(process.env.MONGO_URL);
  const users = mongoose.connection.db.collection("users");
  await users.deleteMany({ userId: { $in: ["__SEC_TEST_USER_A__", "__SEC_TEST_USER_B__"] } });
  await users.insertMany([
    { userId: "__SEC_TEST_USER_A__", email: "__sec_a@test.local", tokenVersion: 0 },
    { userId: "__SEC_TEST_USER_B__", email: "__sec_b@test.local", tokenVersion: 0 },
  ]);

  const createRes = await apiRequest("/saveBasket", {
    method: "POST",
    token: tokenA,
    body: {
      name: "__Security Regression Test Basket__",
      items: [{ symbol: "INFY", qty: 1, price: 1800, mode: "BUY", product: "CNC" }],
    },
  });
  assert.equal(createRes.status, 201);
  const basketId = createRes.data?.basket?._id;
  assert.ok(basketId);

  try {
    // Attacker (User B) tries to delete User A's basket
    const attackerRes = await apiRequest(`/deleteBasket/${basketId}`, {
      method: "DELETE",
      token: tokenB,
    });
    assert.equal(attackerRes.status, 404, "Cross-tenant delete must fail with 404");

    // Owner (User A) deletes own basket
    const ownerRes = await apiRequest(`/deleteBasket/${basketId}`, {
      method: "DELETE",
      token: tokenA,
    });
    assert.equal(ownerRes.status, 200);
  } finally {
    await apiRequest(`/deleteBasket/${basketId}`, { method: "DELETE", token: tokenA }).catch(() => {});
    await users.deleteMany({ userId: { $in: ["__SEC_TEST_USER_A__", "__SEC_TEST_USER_B__"] } });
  }
});

test("SEC-Funds: Withdraw rejects negative, non-numeric, and concurrent double-spend attempts", async () => {
  const testUser = "__SEC_TEST_FUNDS__";
  const token = mintToken(testUser);
  await mongoose.connect(process.env.MONGO_URL);
  const users = mongoose.connection.db.collection("users");
  const fundsCol = mongoose.connection.db.collection("funds");
  await users.deleteMany({ userId: testUser });
  await fundsCol.deleteMany({ userId: testUser });
  await users.insertOne({ userId: testUser, email: "__sec_funds@test.local", tokenVersion: 0 });
  await fundsCol.insertOne({
    userId: testUser,
    equity: {
      availableMargin: "1,24,500.00",
      usedMargin: "0.00",
      availableCash: "1,24,500.00",
      openingBalance: "1,24,500.00",
    },
  });

  for (const invalidAmount of [-500, 0, "NaN", "abc", 1000000000]) {
    const badRes = await apiRequest("/withdrawFunds", {
      method: "POST",
      token,
      body: { amount: invalidAmount },
    });
    assert.equal(badRes.status, 400, `Amount ${invalidAmount} must be rejected with 400`);
  }

  // Concurrent double-withdrawal race condition check (default cash is 1,24,500.00)
  try {
    const [r1, r2] = await Promise.all([
      apiRequest("/withdrawFunds", { method: "POST", token, body: { amount: 100000 } }),
      apiRequest("/withdrawFunds", { method: "POST", token, body: { amount: 100000 } }),
    ]);
    const statuses = [r1.status, r2.status].sort();
    assert.equal(statuses.includes(200), true, "One withdrawal should succeed");
    assert.equal(
      statuses.some((s) => s === 429 || s === 409 || s === 400),
      true,
      `Concurrent second withdrawal must be blocked (statuses: ${statuses.join(",")})`
    );
  } finally {
    if (process.env.MONGO_URL) {
      await mongoose.connect(process.env.MONGO_URL);
    if (mongoose.connection.readyState !== 1) {
      await new Promise((resolve) => mongoose.connection.once("connected", resolve));
    }
      await users.deleteMany({ userId: testUser });
    await mongoose.connection.db.collection("funds").deleteMany({ userId: testUser });
      await mongoose.connection.db.collection("fundstransactions").deleteMany({ userId: testUser });
      await mongoose.connection.db.collection("notifications").deleteMany({ userId: testUser });
      // kept connected for isolatedServer; disconnected in test.after
    }
  }
});
