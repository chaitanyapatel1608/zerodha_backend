const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "..", ".env") });
const test = require("node:test");
const assert = require("node:assert/strict");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const { hashPassword } = require("../utils/security");
const {
  toPaise,
  fromPaise,
  addPaise,
  subPaise,
  formatPaiseINR,
  validatePositiveAmount,
} = require("../utils/money");
const { escapeHtml, renderConfirmationPage } = require("../utils/html");

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

function mintToken(userId, email) {
  return jwt.sign({ userId, email: email || `${userId.toLowerCase()}@test.local` }, JWT_SECRET, {
    expiresIn: "15m",
  });
}

async function apiRequest(route, { method = "GET", token, body, rawBody, headers: extraHeaders } = {}) {
  const headers = { ...(extraHeaders || {}) };
  if (rawBody === undefined && body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${route}`, {
    method,
    headers,
    body: rawBody !== undefined ? rawBody : body !== undefined ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  let data = null;
  try {
    data = JSON.parse(text);
  } catch (e) {}
  return { status: res.status, headers: res.headers, data, text };
}

test("MONEY-Paise: Eliminates floating-point drift and validates numeric bounds", () => {
  // 0.1 + 0.2 === 0.30000000000000004 in IEEE-754
  const sumPaise = addPaise(toPaise(0.1), toPaise(0.2));
  assert.equal(sumPaise, 30);
  assert.equal(fromPaise(sumPaise), 0.3);

  const remPaise = subPaise(toPaise("1,24,500.00"), toPaise(24500.25));
  assert.equal(remPaise, 9999975);
  assert.equal(formatPaiseINR(remPaise), "99,999.75");

  assert.equal(validatePositiveAmount(-10).valid, false);
  assert.equal(validatePositiveAmount(NaN).valid, false);
  assert.equal(validatePositiveAmount(1000000000).valid, false);
  assert.equal(validatePositiveAmount("2500.50").paise, 250050);
});

test("HTML-XSS: escapeHtml neutralizes script tags and confirmation form uses POST", () => {
  const escaped = escapeHtml(`<script>alert("xss")</script>'&`);
  assert.equal(escaped.includes("<script>"), false);
  assert.ok(escaped.includes("&lt;script&gt;"));

  const html = renderConfirmationPage({
    title: "Approve <Deposit>",
    subtitle: "Check details",
    actionUrl: "http://localhost:3002/fundDeposit/action",
    token: "tok123",
    decision: "APPROVE",
    details: [["UPI", "test<script>@upi"]],
    returnUrl: "http://localhost:3001/funds",
  });
  assert.ok(html.includes('method="POST"'));
  assert.equal(html.includes("<script>"), false);
});

test("OBS-Health: /health and /ready return 200 and service status", async () => {
  const h = await apiRequest("/health");
  assert.equal(h.status, 200);
  assert.equal(h.data?.status, "ok");

  const r = await apiRequest("/ready");
  assert.equal(r.status, 200);
  assert.equal(r.data?.status, "ready");
});

test("AUTH-ProtectedRoutes: Newly hardened routes reject unauthenticated calls with 401", async () => {
  const checks = [
    ["GET", "/verifyUser?userId=SPOOF"],
    ["GET", "/userFunds?userId=SPOOF"],
    ["GET", "/allHoldings"],
    ["GET", "/allOrders"],
    ["GET", "/userWatchlist"],
    ["GET", "/notifications"],
    ["PATCH", "/notifications/000000000000000000000001/read"],
    ["DELETE", "/notifications/000000000000000000000001"],
    ["POST", "/fundDeposit/initiate"],
    ["POST", "/pledgeHolding"],
    ["POST", "/cdsl/generate-tpin"],
    ["POST", "/sendSegmentOtp"],
    ["POST", "/newOrder"],
  ];
  for (const [method, route] of checks) {
    const res = await apiRequest(route, {
      method,
      body: method === "GET" || method === "DELETE" ? undefined : { userId: "SPOOF" },
    });
    assert.equal(res.status, 401, `${method} ${route} expected 401, got ${res.status}`);
  }
});

test("AUTH-KiteLogin & VerifyUser: Blocks passwordless login, unset password, and hides PII", async () => {
  const uidUnset = `__TEST_UNSET_${Date.now()}__`;
  const uidValid = `__TEST_VALID_${Date.now()}__`;
  await mongoose.connect(process.env.MONGO_URL);
  const users = mongoose.connection.db.collection("users");
  try {
    await users.insertMany([
      {
        userId: uidUnset,
        email: `${uidUnset.toLowerCase()}@test.local`,
        fullName: "Unset User",
        pan: "ABCDE1234F",
      },
      {
        userId: uidValid,
        email: `${uidValid.toLowerCase()}@test.local`,
        fullName: "Valid User",
        password: hashPassword("CorrectPass@2026"),
        pan: "XYZPQ9876K",
        dob: "1995-01-01",
      },
    ]);

    // Missing password -> 400
    const missingPw = await apiRequest("/kite-login", {
      method: "POST",
      body: { identifier: uidValid },
    });
    assert.equal(missingPw.status, 400);

    // Account with no password initialized -> 403
    const unsetPw = await apiRequest("/kite-login", {
      method: "POST",
      body: { identifier: uidUnset, password: "AnyPassword1" },
    });
    assert.equal(unsetPw.status, 403);
    assert.equal(unsetPw.data?.code, "PASSWORD_NOT_INITIALIZED");

    // Wrong password -> 401
    const wrongPw = await apiRequest("/kite-login", {
      method: "POST",
      body: { identifier: uidValid, password: "WrongPassword99" },
    });
    assert.equal(wrongPw.status, 401);

    // Correct password -> 200, no PII (pan/dob/password) returned
    const okLogin = await apiRequest("/kite-login", {
      method: "POST",
      body: { identifier: uidValid, password: "CorrectPass@2026" },
    });
    assert.equal(okLogin.status, 200);
    assert.ok(okLogin.data?.token);
    assert.equal(okLogin.data?.user?.pan, undefined);
    assert.equal(okLogin.data?.user?.dob, undefined);
    assert.equal(okLogin.data?.user?.password, undefined);

    // VerifyUser uses JWT and strips secrets
    const verifyRes = await apiRequest(`/verifyUser?userId=${uidUnset}`, {
      method: "GET",
      token: okLogin.data.token,
    });
    assert.equal(verifyRes.status, 200);
    assert.equal(verifyRes.data?.user?.userId, uidValid);
    assert.equal(verifyRes.data?.user?.password, undefined);
  } finally {
    await users.deleteMany({ userId: { $in: [uidUnset, uidValid] } });
    // kept connected for isolatedServer; disconnected in test.after
  }
});

test("IDOR-Notifications: Cross-tenant notification read/delete rejected with 404", async () => {
  const userA = `__NOTIF_A_${Date.now()}__`;
  const userB = `__NOTIF_B_${Date.now()}__`;
  const tokenA = mintToken(userA);
  const tokenB = mintToken(userB);
  await mongoose.connect(process.env.MONGO_URL);
  const notifs = mongoose.connection.db.collection("notifications");
  const users = mongoose.connection.db.collection("users");
  let insertedId = null;
  try {
    await users.insertMany([
      { userId: userA, email: `${userA.toLowerCase()}@test.local`, tokenVersion: 0 },
      { userId: userB, email: `${userB.toLowerCase()}@test.local`, tokenVersion: 0 },
    ]);
    const ins = await notifs.insertOne({
      userId: userA,
      type: "ORDER",
      category: "EXECUTION",
      title: "Private Order Notice",
      description: "Test tenant notification",
      unread: true,
      createdAt: new Date(),
    });
    insertedId = ins.insertedId.toString();

    const readAttacker = await apiRequest(`/notifications/${insertedId}/read`, {
      method: "PATCH",
      token: tokenB,
    });
    assert.equal(readAttacker.status, 404);

    const delAttacker = await apiRequest(`/notifications/${insertedId}`, {
      method: "DELETE",
      token: tokenB,
    });
    assert.equal(delAttacker.status, 404);

    const readOwner = await apiRequest(`/notifications/${insertedId}/read`, {
      method: "PATCH",
      token: tokenA,
    });
    assert.equal(readOwner.status, 200);
  } finally {
    await notifs.deleteMany({ userId: { $in: [userA, userB] } });
    await users.deleteMany({ userId: { $in: [userA, userB] } });
    // kept connected for isolatedServer; disconnected in test.after
  }
});

test("FIN-Deposit-Confirmation: GET does not mutate state; POST approves once & blocks replay", async () => {
  const uid = `__DEP_TEST_${Date.now()}__`;
  const token = mintToken(uid, `${uid.toLowerCase()}@test.local`);
  await mongoose.connect(process.env.MONGO_URL);
  const db = mongoose.connection.db;
  try {
    await db.collection("users").insertOne({
      userId: uid,
      email: `${uid.toLowerCase()}@test.local`,
      fullName: "Deposit Tester",
    });

    const initRes = await apiRequest("/fundDeposit/initiate", {
      method: "POST",
      token,
      body: { amount: 5000.25, upiId: "tester@okhdfcbank", userEmail: "attacker@evil.com" },
    });
    assert.equal(initRes.status, 201);
    assert.equal(initRes.data?.approveUrl, undefined, "approveUrl must not leak in JSON");
    assert.equal(initRes.data?.transaction?.approvalToken, undefined, "approvalToken must not leak in JSON");

    const txDoc = await db.collection("funds_transactions").findOne({ userId: uid });
    assert.ok(txDoc?.approvalToken);

    // GET confirmation renders HTML form without mutating balance or status
    const getAction = await apiRequest(
      `/fundDeposit/action?token=${txDoc.approvalToken}&decision=APPROVE`,
      { method: "GET" }
    );
    assert.equal(getAction.status, 200);
    assert.ok(getAction.text.includes('method="POST"'));

    const afterGetTx = await db.collection("funds_transactions").findOne({ _id: txDoc._id });
    assert.equal(afterGetTx.status, "PENDING_APPROVAL", "GET must not mutate transaction state");

    // POST executes credit atomically
    const form = new URLSearchParams({ token: txDoc.approvalToken, decision: "APPROVE" });
    const postAction = await apiRequest("/fundDeposit/action", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      rawBody: form.toString(),
    });
    assert.equal(postAction.status, 200);

    const completedTx = await db.collection("funds_transactions").findOne({ _id: txDoc._id });
    assert.equal(completedTx.status, "COMPLETED");
    assert.equal(completedTx.approvalToken, null);

    // Second POST replay must fail cleanly with 409
    const replayAction = await apiRequest("/fundDeposit/action", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      rawBody: form.toString(),
    });
    assert.equal(replayAction.status, 409);
  } finally {
    await db.collection("users").deleteMany({ userId: uid });
    await db.collection("funds").deleteMany({ userId: uid });
    await db.collection("funds_transactions").deleteMany({ userId: uid });
    await db.collection("notifications").deleteMany({ userId: uid });
    // kept connected for isolatedServer; disconnected in test.after
  }
});

test("CDSL-TPIN: Stores scrypt hash, never leaks devTpin outside test, and locks after 5 invalid attempts", async () => {
  const uid = `__CDSL_TEST_${Date.now()}__`;
  const token = mintToken(uid);
  await mongoose.connect(process.env.MONGO_URL);
  const db = mongoose.connection.db;
  try {
    await db.collection("users").insertOne({
      userId: uid,
      email: `${uid.toLowerCase()}@test.local`,
      fullName: "CDSL Tester",
    });

    const genRes = await apiRequest("/cdsl/generate-tpin", {
      method: "POST",
      token,
    });
    assert.equal(genRes.status, 200);
    // Running server in development/production must never return devTpin
    assert.equal(genRes.data?.devTpin, undefined);

    const userDoc = await db.collection("users").findOne({ userId: uid });
    assert.ok(userDoc.cdslTpin && userDoc.cdslTpin.includes(":"), "CDSL TPIN must be stored as salt:hash");

    // 4 wrong attempts return 400, 5th locks account with 429
    for (let i = 1; i <= 4; i++) {
      const bad = await apiRequest("/cdsl/verify-tpin", {
        method: "POST",
        token,
        body: { tpin: "000000" },
      });
      assert.equal(bad.status, 400, `Attempt ${i} expected 400, got ${bad.status}`);
    }
    const fifth = await apiRequest("/cdsl/verify-tpin", {
      method: "POST",
      token,
      body: { tpin: "000000" },
    });
    assert.equal(fifth.status, 429, "5th wrong TPIN attempt must enforce 429 lockout");
  } finally {
    await db.collection("users").deleteMany({ userId: uid });
  }
});
