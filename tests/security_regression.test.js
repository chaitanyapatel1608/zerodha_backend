const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");

process.env.NODE_ENV = "test";
require("dotenv").config();

const { app, startServer, stopServer } = require("../index");
const { JWT_SECRET } = require("../config/env");
const { UserModel } = require("../model/UserModel");
const { HoldingsModel } = require("../model/HoldingsModel");
const { BasketModel } = require("../model/BasketModel");
const { SipModel } = require("../model/SipModel");
const { SupportTicketModel } = require("../model/SupportTicketModel");
const { OtpModel } = require("../model/OtpModel");
const { hashPassword } = require("../utils/security");
const { encryptField, decryptField, isEncrypted } = require("../utils/encryption");

let server;
let baseUrl;

async function req(path, { method = "GET", token, cookie, csrf, body } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  if (cookie) headers.Cookie = cookie;
  if (csrf) headers["X-CSRF-Token"] = csrf;
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = null;
  try {
    data = JSON.parse(text);
  } catch (_) {}
  return { status: res.status, headers: res.headers, data, text };
}

function makeToken(userId, tokenVersion = 0) {
  return jwt.sign({ userId, email: `${userId}@example.com`, role: "user", tv: tokenVersion }, JWT_SECRET, {
    expiresIn: "1h",
  });
}

test.before(async () => {
  await mongoose.connect(process.env.MONGO_URL);
  server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  const addr = server.address();
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

test.after(async () => {
  if (server) {
    await new Promise((resolve) => server.close(resolve));
  }
  await mongoose.disconnect();
});

test("VULN-01 ReDoS: /masterInstruments escapes regex metacharacters and rejects oversized queries", async () => {
  const normal = await req("/masterInstruments?q=RELIANCE");
  assert.equal(normal.status, 200);
  assert.ok(normal.data.some((i) => i.symbol === "RELIANCE"));

  const t0 = Date.now();
  const malicious = await req("/masterInstruments?q=" + encodeURIComponent("((((a+)+)+)+)+$"));
  const elapsed = Date.now() - t0;
  assert.equal(malicious.status, 200);
  assert.ok(Array.isArray(malicious.data));
  assert.ok(elapsed < 1000, `Expected bounded search time, got ${elapsed}ms`);

  const tooLong = await req("/masterInstruments?q=" + "A".repeat(65));
  assert.equal(tooLong.status, 400);
});

test("VULN-02 BOLA: User B cannot create a SIP from User A's basket; Owner User A succeeds", async () => {
  const ts = Date.now();
  const userA = `__BOLA_A_${ts}__`;
  const userB = `__BOLA_B_${ts}__`;
  await UserModel.create([
    { userId: userA, email: `${userA}@example.com`, fullName: "User A", password: hashPassword("Pass@123") },
    { userId: userB, email: `${userB}@example.com`, fullName: "User B", password: hashPassword("Pass@123") },
  ]);
  const basketA = await BasketModel.create({
    userId: userA,
    name: "Secret Alpha Basket",
    items: [{ symbol: "INFY", qty: 1, price: 1500, mode: "BUY", product: "CNC" }],
    marginRequired: 1500,
  });

  try {
    const badIdRes = await req("/createSip", {
      method: "POST",
      token: makeToken(userB),
      body: { basketId: "not-an-objectid", frequency: "MONTHLY", scheduleDay: 5 },
    });
    assert.equal(badIdRes.status, 400);

    const crossTenant = await req("/createSip", {
      method: "POST",
      token: makeToken(userB),
      body: { basketId: String(basketA._id), frequency: "MONTHLY", scheduleDay: 5 },
    });
    assert.equal(crossTenant.status, 404);

    const ownerRes = await req("/createSip", {
      method: "POST",
      token: makeToken(userA),
      body: { basketId: String(basketA._id), frequency: "MONTHLY", scheduleDay: 5 },
    });
    assert.equal(ownerRes.status, 201);
  } finally {
    await SipModel.deleteMany({ userId: { $in: [userA, userB] } });
    await BasketModel.deleteMany({ _id: basketA._id });
    await UserModel.deleteMany({ userId: { $in: [userA, userB] } });
  }
});

test("VULN-04 CDSL E-DIS: CNC SELL requires server-side CDSL authorization and blocks expired/unverified users", async () => {
  const ts = Date.now();
  const uid = `__CDSL_ENF_${ts}__`;
  const email = `${uid.toLowerCase()}@example.com`;
  await UserModel.create({
    userId: uid,
    email,
    fullName: "CDSL Enforcer",
    password: hashPassword("Pass@123"),
    cdslTpin: hashPassword("654321"),
  });
  await HoldingsModel.create({
    userId: uid,
    name: "INFY",
    instrument: "INFY",
    qty: 5,
    avg: 1500,
    price: 1600,
    net: "+6.67%",
    day: "+1.00%",
  });

  const tok = makeToken(uid);
  try {
    // 1. Attempt CNC SELL without authorization -> 403
    const unauthSell = await req("/newOrder", {
      method: "POST",
      token: tok,
      body: { name: "INFY", qty: 1, price: 1600, mode: "SELL", product: "CNC" },
    });
    assert.equal(unauthSell.status, 403);
    assert.equal(unauthSell.data?.code, "CDSL_AUTH_REQUIRED");

    // 2. Expired authorization -> 403
    await UserModel.updateOne({ userId: uid }, { $set: { cdslAuthorizedUntil: new Date(Date.now() - 60_000) } });
    const expiredSell = await req("/newOrder", {
      method: "POST",
      token: tok,
      body: { name: "INFY", qty: 1, price: 1600, mode: "SELL", product: "CNC" },
    });
    assert.equal(expiredSell.status, 403);

    // 3. Complete valid CDSL OTP verification -> sets cdslAuthorizedUntil & permits CNC SELL
    await OtpModel.create({
      email: `${email}_cdsl_otp`,
      otp: "112233",
      expiresAt: new Date(Date.now() + 5 * 60_000),
      attempts: 0,
    });
    const verifyRes = await req("/cdsl/verify-otp", {
      method: "POST",
      token: tok,
      body: { otp: "112233" },
    });
    assert.equal(verifyRes.status, 200);
    assert.ok(verifyRes.data?.cdslAuthorizedUntil);

    const allowedSell = await req("/newOrder", {
      method: "POST",
      token: tok,
      body: { name: "INFY", qty: 1, price: 1600, mode: "SELL", product: "CNC" },
    });
    assert.equal(allowedSell.status, 201);
  } finally {
    await OtpModel.deleteMany({ email: `${email}_cdsl_otp` });
    await HoldingsModel.deleteMany({ userId: uid });
    await UserModel.deleteMany({ userId: uid });
  }
});

test("VULN-05 Auth & Session: HttpOnly cookies, CSRF double-submit check, and server-side logout revocation", async () => {
  const ts = Date.now();
  const uid = `__SESS_${ts}__`;
  const email = `${uid.toLowerCase()}@example.com`;
  await UserModel.create({
    userId: uid,
    email,
    fullName: "Session Tester",
    password: hashPassword("StrongPass@1"),
  });

  try {
    const loginRes = await req("/kite-login", {
      method: "POST",
      body: { identifier: uid, password: "StrongPass@1" },
    });
    assert.equal(loginRes.status, 200);
    const setCookies = loginRes.headers.getSetCookie ? loginRes.headers.getSetCookie() : [];
    const sessionCookie = setCookies.find((c) => c.startsWith("zerodha_session="));
    const csrfCookie = setCookies.find((c) => c.startsWith("zerodha_csrf="));
    assert.ok(sessionCookie && sessionCookie.includes("HttpOnly"), "zerodha_session must be HttpOnly");
    assert.ok(csrfCookie, "zerodha_csrf cookie must be issued");

    const cookiePair = [sessionCookie.split(";")[0], csrfCookie.split(";")[0]].join("; ");
    const csrfVal = csrfCookie.split(";")[0].split("=")[1];

    // Cookie-authenticated POST without X-CSRF-Token -> 403
    const noCsrf = await req("/logout", { method: "POST", cookie: cookiePair });
    assert.equal(noCsrf.status, 403);

    // Cookie-authenticated POST WITH valid X-CSRF-Token -> 200 and revokes tokenVersion
    const logoutOk = await req("/logout", { method: "POST", cookie: cookiePair, csrf: csrfVal });
    assert.equal(logoutOk.status, 200);

    // Prior JWT is immediately rejected after logout
    const reusedToken = await req("/verifyUser", { token: loginRes.data.token });
    assert.equal(reusedToken.status, 401);
  } finally {
    await UserModel.deleteMany({ userId: uid });
  }
});

test("VULN-06 ObjectId & Support Ticket: Rejects malformed :id with 400 and ignores spoofed ticket identity", async () => {
  const ts = Date.now();
  const uid = `__SUP_${ts}__`;
  await UserModel.create({
    userId: uid,
    email: `real_${ts}@example.com`,
    fullName: "Verified Owner",
    password: hashPassword("Pass@123"),
  });
  const tok = makeToken(uid);

  try {
    const badObjId = await req("/deleteBasket/invalid-id-123", { method: "DELETE", token: tok });
    assert.equal(badObjId.status, 400);

    const ticketRes = await req("/createSupportTicket", {
      method: "POST",
      token: tok,
      body: {
        userName: "Spoofed Admin",
        userEmail: "attacker@evil.com",
        subject: "Margin query",
        description: "Checking verified identity persistence.",
      },
    });
    assert.equal(ticketRes.status, 201);
    assert.equal(ticketRes.data.ticket.userName, "Verified Owner");
    assert.equal(ticketRes.data.ticket.userEmail, `real_${ts}@example.com`);
  } finally {
    await SupportTicketModel.deleteMany({ userId: uid });
    await UserModel.deleteMany({ userId: uid });
  }
});

test("VULN-07 Encryption: AES-256-GCM uses unique IVs, validates auth tags, and encrypts User PII at rest", async () => {
  const plain = "ABCDE1234F";
  const c1 = encryptField(plain);
  const c2 = encryptField(plain);
  assert.ok(isEncrypted(c1));
  assert.notEqual(c1, c2, "Unique random IV required per encryption");
  assert.equal(decryptField(c1), plain);
  assert.equal(decryptField("LEGACY_PLAINTEXT"), "LEGACY_PLAINTEXT");

  // Tamper ciphertext -> GCM auth tag rejection returns empty string safely
  const tampered = c1.slice(0, -4) + "ffff";
  assert.equal(decryptField(tampered), "");

  const ts = Date.now();
  const uid = `__ENC_${ts}__`;
  const user = await UserModel.create({
    userId: uid,
    email: `${uid}@example.com`,
    pan: "ABCDE1234F",
    dob: "1995-05-15",
    phone: "+919876543210",
  });
  try {
    const rawDoc = await UserModel.findById(user._id).lean();
    assert.ok(isEncrypted(rawDoc.pan), "PAN must be encrypted in MongoDB document");
    assert.ok(isEncrypted(rawDoc.dob), "DOB must be encrypted in MongoDB document");
    assert.ok(isEncrypted(rawDoc.phone), "Phone must be encrypted in MongoDB document");
    assert.equal(decryptField(rawDoc.pan), "ABCDE1234F");
  } finally {
    await UserModel.deleteMany({ userId: uid });
  }
});

test("AUD-01 Startup: Production enforces 64-hex DATA_ENCRYPTION_KEY at boot; non-prod allows test config", () => {
  const backendDir = path.resolve(__dirname, "..");
  const validKey = "a".repeat(64);

  const runEnvBoot = (extraEnv) => {
    try {
      execFileSync(process.execPath, ["-e", "require('./config/env')"], {
        cwd: backendDir,
        env: { ...process.env, ...extraEnv },
        stdio: "pipe",
      });
      return { code: 0 };
    } catch (err) {
      return { code: err.status ?? 1, stderr: String(err.stderr || "") };
    }
  };

  // 1. Production with missing key -> must fail
  const missing = runEnvBoot({
    NODE_ENV: "production",
    MONGO_URL: "mongodb://127.0.0.1:27017/test",
    JWT_SECRET: "prod_jwt_secret_123",
    DATA_ENCRYPTION_KEY: "",
  });
  assert.notEqual(missing.code, 0);

  // 2. Production with malformed key -> must fail without printing key
  const badKey = "not_a_valid_64_hex_key";
  const malformed = runEnvBoot({
    NODE_ENV: "production",
    MONGO_URL: "mongodb://127.0.0.1:27017/test",
    JWT_SECRET: "prod_jwt_secret_123",
    DATA_ENCRYPTION_KEY: badKey,
  });
  assert.notEqual(malformed.code, 0);
  assert.ok(!malformed.stderr.includes(badKey), "Startup error must never print the encryption key");

  // 3. Production with valid 64-hex key -> must succeed
  const valid = runEnvBoot({
    NODE_ENV: "production",
    MONGO_URL: "mongodb://127.0.0.1:27017/test",
    JWT_SECRET: "prod_jwt_secret_123",
    DATA_ENCRYPTION_KEY: validKey,
  });
  assert.equal(valid.code, 0);

  // 4. Test mode without DATA_ENCRYPTION_KEY -> must succeed
  const testMode = runEnvBoot({
    NODE_ENV: "test",
    DATA_ENCRYPTION_KEY: "",
  });
  assert.equal(testMode.code, 0);
});
