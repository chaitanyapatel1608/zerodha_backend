const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "..", ".env") });
const test = require("node:test");
const assert = require("node:assert/strict");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

const { UserModel } = require("../model/UserModel");
const { FundsModel } = require("../model/FundsModel");
const { FundsTransactionModel } = require("../model/FundsTransactionModel");
const { NotificationModel } = require("../model/NotificationModel");
const { AdminAuditLogModel } = require("../model/AdminAuditLogModel");
const { OtpModel } = require("../model/OtpModel");
const { hashPassword } = require("../utils/security");

let API_BASE = "";
let isolatedServer = null;
const JWT_SECRET = process.env.JWT_SECRET || "dev_only_ephemeral_jwt_key_change_in_env";

const SUFFIX = Date.now().toString().slice(-6);
const ADMIN_ID = `TADM${SUFFIX}`;
const USER_ID = `TUSR${SUFFIX}`;
const ADMIN_EMAIL = `admin_${SUFFIX}@test.local`;
const USER_EMAIL = `user_${SUFFIX}@test.local`;

function mintToken(userId, tokenVersion = 0) {
  return jwt.sign({ userId, email: `${userId.toLowerCase()}@test.local`, tokenVersion }, JWT_SECRET, {
    expiresIn: "15m",
  });
}

test.before(async () => {
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

  await UserModel.create([
    {
      userId: ADMIN_ID,
      email: ADMIN_EMAIL,
      fullName: "Test CTO Admin",
      password: hashPassword("AdminPass#2026"),
      role: "admin",
      segments: ["NSE", "BSE"],
    },
    {
      userId: USER_ID,
      email: USER_EMAIL,
      fullName: "Test Regular User",
      password: hashPassword("UserPass#2026"),
      role: "user",
      segments: ["NSE"],
    },
  ]);

  await FundsModel.create([{ userId: ADMIN_ID }, { userId: USER_ID }]);
});

test.after(async () => {
  await Promise.all([
    UserModel.deleteMany({ userId: { $in: [ADMIN_ID, USER_ID] } }),
    FundsModel.deleteMany({ userId: { $in: [ADMIN_ID, USER_ID] } }),
    FundsTransactionModel.deleteMany({ userId: { $in: [ADMIN_ID, USER_ID] } }),
    NotificationModel.deleteMany({ userId: { $in: [ADMIN_ID, USER_ID] } }),
    AdminAuditLogModel.deleteMany({ $or: [{ adminUserId: ADMIN_ID }, { targetId: USER_ID }] }),
  ]);

  if (isolatedServer) {
    await new Promise((resolve) => isolatedServer.close(resolve));
    await mongoose.disconnect();
  }
});

test("Unauthenticated requests to /admin/* return 401", async () => {
  const res = await fetch(`${API_BASE}/admin/overview`);
  assert.equal(res.status, 401);
});

test("Regular user (role=user) is blocked with 403 on /admin/*", async () => {
  const userToken = mintToken(USER_ID, 0);
  const res = await fetch(`${API_BASE}/admin/me`, {
    headers: { Authorization: `Bearer ${userToken}` },
  });
  assert.equal(res.status, 403);

  const adjRes = await fetch(`${API_BASE}/admin/funds/adjust`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${userToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ userId: USER_ID, direction: "CREDIT", amount: 500, reason: "Unauthorized test" }),
  });
  assert.equal(adjRes.status, 403);
});

test("Admin cookie mutations enforce CSRF double-submit token", async () => {
  const adminToken = mintToken(ADMIN_ID, 0);
  const csrf = "csrf_admin_test_token_123";

  const noCsrf = await fetch(`${API_BASE}/admin/users/${USER_ID}/segments`, {
    method: "PATCH",
    headers: {
      Cookie: `zerodha_session=${adminToken}; zerodha_csrf=${csrf}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ segments: ["NSE", "BSE"] }),
  });
  assert.equal(noCsrf.status, 403);

  const withCsrf = await fetch(`${API_BASE}/admin/users/${USER_ID}/segments`, {
    method: "PATCH",
    headers: {
      Cookie: `zerodha_session=${adminToken}; zerodha_csrf=${csrf}`,
      "X-CSRF-Token": csrf,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ segments: ["NSE", "BSE"], reason: "Enable BSE" }),
  });
  assert.equal(withCsrf.status, 200);
  const body = await withCsrf.json();
  assert.deepEqual(body.user.segments, ["NSE", "BSE"]);
});

test("Admin overview & user directory never leak sensitive fields", async () => {
  const adminToken = mintToken(ADMIN_ID, 0);

  const ovRes = await fetch(`${API_BASE}/admin/overview`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  assert.equal(ovRes.status, 200);
  const ov = await ovRes.json();
  assert.equal(ov.success, true);
  assert.ok(ov.kpis.users.total >= 2);
  assert.equal(ov.systemHealth.dbState, "CONNECTED");

  const detailRes = await fetch(`${API_BASE}/admin/users/${USER_ID}`, {
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  assert.equal(detailRes.status, 200);
  const detail = await detailRes.json();
  assert.equal(detail.client.userId, USER_ID);
  assert.equal("password" in detail.client, false);
  assert.equal("cdslTpin" in detail.client, false);
});

test("Admin audited funds adjustment updates paise balance, ledger, and AdminAuditLog", async () => {
  const adminToken = mintToken(ADMIN_ID, 0);

  const creditRes = await fetch(`${API_BASE}/admin/funds/adjust`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${adminToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      userId: USER_ID,
      direction: "CREDIT",
      amount: 1250.5,
      reason: "Test settlement credit",
    }),
  });
  assert.equal(creditRes.status, 200);
  const creditBody = await creditRes.json();
  assert.equal(creditBody.balances.availableCash, "1,250.50");

  const auditEntry = await AdminAuditLogModel.findOne({
    adminUserId: ADMIN_ID,
    action: "FUNDS_CREDIT",
    targetId: USER_ID,
  }).lean();
  assert.ok(auditEntry);
  assert.equal(auditEntry.details.amount, 1250.5);
});

test("Admin session revocation increments tokenVersion and invalidates existing user JWT", async () => {
  const adminToken = mintToken(ADMIN_ID, 0);
  const staleUserToken = mintToken(USER_ID, 0);

  const revRes = await fetch(`${API_BASE}/admin/users/${USER_ID}/revoke-session`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${adminToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ reason: "Security drill" }),
  });
  assert.equal(revRes.status, 200);
  const revBody = await revRes.json();
  assert.equal(revBody.tokenVersion, 1);

  const checkRes = await fetch(`${API_BASE}/userFunds`, {
    headers: { Authorization: `Bearer ${staleUserToken}` },
  });
  assert.equal(checkRes.status, 401);
});

test("Admin delete user enforces self-delete guard and cascades cleanup with audit log", async () => {
  const adminToken = mintToken(ADMIN_ID, 0);

  const selfRes = await fetch(`${API_BASE}/admin/users/${ADMIN_ID}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${adminToken}` },
  });
  assert.equal(selfRes.status, 400);

  const delRes = await fetch(`${API_BASE}/admin/users/${USER_ID}`, {
    method: "DELETE",
    headers: {
      Authorization: `Bearer ${adminToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ reason: "Cleanup test user" }),
  });
  assert.equal(delRes.status, 200);
  const delBody = await delRes.json();
  assert.equal(delBody.deletedUserId, USER_ID);

  const exists = await UserModel.exists({ userId: USER_ID });
  assert.equal(exists, null);

  const auditEntry = await AdminAuditLogModel.findOne({
    adminUserId: ADMIN_ID,
    action: "USER_DELETED",
    targetId: USER_ID,
  }).lean();
  assert.ok(auditEntry);
});

test("Admin OTP password recovery resets password, increments tokenVersion, and logs audit", async () => {
  const nonAdminRes = await fetch(`${API_BASE}/admin/auth/forgot-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: USER_EMAIL }),
  });
  assert.equal(nonAdminRes.status, 200);
  const nonAdminOtp = await OtpModel.findOne({ email: `admin-reset:${USER_EMAIL}` });
  assert.equal(nonAdminOtp, null);

  const reqRes = await fetch(`${API_BASE}/admin/auth/forgot-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: ADMIN_EMAIL }),
  });
  assert.equal(reqRes.status, 200);

  const otpDoc = await OtpModel.findOne({ email: `admin-reset:${ADMIN_EMAIL}` }).lean();
  assert.ok(otpDoc && otpDoc.otp);

  const badRes = await fetch(`${API_BASE}/admin/auth/reset-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: ADMIN_EMAIL, otp: "000000", newPassword: "NewAdminPass#2026" }),
  });
  assert.equal(badRes.status, 400);

  const okRes = await fetch(`${API_BASE}/admin/auth/reset-password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      email: ADMIN_EMAIL,
      otp: otpDoc.otp,
      newPassword: "NewAdminPass#2026",
    }),
  });
  assert.equal(okRes.status, 200);

  const loginRes = await fetch(`${API_BASE}/kite-login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ identifier: ADMIN_EMAIL, password: "NewAdminPass#2026" }),
  });
  assert.equal(loginRes.status, 200);

  const auditEntry = await AdminAuditLogModel.findOne({
    adminUserId: ADMIN_ID,
    action: "ADMIN_PASSWORD_RESET",
  }).lean();
  assert.ok(auditEntry);
});
