const test = require("node:test");
const assert = require("node:assert/strict");
const jwt = require("jsonwebtoken");

const {
  toPaise,
  fromPaise,
  addPaise,
  subPaise,
  formatPaiseINR,
  formatIndianCurrency,
  validatePositiveAmount,
} = require("../utils/money");

const {
  isEncrypted,
  encryptField,
  decryptField,
  blindIndex,
} = require("../utils/encryption");

const {
  hashPassword,
  verifyPassword,
  constantTimeEquals,
  escapeRegex,
  isValidObjectId,
  parseCookies,
  resolveAuthContext,
  resolveAuthenticatedUserId,
} = require("../utils/security");

const { escapeHtml, renderConfirmationPage } = require("../utils/html");

// ==========================================
// 1. Money & Integer-Paise Precision Unit Tests
// ==========================================

test("UNIT-Money: toPaise & fromPaise handle IEEE-754 decimals, commas, and invalid inputs", () => {
  assert.equal(toPaise(0.1) + toPaise(0.2), 30);
  assert.equal(fromPaise(addPaise(toPaise(0.1), toPaise(0.2))), 0.3);
  assert.equal(subPaise(toPaise(1000.5), toPaise(0.55)), 99995);
  assert.equal(toPaise("1,23,456.78"), 12345678);
  assert.equal(toPaise("  99.99 "), 9999);
  assert.equal(toPaise(""), 0);
  assert.equal(toPaise("   "), 0);
  assert.equal(toPaise("abc"), 0);
  assert.equal(toPaise(NaN), 0);
  assert.equal(toPaise(Infinity), 0);
  assert.equal(toPaise(-Infinity), 0);
  assert.equal(toPaise(null), 0);
  assert.equal(toPaise(undefined), 0);
  assert.equal(fromPaise(NaN), 0);
  assert.equal(fromPaise(Infinity), 0);
  assert.equal(formatPaiseINR(12345678), "1,23,456.78");
  assert.equal(formatIndianCurrency(1000), "1,000.00");
});

test("UNIT-Money: validatePositiveAmount enforces min/max boundaries and rejects non-finite inputs", () => {
  assert.equal(validatePositiveAmount(1).valid, true);
  assert.equal(validatePositiveAmount(1).paise, 100);
  assert.equal(validatePositiveAmount(0.99).valid, false);
  assert.equal(validatePositiveAmount(0).valid, false);
  assert.equal(validatePositiveAmount(-50).valid, false);
  assert.equal(validatePositiveAmount(100000000).valid, true);
  assert.equal(validatePositiveAmount(100000001).valid, false);
  assert.equal(validatePositiveAmount("1e3").valid, true);
  assert.equal(validatePositiveAmount("1e3").amount, 1000);
  assert.equal(validatePositiveAmount(NaN).valid, false);
  assert.equal(validatePositiveAmount(Infinity).valid, false);
  assert.equal(validatePositiveAmount(null).valid, false);
  assert.equal(validatePositiveAmount("").valid, false);
  assert.equal(validatePositiveAmount("invalid").valid, false);
});

// ==========================================
// 2. AES-256-GCM Encryption & Blind Index Tests
// ==========================================

test("UNIT-Encryption: encryptField, decryptField, tamper resistance, and key rotation", () => {
  const prevKey = process.env.DATA_ENCRYPTION_KEY;
  const prevOld = process.env.DATA_ENCRYPTION_KEYS_PREVIOUS;
  const keyA = "a".repeat(64);
  const keyB = "b".repeat(64);

  try {
    process.env.DATA_ENCRYPTION_KEY = keyA;
    delete process.env.DATA_ENCRYPTION_KEYS_PREVIOUS;

    assert.equal(encryptField(null), null);
    assert.equal(encryptField(undefined), undefined);
    assert.equal(encryptField(""), "");
    assert.equal(decryptField(null), null);
    assert.equal(decryptField(undefined), undefined);
    assert.equal(decryptField("LEGACY_PLAIN"), "LEGACY_PLAIN");

    const ct1 = encryptField("ABCDE1234F");
    const ct2 = encryptField("ABCDE1234F");
    assert.ok(isEncrypted(ct1));
    assert.notEqual(ct1, ct2, "Each encryption must use a fresh 12-byte IV");
    assert.equal(encryptField(ct1), ct1, "encryptField must be idempotent");
    assert.equal(decryptField(ct1), "ABCDE1234F");

    // Tampered auth tag or malformed format must fail closed to ""
    const parts = ct1.split(":");
    parts[3] = "0".repeat(parts[3].length);
    assert.equal(decryptField(parts.join(":")), "");
    assert.equal(decryptField("enc:v1:malformed"), "");

    // Key rotation: rotate to keyB while keeping keyA in DATA_ENCRYPTION_KEYS_PREVIOUS
    process.env.DATA_ENCRYPTION_KEY = keyB;
    process.env.DATA_ENCRYPTION_KEYS_PREVIOUS = keyA;
    assert.equal(decryptField(ct1), "ABCDE1234F");

    // Blind index normalizes whitespace and case
    assert.equal(blindIndex(""), "");
    assert.equal(blindIndex(" abcde1234f "), blindIndex("ABCDE1234F"));
  } finally {
    if (prevKey === undefined) delete process.env.DATA_ENCRYPTION_KEY;
    else process.env.DATA_ENCRYPTION_KEY = prevKey;
    if (prevOld === undefined) delete process.env.DATA_ENCRYPTION_KEYS_PREVIOUS;
    else process.env.DATA_ENCRYPTION_KEYS_PREVIOUS = prevOld;
  }
});

// ==========================================
// 3. Security Helpers, Cookie Parser & JWT Resolver
// ==========================================

test("UNIT-Security: scrypt hashing, constantTimeEquals, escapeRegex, ObjectId, and cookies", () => {
  const hashed = hashPassword("StrongPass#2026");
  assert.ok(hashed.includes(":"));
  assert.equal(verifyPassword("StrongPass#2026", hashed), true);
  assert.equal(verifyPassword("WrongPass", hashed), false);
  assert.equal(verifyPassword("", hashed), false);
  assert.equal(verifyPassword("abc", null), false);
  assert.equal(verifyPassword("abc", "bad:format:extra"), false);
  // Legacy non-salted fallback
  assert.equal(verifyPassword("legacySecret", "legacySecret"), true);
  assert.equal(verifyPassword("wrong", "legacySecret"), false);

  assert.equal(constantTimeEquals("123456", "123456"), true);
  assert.equal(constantTimeEquals("123456", "123457"), false);
  assert.equal(constantTimeEquals("123456", 123456), false);

  const escaped = escapeRegex("a+b*(c)?[d]{1}^$.|\\");
  assert.doesNotThrow(() => new RegExp(escaped));

  assert.equal(isValidObjectId("507f1f77bcf86cd799439011"), true);
  assert.equal(isValidObjectId(" 507f1f77bcf86cd799439011 "), true);
  assert.equal(isValidObjectId("507f1f77bcf86cd79943901"), false);
  assert.equal(isValidObjectId("507f1f77bcf86cd79943901z"), false);
  assert.equal(isValidObjectId(null), false);

  const parsed = parseCookies("zerodha_session=abc%20123; zerodha_csrf=xyz; bad=%E0%A4%A");
  assert.equal(parsed.zerodha_session, "abc 123");
  assert.equal(parsed.zerodha_csrf, "xyz");
  assert.equal(parsed.bad, "%E0%A4%A");
  assert.deepEqual(parseCookies(""), {});
});

test("UNIT-Security: resolveAuthContext validates HS256 JWTs from Bearer and cookie", () => {
  const secret = "unit_test_jwt_secret_64_chars_minimum_for_hs256_verification";
  const validToken = jwt.sign({ userId: "ZU1001", tv: 2 }, secret, { expiresIn: "1h" });
  const expiredToken = jwt.sign({ userId: "ZU1001", tv: 0 }, secret, { expiresIn: -10 });
  const wrongSecretToken = jwt.sign({ userId: "ZU1001" }, "wrong_secret", { expiresIn: "1h" });
  const emptyUserToken = jwt.sign({ userId: "   " }, secret, { expiresIn: "1h" });

  const bearerCtx = resolveAuthContext({ headers: { authorization: `Bearer ${validToken}` } }, secret);
  assert.deepEqual(bearerCtx, { userId: "ZU1001", tokenVersion: 2, authSource: "bearer" });

  const cookieCtx = resolveAuthContext({ headers: { cookie: `zerodha_session=${validToken}` } }, secret);
  assert.deepEqual(cookieCtx, { userId: "ZU1001", tokenVersion: 2, authSource: "cookie" });

  assert.equal(resolveAuthenticatedUserId({ headers: { authorization: `Bearer ${expiredToken}` } }, secret), null);
  assert.equal(resolveAuthenticatedUserId({ headers: { authorization: `Bearer ${wrongSecretToken}` } }, secret), null);
  assert.equal(resolveAuthenticatedUserId({ headers: { authorization: `Bearer ${emptyUserToken}` } }, secret), null);
  assert.equal(resolveAuthenticatedUserId({ query: { userId: "SPOOF" }, body: { userId: "SPOOF" } }, secret), null);
});

// ==========================================
// 4. HTML Escaping & Confirmation Template Tests
// ==========================================

test("UNIT-HTML: escapeHtml and renderConfirmationPage neutralize XSS payloads", () => {
  assert.equal(escapeHtml(null), "");
  assert.equal(escapeHtml(undefined), "");
  assert.equal(escapeHtml(`<script>"'&`), "&lt;script&gt;&quot;&#39;&amp;");

  const html = renderConfirmationPage({
    title: `<img src=x onerror=alert(1)>`,
    subtitle: "Confirm",
    actionUrl: "https://api.example.com/action",
    token: `tok" onclick="alert(2)`,
    decision: "REJECT",
    details: [["Amount", "₹1,000.00"]],
    returnUrl: "https://kite.example.com/funds",
  });
  assert.ok(html.includes('method="POST"'));
  assert.ok(!html.includes("<img src=x"));
  assert.ok(!html.includes('onclick="alert(2)'));
});
