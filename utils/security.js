const crypto = require("crypto");
const jwt = require("jsonwebtoken");

/**
 * Cryptographic Password Hashing (Scrypt with 16-byte random salt)
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(String(password), salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

/**
 * Constant-time password/PIN verification supporting scrypt salts and safe digest checks.
 */
function verifyPassword(password, stored) {
  if (!password || !stored || typeof stored !== "string") return false;
  if (!stored.includes(":")) {
    // Legacy plaintext fallback using fixed-length hash comparison to prevent timing leaks
    const a = crypto.createHash("sha256").update(String(password)).digest();
    const b = crypto.createHash("sha256").update(String(stored)).digest();
    return crypto.timingSafeEqual(a, b);
  }
  const [salt, key] = stored.split(":");
  if (!salt || !key) return false;
  const hash = crypto.scryptSync(String(password), salt, 64).toString("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(key, "hex"));
  } catch (e) {
    return false;
  }
}

/**
 * Constant-time equality check for short numeric OTP/token comparisons.
 */
function constantTimeEquals(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const da = crypto.createHash("sha256").update(a).digest();
  const db = crypto.createHash("sha256").update(b).digest();
  return crypto.timingSafeEqual(da, db);
}

/**
 * Escapes user-supplied strings before constructing RegExp filters to prevent ReDoS.
 */
function escapeRegex(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Validates MongoDB ObjectId strings without throwing CastError.
 */
function isValidObjectId(id) {
  return typeof id === "string" && /^[a-fA-F0-9]{24}$/.test(id.trim());
}

/**
 * Parses Cookie header string into key-value map without external dependencies.
 */
function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader || typeof cookieHeader !== "string") return cookies;
  const pairs = cookieHeader.split(";");
  for (const pair of pairs) {
    const idx = pair.indexOf("=");
    if (idx <= 0) continue;
    const key = pair.slice(0, idx).trim();
    const val = pair.slice(idx + 1).trim();
    if (key) {
      try {
        cookies[key] = decodeURIComponent(val);
      } catch (_) {
        cookies[key] = val;
      }
    }
  }
  return cookies;
}

/**
 * Resolves authenticated userId, tokenVersion, and authSource ("bearer" | "cookie")
 * from Authorization Bearer header or HttpOnly zerodha_session cookie.
 */
function resolveAuthContext(req, jwtSecret) {
  let token = null;
  let authSource = null;

  const authHeader = req?.headers?.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    token = authHeader.slice(7).trim();
    authSource = "bearer";
  } else if (req?.body?.authToken && typeof req.body.authToken === "string") {
    token = req.body.authToken.trim();
    authSource = "bearer";
  } else if (req?.headers?.cookie) {
    const cookies = parseCookies(req.headers.cookie);
    if (cookies.zerodha_session) {
      token = cookies.zerodha_session.trim();
      authSource = "cookie";
    }
  }

  // Support authenticated handoff token passed via secure redirect query
  if (!token && req?.query?.auth_token && typeof req.query.auth_token === "string") {
    token = req.query.auth_token.trim();
    authSource = "bearer";
  }

  if (!token) return null;
  try {
    const decoded = jwt.verify(token, jwtSecret, { algorithms: ["HS256"] });
    if (decoded && typeof decoded.userId === "string" && decoded.userId.trim() !== "") {
      return {
        userId: decoded.userId.trim(),
        tokenVersion: typeof decoded.tv === "number" ? decoded.tv : 0,
        authSource,
      };
    }
  } catch (e) {
    return null;
  }
  return null;
}

/**
 * Strictly resolves authenticated userId exclusively from verified Bearer JWT or session cookie.
 * Never trusts client-supplied req.body.userId or req.query.userId overrides.
 */
function resolveAuthenticatedUserId(req, jwtSecret) {
  const ctx = resolveAuthContext(req, jwtSecret);
  return ctx ? ctx.userId : null;
}

const {
  isEncrypted,
  encryptField,
  decryptField,
  blindIndex: hashSearchToken,
} = require("./encryption");

/**
 * PII Data Masking utilities for SEBI compliant client views and logs
 */
function maskPan(pan) {
  if (!pan || typeof pan !== "string") return "";
  const clean = pan.trim().toUpperCase();
  if (clean.length !== 10) return "******";
  return `${clean.slice(0, 5)}****${clean.slice(-1)}`;
}

function maskAadhaar(aadhaar) {
  if (!aadhaar || typeof aadhaar !== "string") return "";
  const clean = aadhaar.replace(/\D/g, "");
  if (clean.length < 4) return "********";
  return `********${clean.slice(-4)}`;
}

function maskPhone(phone) {
  if (!phone || typeof phone !== "string") return "";
  const clean = phone.replace(/\D/g, "");
  if (clean.length < 4) return "******";
  return `${clean.slice(0, 2)}******${clean.slice(-2)}`;
}

function maskEmail(email) {
  if (!email || typeof email !== "string" || !email.includes("@")) return "";
  const [user, domain] = email.trim().toLowerCase().split("@");
  if (user.length <= 2) return `*@${domain}`;
  return `${user[0]}***${user[user.length - 1]}@${domain}`;
}

module.exports = {
  hashPassword,
  verifyPassword,
  constantTimeEquals,
  escapeRegex,
  isValidObjectId,
  parseCookies,
  resolveAuthContext,
  resolveAuthenticatedUserId,
  isEncrypted,
  encryptField,
  decryptField,
  hashSearchToken,
  maskPan,
  maskAadhaar,
  maskPhone,
  maskEmail,
};
