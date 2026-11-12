const crypto = require("crypto");
const jwt = require("jsonwebtoken");

/**
 * Cryptographic Password Hashing (Scrypt with 16-byte random salt)
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

/**
 * Constant-time password verification supporting scrypt salts and legacy migration.
 */
function verifyPassword(password, stored) {
  if (!stored) return false;
  if (!stored.includes(":")) {
    return stored === password;
  }
  const [salt, key] = stored.split(":");
  if (!salt || !key) return false;
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(key, "hex"));
  } catch (e) {
    return false;
  }
}

/**
 * Escapes user-supplied strings before constructing RegExp filters to prevent ReDoS.
 */
function escapeRegex(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Resolves authenticated userId from Bearer JWT; rejects query/body spoofing in production.
 */
function resolveAuthenticatedUserId(req, jwtSecret, nodeEnv = process.env.NODE_ENV) {
  const authHeader = req?.headers?.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    try {
      const token = authHeader.split(" ")[1];
      const decoded = jwt.verify(token, jwtSecret);
      if (decoded && decoded.userId) {
        return decoded.userId;
      }
    } catch (e) {
      // Invalid or expired JWT falls through to null in production
    }
  }
  if (nodeEnv === "production") {
    return null;
  }
  const explicitId = req?.query?.userId || req?.body?.userId;
  if (explicitId && typeof explicitId === "string" && explicitId.trim() !== "") {
    return explicitId.trim();
  }
  return null;
}

module.exports = {
  hashPassword,
  verifyPassword,
  escapeRegex,
  resolveAuthenticatedUserId,
};
