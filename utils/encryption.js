const crypto = require("crypto");

const PREFIX = "enc:v1:";

function resolvePrimaryKey() {
  const raw = process.env.DATA_ENCRYPTION_KEY;
  if (raw && /^[a-fA-F0-9]{64}$/.test(raw.trim())) {
    return Buffer.from(raw.trim(), "hex");
  }
  if (process.env.NODE_ENV === "production") {
    throw new Error("FATAL: DATA_ENCRYPTION_KEY (64 hex characters / 32 bytes) is required in production.");
  }
  // Ephemeral non-production fallback derived from runtime secret/process (never for production)
  const devSeed = process.env.JWT_SECRET || "dev_ephemeral_field_key_material";
  return crypto.scryptSync(devSeed, "zerodha_dev_field_salt", 32);
}

function getKeyring() {
  const keys = [resolvePrimaryKey()];
  const prev = process.env.DATA_ENCRYPTION_KEYS_PREVIOUS || "";
  for (const candidate of prev.split(",")) {
    const trimmed = candidate.trim();
    if (/^[a-fA-F0-9]{64}$/.test(trimmed)) {
      keys.push(Buffer.from(trimmed, "hex"));
    }
  }
  return keys;
}

function isEncrypted(value) {
  return typeof value === "string" && value.startsWith(PREFIX);
}

/**
 * Encrypts sensitive string with AES-256-GCM and a unique 12-byte IV.
 * Idempotent: returns already-encrypted values unchanged.
 */
function encryptField(plaintext) {
  if (plaintext === null || plaintext === undefined) return plaintext;
  const str = String(plaintext);
  if (str === "" || isEncrypted(str)) return str;

  const key = resolvePrimaryKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(str, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${PREFIX}${iv.toString("hex")}:${tag.toString("hex")}:${encrypted.toString("hex")}`;
}

/**
 * Decrypts AES-256-GCM field values. Supports legacy plaintext rows transparently
 * and tries previous rotation keys if configured.
 */
function decryptField(value) {
  if (value === null || value === undefined) return value;
  const str = String(value);
  if (!isEncrypted(str)) return str;

  const payload = str.slice(PREFIX.length);
  const parts = payload.split(":");
  if (parts.length !== 3) return "";

  const [ivHex, tagHex, cipherHex] = parts;
  let iv;
  let tag;
  let ciphertext;
  try {
    iv = Buffer.from(ivHex, "hex");
    tag = Buffer.from(tagHex, "hex");
    ciphertext = Buffer.from(cipherHex, "hex");
  } catch (_) {
    return "";
  }

  for (const key of getKeyring()) {
    try {
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return decrypted.toString("utf8");
    } catch (_) {
      // Try next key in rotation keyring
    }
  }
  return "";
}

/**
 * Keyed HMAC-SHA256 blind index for exact-match lookups on encrypted fields.
 */
function blindIndex(value) {
  if (!value) return "";
  const key = resolvePrimaryKey();
  return crypto.createHmac("sha256", key).update(String(value).trim().toUpperCase()).digest("hex");
}

module.exports = {
  isEncrypted,
  encryptField,
  decryptField,
  blindIndex,
};
