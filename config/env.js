const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "..", ".env") });

const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PROD = NODE_ENV === "production";
const IS_TEST = NODE_ENV === "test";

if (!process.env.MONGO_URL && !IS_TEST) {
  console.error("FATAL: MONGO_URL environment variable is required.");
  process.exit(1);
}

if (IS_PROD && !process.env.JWT_SECRET) {
  console.error("FATAL: JWT_SECRET environment variable must be configured in production.");
  process.exit(1);
}

if (IS_PROD) {
  const rawEncKey = process.env.DATA_ENCRYPTION_KEY;
  if (!rawEncKey || !/^[a-fA-F0-9]{64}$/.test(rawEncKey.trim())) {
    console.error("FATAL: DATA_ENCRYPTION_KEY (64 hexadecimal characters / 32 bytes) must be configured in production.");
    process.exit(1);
  }
}

// Development/test ephemeral fallback if JWT_SECRET is omitted locally (never allowed in production)
const JWT_SECRET =
  process.env.JWT_SECRET ||
  (IS_PROD ? "" : "dev_only_ephemeral_jwt_key_change_in_env");

const PORT = Number(process.env.PORT) || 3002;
const MONGO_URL = process.env.MONGO_URL;
const PUBLIC_FRONTEND_URL = process.env.PUBLIC_FRONTEND_URL || "http://localhost:3001";
const PUBLIC_BACKEND_URL = process.env.PUBLIC_BACKEND_URL || "http://localhost:3002";

const rawAllowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const ALLOWED_ORIGINS = [
  ...(!IS_PROD
    ? ["http://localhost:3000", "http://localhost:3001", "http://localhost:3003"]
    : []),
  ...rawAllowedOrigins,
  process.env.FRONTEND_URL,
  process.env.PUBLIC_FRONTEND_URL,
  process.env.ADMIN_URL,
  process.env.PUBLIC_ADMIN_URL,
].filter(Boolean);

module.exports = {
  NODE_ENV,
  IS_PROD,
  IS_TEST,
  PORT,
  MONGO_URL,
  JWT_SECRET,
  PUBLIC_FRONTEND_URL,
  PUBLIC_BACKEND_URL,
  ALLOWED_ORIGINS,
};
