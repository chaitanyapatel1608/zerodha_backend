const { randomBytes } = require("node:crypto");

function validateTestDatabaseUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new Error("TEST_MONGO_URL must specify a disposable local database"); }
  if (url.protocol !== "mongodb:" ||
      !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname) ||
      url.username || url.password ||
      !/^\/zerodha_test_[a-z0-9_]+$/.test(url.pathname) ||
      url.hash ||
      [...url.searchParams.keys()].some(key => !["replicaSet", "directConnection", "serverSelectionTimeoutMS"].includes(key))) {
    throw new Error("TEST_MONGO_URL must use loopback and a zerodha_test_ database; remote/authenticated targets are refused");
  }
  return url.href;
}

function configureIntegrationEnvironment(env = process.env) {
  // Validate before altering the environment or importing any application module.
  const uri = validateTestDatabaseUrl(env.TEST_MONGO_URL);
  if (env.TEST_API_BASE) throw new Error("External TEST_API_BASE targets are refused; integration tests start their own server");
  env.NODE_ENV = "test";
  env.MONGO_URL = uri;
  env.JWT_SECRET = randomBytes(32).toString("hex");
  env.DATA_ENCRYPTION_KEY = "a".repeat(64);
  delete env.DATA_ENCRYPTION_KEYS_PREVIOUS;
  for (const key of Object.keys(env)) {
    if (/^(EMAIL_|EMAILJS_|RESEND_|BREVO_)/.test(key)) delete env[key];
  }
  return uri;
}

module.exports = { validateTestDatabaseUrl, configureIntegrationEnvironment };
