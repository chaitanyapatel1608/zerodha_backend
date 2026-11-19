const test = require("node:test");
const assert = require("node:assert/strict");
const { validateTestDatabaseUrl, configureIntegrationEnvironment } = require("./helpers/testDatabaseGuard");

test("integration guard refuses unknown, remote, ordinary and ambiguous database targets", () => {
  for (const url of [undefined, "", "mongodb://127.0.0.1/production", "mongodb://db.example.com/zerodha_test_ci", "mongodb+srv://localhost/zerodha_test_ci", "mongodb://user:pass@localhost/zerodha_test_ci", "mongodb://localhost/zerodha_test_ci?authSource=production", "mongodb://localhost/zerodha_test_ci%2fproduction", "mongodb://localhost,remote/zerodha_test_ci"]) {
    assert.throws(() => validateTestDatabaseUrl(url), /TEST_MONGO_URL/);
  }
  assert.equal(validateTestDatabaseUrl("mongodb://127.0.0.1:27017/zerodha_test_ci?replicaSet=rs0"), "mongodb://127.0.0.1:27017/zerodha_test_ci?replicaSet=rs0");
});

test("integration setup never falls back to MONGO_URL and isolates mail/auth configuration", () => {
  const unsafe = { MONGO_URL: "mongodb://production/accounts" };
  assert.throws(() => configureIntegrationEnvironment(unsafe));
  assert.deepEqual(unsafe, { MONGO_URL: "mongodb://production/accounts" });
  const env = { ...unsafe, TEST_MONGO_URL: "mongodb://localhost/zerodha_test_ci", EMAIL_PASS: "secret", RESEND_API_KEY: "secret", JWT_SECRET: "production-key" };
  configureIntegrationEnvironment(env);
  assert.equal(env.NODE_ENV, "test");
  assert.equal(env.MONGO_URL, env.TEST_MONGO_URL);
  assert.equal(env.EMAIL_PASS, undefined);
  assert.equal(env.RESEND_API_KEY, undefined);
  assert.notEqual(env.JWT_SECRET, "production-key");
  assert.throws(() => configureIntegrationEnvironment({ TEST_MONGO_URL: env.TEST_MONGO_URL, TEST_API_BASE: "http://localhost:3002" }), /External/);
});
