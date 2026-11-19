const test = require("node:test");
const assert = require("node:assert/strict");
const nodemailer = require("nodemailer");
const { sendOtpEmail } = require("../utils/emailService");

test("email dispatch preserves recipient, validates SMTP TLS and never logs OTP subjects/provider bodies", async (t) => {
  const previous = { ...process.env };
  const logs = [];
  const requests = [];
  let smtpOptions;
  for (const key of Object.keys(process.env)) if (/^(EMAIL_|EMAILJS_|RESEND_|BREVO_)/.test(key)) delete process.env[key];
  for (const level of ["log", "warn", "error"]) t.mock.method(console, level, (...args) => logs.push(args.join(" ")));
  t.mock.method(global, "fetch", async (_url, options) => {
    requests.push(JSON.parse(options.body));
    return { ok: true, json: async () => ({ id: "test-delivery" }) };
  });
  t.mock.method(nodemailer, "createTransport", options => {
    smtpOptions = options;
    return { sendMail: async () => ({ messageId: "test-smtp" }) };
  });
  try {
    Object.assign(process.env, { EMAILJS_SERVICE_ID: "fake", EMAILJS_TEMPLATE_ID: "fake", EMAILJS_PUBLIC_KEY: "fake" });
    assert.equal((await sendOtpEmail("alice@example.com", "742913")).delivered, true);
    assert.equal(requests[0].template_params.to_email, "alice@example.com");
    assert.ok(requests[0].template_params.subject.includes("742913"));
    delete process.env.EMAILJS_SERVICE_ID;
    process.env.RESEND_API_KEY = "fake";
    process.env.RESEND_TEST_RECIPIENT = "unrelated@example.com";
    assert.equal((await sendOtpEmail("alice@example.com", "742913")).delivered, true);
    assert.deepEqual(requests[1].to, ["alice@example.com"]);
    t.mock.method(global, "fetch", async () => ({ ok: false, status: 403, text: async () => "provider echoed OTP 742913" }));
    await sendOtpEmail("alice@example.com", "742913");
    delete process.env.RESEND_API_KEY;
    process.env.EMAIL_USER = "test@example.com";
    process.env.EMAIL_PASS = "fake";
    assert.equal((await sendOtpEmail("alice@example.com", "742913")).delivered, true);
    assert.equal(smtpOptions.tls.rejectUnauthorized, true);
    assert.equal(smtpOptions.requireTLS, true);
    assert.ok(!logs.join("\n").includes("742913"));
  } finally {
    for (const key of Object.keys(process.env)) if (!(key in previous)) delete process.env[key];
    Object.assign(process.env, previous);
  }
});
