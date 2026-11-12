const SENSITIVE_KEYS = new Set([
  "password",
  "token",
  "jwt",
  "otp",
  "devotp",
  "tpin",
  "cdsltpin",
  "devtpin",
  "approvaltoken",
  "mandatetoken",
  "authorization",
  "cookie",
  "pan",
  "secret",
]);

function redactObject(value, depth = 0) {
  if (depth > 4 || value === null || value === undefined) return value;
  if (typeof value !== "object") return value;
  if (Array.isArray(value)) return value.slice(0, 20).map((v) => redactObject(v, depth + 1));

  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (SENSITIVE_KEYS.has(k.toLowerCase())) {
      out[k] = "[REDACTED]";
    } else {
      out[k] = redactObject(v, depth + 1);
    }
  }
  return out;
}

function writeLog(level, event, meta = {}) {
  const entry = {
    ts: new Date().toISOString(),
    level,
    event,
    ...redactObject(meta),
  };
  const line = JSON.stringify(entry);
  if (level === "error") {
    console.error(line);
  } else if (level === "warn") {
    console.warn(line);
  } else if (process.env.NODE_ENV !== "test") {
    console.log(line);
  }
}

module.exports = {
  info: (event, meta) => writeLog("info", event, meta),
  warn: (event, meta) => writeLog("warn", event, meta),
  error: (event, meta) => writeLog("error", event, meta),
  redactObject,
};
