/**
 * Integer-paise monetary arithmetic & strict validation utilities.
 * Stores all arithmetic internally as integer paise (1 INR = 100 paise)
 * to eliminate IEEE-754 floating-point rounding drift while preserving
 * backward-compatible INR string formatting.
 */

function toPaise(value) {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) return 0;
    return Math.round(value * 100);
  }
  if (typeof value === "string") {
    const cleaned = value.replace(/,/g, "").trim();
    if (!cleaned) return 0;
    const parsed = Number(cleaned);
    if (!Number.isFinite(parsed)) return 0;
    return Math.round(parsed * 100);
  }
  return 0;
}

function fromPaise(paise) {
  const n = Number(paise);
  if (!Number.isFinite(n)) return 0;
  return Math.round(n) / 100;
}

function addPaise(a, b) {
  return Math.round(a) + Math.round(b);
}

function subPaise(a, b) {
  return Math.round(a) - Math.round(b);
}

function formatPaiseINR(paise) {
  return fromPaise(paise).toLocaleString("en-IN", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
}

function formatIndianCurrency(num) {
  const paise = toPaise(num);
  return formatPaiseINR(paise);
}

/**
 * Validates user-submitted monetary inputs strictly against finite range limits.
 */
function validatePositiveAmount(raw, { min = 1, max = 100000000 } = {}) {
  const num = Number(raw);
  if (!Number.isFinite(num) || num < min || num > max) {
    return {
      valid: false,
      message: `Amount must be a finite number between ₹${min.toLocaleString("en-IN")} and ₹${max.toLocaleString("en-IN")}.`,
    };
  }
  const paise = toPaise(num);
  if (paise < Math.round(min * 100)) {
    return { valid: false, message: "Amount is below the minimum permissible value." };
  }
  return { valid: true, amount: fromPaise(paise), paise };
}

module.exports = {
  toPaise,
  fromPaise,
  addPaise,
  subPaise,
  formatPaiseINR,
  formatIndianCurrency,
  validatePositiveAmount,
};
