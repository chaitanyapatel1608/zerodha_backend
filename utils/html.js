/**
 * Escapes untrusted text before interpolating into server-rendered HTML templates.
 */
function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Renders a state-safe HTML confirmation form for email approval links so
 * GET pre-fetchers or link scanners cannot mutate financial or IPO records.
 */
function renderConfirmationPage({
  title,
  subtitle,
  actionUrl,
  token,
  decision,
  details = [],
  returnUrl,
}) {
  const isApprove = String(decision).toUpperCase() === "APPROVE";
  const accent = isApprove ? "#16a34a" : "#dc2626";
  const buttonLabel = isApprove ? "Confirm Approval" : "Confirm Decline";

  const rowsHtml = details
    .map(
      ([label, value]) =>
        `<tr><td class="label">${escapeHtml(label)}</td><td class="val">${escapeHtml(value)}</td></tr>`
    )
    .join("");

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>${escapeHtml(title)} - Zerodha Kite</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; margin: 0; padding: 40px 20px; color: #0f172a; text-align: center; }
    .card { max-width: 500px; margin: 0 auto; background: #fff; padding: 36px 28px; border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 10px 25px rgba(0,0,0,0.06); }
    h2 { margin: 0 0 8px 0; color: #0f172a; font-size: 22px; }
    p { color: #64748b; font-size: 14px; line-height: 1.5; margin: 0 0 22px 0; }
    .details { width: 100%; border-collapse: collapse; margin-bottom: 24px; text-align: left; font-size: 13.5px; }
    .details td { padding: 10px 0; border-bottom: 1px solid #f1f5f9; }
    .details .label { color: #64748b; }
    .details .val { font-weight: 600; text-align: right; color: #0f172a; }
    .btn { display: inline-block; background: ${accent}; color: #fff; border: none; padding: 12px 28px; border-radius: 4px; font-weight: 600; font-size: 14px; cursor: pointer; }
    .cancel-link { display: inline-block; margin-left: 12px; color: #64748b; font-size: 13px; text-decoration: none; }
  </style>
</head>
<body>
  <div class="card">
    <h2>${escapeHtml(title)}</h2>
    <p>${escapeHtml(subtitle)}</p>
    <table class="details">${rowsHtml}</table>
    <form method="POST" action="${escapeHtml(actionUrl)}">
      <input type="hidden" name="token" value="${escapeHtml(token)}" />
      <input type="hidden" name="decision" value="${escapeHtml(decision)}" />
      <button type="submit" class="btn">${escapeHtml(buttonLabel)}</button>
      <a href="${escapeHtml(returnUrl)}" class="cancel-link">Cancel</a>
    </form>
  </div>
</body>
</html>`;
}

module.exports = {
  escapeHtml,
  renderConfirmationPage,
};
