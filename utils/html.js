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
  csrfToken,
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
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)} - Zerodha Kite</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #f8fafc; margin: 0; padding: 40px 20px; color: #0f172a; text-align: center; -webkit-font-smoothing: antialiased; }
    .card { max-width: 520px; margin: 0 auto; background: #fff; padding: 40px 32px; border-radius: 10px; border: 1px solid #e2e8f0; box-shadow: 0 10px 30px rgba(0,0,0,0.06); text-align: left; }
    .header-logo { text-align: center; margin-bottom: 24px; border-bottom: 2px solid #387ed1; padding-bottom: 16px; }
    .header-brand { font-size: 22px; font-weight: 700; color: #387ed1; letter-spacing: 1.2px; margin: 0; }
    .header-tag { font-size: 11px; text-transform: uppercase; letter-spacing: 1.5px; color: #64748b; font-weight: 600; margin-top: 4px; }
    h2 { margin: 0 0 8px 0; color: #0f172a; font-size: 20px; text-align: center; font-weight: 600; }
    p.subtitle { color: #64748b; font-size: 13.5px; line-height: 1.5; margin: 0 0 24px 0; text-align: center; }
    .details { width: 100%; border-collapse: collapse; margin-bottom: 26px; font-size: 13.5px; background: #f8fafc; border-radius: 6px; border: 1px solid #e2e8f0; padding: 8px 16px; }
    .details td { padding: 11px 14px; border-bottom: 1px solid #e2e8f0; }
    .details tr:last-child td { border-bottom: none; }
    .details .label { color: #64748b; }
    .details .val { font-weight: 600; text-align: right; color: #0f172a; }
    .form-actions { text-align: center; margin-top: 10px; }
    .btn { display: inline-block; background: ${accent}; color: #fff; border: none; padding: 13px 32px; border-radius: 5px; font-weight: 600; font-size: 14.5px; cursor: pointer; box-shadow: 0 2px 8px ${isApprove ? 'rgba(22, 163, 74, 0.3)' : 'rgba(220, 38, 38, 0.3)'}; transition: opacity 0.15s ease; }
    .btn:hover { opacity: 0.92; }
    .cancel-link { display: inline-block; margin-left: 16px; color: #64748b; font-size: 13.5px; text-decoration: none; font-weight: 500; }
    .cancel-link:hover { text-decoration: underline; color: #334155; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header-logo">
      <h1 class="header-brand">ZERODHA</h1>
      <div class="header-tag">Instant Payment Authorization Gateway</div>
    </div>
    <h2>${escapeHtml(title)}</h2>
    <p class="subtitle">${escapeHtml(subtitle)}</p>
    <table class="details">${rowsHtml}</table>
    <form method="POST" action="${escapeHtml(actionUrl)}" class="form-actions">
      ${csrfToken ? `<input type="hidden" name="csrfToken" value="${escapeHtml(csrfToken)}" />` : ""}
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
