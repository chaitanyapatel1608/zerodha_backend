const { JWT_SECRET, PUBLIC_FRONTEND_URL } = require("../config/env");
const {
  resolveAuthContext,
  resolveAuthenticatedUserId,
  parseCookies,
  constantTimeEquals,
} = require("../utils/security");
const { escapeHtml } = require("../utils/html");
const { UserModel } = require("../model/UserModel");

const STATE_CHANGING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * Extracts verified userId attached by requireAuth or resolves directly from JWT/cookie.
 */
function getAuthenticatedUserId(req) {
  if (req && req.authUserId) {
    return req.authUserId;
  }
  return resolveAuthenticatedUserId(req, JWT_SECRET);
}

/**
 * Express middleware enforcing valid JWT (Bearer or HttpOnly cookie),
 * server-side tokenVersion revocation check, and CSRF double-submit verification for cookie sessions.
 */
async function requireAuth(req, res, next) {
  const ctx = resolveAuthContext(req, JWT_SECRET);
  if (!ctx) {
    if (req.path === "/fundDeposit/action" || req.path === "/ipoMandate/action") {
      const loginUrl = `${PUBLIC_FRONTEND_URL}/login?notice=${encodeURIComponent("Please log in to your Kite account to authorize this transaction.")}`;
      if (req.method === "GET") {
        return res.redirect(loginUrl);
      }
      return res.status(401).send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Authentication Required - Zerodha Kite</title><style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;padding:50px 20px;text-align:center;color:#0f172a;}.card{max-width:500px;margin:0 auto;background:#fff;padding:36px;border-radius:10px;border:1px solid #e2e8f0;box-shadow:0 10px 30px rgba(0,0,0,0.06);}.btn{display:inline-block;background:#387ed1;color:#fff !important;padding:12px 24px;border-radius:4px;text-decoration:none;font-weight:500;margin-top:18px;}</style></head><body><div class="card"><h2>Authentication Required</h2><p style="color:#64748b;font-size:14px;margin-top:8px;">Please log in to your Zerodha Kite account to authorize this transaction.</p><a href="${escapeHtml(loginUrl)}" class="btn">Log In to Kite</a></div></body></html>`);
    }
    return res.status(401).json({
      success: false,
      message: "Authentication required. Please log in to continue.",
    });
  }

  // Enforce CSRF double-submit check on state-changing requests authenticated via browser cookie
  if (ctx.authSource === "cookie" && STATE_CHANGING_METHODS.has(String(req.method || "").toUpperCase())) {
    const hasValidBodyAuth = req.body?.authToken && typeof req.body.authToken === "string";
    if (!hasValidBodyAuth) {
      const cookies = parseCookies(req.headers?.cookie || "");
      const csrfCookie = cookies.zerodha_csrf || "";
      const csrfHeader = String(req.headers["x-csrf-token"] || (req.path === "/fundDeposit/action" && req.body?.csrfToken) || (req.path === "/ipoMandate/action" && req.body?.csrfToken) || "");
      if (!csrfCookie || !csrfHeader || !constantTimeEquals(csrfCookie, csrfHeader)) {
        if (req.path === "/fundDeposit/action" || req.path === "/ipoMandate/action") {
          return res.status(403).send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Validation Error</title><style>body{font-family:sans-serif;text-align:center;padding:50px;}.btn{display:inline-block;background:#387ed1;color:#fff;padding:12px 24px;border-radius:4px;text-decoration:none;margin-top:16px;}</style></head><body><h2>Session Validation Expired</h2><p>Please refresh the authorization page and try again.</p><a href="javascript:location.reload()" class="btn">Refresh Page</a></body></html>`);
        }
        return res.status(403).json({
          success: false,
          message: "CSRF validation failed. Please refresh and try again.",
        });
      }
    }
  }

  try {
    const user = await UserModel.findOne({ userId: ctx.userId }).select("tokenVersion").lean();
    if (!user || (user.tokenVersion || 0) !== ctx.tokenVersion) {
      if (req.path === "/fundDeposit/action" || req.path === "/ipoMandate/action") {
        const loginUrl = `${PUBLIC_FRONTEND_URL}/login?notice=${encodeURIComponent("Your session has expired. Please log in again to authorize this transaction.")}`;
        if (req.method === "GET") {
          return res.redirect(loginUrl);
        }
        return res.status(401).send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Session Expired - Zerodha Kite</title><style>body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8fafc;padding:50px 20px;text-align:center;color:#0f172a;}.card{max-width:500px;margin:0 auto;background:#fff;padding:36px;border-radius:10px;border:1px solid #e2e8f0;box-shadow:0 10px 30px rgba(0,0,0,0.06);}.btn{display:inline-block;background:#387ed1;color:#fff !important;padding:12px 24px;border-radius:4px;text-decoration:none;font-weight:500;margin-top:18px;}</style></head><body><div class="card"><h2>Session Expired</h2><p style="color:#64748b;font-size:14px;margin-top:8px;">Your session has expired. Please log in again to authorize this transaction.</p><a href="${escapeHtml(loginUrl)}" class="btn">Log In to Kite</a></div></body></html>`);
      }
      return res.status(401).json({
        success: false,
        message: "Session has been revoked or expired. Please log in again.",
      });
    }
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Authentication verification error",
    });
  }

  req.authUserId = ctx.userId;
  req.authSource = ctx.authSource;
  return next();
}

/**
 * Express middleware enforcing admin RBAC by checking UserModel.role in MongoDB.
 * Must run after requireAuth.
 */
async function requireAdmin(req, res, next) {
  if (!req.authUserId) {
    return res.status(401).json({
      success: false,
      message: "Authentication required.",
    });
  }

  try {
    const user = await UserModel.findOne({ userId: req.authUserId })
      .select("role email fullName")
      .lean();
    if (!user || user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Admin privileges required.",
      });
    }
    req.adminUser = {
      userId: req.authUserId,
      email: user.email || "",
      fullName: user.fullName || "",
      role: user.role,
    };
    return next();
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Authorization verification error",
    });
  }
}

module.exports = {
  getAuthenticatedUserId,
  requireAuth,
  requireAdmin,
};
