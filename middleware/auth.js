const { JWT_SECRET } = require("../config/env");
const {
  resolveAuthContext,
  resolveAuthenticatedUserId,
  parseCookies,
  constantTimeEquals,
} = require("../utils/security");
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
    return res.status(401).json({
      success: false,
      message: "Authentication required. Please log in to continue.",
    });
  }

  // Enforce CSRF double-submit check on state-changing requests authenticated via browser cookie
  if (ctx.authSource === "cookie" && STATE_CHANGING_METHODS.has(String(req.method || "").toUpperCase())) {
    const cookies = parseCookies(req.headers?.cookie || "");
    const csrfCookie = cookies.zerodha_csrf || "";
    const csrfHeader = String(req.headers["x-csrf-token"] || "");
    if (!csrfCookie || !csrfHeader || !constantTimeEquals(csrfCookie, csrfHeader)) {
      return res.status(403).json({
        success: false,
        message: "CSRF validation failed. Please refresh and try again.",
      });
    }
  }

  try {
    const user = await UserModel.findOne({ userId: ctx.userId }).select("tokenVersion").lean();
    if (!user || (user.tokenVersion || 0) !== ctx.tokenVersion) {
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
