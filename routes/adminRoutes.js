const express = require("express");
const crypto = require("crypto");
const mongoose = require("mongoose");
const { requireAuth, requireAdmin } = require("../middleware/auth");
const { otpLimiter, authLimiter } = require("../middleware/rateLimiters");
const {
  escapeRegex,
  isValidObjectId,
  hashPassword,
  constantTimeEquals,
} = require("../utils/security");
const { sendOtpEmail } = require("../utils/emailService");
const { decryptField } = require("../utils/encryption");
const {
  toPaise,
  addPaise,
  subPaise,
  formatPaiseINR,
  validatePositiveAmount,
} = require("../utils/money");
const { withUserLock } = require("../utils/locks");
const { runInTransaction } = require("../utils/transactions");

const { UserModel } = require("../model/UserModel");
const { FundsModel } = require("../model/FundsModel");
const { FundsTransactionModel } = require("../model/FundsTransactionModel");
const { BankAccountModel } = require("../model/BankAccountModel");
const { OrdersModel } = require("../model/OrdersModel");
const { HoldingsModel } = require("../model/HoldingsModel");
const { PositionsModel } = require("../model/PositionsModel");
const { PledgedCollateralModel } = require("../model/PledgedCollateralModel");
const { IpoModel } = require("../model/IpoModel");
const { IpoApplicationModel } = require("../model/IpoApplicationModel");
const { SseIpoModel } = require("../model/SseIpoModel");
const { SseApplicationModel } = require("../model/SseApplicationModel");
const { AuctionModel } = require("../model/AuctionModel");
const { SupportTicketModel } = require("../model/SupportTicketModel");
const { NotificationModel } = require("../model/NotificationModel");
const { AdminAuditLogModel } = require("../model/AdminAuditLogModel");
const { GttModel } = require("../model/GttModel");
const { BasketModel } = require("../model/BasketModel");
const { SipModel } = require("../model/SipModel");
const AlertModel = require("../model/AlertModel");
const { GsecBidModel } = require("../model/GsecBidModel");
const { AuctionOfferModel } = require("../model/AuctionOfferModel");
const { UserWatchlistModel } = require("../model/UserWatchlistModel");
const { OtpModel } = require("../model/OtpModel");

const router = express.Router();

const ALLOWED_SEGMENTS = ["NSE", "BSE", "NFO", "MCX", "BFO", "CDS"];
const ALLOWED_IPO_STATUSES = ["Upcoming", "Pre-apply", "Apply", "Closed"];
const ALLOWED_TICKET_STATUSES = ["OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"];
const ALLOWED_TICKET_PRIORITIES = ["NORMAL", "HIGH", "URGENT"];

function parsePagination(query, defaultLimit = 25, maxLimit = 100) {
  const page = Math.max(1, parseInt(query.page, 10) || 1);
  const limit = Math.min(maxLimit, Math.max(1, parseInt(query.limit, 10) || defaultLimit));
  const skip = (page - 1) * limit;
  return { page, limit, skip };
}

function maskPan(rawPan) {
  if (!rawPan) return "";
  try {
    const plain = decryptField(String(rawPan)) || "";
    if (plain.length <= 4) return "••••";
    return `${plain.slice(0, 2)}${"•".repeat(Math.max(2, plain.length - 4))}${plain.slice(-2)}`;
  } catch {
    return "••••••••••";
  }
}

function sanitizeUser(user, fundsDoc = null) {
  const now = Date.now();
  const cdslLocked = Boolean(user.cdslLockedUntil && new Date(user.cdslLockedUntil).getTime() > now);
  return {
    userId: user.userId,
    email: user.email || "",
    fullName: user.fullName || "",
    phone: user.phone || "",
    panMasked: maskPan(user.pan),
    role: user.role || "user",
    segments: Array.isArray(user.segments) ? user.segments : [],
    nomineeStatus: user.nomineeStatus || "Not Added",
    dematAccountNo: user.demat?.dematAccountNo || "",
    dpName: user.demat?.dpName || "",
    tokenVersion: user.tokenVersion || 0,
    cdslLocked,
    cdslAttempts: user.cdslAttempts || 0,
    cdslLockedUntil: user.cdslLockedUntil || null,
    createdAt: user.createdAt || null,
    funds: fundsDoc
      ? {
          availableCash: fundsDoc.equity?.availableCash || "0.00",
          availableMargin: fundsDoc.equity?.availableMargin || "0.00",
          usedMargin: fundsDoc.equity?.usedMargin || "0.00",
          totalCollateral: fundsDoc.equity?.totalCollateral || "0.00",
        }
      : null,
  };
}

async function recordAudit(req, { action, targetType, targetId = "", reason = "", details = {} }) {
  try {
    await AdminAuditLogModel.create({
      adminUserId: req.adminUser?.userId || req.authUserId || "SYSTEM",
      adminEmail: req.adminUser?.email || "",
      action,
      targetType,
      targetId: String(targetId || ""),
      reason: String(reason || "").slice(0, 500),
      details,
      ipAddress: req.ip || req.headers["x-forwarded-for"] || "",
      userAgent: String(req.headers["user-agent"] || "").slice(0, 240),
    });
  } catch (err) {
    console.error("Failed to write AdminAuditLog:", err.message);
  }
}

// Public (rate-limited) Admin Password Recovery via Email OTP
router.post("/auth/forgot-password", otpLimiter, async (req, res) => {
  try {
    const cleanEmail = String(req.body?.email || "").trim().toLowerCase();
    if (!cleanEmail || !cleanEmail.includes("@")) {
      return res.status(400).json({ success: false, message: "Valid admin email is required." });
    }

    const genericMsg =
      "If an admin account exists for that email, a 6-digit recovery OTP has been sent.";
    const admin = await UserModel.findOne({ email: cleanEmail, role: "admin" })
      .select("userId email")
      .lean();
    if (!admin) {
      return res.json({ success: true, message: genericMsg });
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    const key = `admin-reset:${cleanEmail}`;
    await OtpModel.deleteMany({ email: key });
    await OtpModel.create({
      email: key,
      otp,
      attempts: 0,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    });

    await sendOtpEmail(cleanEmail, otp);
    return res.json({ success: true, message: genericMsg });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to initiate password recovery." });
  }
});

router.post("/auth/reset-password", authLimiter, async (req, res) => {
  try {
    const cleanEmail = String(req.body?.email || "").trim().toLowerCase();
    const cleanOtp = String(req.body?.otp || "").trim();
    const newPassword = String(req.body?.newPassword || "");

    if (!cleanEmail || !cleanOtp || newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Email, 6-digit OTP, and a new password (min 8 chars) are required.",
      });
    }

    const key = `admin-reset:${cleanEmail}`;
    const otpDoc = await OtpModel.findOne({ email: key });
    if (!otpDoc || otpDoc.expiresAt.getTime() < Date.now()) {
      return res.status(400).json({ success: false, message: "OTP expired or invalid." });
    }

    if (otpDoc.attempts >= 5) {
      await OtpModel.deleteMany({ email: key });
      return res.status(429).json({
        success: false,
        message: "Too many invalid OTP attempts. Please request a new OTP.",
      });
    }

    if (!constantTimeEquals(otpDoc.otp, cleanOtp)) {
      otpDoc.attempts += 1;
      await otpDoc.save();
      return res.status(400).json({ success: false, message: "Invalid OTP." });
    }

    const admin = await UserModel.findOne({ email: cleanEmail, role: "admin" });
    if (!admin) {
      return res.status(404).json({ success: false, message: "Admin account not found." });
    }

    admin.password = hashPassword(newPassword);
    admin.tokenVersion = (admin.tokenVersion || 0) + 1;
    await admin.save();
    await OtpModel.deleteMany({ email: key });

    await AdminAuditLogModel.create({
      adminUserId: admin.userId,
      adminEmail: admin.email || cleanEmail,
      action: "ADMIN_PASSWORD_RESET",
      targetType: "user",
      targetId: admin.userId,
      reason: "Self-service OTP password recovery",
      ipAddress: req.ip || req.headers["x-forwarded-for"] || "",
      userAgent: String(req.headers["user-agent"] || "").slice(0, 240),
    });

    return res.json({
      success: true,
      message: "Admin password updated. Please sign in with your new password.",
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to reset admin password." });
  }
});

router.use(requireAuth, requireAdmin);

// 1. Admin Identity
router.get("/me", (req, res) => {
  return res.json({
    success: true,
    admin: req.adminUser,
  });
});

// 2. Executive Command Overview
router.get("/overview", async (req, res) => {
  try {
    const startOfToday = new Date();
    startOfToday.setHours(0, 0, 0, 0);

    const [
      totalUsers,
      adminCount,
      cdslLockedCount,
      allFunds,
      totalOrders,
      ordersToday,
      openPositions,
      pledgedDocs,
      openTickets,
      urgentTickets,
      activeIpos,
      activeSseIpos,
      openAuctions,
      pendingIpoApps,
    ] = await Promise.all([
      UserModel.countDocuments({}),
      UserModel.countDocuments({ role: "admin" }),
      UserModel.countDocuments({ cdslLockedUntil: { $gt: new Date() } }),
      FundsModel.find({}).select("equity").lean(),
      OrdersModel.countDocuments({}),
      OrdersModel.countDocuments({ createdAt: { $gte: startOfToday } }),
      PositionsModel.find({ status: { $ne: "CLOSED" } }).select("pnl unrealizedPnl qty").lean(),
      PledgedCollateralModel.find({ status: "PLEDGED" }).select("collateralValue").lean(),
      SupportTicketModel.countDocuments({ status: { $in: ["OPEN", "IN_PROGRESS"] } }),
      SupportTicketModel.countDocuments({ status: { $in: ["OPEN", "IN_PROGRESS"] }, priority: "URGENT" }),
      IpoModel.countDocuments({ status: { $in: ["Apply", "Pre-apply"] } }),
      SseIpoModel.countDocuments({ status: "Apply" }),
      AuctionModel.countDocuments({ status: "OPEN" }),
      IpoApplicationModel.countDocuments({}),
    ]);

    let totalCashPaise = 0;
    let totalMarginPaise = 0;
    let totalUsedMarginPaise = 0;
    let totalCollateralPaise = 0;

    for (const f of allFunds) {
      totalCashPaise = addPaise(totalCashPaise, toPaise(f.equity?.availableCash || 0));
      totalMarginPaise = addPaise(totalMarginPaise, toPaise(f.equity?.availableMargin || 0));
      totalUsedMarginPaise = addPaise(totalUsedMarginPaise, toPaise(f.equity?.usedMargin || 0));
      totalCollateralPaise = addPaise(totalCollateralPaise, toPaise(f.equity?.totalCollateral || 0));
    }

    let openPositionsPnl = 0;
    for (const pos of openPositions) {
      openPositionsPnl += Number(pos.pnl ?? pos.unrealizedPnl ?? 0);
    }

    let pledgedTotalValue = 0;
    for (const p of pledgedDocs) {
      pledgedTotalValue += Number(p.collateralValue || 0);
    }

    const mem = process.memoryUsage();
    return res.json({
      success: true,
      kpis: {
        users: {
          total: totalUsers,
          admins: adminCount,
          cdslLocked: cdslLockedCount,
        },
        treasury: {
          totalAvailableCash: formatPaiseINR(totalCashPaise),
          totalAvailableMargin: formatPaiseINR(totalMarginPaise),
          totalUsedMargin: formatPaiseINR(totalUsedMarginPaise),
          totalCollateral: formatPaiseINR(totalCollateralPaise),
        },
        trading: {
          totalOrders,
          ordersToday,
          openPositionsCount: openPositions.length,
          openPositionsPnl: Number(openPositionsPnl.toFixed(2)),
          pledgedCollateralCount: pledgedDocs.length,
          pledgedCollateralValue: Number(pledgedTotalValue.toFixed(2)),
        },
        operations: {
          openTickets,
          urgentTickets,
          activeIpos,
          activeSseIpos,
          openAuctions,
          totalIpoApplications: pendingIpoApps,
        },
      },
      systemHealth: {
        dbState: mongoose.connection.readyState === 1 ? "CONNECTED" : "DEGRADED",
        uptimeSeconds: Math.floor(process.uptime()),
        memoryRssMb: Math.round(mem.rss / (1024 * 1024)),
        nodeVersion: process.version,
        timestamp: new Date().toISOString(),
      },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to load executive overview" });
  }
});

// 3. Client Directory & 360° Inspector
router.get("/users", async (req, res) => {
  try {
    const { page, limit, skip } = parsePagination(req.query, 25, 100);
    const q = String(req.query.q || "").trim();
    const roleFilter = String(req.query.role || "").trim();

    const filter = {};
    if (roleFilter === "user" || roleFilter === "admin") {
      filter.role = roleFilter;
    }
    if (q) {
      const rx = new RegExp(escapeRegex(q), "i");
      filter.$or = [{ userId: rx }, { email: rx }, { fullName: rx }, { phone: rx }];
    }

    const [users, total] = await Promise.all([
      UserModel.find(filter)
        .select("-password -cdslTpin")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      UserModel.countDocuments(filter),
    ]);

    const userIds = users.map((u) => u.userId);
    const fundsDocs = await FundsModel.find({ userId: { $in: userIds } }).lean();
    const fundsMap = new Map(fundsDocs.map((f) => [f.userId, f]));

    return res.json({
      success: true,
      users: users.map((u) => sanitizeUser(u, fundsMap.get(u.userId))),
      pagination: { page, limit, total, pages: Math.max(1, Math.ceil(total / limit)) },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to list users" });
  }
});

router.get("/users/:userId", async (req, res) => {
  try {
    const userId = String(req.params.userId || "").trim();
    const user = await UserModel.findOne({ userId }).select("-password -cdslTpin").lean();
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const [funds, banks, orders, holdings, positions, pledges, transactions, tickets] = await Promise.all([
      FundsModel.findOne({ userId }).lean(),
      BankAccountModel.find({ userId }).select("-accountNumber").lean(),
      OrdersModel.find({ userId }).sort({ createdAt: -1 }).limit(25).lean(),
      HoldingsModel.find({ userId }).lean(),
      PositionsModel.find({ userId }).sort({ updatedAt: -1 }).lean(),
      PledgedCollateralModel.find({ userId }).sort({ pledgedAt: -1 }).lean(),
      FundsTransactionModel.find({ userId }).select("-approvalToken").sort({ createdAt: -1 }).limit(25).lean(),
      SupportTicketModel.find({ userId }).sort({ createdAt: -1 }).limit(15).lean(),
    ]);

    return res.json({
      success: true,
      client: sanitizeUser(user, funds),
      funds: funds || null,
      banks,
      orders,
      holdings,
      positions,
      pledges,
      transactions,
      tickets,
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to load client 360 profile" });
  }
});

router.patch("/users/:userId/segments", async (req, res) => {
  try {
    const userId = String(req.params.userId || "").trim();
    const rawSegments = Array.isArray(req.body.segments) ? req.body.segments : null;
    if (!rawSegments) {
      return res.status(400).json({ success: false, message: "segments array is required" });
    }
    const cleanSegments = [...new Set(rawSegments.map((s) => String(s).toUpperCase()).filter((s) => ALLOWED_SEGMENTS.includes(s)))];
    const user = await UserModel.findOneAndUpdate(
      { userId },
      { $set: { segments: cleanSegments } },
      { new: true }
    ).select("-password -cdslTpin").lean();

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    await recordAudit(req, {
      action: "USER_SEGMENTS_UPDATED",
      targetType: "user",
      targetId: userId,
      reason: req.body.reason || "Segment permission update",
      details: { segments: cleanSegments },
    });

    return res.json({ success: true, user: sanitizeUser(user) });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to update user segments" });
  }
});

router.post("/users/:userId/revoke-session", async (req, res) => {
  try {
    const userId = String(req.params.userId || "").trim();
    const user = await UserModel.findOneAndUpdate(
      { userId },
      { $inc: { tokenVersion: 1 } },
      { new: true }
    ).select("userId tokenVersion").lean();

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    await recordAudit(req, {
      action: "USER_SESSION_REVOKED",
      targetType: "user",
      targetId: userId,
      reason: req.body.reason || "Admin forced session revocation",
      details: { newTokenVersion: user.tokenVersion },
    });

    return res.json({ success: true, tokenVersion: user.tokenVersion });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to revoke user session" });
  }
});

router.post("/users/:userId/unlock-cdsl", async (req, res) => {
  try {
    const userId = String(req.params.userId || "").trim();
    const user = await UserModel.findOneAndUpdate(
      { userId },
      { $set: { cdslAttempts: 0, cdslLockedUntil: null } },
      { new: true }
    ).select("userId cdslAttempts cdslLockedUntil").lean();

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    await recordAudit(req, {
      action: "USER_CDSL_UNLOCKED",
      targetType: "user",
      targetId: userId,
      reason: req.body.reason || "Admin unlocked CDSL TPIN",
    });

    return res.json({ success: true, message: "CDSL TPIN lock cleared" });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to unlock CDSL TPIN" });
  }
});

router.patch("/users/:userId/role", async (req, res) => {
  try {
    const userId = String(req.params.userId || "").trim();
    const nextRole = String(req.body.role || "").trim();
    if (!["user", "admin"].includes(nextRole)) {
      return res.status(400).json({ success: false, message: "role must be 'user' or 'admin'" });
    }
    if (userId === req.authUserId && nextRole !== "admin") {
      return res.status(400).json({ success: false, message: "Cannot demote your own active admin account" });
    }

    const user = await UserModel.findOneAndUpdate(
      { userId },
      { $set: { role: nextRole } },
      { new: true }
    ).select("-password -cdslTpin").lean();

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    await recordAudit(req, {
      action: "USER_ROLE_CHANGED",
      targetType: "user",
      targetId: userId,
      reason: req.body.reason || `Role set to ${nextRole}`,
      details: { role: nextRole },
    });

    return res.json({ success: true, user: sanitizeUser(user) });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to update user role" });
  }
});

router.delete("/users/:userId", async (req, res) => {
  try {
    const userId = String(req.params.userId || "").trim();
    if (!userId) {
      return res.status(400).json({ success: false, message: "userId is required" });
    }
    if (userId === req.authUserId) {
      return res.status(400).json({ success: false, message: "Cannot delete your own active admin account" });
    }

    const target = await UserModel.findOne({ userId }).select("userId email fullName role").lean();
    if (!target) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (target.role === "admin") {
      const adminCount = await UserModel.countDocuments({ role: "admin" });
      if (adminCount <= 1) {
        return res.status(400).json({ success: false, message: "Cannot delete the last remaining admin account" });
      }
    }

    const cleanupResults = await Promise.all([
      UserModel.deleteOne({ userId }),
      FundsModel.deleteMany({ userId }),
      FundsTransactionModel.deleteMany({ userId }),
      BankAccountModel.deleteMany({ userId }),
      OrdersModel.deleteMany({ userId }),
      HoldingsModel.deleteMany({ userId }),
      PositionsModel.deleteMany({ userId }),
      PledgedCollateralModel.deleteMany({ userId }),
      IpoApplicationModel.deleteMany({ userId }),
      SseApplicationModel.deleteMany({ userId }),
      SupportTicketModel.deleteMany({ userId }),
      NotificationModel.deleteMany({ userId }),
      GttModel.deleteMany({ userId }),
      BasketModel.deleteMany({ userId }),
      SipModel.deleteMany({ userId }),
      AlertModel.deleteMany({ userId }),
      GsecBidModel.deleteMany({ userId }),
      AuctionOfferModel.deleteMany({ userId }),
      UserWatchlistModel.deleteMany({ userId }),
    ]);

    const reason = String(req.body?.reason || "Admin deleted user account").trim();
    await recordAudit(req, {
      action: "USER_DELETED",
      targetType: "user",
      targetId: userId,
      reason,
      details: {
        deletedEmail: target.email || "",
        deletedRole: target.role || "user",
        totalDocumentsRemoved: cleanupResults.reduce((sum, r) => sum + (r?.deletedCount || 0), 0),
      },
    });

    return res.json({
      success: true,
      deletedUserId: userId,
      message: `User ${userId} and associated records deleted.`,
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to delete user" });
  }
});

// 4. Treasury & Ledger
router.get("/transactions", async (req, res) => {
  try {
    const { page, limit, skip } = parsePagination(req.query, 30, 100);
    const filter = {};
    if (req.query.type) filter.type = String(req.query.type).toUpperCase();
    if (req.query.status) filter.status = String(req.query.status).toUpperCase();
    if (req.query.userId) filter.userId = String(req.query.userId).trim();

    const [transactions, total] = await Promise.all([
      FundsTransactionModel.find(filter)
        .select("-approvalToken")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      FundsTransactionModel.countDocuments(filter),
    ]);

    return res.json({
      success: true,
      transactions,
      pagination: { page, limit, total, pages: Math.max(1, Math.ceil(total / limit)) },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to load transactions" });
  }
});

router.post("/funds/adjust", async (req, res) => {
  try {
    const userId = String(req.body.userId || "").trim();
    const direction = String(req.body.direction || "").toUpperCase();
    const reason = String(req.body.reason || "").trim();

    if (!userId) {
      return res.status(400).json({ success: false, message: "userId is required" });
    }
    if (!["CREDIT", "DEBIT"].includes(direction)) {
      return res.status(400).json({ success: false, message: "direction must be CREDIT or DEBIT" });
    }
    if (!reason || reason.length < 3) {
      return res.status(400).json({ success: false, message: "Audit reason (min 3 chars) is required" });
    }

    const amountCheck = validatePositiveAmount(req.body.amount, { max: 100000000 });
    if (!amountCheck.valid) {
      return res.status(400).json({ success: false, message: amountCheck.message });
    }
    const deltaPaise = amountCheck.paise;
    const amountRupees = amountCheck.amount;

    const userExists = await UserModel.exists({ userId });
    if (!userExists) {
      return res.status(404).json({ success: false, message: "Target user not found" });
    }

    const referenceId = `ADM${Date.now().toString().slice(-8)}${crypto.randomBytes(2).toString("hex").toUpperCase()}`;

    const result = await withUserLock(userId, () =>
      runInTransaction(async (session) => {
        let funds = await FundsModel.findOne({ userId }).session(session);
        if (!funds) {
          const created = await FundsModel.create([{ userId }], { session });
          funds = created[0];
        }

        const currentCashPaise = toPaise(funds.equity?.availableCash || 0);
        const currentMarginPaise = toPaise(funds.equity?.availableMargin || 0);
        const currentPayinPaise = toPaise(funds.equity?.payin || 0);

        if (direction === "DEBIT" && currentCashPaise < deltaPaise) {
          const err = new Error("Insufficient available cash for debit adjustment");
          err.statusCode = 400;
          throw err;
        }

        const nextCashPaise =
          direction === "CREDIT"
            ? addPaise(currentCashPaise, deltaPaise)
            : subPaise(currentCashPaise, deltaPaise);
        const nextMarginPaise =
          direction === "CREDIT"
            ? addPaise(currentMarginPaise, deltaPaise)
            : Math.max(0, subPaise(currentMarginPaise, deltaPaise));
        const nextPayinPaise =
          direction === "CREDIT" ? addPaise(currentPayinPaise, deltaPaise) : currentPayinPaise;

        funds.equity.availableCash = formatPaiseINR(nextCashPaise);
        funds.equity.availableMargin = formatPaiseINR(nextMarginPaise);
        funds.equity.payin = formatPaiseINR(nextPayinPaise);
        await funds.save({ session });

        await FundsTransactionModel.create(
          [
            {
              userId,
              type: direction === "CREDIT" ? "PAYIN" : "PAYOUT",
              amount: amountRupees,
              paymentMethod: "ADMIN_ADJUSTMENT",
              bankAccount: "Treasury Ops",
              status: "COMPLETED",
              referenceId,
              remarks: `${direction}: ${reason}`,
              completedAt: new Date(),
            },
          ],
          { session }
        );

        await NotificationModel.create(
          [
            {
              userId,
              type: "FUNDS",
              category: "TREASURY_ADJUSTMENT",
              title: `Treasury ${direction === "CREDIT" ? "Credit" : "Debit"} of ₹${amountRupees.toFixed(2)}`,
              description: `${reason} (Ref: ${referenceId})`,
              metadata: { amount: amountRupees, referenceId, actionUrl: "/funds" },
              priority: "HIGH",
            },
          ],
          { session }
        );

        return {
          availableCash: funds.equity.availableCash,
          availableMargin: funds.equity.availableMargin,
        };
      })
    );

    await recordAudit(req, {
      action: `FUNDS_${direction}`,
      targetType: "funds",
      targetId: userId,
      reason,
      details: { amount: amountRupees, referenceId, newBalances: result },
    });

    return res.json({
      success: true,
      referenceId,
      balances: result,
    });
  } catch (err) {
    const status = err.statusCode || 500;
    return res.status(status).json({
      success: false,
      message: err.message || "Failed to adjust funds",
    });
  }
});

// 5. Trading & Risk (RMS)
router.get("/orders", async (req, res) => {
  try {
    const { page, limit, skip } = parsePagination(req.query, 30, 100);
    const filter = {};
    if (req.query.status) filter.status = String(req.query.status).toUpperCase();
    if (req.query.mode) filter.mode = String(req.query.mode).toUpperCase();
    if (req.query.userId) filter.userId = String(req.query.userId).trim();
    if (req.query.q) {
      const rx = new RegExp(escapeRegex(String(req.query.q).trim()), "i");
      filter.$or = [{ name: rx }, { orderId: rx }, { userId: rx }];
    }

    const [orders, total] = await Promise.all([
      OrdersModel.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      OrdersModel.countDocuments(filter),
    ]);

    return res.json({
      success: true,
      orders,
      pagination: { page, limit, total, pages: Math.max(1, Math.ceil(total / limit)) },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to load orders" });
  }
});

router.get("/positions", async (req, res) => {
  try {
    const filter = {};
    if (req.query.status) filter.status = String(req.query.status).toUpperCase();
    if (req.query.userId) filter.userId = String(req.query.userId).trim();

    const [positions, pledges] = await Promise.all([
      PositionsModel.find(filter).sort({ updatedAt: -1 }).limit(100).lean(),
      PledgedCollateralModel.find({ status: "PLEDGED" }).sort({ pledgedAt: -1 }).limit(100).lean(),
    ]);

    return res.json({ success: true, positions, pledges });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to load positions" });
  }
});

router.post("/positions/:id/square-off", async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ success: false, message: "Invalid position id" });
    }

    const position = await PositionsModel.findById(id);
    if (!position) {
      return res.status(404).json({ success: false, message: "Position not found" });
    }
    if (position.status === "CLOSED") {
      return res.status(400).json({ success: false, message: "Position is already closed" });
    }

    const closedQty = Math.abs(Number(position.qty || 0));
    const exitPrice = Number(position.ltp || position.price || position.avg || 0);
    const reason = String(req.body.reason || "RMS administrative square-off").trim();

    position.status = "CLOSED";
    position.closedAt = new Date();
    position.updatedAt = new Date();
    position.qty = 0;
    await position.save();

    if (closedQty > 0) {
      await OrdersModel.create({
        userId: position.userId,
        name: position.name || position.instrument || "UNKNOWN",
        qty: closedQty,
        price: exitPrice,
        mode: "SELL",
        product: position.product || "MIS",
        status: "COMPLETE",
      });
    }

    await NotificationModel.create({
      userId: position.userId,
      type: "COMPLIANCE",
      category: "RMS_SQUARE_OFF",
      title: `RMS Square-Off: ${position.name || position.instrument}`,
      description: `Admin RMS squared off ${closedQty} qty (${position.product || "MIS"}). Reason: ${reason}`,
      metadata: { symbol: position.name || "", qty: closedQty, price: exitPrice, actionUrl: "/positions" },
      priority: "CRITICAL",
    });

    await recordAudit(req, {
      action: "RMS_POSITION_SQUAREOFF",
      targetType: "position",
      targetId: String(position._id),
      reason,
      details: { userId: position.userId, symbol: position.name, closedQty, exitPrice },
    });

    return res.json({ success: true, position });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to square off position" });
  }
});

// 6. Primary Markets & Offerings
router.get("/offerings", async (req, res) => {
  try {
    const [ipos, sseIpos, auctions] = await Promise.all([
      IpoModel.find({}).lean(),
      SseIpoModel.find({}).lean(),
      AuctionModel.find({}).lean(),
    ]);
    return res.json({ success: true, ipos, sseIpos, auctions });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to load offerings" });
  }
});

router.post("/offerings/ipo", async (req, res) => {
  try {
    const symbol = String(req.body.symbol || "").trim().toUpperCase();
    const name = String(req.body.name || "").trim();
    const priceRange = String(req.body.priceRange || "").trim();
    const dates = String(req.body.dates || "").trim();
    const minQty = Math.max(1, parseInt(req.body.minQty, 10) || 1);
    const minAmount = String(req.body.minAmount || "").trim();
    const status = ALLOWED_IPO_STATUSES.includes(req.body.status) ? req.body.status : "Upcoming";

    if (!symbol || !name || !priceRange) {
      return res.status(400).json({ success: false, message: "symbol, name, and priceRange are required" });
    }

    const exists = await IpoModel.exists({ symbol });
    if (exists) {
      return res.status(409).json({ success: false, message: `IPO ${symbol} already exists` });
    }

    const ipo = await IpoModel.create({
      symbol,
      name,
      dates: dates || "TBA",
      priceRange,
      minQty,
      minAmount: minAmount || "TBA",
      status,
      issueSize: String(req.body.issueSize || "₹1,000 Cr"),
      gmp: String(req.body.gmp || "₹0 (0.0%)"),
    });

    await recordAudit(req, {
      action: "IPO_CREATED",
      targetType: "ipo",
      targetId: ipo.symbol,
      reason: "New IPO offering listed",
      details: { name: ipo.name, status: ipo.status, priceRange: ipo.priceRange },
    });

    return res.status(201).json({ success: true, ipo });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to create IPO" });
  }
});

router.patch("/offerings/ipo/:id/status", async (req, res) => {
  try {
    const { id } = req.params;
    const status = String(req.body.status || "").trim();
    if (!isValidObjectId(id)) {
      return res.status(400).json({ success: false, message: "Invalid IPO id" });
    }
    if (!ALLOWED_IPO_STATUSES.includes(status)) {
      return res.status(400).json({ success: false, message: "Invalid IPO status" });
    }

    const ipo = await IpoModel.findByIdAndUpdate(id, { $set: { status } }, { new: true }).lean();
    if (!ipo) {
      return res.status(404).json({ success: false, message: "IPO not found" });
    }

    await recordAudit(req, {
      action: "IPO_STATUS_UPDATED",
      targetType: "ipo",
      targetId: ipo.symbol,
      reason: `Status changed to ${status}`,
      details: { status },
    });

    return res.json({ success: true, ipo });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to update IPO status" });
  }
});

router.get("/applications", async (req, res) => {
  try {
    const [ipoApps, sseApps] = await Promise.all([
      IpoApplicationModel.find({})
        .select("-mandateToken")
        .sort({ createdAt: -1 })
        .limit(100)
        .lean(),
      SseApplicationModel.find({}).sort({ createdAt: -1 }).limit(100).lean(),
    ]);
    return res.json({
      success: true,
      ipoApplications: ipoApps.map((a) => ({
        ...a,
        pan: a.pan ? `${String(a.pan).slice(0, 2)}••••${String(a.pan).slice(-2)}` : "",
      })),
      sseApplications: sseApps.map((a) => ({
        ...a,
        panNumber: a.panNumber ? `${String(a.panNumber).slice(0, 2)}••••${String(a.panNumber).slice(-2)}` : "",
      })),
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to load applications" });
  }
});

// 7. Support Tickets & Broadcasts
router.get("/tickets", async (req, res) => {
  try {
    const filter = {};
    if (req.query.status) filter.status = String(req.query.status).toUpperCase();
    if (req.query.priority) filter.priority = String(req.query.priority).toUpperCase();
    if (req.query.category) filter.category = String(req.query.category).toUpperCase();

    const tickets = await SupportTicketModel.find(filter).sort({ createdAt: -1 }).limit(100).lean();
    return res.json({ success: true, tickets });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to load support tickets" });
  }
});

router.patch("/tickets/:id", async (req, res) => {
  try {
    const idParam = String(req.params.id || "").trim();
    const query = isValidObjectId(idParam) ? { _id: idParam } : { ticketId: idParam };

    const update = {};
    if (req.body.status !== undefined) {
      const status = String(req.body.status).toUpperCase();
      if (!ALLOWED_TICKET_STATUSES.includes(status)) {
        return res.status(400).json({ success: false, message: "Invalid ticket status" });
      }
      update.status = status;
      if (status === "RESOLVED" || status === "CLOSED") {
        update.resolvedAt = new Date();
      }
    }
    if (req.body.priority !== undefined) {
      const priority = String(req.body.priority).toUpperCase();
      if (!ALLOWED_TICKET_PRIORITIES.includes(priority)) {
        return res.status(400).json({ success: false, message: "Invalid ticket priority" });
      }
      update.priority = priority;
    }
    if (req.body.assignedTo !== undefined) {
      update.assignedTo = String(req.body.assignedTo).trim().slice(0, 80);
    }

    const ticket = await SupportTicketModel.findOneAndUpdate(query, { $set: update }, { new: true }).lean();
    if (!ticket) {
      return res.status(404).json({ success: false, message: "Support ticket not found" });
    }

    await recordAudit(req, {
      action: "SUPPORT_TICKET_UPDATED",
      targetType: "ticket",
      targetId: ticket.ticketId || String(ticket._id),
      reason: req.body.reason || "Ticket updated by admin",
      details: update,
    });

    return res.json({ success: true, ticket });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to update ticket" });
  }
});

router.post("/notifications/broadcast", async (req, res) => {
  try {
    const title = String(req.body.title || "").trim();
    const description = String(req.body.description || "").trim();
    const priority = ["LOW", "NORMAL", "HIGH", "CRITICAL"].includes(String(req.body.priority || "").toUpperCase())
      ? String(req.body.priority).toUpperCase()
      : "HIGH";
    const targetUserId = String(req.body.targetUserId || "").trim();

    if (!title || !description) {
      return res.status(400).json({ success: false, message: "title and description are required" });
    }

    let recipientIds = [];
    if (targetUserId) {
      const exists = await UserModel.exists({ userId: targetUserId });
      if (!exists) {
        return res.status(404).json({ success: false, message: "Target user not found" });
      }
      recipientIds = [targetUserId];
    } else {
      const users = await UserModel.find({}).select("userId").lean();
      recipientIds = users.map((u) => u.userId);
    }

    if (recipientIds.length > 0) {
      await NotificationModel.insertMany(
        recipientIds.map((uid) => ({
          userId: uid,
          type: "SYSTEM",
          category: "ADMIN_BROADCAST",
          title,
          description,
          priority,
          metadata: { actionUrl: "/orders" },
        }))
      );
    }

    await recordAudit(req, {
      action: "NOTIFICATION_BROADCAST",
      targetType: targetUserId ? "user" : "all_users",
      targetId: targetUserId || "ALL",
      reason: title,
      details: { recipientCount: recipientIds.length, priority },
    });

    return res.json({
      success: true,
      sentCount: recipientIds.length,
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to broadcast notification" });
  }
});

// 8. Immutable Audit Log Viewer
router.get("/audit-logs", async (req, res) => {
  try {
    const { page, limit, skip } = parsePagination(req.query, 40, 100);
    const filter = {};
    if (req.query.action) filter.action = String(req.query.action).trim();
    if (req.query.targetType) filter.targetType = String(req.query.targetType).trim();

    const [logs, total] = await Promise.all([
      AdminAuditLogModel.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      AdminAuditLogModel.countDocuments(filter),
    ]);

    return res.json({
      success: true,
      logs,
      pagination: { page, limit, total, pages: Math.max(1, Math.ceil(total / limit)) },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: "Failed to load audit logs" });
  }
});

module.exports = router;
