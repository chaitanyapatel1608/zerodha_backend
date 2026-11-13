const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const {
  NODE_ENV,
  IS_PROD,
  IS_TEST,
  PORT,
  MONGO_URL: uri,
  JWT_SECRET,
  PUBLIC_FRONTEND_URL,
  PUBLIC_BACKEND_URL,
  ALLOWED_ORIGINS: allowedOrigins,
} = require("./config/env");
const logger = require("./utils/logger");
const {
  hashPassword,
  verifyPassword,
  constantTimeEquals,
  escapeRegex,
  isValidObjectId,
} = require("./utils/security");
const { getAuthenticatedUserId, requireAuth } = require("./middleware/auth");
const { otpLimiter, authLimiter, tradeFundsLimiter, catalogLimiter } = require("./middleware/rateLimiters");
const {
  toPaise,
  fromPaise,
  addPaise,
  subPaise,
  formatPaiseINR,
  formatIndianCurrency,
  validatePositiveAmount,
} = require("./utils/money");
const { escapeHtml, renderConfirmationPage } = require("./utils/html");
const { decryptField } = require("./utils/encryption");
const { withUserLock, acquireDistributedLock, releaseDistributedLock } = require("./utils/locks");
const { runInTransaction } = require("./utils/transactions");
const healthRoutes = require("./routes/healthRoutes");
const adminRoutes = require("./routes/adminRoutes");

const { HoldingsModel } = require("./model/HoldingsModel");
const { PositionsModel } = require("./model/PositionsModel");
const { OrdersModel } = require("./model/OrdersModel");
const { WatchlistModel } = require("./model/WatchlistModel");
const { FundsModel } = require("./model/FundsModel");
const { FundsTransactionModel } = require("./model/FundsTransactionModel");
const { PledgedCollateralModel } = require("./model/PledgedCollateralModel");
const { BankAccountModel } = require("./model/BankAccountModel");
const { IpoModel } = require("./model/IpoModel");
const { IpoApplicationModel } = require("./model/IpoApplicationModel");
const { GsecBidModel } = require("./model/GsecBidModel");
const { CorporateActionModel } = require("./model/CorporateActionModel");
const { AuctionModel } = require("./model/AuctionModel");
const { AuctionOfferModel } = require("./model/AuctionOfferModel");
const { SseIpoModel } = require("./model/SseIpoModel");
const { SseApplicationModel } = require("./model/SseApplicationModel");
const { UserModel } = require("./model/UserModel");
const { GttModel } = require("./model/GttModel");
const { BasketModel } = require("./model/BasketModel");
const { SipModel } = require("./model/SipModel");
const { UserWatchlistModel } = require("./model/UserWatchlistModel");
const { NotificationModel } = require("./model/NotificationModel");
const { SupportTicketModel } = require("./model/SupportTicketModel");
const { masterInstruments } = require("./data/masterInstruments");
const { OtpModel } = require("./model/OtpModel");
const {
  sendOtpEmail,
  sendIpoMandateEmail,
  sendFundDepositEmail,
  sendSipFailureEmail,
  sendSipSuccessEmail,
  sendAlertTriggeredEmail,
  sendCdslTpinEmail,
  sendCdslTransactionOtpEmail,
} = require("./utils/emailService");
const { ipoData50 } = require("./data/ipoData50");
const { marketSips50 } = require("./data/marketSips50");
const { InstrumentModel } = require("./model/InstrumentModel");
const { MarketSipCatalogModel } = require("./model/MarketSipCatalogModel");
const AlertModel = require("./model/AlertModel");
const { seedCatalogsToDb } = require("./data/seedCatalogsToDb");

const app = express();

// Middlewares & Security Headers
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin) || !IS_PROD) {
        return callback(null, true);
      }
      return callback(new Error("CORS origin blocked by policy: " + origin));
    },
    credentials: true,
  })
);
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));
app.use(healthRoutes);
app.use("/admin", adminRoutes);

// Global ObjectId pre-validation for all :id routes (prevents CastError 500s)
app.param("id", (req, res, next, id) => {
  if (!isValidObjectId(String(id))) {
    return res.status(400).json({ success: false, message: "Invalid resource identifier" });
  }
  return next();
});

function buildCookieOptions(req, httpOnly) {
  const isSecure = IS_PROD || Boolean(req?.secure) || req?.headers?.["x-forwarded-proto"] === "https";
  const opts = {
    httpOnly,
    secure: isSecure,
    sameSite: "lax",
    path: "/",
    maxAge: 24 * 60 * 60 * 1000,
  };
  if (process.env.COOKIE_DOMAIN) {
    opts.domain = process.env.COOKIE_DOMAIN;
  }
  return opts;
}

function issueAuthSession(res, req, user) {
  const token = jwt.sign(
    {
      userId: user.userId,
      email: user.email,
      role: user.role,
      tv: user.tokenVersion || 0,
    },
    JWT_SECRET,
    { expiresIn: "24h" }
  );
  const csrfToken = crypto.randomBytes(32).toString("hex");
  res.cookie("zerodha_session", token, buildCookieOptions(req, true));
  res.cookie("zerodha_csrf", csrfToken, buildCookieOptions(req, false));
  res.setHeader("Cache-Control", "no-store");
  return token;
}

function clearAuthCookies(res, req) {
  const baseHttpOnly = buildCookieOptions(req, true);
  const baseReadable = buildCookieOptions(req, false);
  delete baseHttpOnly.maxAge;
  delete baseReadable.maxAge;
  res.clearCookie("zerodha_session", baseHttpOnly);
  res.clearCookie("zerodha_csrf", baseReadable);
  res.setHeader("Cache-Control", "no-store");
}

// MongoDB Connection
mongoose
  .connect(uri)
  .then(() => {
    logger.info("db_connected");
    seedCatalogsToDb();
  })
  .catch((err) => logger.error("db_connection_error", { message: err.message }));

// ==========================================
// Authentication Routes (Passwordless OTP)
// ==========================================

// 1. Send OTP Endpoint
app.post("/send-otp", otpLimiter, async (req, res) => {
  try {
    let { email, type, pan, phone, identifier } = req.body;

    // If identifier is passed (e.g. Kite login with User ID, Phone, or Email)
    if (!email && identifier) {
      const cleanId = identifier.trim();
      const existing = await UserModel.findOne({
        $or: [
          { userId: { $regex: new RegExp(`^${escapeRegex(cleanId)}$`, "i") } },
          { email: cleanId.toLowerCase() },
          { phone: cleanId },
        ],
      });
      if (existing) {
        email = existing.email;
      } else if (type === "login") {
        return res.status(404).json({
          success: false,
          code: "USER_NOT_FOUND",
          message: `No Zerodha account registered with '${cleanId}'. Please open a new account to continue.`,
          notRegisteredEmail: cleanId,
        });
      }
    }

    if (!email || typeof email !== "string") {
      return res.status(400).json({ success: false, message: "Valid email or User ID is required" });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegex.test(normalizedEmail)) {
      return res.status(400).json({ success: false, message: "Please provide a valid email address" });
    }

    // 1. ENFORCEMENT: One Account per Email for Signup
    if (type === "signup") {
      const existingUserByEmail = await UserModel.findOne({ email: normalizedEmail });
      if (existingUserByEmail) {
        return res.status(409).json({
          success: false,
          code: "USER_ALREADY_EXISTS",
          message: `An account with ${normalizedEmail} already exists. Please log in instead.`,
          existingEmail: normalizedEmail,
        });
      }

      // SEBI Compliance: One Demat Account per PAN
      if (pan && pan.trim()) {
        const cleanPan = pan.trim().toUpperCase();
        const existingUserByPan = await UserModel.findOne({ pan: cleanPan });
        if (existingUserByPan) {
          return res.status(409).json({
            success: false,
            code: "PAN_ALREADY_EXISTS",
            message: `PAN card ${cleanPan} is already registered with another Zerodha account.`,
          });
        }
      }

      // One Demat Account per Mobile Number
      if (phone && phone.trim()) {
        const cleanPhone = phone.trim();
        const existingUserByPhone = await UserModel.findOne({ phone: cleanPhone });
        if (existingUserByPhone) {
          return res.status(409).json({
            success: false,
            code: "PHONE_ALREADY_EXISTS",
            message: `Mobile number +91 ${cleanPhone} is already linked with another Zerodha account.`,
          });
        }
      }
    }

    // 2. ENFORCEMENT: Account must exist to Login
    if (type === "login") {
      const existingUser = await UserModel.findOne({ email: normalizedEmail });
      if (!existingUser) {
        return res.status(404).json({
          success: false,
          code: "USER_NOT_FOUND",
          message: `No Zerodha account registered with ${normalizedEmail}. Please open a new account to continue.`,
          notRegisteredEmail: normalizedEmail,
        });
      }
    }

    // Generate secure 6-digit numeric OTP
    const generatedOtp = crypto.randomInt(100000, 1000000).toString();

    // Upsert into OtpModel (5 minutes expiry)
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    await OtpModel.findOneAndUpdate(
      { email: normalizedEmail },
      {
        otp: generatedOtp,
        attempts: 0,
        expiresAt,
        createdAt: new Date(),
      },
      { upsert: true, returnDocument: "after", setDefaultsOnInsert: true }
    );

    // Dispatch live email via Nodemailer
    const emailResult = await sendOtpEmail(normalizedEmail, generatedOtp);

    return res.status(200).json({
      success: true,
      message: emailResult.delivered
        ? `A 6-digit verification code has been sent to ${normalizedEmail}`
        : `Verification code sent to ${normalizedEmail}`,
      isLiveEmail: emailResult.delivered,
      devOtp: process.env.NODE_ENV === "test" ? generatedOtp : undefined,
    });
  } catch (error) {
    console.error("Error sending OTP:", error);
    return res.status(500).json({ success: false, message: "Internal server error while dispatching OTP" });
  }
});

// 2. Verify OTP Endpoint (Unified Signup & Login)
app.post("/verify-otp", authLimiter, async (req, res) => {
  try {
    const { email, otp, type, fullName, phone, pan, dob, annualIncome, tradingExp } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ success: false, message: "Email and OTP are both required" });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const cleanOtp = otp.toString().trim();

    if (!/^\d{6}$/.test(cleanOtp)) {
      return res.status(400).json({ success: false, message: "Verification code must be exactly 6 digits" });
    }

    if (phone && !/^[6-9]\d{9}$/.test(phone.trim())) {
      return res.status(400).json({ success: false, message: "Invalid Indian mobile number. Must be 10 digits starting with 6, 7, 8, or 9" });
    }

    if (pan && !/^[A-Z]{5}[0-9]{4}[A-Z]{1}$/.test(pan.trim().toUpperCase())) {
      return res.status(400).json({ success: false, message: "Invalid PAN card format (e.g. ABCDE1234F)" });
    }

    if (dob) {
      const dobDate = new Date(dob);
      const today = new Date();
      let age = today.getFullYear() - dobDate.getFullYear();
      const monthDiff = today.getMonth() - dobDate.getMonth();
      if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < dobDate.getDate())) {
        age--;
      }
      if (age < 18) {
        return res.status(400).json({ success: false, message: "Account holder must be at least 18 years of age" });
      }
    }

    // Query active OTP record
    const otpRecord = await OtpModel.findOne({ email: normalizedEmail });

    if (!otpRecord) {
      return res.status(400).json({
        success: false,
        message: "OTP expired or not requested. Please request a fresh OTP.",
      });
    }

    // Check if expired
    if (new Date(otpRecord.expiresAt) < new Date()) {
      await OtpModel.deleteOne({ _id: otpRecord._id });
      return res.status(400).json({
        success: false,
        message: "OTP has expired. Please request a fresh OTP.",
      });
    }

    // Check failed attempts (brute force mitigation)
    if (otpRecord.attempts >= 5) {
      await OtpModel.deleteOne({ _id: otpRecord._id });
      return res.status(429).json({
        success: false,
        message: "Too many failed attempts. Please request a new OTP.",
      });
    }

    // Compare OTP in constant time
    if (!constantTimeEquals(String(otpRecord.otp), cleanOtp)) {
      otpRecord.attempts += 1;
      await otpRecord.save();
      const remaining = 5 - otpRecord.attempts;
      return res.status(400).json({
        success: false,
        message: `Invalid OTP. ${remaining} attempt${remaining === 1 ? "" : "s"} remaining.`,
      });
    }

    // OTP verified! Delete consumed OTP immediately
    await OtpModel.deleteOne({ _id: otpRecord._id });

    // Atomic User Provisioning / Login
    let user = await UserModel.findOne({ email: normalizedEmail });

    if (type === "signup" && user) {
      return res.status(409).json({
        success: false,
        code: "USER_ALREADY_EXISTS",
        message: `An account with ${normalizedEmail} is already registered. Please log in instead.`,
      });
    }

    if (type === "login" && !user) {
      return res.status(404).json({
        success: false,
        code: "USER_NOT_FOUND",
        message: `No Zerodha account found for ${normalizedEmail}. Please open a new account to continue.`,
      });
    }

    if (!user) {
      // Generate unique Zerodha Kite client ID (e.g., ZU + 4 digits)
      const randomId = crypto.randomInt(1000, 10000);
      const generatedUserId = `ZU${randomId}`;
      const name = fullName && fullName.trim() ? fullName.trim() : "Trader";
      const initials = name
        .split(" ")
        .filter(Boolean)
        .map((n) => n[0])
        .join("")
        .toUpperCase()
        .slice(0, 2) || "TR";

      user = new UserModel({
        userId: generatedUserId,
        email: normalizedEmail,
        fullName: name,
        phone: phone ? phone.trim() : "",
        pan: pan ? pan.trim().toUpperCase() : "",
        dob: dob || "",
        annualIncome: annualIncome || "₹1L - ₹5L",
        tradingExp: tradingExp || "1-3 Years",
        avatarText: initials,
        role: "user",
        createdAt: new Date(),
        lastLogin: new Date(),
      });
      await user.save();
      logger.info("user_provisioned", { userId: user.userId });
    } else {
      user.lastLogin = new Date();
      if (fullName && fullName.trim()) {
        user.fullName = fullName.trim();
        user.avatarText = user.fullName
          .split(" ")
          .filter(Boolean)
          .map((n) => n[0])
          .join("")
          .toUpperCase()
          .slice(0, 2) || "TR";
      }
      if (phone && phone.trim()) user.phone = phone.trim();
      if (pan && pan.trim()) user.pan = pan.trim().toUpperCase();
      if (dob) user.dob = dob;
      if (annualIncome) user.annualIncome = annualIncome;
      if (tradingExp) user.tradingExp = tradingExp;
      await user.save();
      console.log(`🔓 [USER LOGGED IN] ${user.userId} (${user.email}) - Name: ${user.fullName}`);
    }

    // Sign versioned JWT and issue HttpOnly session + CSRF cookies
    const token = issueAuthSession(res, req, user);

    return res.status(200).json({
      success: true,
      message: "Authentication successful!",
      token,
      user: {
        userId: user.userId,
        email: user.email,
        fullName: user.fullName,
        phone: decryptField(user.phone || ""),
        pan: decryptField(user.pan || ""),
        dob: decryptField(user.dob || ""),
        demat: user.demat || "1208160012345678",
        annualIncome: user.annualIncome || "₹1L - ₹5L",
        tradingExp: user.tradingExp || "1-3 Years",
        broker: user.broker || "Zerodha Broking Ltd.",
        avatarText: user.avatarText,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Error verifying OTP:", error);
    return res.status(500).json({ success: false, message: "Internal server error during verification" });
  }
});

// 2.5 Kite Direct Password Login Endpoint
app.post("/kite-login", authLimiter, async (req, res) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || typeof identifier !== "string" || !identifier.trim()) {
      return res.status(400).json({ success: false, message: "User ID, Phone number, or Email is required" });
    }
    if (!password || typeof password !== "string" || password.length === 0) {
      return res.status(400).json({ success: false, message: "Password is required for password-based login." });
    }

    const cleanId = identifier.trim();
    const user = await UserModel.findOne({
      $or: [
        { userId: { $regex: new RegExp(`^${escapeRegex(cleanId)}$`, "i") } },
        { email: cleanId.toLowerCase() },
        { phone: cleanId },
      ],
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        code: "INVALID_CREDENTIALS",
        message: "Invalid account identifier or password.",
      });
    }

    if (!user.password) {
      return res.status(403).json({
        success: false,
        code: "PASSWORD_NOT_INITIALIZED",
        message: "Password login is not enabled for this account. Please sign in with OTP verification first.",
      });
    }

    const isValid = verifyPassword(password, user.password);
    if (!isValid) {
      logger.warn("kite_login_failed", { userId: user.userId });
      return res.status(401).json({ success: false, message: "Incorrect password. Please try again." });
    }

    // Transparently upgrade legacy plaintext password to scrypt digest on verified login
    if (!user.password.includes(":")) {
      user.password = hashPassword(password);
    }

    user.lastLogin = new Date();
    await user.save();

    const token = issueAuthSession(res, req, user);

    logger.info("kite_login_success", { userId: user.userId });

    return res.status(200).json({
      success: true,
      message: "Login successful!",
      token,
      user: {
        userId: user.userId,
        email: user.email,
        fullName: user.fullName,
        phone: user.phone || "",
        demat: user.demat || "",
        annualIncome: user.annualIncome || "₹1L - ₹5L",
        tradingExp: user.tradingExp || "1-3 Years",
        broker: user.broker || "Zerodha Broking Ltd.",
        avatarText: user.avatarText,
        role: user.role,
      },
    });
  } catch (error) {
    logger.error("kite_login_error", { message: error.message });
    return res.status(500).json({ success: false, message: "Internal server error during login" });
  }
});

// 3. Verify Active Session Token
app.get("/verifyUser", requireAuth, async (req, res) => {
  try {
    const resolvedUserId = req.authUserId;
    const user = await UserModel.findOne({ userId: resolvedUserId }).select(
      "-password -cdslTpin -cdslAttempts -cdslLockedUntil -__v"
    );
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    return res.status(200).json({
      success: true,
      user: {
        userId: user.userId,
        email: user.email,
        fullName: user.fullName,
        phone: decryptField(user.phone || ""),
        pan: decryptField(user.pan || ""),
        demat: user.demat || "",
        annualIncome: user.annualIncome || "₹1L - ₹5L",
        tradingExp: user.tradingExp || "1-3 Years",
        broker: user.broker || "Zerodha Broking Ltd.",
        avatarText: user.avatarText,
        role: user.role,
        nomineeStatus: user.nomineeStatus || "PENDING",
        nominees: user.nominees || [],
        cdslAuthorizedUntil: user.cdslAuthorizedUntil || null,
        isCdslAuthorizedToday: Boolean(
          user.cdslAuthorizedUntil && new Date() <= new Date(user.cdslAuthorizedUntil)
        ),
      },
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Error verifying user profile" });
  }
});

// 4. Logout & Server-Side Token Revocation
app.post("/logout", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    await UserModel.updateOne({ userId }, { $inc: { tokenVersion: 1 } });
    clearAuthCookies(res, req);
    logger.info("user_logged_out", { userId });
    return res.status(200).json({ success: true, message: "Logged out securely." });
  } catch (error) {
    logger.error("logout_error", { error: error.message });
    return res.status(500).json({ success: false, message: "Failed to log out" });
  }
});

// ==========================================
// Core Trading & Market Data Routes
// ==========================================

app.get("/allHoldings", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(200).json([]);
    }
    const allHoldings = await HoldingsModel.find({ userId });
    res.status(200).json(allHoldings);
  } catch (error) {
    console.error("Error fetching holdings:", error);
    res.status(500).json({ error: "Failed to fetch holdings" });
  }
});

app.get("/allPositions", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(200).json([]);
    }
    const allPositions = await PositionsModel.find({ userId });
    res.status(200).json(allPositions);
  } catch (error) {
    console.error("Error fetching positions:", error);
    res.status(500).json({ error: "Failed to fetch positions" });
  }
});

// ==========================================
// POSITIONS ENGINE (SQUARE OFF & CONVERT)
// ==========================================

// 1. Square Off Single Position (MIS or Overnight)
app.post("/squareOffPosition", requireAuth, tradeFundsLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "User authentication required" });
    }
    const { positionId, exitPrice } = req.body;
    const position = await PositionsModel.findOne({ _id: positionId, userId });
    if (!position || position.qty === 0) {
      return res.status(400).json({ success: false, message: "Position not found or already squared off." });
    }

    const sym = position.instrument || position.name;
    const ltp = Number(exitPrice) || position.ltp || position.price || position.avg;
    const qty = position.qty;
    const avg = position.avg || ltp;

    // Realized P&L calculation:
    // Long (qty > 0): (ltp - avg) * qty
    // Short (qty < 0): (avg - ltp) * Math.abs(qty)
    const realizedPnl = Number((qty > 0 ? (ltp - avg) * qty : (avg - ltp) * Math.abs(qty)).toFixed(2));

    // Release margin and add/deduct P&L from funds
    const funds = await getOrCreateUserFunds(userId);
    if (funds) {
      const orderCost = Math.abs(qty) * avg;
      const marginBlocked = (position.product || "MIS") === "MIS" ? orderCost * 0.2 : orderCost;
      let currentAvailable = parseFloat(funds.equity.availableMargin.replace(/,/g, "")) || 0;
      let currentUsed = parseFloat(funds.equity.usedMargin.replace(/,/g, "")) || 0;

      currentAvailable += (marginBlocked + realizedPnl);
      currentUsed = Math.max(0, currentUsed - marginBlocked);

      funds.equity.availableMargin = formatIndianCurrency(currentAvailable);
      funds.equity.usedMargin = formatIndianCurrency(currentUsed);
      funds.equity.availableCash = formatIndianCurrency(currentAvailable);
      await funds.save();
    }

    // Record square off order in OrdersModel
    const exitMode = qty > 0 ? "SELL" : "BUY";
    const exitOrder = new OrdersModel({
      userId,
      name: sym,
      qty: Math.abs(qty),
      price: ltp,
      mode: exitMode,
      product: position.product || "MIS",
      status: "COMPLETE",
      tag: "SQUARE_OFF",
    });
    await exitOrder.save();

    // Mark position as closed with final realized P&L
    position.realizedPnl = Number(((position.realizedPnl || 0) + realizedPnl).toFixed(2));
    position.pnl = position.realizedPnl;
    position.unrealizedPnl = 0;
    position.qty = 0;
    position.ltp = ltp;
    position.status = "CLOSED";
    position.closedAt = new Date();
    position.isProfit = position.realizedPnl >= 0;
    position.isLoss = position.realizedPnl < 0;
    await position.save();

    // Send in-app notification
    try {
      await createNotification({
        userId,
        type: "ORDER",
        category: "TRADE",
        title: `Position Squared Off: ${sym}`,
        description: `Closed ${Math.abs(qty)} ${sym} (${position.product}) @ ₹${ltp.toFixed(2)}. Realized P&L: ${realizedPnl >= 0 ? "+" : ""}₹${realizedPnl.toFixed(2)}`,
        status: "SUCCESS",
      });
    } catch (e) {}

    res.status(200).json({
      success: true,
      message: `Position in ${sym} squared off successfully! Realized P&L: ${realizedPnl >= 0 ? "+" : ""}₹${realizedPnl.toFixed(2)}`,
      position,
      realizedPnl,
    });
  } catch (error) {
    console.error("Error squaring off position:", error);
    res.status(500).json({ success: false, message: "Failed to square off position." });
  }
});

// 2. Square Off All Open Positions (Emergency / 15:20 RMS Square Off)
app.post("/squareOffAllPositions", requireAuth, tradeFundsLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "User authentication required" });
    }
    const openPositions = await PositionsModel.find({ userId, qty: { $ne: 0 } });
    if (!openPositions || openPositions.length === 0) {
      return res.status(400).json({ success: false, message: "No open positions to square off." });
    }

    const funds = await getOrCreateUserFunds(userId);
    let totalRealized = 0;
    const closedPositions = [];

    for (const pos of openPositions) {
      const sym = pos.instrument || pos.name;
      const ltp = pos.ltp || pos.price || pos.avg;
      const qty = pos.qty;
      const avg = pos.avg || ltp;
      const pnl = Number((qty > 0 ? (ltp - avg) * qty : (avg - ltp) * Math.abs(qty)).toFixed(2));
      totalRealized += pnl;

      if (funds) {
        const orderCost = Math.abs(qty) * avg;
        const marginBlocked = (pos.product || "MIS") === "MIS" ? orderCost * 0.2 : orderCost;
        let currentAvailable = parseFloat(funds.equity.availableMargin.replace(/,/g, "")) || 0;
        let currentUsed = parseFloat(funds.equity.usedMargin.replace(/,/g, "")) || 0;

        currentAvailable += (marginBlocked + pnl);
        currentUsed = Math.max(0, currentUsed - marginBlocked);

        funds.equity.availableMargin = formatIndianCurrency(currentAvailable);
        funds.equity.usedMargin = formatIndianCurrency(currentUsed);
        funds.equity.availableCash = formatIndianCurrency(currentAvailable);
      }

      // Exit order log
      const exitOrder = new OrdersModel({
        userId,
        name: sym,
        qty: Math.abs(qty),
        price: ltp,
        mode: qty > 0 ? "SELL" : "BUY",
        product: pos.product || "MIS",
        status: "COMPLETE",
        tag: "RMS_SQUARE_OFF_ALL",
      });
      await exitOrder.save();

      pos.realizedPnl = Number(((pos.realizedPnl || 0) + pnl).toFixed(2));
      pos.pnl = pos.realizedPnl;
      pos.unrealizedPnl = 0;
      pos.qty = 0;
      pos.ltp = ltp;
      pos.status = "CLOSED";
      pos.closedAt = new Date();
      pos.isProfit = pos.realizedPnl >= 0;
      pos.isLoss = pos.realizedPnl < 0;
      await pos.save();
      closedPositions.push(pos);
    }

    if (funds) await funds.save();

    try {
      await createNotification({
        userId,
        type: "ORDER",
        category: "SYSTEM",
        title: `All Positions Squared Off (${closedPositions.length})`,
        description: `Emergency square-off executed for ${closedPositions.length} open position(s). Total Day Realized P&L: ${totalRealized >= 0 ? "+" : ""}₹${totalRealized.toFixed(2)}.`,
        status: "SUCCESS",
      });
    } catch (e) {}

    res.status(200).json({
      success: true,
      message: `All ${closedPositions.length} open positions squared off at market price! Total Realized P&L: ${totalRealized >= 0 ? "+" : ""}₹${totalRealized.toFixed(2)}`,
      count: closedPositions.length,
      totalRealized,
      positions: closedPositions,
    });
  } catch (error) {
    console.error("Error squaring off all positions:", error);
    res.status(500).json({ success: false, message: "Failed to square off all positions." });
  }
});

// 3. Convert Position (MIS <-> CNC/NRML)
app.post("/convertPosition", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "User authentication required" });
    }
    const { positionId, targetProduct } = req.body;
    const position = await PositionsModel.findOne({ _id: positionId, userId });
    if (!position || position.qty === 0) {
      return res.status(400).json({ success: false, message: "Active open position required to convert." });
    }

    const currentProduct = (position.product || "MIS").toUpperCase();
    const desiredProduct = (targetProduct || (currentProduct === "MIS" ? "CNC" : "MIS")).toUpperCase();

    if (currentProduct === desiredProduct) {
      return res.status(400).json({ success: false, message: `Position is already ${currentProduct}.` });
    }

    const sym = position.instrument || position.name;
    const qty = Math.abs(position.qty);
    const avg = position.avg;
    const orderCost = qty * avg;
    const funds = await getOrCreateUserFunds(userId);

    if (currentProduct === "MIS" && (desiredProduct === "CNC" || desiredProduct === "NRML")) {
      // MIS (20%) -> CNC/NRML (100%): Requires additional 80% margin!
      const additionalMarginRequired = orderCost * 0.8;
      let currentAvailable = parseFloat(funds?.equity?.availableMargin?.replace(/,/g, "") || "0");

      if (currentAvailable < additionalMarginRequired) {
        return res.status(400).json({
          success: false,
          code: "INSUFFICIENT_MARGIN",
          message: `Cannot convert to ${desiredProduct}! Insufficient cash margin. Additional required: ₹${formatIndianCurrency(additionalMarginRequired)}, Available: ₹${formatIndianCurrency(currentAvailable)}.`,
        });
      }

      currentAvailable -= additionalMarginRequired;
      let currentUsed = parseFloat(funds.equity.usedMargin.replace(/,/g, "")) || 0;
      currentUsed += additionalMarginRequired;

      funds.equity.availableMargin = formatIndianCurrency(currentAvailable);
      funds.equity.usedMargin = formatIndianCurrency(currentUsed);
      funds.equity.availableCash = formatIndianCurrency(currentAvailable);
      await funds.save();

      // If converting to CNC, also mirror into Demat HoldingsModel if long
      if (desiredProduct === "CNC" && position.qty > 0) {
        let holding = await HoldingsModel.findOne({ userId, $or: [{ name: sym }, { instrument: sym }] });
        if (holding) {
          const totalShares = holding.qty + qty;
          const totalCost = holding.qty * (holding.avg || holding.price) + qty * avg;
          holding.avg = Number((totalCost / totalShares).toFixed(2));
          holding.qty = totalShares;
          holding.curVal = Number((totalShares * (position.ltp || avg)).toFixed(2));
          await holding.save();
        } else {
          holding = new HoldingsModel({
            userId,
            name: sym,
            instrument: sym,
            qty,
            avg,
            avgCost: avg,
            price: avg,
            ltp: position.ltp || avg,
            curVal: Number((qty * (position.ltp || avg)).toFixed(2)),
            pnl: 0,
            net: "+0.00%",
            day: "+0.00%",
            isProfit: true,
          });
          await holding.save();
        }
      }
    } else if ((currentProduct === "CNC" || currentProduct === "NRML") && desiredProduct === "MIS") {
      // CNC (100%) -> MIS (20%): Releases 80% margin back to available cash!
      const releasedMargin = orderCost * 0.8;
      let currentAvailable = parseFloat(funds?.equity?.availableMargin?.replace(/,/g, "") || "0");
      let currentUsed = parseFloat(funds?.equity?.usedMargin?.replace(/,/g, "")) || 0;

      currentAvailable += releasedMargin;
      currentUsed = Math.max(0, currentUsed - releasedMargin);

      funds.equity.availableMargin = formatIndianCurrency(currentAvailable);
      funds.equity.usedMargin = formatIndianCurrency(currentUsed);
      funds.equity.availableCash = formatIndianCurrency(currentAvailable);
      await funds.save();

      // Remove from holdings if it came from CNC
      if (currentProduct === "CNC") {
        let holding = await HoldingsModel.findOne({ userId, $or: [{ name: sym }, { instrument: sym }] });
        if (holding) {
          holding.qty = Math.max(0, holding.qty - qty);
          if (holding.qty === 0) {
            await HoldingsModel.deleteOne({ _id: holding._id });
          } else {
            await holding.save();
          }
        }
      }
    }

    position.product = desiredProduct;
    position.convertedAt = new Date();
    await position.save();

    try {
      await createNotification({
        userId,
        type: "ORDER",
        category: "TRADE",
        title: `Position Converted: ${sym}`,
        description: `Successfully converted ${qty} ${sym} from ${currentProduct} to ${desiredProduct}.`,
        status: "SUCCESS",
      });
    } catch (e) {}

    res.status(200).json({
      success: true,
      message: `Position in ${sym} successfully converted from ${currentProduct} to ${desiredProduct}!`,
      position,
    });
  } catch (error) {
    console.error("Error converting position:", error);
    res.status(500).json({ success: false, message: "Failed to convert position." });
  }
});

app.get("/allOrders", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(200).json([]);
    }
    const allOrders = await OrdersModel.find({ userId }).sort({ createdAt: -1 });
    res.status(200).json(allOrders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Failed to fetch orders" });
  }
});


// Dynamic Real-Time Notification Dispatcher
async function createNotification({
  userId,
  type = "ORDER",
  category = "EXECUTION",
  title,
  description,
  metadata = {},
  priority = "NORMAL",
}) {
  try {
    const notification = new NotificationModel({
      userId,
      type,
      category,
      title,
      description,
      metadata,
      unread: true,
      priority,
      createdAt: new Date(),
    });
    const saved = await notification.save();
    console.log(`🔔 [NOTIFICATION DISPATCHED] [${type}] ${title} for ${userId}`);
    return saved;
  } catch (err) {
    console.error("Error in createNotification:", err.message);
    return null;
  }
}

// Helper: Strictly isolate user funds per tenant/user account (transaction-session aware)
async function getOrCreateUserFunds(userId, session = null) {
  if (!userId) return null;
  const query = FundsModel.findOne({ userId });
  if (session) query.session(session);
  let funds = await query;
  if (!funds) {
    funds = new FundsModel({
      userId,
      equity: {
        availableMargin: "0.00",
        usedMargin: "0.00",
        availableCash: "0.00",
        openingBalance: "0.00",
      },
      commodity: {
        availableMargin: "0.00",
        usedMargin: "0.00",
        availableCash: "0.00",
        openingBalance: "0.00",
      },
    });
    await funds.save(session ? { session } : undefined);
    logger.info("user_funds_initialized", { userId });
  }
  return funds;
}

// Unified Order Execution Helper
async function executeOrderInternal({ name, qty, price, mode = "BUY", product = "CNC", userId }) {
  const numQty = Number(qty);
  const numPrice = Number(price);

  if (!name || isNaN(numQty) || numQty <= 0 || isNaN(numPrice) || numPrice <= 0) {
    return { success: false, message: "Valid instrument name, positive quantity, and price are required." };
  }

  // 🛡️ Pre-Trade Risk Engine: Segments & Kill Switch Enforcement
  try {
    const userDoc = await UserModel.findOne({ userId });
    if (userDoc && userDoc.segments) {
      let requiredSegment = "equity";
      const upperName = (name || "").toUpperCase();
      if (
        upperName.includes(" FUT") ||
        upperName.includes(" CE") ||
        upperName.includes(" PE") ||
        (upperName.includes("NIFTY") && (upperName.includes("OPT") || upperName.includes("FUT")))
      ) {
        requiredSegment = "futuresAndOptions";
      } else if (
        upperName.includes("CRUDEOIL") ||
        upperName.includes("GOLD") ||
        upperName.includes("SILVER") ||
        upperName.includes("NATURALGAS") ||
        upperName.includes("MCX")
      ) {
        requiredSegment = "commodity";
      } else if (
        upperName.includes("USDINR") ||
        upperName.includes("EURINR") ||
        upperName.includes("GBPINR") ||
        upperName.includes("JPYINR")
      ) {
        requiredSegment = "currency";
      }

      const segConfig = userDoc.segments[requiredSegment];
      if (segConfig && segConfig.active === false) {
        const segDisplayName = segConfig.name || requiredSegment;
        return {
          success: false,
          code: "SEGMENT_DISABLED",
          message: `Order rejected! Trading in "${segDisplayName}" is disabled under your Risk Settings / Kill Switch.`,
        };
      }
    }
  } catch (segErr) {
    console.warn("Segment validation warning:", segErr.message);
  }

  const orderMode = mode.toUpperCase();
  const orderProduct = product.toUpperCase();
  if (!["BUY", "SELL"].includes(orderMode) || !["CNC", "MIS", "NRML"].includes(orderProduct)) {
    return { success: false, message: "Invalid order mode or product type." };
  }
  const orderCostPaise = Math.round(numQty * toPaise(numPrice));
  const marginRequiredPaise = orderProduct === "MIS" ? Math.round(orderCostPaise * 0.2) : orderCostPaise;
  const orderCost = fromPaise(orderCostPaise);

  return await withUserLock(`trade:${userId}`, async () =>
    runInTransaction(async (session) => {
      const sOpt = session ? { session } : undefined;
      let funds = await getOrCreateUserFunds(userId, session);
      if (!funds) {
        return {
          success: false,
          code: "FUNDS_UNAVAILABLE",
          message: "Unable to retrieve or initialize trading funds for this user account.",
        };
      }

      let currentAvailablePaise = toPaise(funds.equity.availableMargin);
      let currentUsedPaise = toPaise(funds.equity.usedMargin);

      if (orderMode === "BUY") {
        if (currentAvailablePaise < marginRequiredPaise) {
          return {
            success: false,
            code: "INSUFFICIENT_MARGIN",
            message: `Insufficient margin! Margin required: ₹${formatPaiseINR(marginRequiredPaise)}, but available margin is only ₹${formatPaiseINR(currentAvailablePaise)}.`,
          };
        }

        currentAvailablePaise = subPaise(currentAvailablePaise, marginRequiredPaise);
        currentUsedPaise = addPaise(currentUsedPaise, marginRequiredPaise);
        funds.equity.availableMargin = formatPaiseINR(currentAvailablePaise);
        funds.equity.usedMargin = formatPaiseINR(currentUsedPaise);
        funds.equity.availableCash = formatPaiseINR(currentAvailablePaise);
        await funds.save(sOpt);

    if (orderProduct === "CNC") {
      let existingHolding = await HoldingsModel.findOne({
        userId,
        $or: [{ name }, { instrument: name }],
      });

      if (existingHolding) {
        const totalShares = existingHolding.qty + numQty;
        const totalCost = existingHolding.qty * (existingHolding.avg || existingHolding.price) + numQty * numPrice;
        existingHolding.avg = Number((totalCost / totalShares).toFixed(2));
        existingHolding.avgCost = existingHolding.avg;
        existingHolding.qty = totalShares;
        existingHolding.price = numPrice;
        existingHolding.ltp = numPrice;
        existingHolding.curVal = Number((totalShares * numPrice).toFixed(2));
        existingHolding.pnl = Number((existingHolding.curVal - totalShares * existingHolding.avg).toFixed(2));
        existingHolding.net = `${existingHolding.pnl >= 0 ? "+" : ""}${((existingHolding.pnl / (totalShares * existingHolding.avg)) * 100).toFixed(2)}%`;
        existingHolding.isProfit = existingHolding.pnl >= 0;
        await existingHolding.save();
      } else {
        const newHolding = new HoldingsModel({
          userId,
          name,
          instrument: name,
          qty: numQty,
          avg: numPrice,
          avgCost: numPrice,
          price: numPrice,
          ltp: numPrice,
          curVal: Number(orderCost.toFixed(2)),
          pnl: 0,
          net: "+0.00%",
          netChg: "0.00",
          day: "+0.00%",
          dayChg: "0.00",
          isProfit: true,
          isDayProfit: true,
        });
        await newHolding.save();
      }
    } else {
      let existingPosition = await PositionsModel.findOne({
        userId,
        $or: [{ name }, { instrument: name }],
        product: orderProduct,
      });

      if (existingPosition) {
        if (existingPosition.qty === 0) {
          existingPosition.qty = numQty;
          existingPosition.avg = numPrice;
          existingPosition.price = numPrice;
          existingPosition.ltp = numPrice;
          existingPosition.status = "OPEN";
          existingPosition.closedAt = null;
        } else if (existingPosition.qty > 0) {
          const totalShares = existingPosition.qty + numQty;
          const totalCost = existingPosition.qty * (existingPosition.avg || existingPosition.price) + numQty * numPrice;
          existingPosition.avg = Number((totalCost / totalShares).toFixed(2));
          existingPosition.qty = totalShares;
          existingPosition.price = numPrice;
          existingPosition.ltp = numPrice;
          existingPosition.status = "OPEN";
          existingPosition.closedAt = null;
        } else {
          // Covering short position
          const netQty = existingPosition.qty + numQty;
          if (netQty > 0) {
            existingPosition.avg = numPrice;
            existingPosition.qty = netQty;
            existingPosition.status = "OPEN";
            existingPosition.closedAt = null;
          } else if (netQty === 0) {
            existingPosition.qty = 0;
            existingPosition.status = "CLOSED";
            existingPosition.closedAt = new Date();
          } else {
            existingPosition.qty = netQty;
            existingPosition.status = "OPEN";
            existingPosition.closedAt = null;
          }
          existingPosition.price = numPrice;
          existingPosition.ltp = numPrice;
        }
        await existingPosition.save();
      } else {
        const newPosition = new PositionsModel({
          userId,
          product: orderProduct || "MIS",
          name,
          instrument: name,
          qty: numQty,
          avg: numPrice,
          price: numPrice,
          ltp: numPrice,
          pnl: 0,
          net: "+0.00%",
          day: "+0.00%",
          chg: "+0.00%",
          isLoss: false,
          isProfit: true,
          status: "OPEN",
          closedAt: null,
        });
        await newPosition.save();
      }
    }
  } else if (orderMode === "SELL") {
    if (orderProduct === "CNC") {
      // Server-side CDSL E-DIS authorization gate for CNC Demat sell orders
      const seller = await UserModel.findOne({ userId }).select("cdslAuthorizedUntil");
      if (!seller || !seller.cdslAuthorizedUntil || new Date() > new Date(seller.cdslAuthorizedUntil)) {
        return {
          success: false,
          code: "CDSL_AUTH_REQUIRED",
          message:
            "CDSL E-DIS authorization required before selling CNC Demat holdings. Please verify your TPIN and OTP.",
        };
      }

      let existingHolding = await HoldingsModel.findOne({
        userId,
        $or: [{ name }, { instrument: name }],
      });

      if (!existingHolding || existingHolding.qty < numQty) {
        return {
          success: false,
          code: "INSUFFICIENT_HOLDINGS",
          message: `Cannot sell! You only hold ${existingHolding ? existingHolding.qty : 0} shares of ${name} in your Demat account.`,
        };
      }

      existingHolding.qty -= numQty;
      if (existingHolding.qty <= 0) {
        await HoldingsModel.deleteOne({ _id: existingHolding._id });
      } else {
        existingHolding.curVal = Number((existingHolding.qty * numPrice).toFixed(2));
        existingHolding.pnl = Number((existingHolding.curVal - existingHolding.qty * existingHolding.avg).toFixed(2));
        await existingHolding.save();
      }

      const proceedsPaise = Math.round(numQty * toPaise(numPrice));
      currentAvailablePaise = addPaise(currentAvailablePaise, proceedsPaise);
      currentUsedPaise = Math.max(0, subPaise(currentUsedPaise, proceedsPaise));
      funds.equity.availableMargin = formatPaiseINR(currentAvailablePaise);
      funds.equity.usedMargin = formatPaiseINR(currentUsedPaise);
      funds.equity.availableCash = formatPaiseINR(currentAvailablePaise);
      await funds.save(sOpt);
    } else {
      let existingPosition = await PositionsModel.findOne({
        userId,
        $or: [{ name }, { instrument: name }],
        product: orderProduct,
      });

      if (existingPosition) {
        if (existingPosition.qty > 0) {
          const netQty = existingPosition.qty - numQty;
          if (netQty === 0) {
            existingPosition.qty = 0;
            existingPosition.status = "CLOSED";
            existingPosition.closedAt = new Date();
          } else if (netQty > 0) {
            existingPosition.qty = netQty;
            existingPosition.status = "OPEN";
            existingPosition.closedAt = null;
          } else {
            // Flipped to short
            existingPosition.avg = numPrice;
            existingPosition.qty = netQty;
            existingPosition.status = "OPEN";
            existingPosition.closedAt = null;
          }
        } else {
          // Already short or 0, increase short position
          const priorShares = Math.abs(existingPosition.qty);
          const totalShares = priorShares + numQty;
          const totalCost = priorShares * (existingPosition.avg || existingPosition.price) + numQty * numPrice;
          existingPosition.avg = Number((totalCost / totalShares).toFixed(2));
          existingPosition.qty = -totalShares;
          existingPosition.status = "OPEN";
          existingPosition.closedAt = null;
        }
        existingPosition.price = numPrice;
        existingPosition.ltp = numPrice;
        await existingPosition.save();
      } else {
        // New Short Intraday / Overnight Position
        const newPosition = new PositionsModel({
          userId,
          product: orderProduct || "MIS",
          name,
          instrument: name,
          qty: -numQty,
          avg: numPrice,
          price: numPrice,
          ltp: numPrice,
          pnl: 0,
          net: "+0.00%",
          day: "+0.00%",
          chg: "+0.00%",
          isLoss: false,
          isProfit: true,
          status: "OPEN",
          closedAt: null,
        });
        await newPosition.save();
      }

      currentAvailablePaise = addPaise(currentAvailablePaise, marginRequiredPaise);
      currentUsedPaise = Math.max(0, subPaise(currentUsedPaise, marginRequiredPaise));
      funds.equity.availableMargin = formatPaiseINR(currentAvailablePaise);
      funds.equity.usedMargin = formatPaiseINR(currentUsedPaise);
      funds.equity.availableCash = formatPaiseINR(currentAvailablePaise);
      await funds.save(sOpt);
    }
  }

  const newOrder = new OrdersModel({
    userId,
    name,
    qty: numQty,
    price: numPrice,
    mode: orderMode,
    product: orderProduct,
    status: "COMPLETE",
    createdAt: new Date(),
  });
  const savedOrder = await newOrder.save(sOpt);

  // Real-Time Dynamic Notification Dispatch
  try {
    await createNotification({
      userId,
      type: "ORDER",
      category: "EXECUTION",
      title: `Order Executed - ${orderMode} ${numQty} ${name}`,
      description: `${orderMode} ${numQty} ${name} @ ₹${numPrice.toFixed(2)} (${orderProduct}) executed at NSE successfully.`,
      metadata: {
        orderId: savedOrder._id ? savedOrder._id.toString() : "",
        symbol: name,
        qty: numQty,
        price: numPrice,
        mode: orderMode,
        product: orderProduct,
        actionUrl: "/orders",
      },
    });
  } catch (notifErr) {
    console.error("Failed to dispatch order notification:", notifErr.message);
  }

  return {
    success: true,
    order: savedOrder,
    funds: funds.equity,
  };
    })
  );
}

// Integer-paise formatIndianCurrency is imported from ./utils/money

// 1. Transactional Order Engine with Portfolio & Funds Synchronization
app.post("/newOrder", requireAuth, tradeFundsLimiter, async (req, res) => {
  try {
    const { name, qty, price, mode = "BUY", product = "CNC" } = req.body;
    const userId = getAuthenticatedUserId(req);
    const result = await executeOrderInternal({ name, qty, price, mode, product, userId });
    if (!result.success) {
      const status = result.code === "CDSL_AUTH_REQUIRED" ? 403 : 400;
      return res.status(status).json(result);
    }
    console.log(`⚡ [ORDER EXECUTED] ${mode} ${qty} ${name} @ ₹${price} (${product}) for ${userId}`);
    return res.status(201).json({
      success: true,
      message: `Order executed: ${mode} ${qty} ${name} @ ₹${price} (${product})`,
      order: result.order,
      funds: result.funds,
    });
  } catch (error) {
    if (error?.status === 429) {
      return res.status(429).json({ success: false, message: error.message });
    }
    logger.error("order_engine_error", { error: error.message });
    return res.status(500).json({ success: false, message: "Internal server error processing order" });
  }
});

app.get("/allWatchlist", async (req, res) => {
  try {
    const allWatchlist = await WatchlistModel.find({});
    res.status(200).json(allWatchlist);
  } catch (error) {
    console.error("Error fetching watchlist:", error);
    res.status(500).json({ error: "Failed to fetch watchlist" });
  }
});

const defaultTab1Stocks = [
  { symbol: "INFY", name: "Infosys Ltd.", exchange: "NSE", sector: "Technology", price: 1845.50, change: -18.25, percent: "-0.98%", isDown: true },
  { symbol: "RELIANCE", name: "Reliance Industries", exchange: "NSE", sector: "Energy", price: 2712.40, change: 24.30, percent: "+0.90%", isDown: false },
  { symbol: "HDFCBANK", name: "HDFC Bank Ltd.", exchange: "NSE", sector: "Banking", price: 1728.15, change: -6.40, percent: "-0.37%", isDown: true },
  { symbol: "TCS", name: "Tata Consultancy Services", exchange: "NSE", sector: "Technology", price: 3982.75, change: 15.60, percent: "+0.39%", isDown: false },
  { symbol: "TATAMOTORS", name: "Tata Motors Ltd.", exchange: "NSE", sector: "Automobile", price: 884.20, change: -12.10, percent: "-1.35%", isDown: true },
  { symbol: "ICICIBANK", name: "ICICI Bank Ltd.", exchange: "NSE", sector: "Banking", price: 1242.00, change: 11.80, percent: "+0.96%", isDown: false },
  { symbol: "SBIN", name: "State Bank of India", exchange: "NSE", sector: "Banking", price: 814.65, change: -4.50, percent: "-0.55%", isDown: true },
  { symbol: "BHARTIARTL", name: "Bharti Airtel Ltd.", exchange: "NSE", sector: "Telecom", price: 1684.90, change: 22.40, percent: "+1.35%", isDown: false },
  { symbol: "ITC", name: "ITC Ltd.", exchange: "NSE", sector: "FMCG", price: 478.30, change: 1.15, percent: "+0.24%", isDown: false },
  { symbol: "WIPRO", name: "Wipro Ltd.", exchange: "NSE", sector: "Technology", price: 546.80, change: -5.20, percent: "-0.94%", isDown: true },
  { symbol: "LT", name: "Larsen & Toubro Ltd.", exchange: "NSE", sector: "Infrastructure", price: 3560.10, change: -28.75, percent: "-0.80%", isDown: true },
  { symbol: "HINDUNILVR", name: "Hindustan Unilever Ltd.", exchange: "NSE", sector: "FMCG", price: 2382.40, change: 8.90, percent: "+0.38%", isDown: false },
  { symbol: "BAJFINANCE", name: "Bajaj Finance Ltd.", exchange: "NSE", sector: "Financial Services", price: 6890.00, change: -45.50, percent: "-0.66%", isDown: true },
  { symbol: "MARUTI", name: "Maruti Suzuki India", exchange: "NSE", sector: "Automobile", price: 11240.50, change: 85.00, percent: "+0.76%", isDown: false },
  { symbol: "SUNPHARMA", name: "Sun Pharmaceutical", exchange: "NSE", sector: "Healthcare", price: 1782.30, change: 14.20, percent: "+0.80%", isDown: false },
];

// GET /masterInstruments - Omnisearch across catalog (Stored in & Fetched from MongoDB Atlas!)
app.get("/masterInstruments", async (req, res) => {
  try {
    const rawQ = req.query.q;
    const rawSector = req.query.sector;
    if ((rawQ !== undefined && typeof rawQ !== "string") || (rawSector !== undefined && typeof rawSector !== "string")) {
      return res.status(400).json({ error: "Invalid query parameter type" });
    }
    const q = (rawQ || "").trim();
    const sector = (rawSector || "").trim();
    if (q.length > 64 || sector.length > 64) {
      return res.status(400).json({ error: "Search query exceeds maximum length of 64 characters" });
    }
    const parsedLimit = parseInt(req.query.limit, 10);
    const limit = Number.isFinite(parsedLimit) ? Math.min(Math.max(parsedLimit, 1), 100) : 50;

    const query = {};
    if (sector) {
      query.sector = new RegExp("^" + escapeRegex(sector) + "$", "i");
    }
    if (q) {
      const safeQ = escapeRegex(q);
      query.$or = [
        { symbol: new RegExp(safeQ, "i") },
        { name: new RegExp(safeQ, "i") },
      ];
    }

    let results = await InstrumentModel.find(query).limit(limit).lean();
    if (!results || results.length === 0) {
      let fallback = masterInstruments;
      if (sector) fallback = fallback.filter((item) => (item.sector || "").toLowerCase() === sector.toLowerCase());
      if (q) {
        const lowerQ = q.toLowerCase();
        fallback = fallback.filter(
          (item) => (item.symbol || "").toLowerCase().includes(lowerQ) || (item.name || "").toLowerCase().includes(lowerQ)
        );
      }
      results = fallback.slice(0, limit);
    }

    return res.status(200).json(results);
  } catch (error) {
    console.error("Error searching master instruments in DB:", error);
    return res.status(500).json({ error: "Failed to search master instruments" });
  }
});

// GET /allInstruments - Complete 104 master instruments catalog with live prices
app.get("/allInstruments", catalogLimiter, async (req, res) => {
  try {
    let results = await InstrumentModel.find({}).lean();
    if (!results || results.length === 0) {
      results = masterInstruments;
    }
    return res.status(200).json(results);
  } catch (error) {
    return res.status(200).json(masterInstruments);
  }
});

// GET /userWatchlistTabs - Get all 7 tabs metadata (id, name, stock count)
app.get("/userWatchlistTabs", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const existing = await UserWatchlistModel.find({ userId });
    const tabMap = {};
    existing.forEach((t) => {
      tabMap[t.tabId] = t;
    });

    const tabs = [];
    for (let id = 1; id <= 7; id++) {
      if (tabMap[id]) {
        tabs.push({
          tabId: id,
          tabName: tabMap[id].tabName || `Watchlist ${id}`,
          count: Array.isArray(tabMap[id].stocks) ? tabMap[id].stocks.length : 0,
        });
      } else {
        tabs.push({ tabId: id, tabName: `Watchlist ${id}`, count: 0 });
      }
    }

    return res.status(200).json(tabs);
  } catch (error) {
    console.error("Error fetching user watchlist tabs:", error);
    return res.status(500).json({ error: "Failed to fetch user watchlist tabs" });
  }
});

// GET /userWatchlist - Get a specific tab's stocks and metadata
app.get("/userWatchlist", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const tabId = parseInt(req.query.tabId) || 1;

    let tabDoc = await UserWatchlistModel.findOne({ userId, tabId });
    if (!tabDoc) {
      tabDoc = new UserWatchlistModel({
        userId,
        tabId,
        tabName: `Watchlist ${tabId}`,
        stocks: [],
      });
      await tabDoc.save();
    }

    return res.status(200).json(tabDoc);
  } catch (error) {
    console.error("Error fetching user watchlist:", error);
    return res.status(500).json({ error: "Failed to fetch user watchlist" });
  }
});

// POST /addWatchlistStock - Add a stock to active tab
app.post("/addWatchlistStock", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const { tabId = 1, stock } = req.body;
    if (!stock || !stock.symbol) {
      return res.status(400).json({ success: false, message: "Valid stock object is required" });
    }

    let tabDoc = await UserWatchlistModel.findOne({ userId, tabId: parseInt(tabId) });
    if (!tabDoc) {
      tabDoc = new UserWatchlistModel({
        userId,
        tabId: parseInt(tabId),
        tabName: `Watchlist ${tabId}`,
        stocks: [],
      });
    }

    if (tabDoc.stocks.length >= 50) {
      return res.status(400).json({
        success: false,
        message: "Watchlist limit reached! Max 50 instruments per watchlist.",
      });
    }

    const alreadyExists = tabDoc.stocks.some((s) => s.symbol.toUpperCase() === stock.symbol.toUpperCase());
    if (alreadyExists) {
      return res.status(400).json({
        success: false,
        message: `${stock.symbol} is already in ${tabDoc.tabName}`,
      });
    }

    tabDoc.stocks.push({
      symbol: stock.symbol.toUpperCase(),
      name: stock.name || stock.symbol,
      exchange: stock.exchange || "NSE",
      price: Number(stock.price) || 0,
      change: Number(stock.change) || 0,
      percent: stock.percent || "0.00%",
      isDown: !!stock.isDown,
      sector: stock.sector || "Equity",
    });

    await tabDoc.save();
    return res.status(200).json({
      success: true,
      message: `Added ${stock.symbol} to ${tabDoc.tabName}`,
      tab: tabDoc,
    });
  } catch (error) {
    console.error("Error adding stock to watchlist:", error);
    return res.status(500).json({ success: false, message: "Failed to add stock to watchlist" });
  }
});

// POST /removeWatchlistStock - Remove a stock from active tab
app.post("/removeWatchlistStock", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const { tabId = 1, symbol } = req.body;
    if (!symbol) {
      return res.status(400).json({ success: false, message: "Symbol is required" });
    }

    let tabDoc = await UserWatchlistModel.findOne({ userId, tabId: parseInt(tabId) });
    if (!tabDoc) {
      return res.status(404).json({ success: false, message: "Watchlist tab not found" });
    }

    tabDoc.stocks = tabDoc.stocks.filter((s) => s.symbol.toUpperCase() !== symbol.toUpperCase());
    await tabDoc.save();

    return res.status(200).json({
      success: true,
      message: `Removed ${symbol} from ${tabDoc.tabName}`,
      tab: tabDoc,
    });
  } catch (error) {
    console.error("Error removing stock from watchlist:", error);
    return res.status(500).json({ success: false, message: "Failed to remove stock from watchlist" });
  }
});

// POST /renameWatchlistTab - Rename a watchlist tab
app.post("/renameWatchlistTab", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const { tabId = 1, tabName } = req.body;
    const cleanName = (tabName || "").trim();
    if (!cleanName) {
      return res.status(400).json({ success: false, message: "Watchlist name cannot be empty" });
    }

    let tabDoc = await UserWatchlistModel.findOne({ userId, tabId: parseInt(tabId) });
    if (!tabDoc) {
      tabDoc = new UserWatchlistModel({
        userId,
        tabId: parseInt(tabId),
        tabName: cleanName,
        stocks: [],
      });
    } else {
      tabDoc.tabName = cleanName;
    }

    await tabDoc.save();
    return res.status(200).json({
      success: true,
      message: `Renamed tab ${tabId} to "${cleanName}"`,
      tabName: tabDoc.tabName,
      tab: tabDoc,
    });
  } catch (error) {
    console.error("Error renaming watchlist tab:", error);
    return res.status(500).json({ success: false, message: "Failed to rename watchlist tab" });
  }
});

app.get("/userFunds", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(400).json({ error: "User ID is required to fetch funds" });
    }
    const funds = await getOrCreateUserFunds(userId);
    res.status(200).json(funds);
  } catch (error) {
    console.error("Error fetching funds:", error);
    res.status(500).json({ error: "Failed to fetch user funds" });
  }
});

app.get("/allIpos", catalogLimiter, async (req, res) => {
  try {
    let allIpos = await IpoModel.find({});
    if (allIpos.length < 50) {
      for (const item of ipoData50) {
        await IpoModel.findOneAndUpdate(
          { symbol: item.symbol },
          { $set: item },
          { upsert: true }
        );
      }
      allIpos = await IpoModel.find({});
    }
    res.status(200).json(allIpos);
  } catch (error) {
    console.error("Error fetching IPOs:", error);
    res.status(500).json({ error: "Failed to fetch IPOs" });
  }
});

// Add or Update Demat Nominee (SEBI Compliance - Up to 3 Nominees)
app.post("/addNominee", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const { nominees, optOut } = req.body;

    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required." });
    }

    const user = await UserModel.findOne({ userId });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    if (optOut) {
      user.nomineeStatus = "OPTED_OUT";
      user.nominees = [];
      user.nominee = {
        fullName: "Opted out",
        submittedAt: new Date(),
      };
      await user.save();
      try {
        await createNotification({
          userId,
          type: "COMPLIANCE",
          category: "ACCOUNT",
          title: "Nomination Opt-Out Recorded",
          description: "Formal opt-out of nominee registration recorded for your Zerodha CDSL Demat account.",
          metadata: { actionUrl: "/dashboard" },
        });
      } catch (e) {}
      return res.status(200).json({
        success: true,
        message: "Nomination opted out successfully as per SEBI declaration.",
        nomineeStatus: "OPTED_OUT",
      });
    }

    // Support array of nominees (up to 3) or legacy single nominee payload
    let nomineeList = [];
    if (Array.isArray(nominees) && nominees.length > 0) {
      nomineeList = nominees;
    } else if (req.body.fullName) {
      nomineeList = [
        {
          fullName: req.body.fullName,
          relationship: req.body.relationship || "Spouse",
          dob: req.body.dob,
          isMinor: !!req.body.isMinor,
          guardian: req.body.guardian || {},
          idType: req.body.idType || "PAN",
          idNumber: req.body.idNumber || req.body.pan || "",
          pan: req.body.pan || "",
          email: req.body.email || "",
          phone: req.body.phone || "",
          address: req.body.address || "",
          allocation: Number(req.body.allocation) || 100,
        },
      ];
    } else {
      return res.status(400).json({ success: false, message: "Nominee details are required." });
    }

    if (nomineeList.length > 3) {
      return res.status(400).json({ success: false, message: "SEBI limits demat nomination to a maximum of 3 nominees." });
    }

    // Validate allocations sum to 100%
    const totalAllocation = nomineeList.reduce((sum, n) => sum + (Number(n.allocation) || 0), 0);
    if (Math.round(totalAllocation) !== 100) {
      return res.status(400).json({
        success: false,
        message: `Total share allocation across all nominees must equal 100% (currently ${totalAllocation}%).`,
      });
    }

    // Validate each nominee
    const processedNominees = [];
    for (let i = 0; i < nomineeList.length; i++) {
      const n = nomineeList[i];
      const nomineeNum = i + 1;

      if (!n.fullName || !n.fullName.trim()) {
        return res.status(400).json({ success: false, message: `Nominee ${nomineeNum}: Full legal name is required.` });
      }
      if (!n.relationship) {
        return res.status(400).json({ success: false, message: `Nominee ${nomineeNum}: Relationship is required.` });
      }
      if (!n.dob) {
        return res.status(400).json({ success: false, message: `Nominee ${nomineeNum}: Date of birth is required.` });
      }

      // Minor validation
      if (n.isMinor) {
        if (!n.guardian || !n.guardian.fullName || !n.guardian.fullName.trim()) {
          return res.status(400).json({
            success: false,
            message: `Nominee ${nomineeNum} is a minor. Guardian full name is mandatory under SEBI guidelines.`,
          });
        }
        if (!n.guardian.relationship) {
          return res.status(400).json({
            success: false,
            message: `Nominee ${nomineeNum}: Guardian relationship is required.`,
          });
        }
      }

      // ID formatting & validation
      const idType = n.idType || "PAN";
      let idNumber = (n.idNumber || n.pan || "").trim().toUpperCase();

      if (idType === "PAN" && idNumber) {
        const panRegex = /^[A-Z]{5}[0-9]{4}[A-Z]{1}$/;
        if (!panRegex.test(idNumber)) {
          return res.status(400).json({
            success: false,
            message: `Nominee ${nomineeNum}: Invalid PAN format. Expected 10 alphanumeric characters (e.g. ABCDE1234F).`,
          });
        }
      } else if (idType === "AADHAAR_LAST4" && idNumber) {
        const aadhaarRegex = /^[0-9]{4}$/;
        if (!aadhaarRegex.test(idNumber)) {
          return res.status(400).json({
            success: false,
            message: `Nominee ${nomineeNum}: Aadhaar proof requires the last 4 digits (e.g. 1234).`,
          });
        }
      }

      processedNominees.push({
        fullName: n.fullName.trim(),
        relationship: n.relationship,
        dob: n.dob,
        isMinor: !!n.isMinor,
        guardian: {
          fullName: n.guardian?.fullName ? n.guardian.fullName.trim() : "",
          relationship: n.guardian?.relationship || "Father",
          idType: n.guardian?.idType || "PAN",
          idNumber: n.guardian?.idNumber ? n.guardian.idNumber.trim().toUpperCase() : "",
          phone: n.guardian?.phone ? n.guardian.phone.trim() : "",
          address: n.guardian?.address ? n.guardian.address.trim() : "",
        },
        idType,
        idNumber,
        pan: idType === "PAN" ? idNumber : (n.pan || ""),
        email: n.email ? n.email.trim().toLowerCase() : "",
        phone: n.phone ? n.phone.trim() : "",
        address: n.address ? n.address.trim() : "",
        allocation: Number(n.allocation) || 100,
        submittedAt: new Date(),
      });
    }

    user.nomineeStatus = "VERIFIED";
    user.nominees = processedNominees;
    user.nominee = processedNominees[0]; // primary for backward compatibility

    await user.save();
    console.log(`📋 [NOMINEES REGISTERED] ${user.userId} added ${processedNominees.length} nominee(s)`);
    try {
      await createNotification({
        userId,
        type: "COMPLIANCE",
        category: "ACCOUNT",
        title: `Demat Nominee Registered (${processedNominees.length})`,
        description: `Successfully registered ${processedNominees.length} nominee(s) (${processedNominees.map(n => n.fullName).join(", ")}) for CDSL Demat.`,
        metadata: { actionUrl: "/dashboard" },
      });
    } catch (e) {}

    return res.status(200).json({
      success: true,
      message: `Successfully registered ${processedNominees.length} nominee(s)! Your Demat account is 100% SEBI compliant.`,
      nomineeStatus: "VERIFIED",
      nominees: user.nominees,
      nominee: user.nominee,
    });
  } catch (error) {
    console.error("Error adding nominee:", error);
    return res.status(500).json({ success: false, message: "Internal server error adding nominee" });
  }
});

// Get Nominee Status & Details
app.get("/getNominee", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    const user = await UserModel.findOne({ userId });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (!user.demat) {
      user.demat = "12081600" + crypto.randomInt(10000000, 100000000);
      await user.save();
    }

    const nominees = user.nominees && user.nominees.length > 0 ? user.nominees : (user.nominee ? [user.nominee] : []);
    return res.status(200).json({
      success: true,
      nomineeStatus: user.nomineeStatus || "PENDING",
      nominees,
      nominee: user.nominee || null,
      demat: user.demat,
      pan: user.pan || "",
      address: user.address || "",
      phone: user.phone || "",
      email: user.email || "",
    });
  } catch (error) {
    console.error("Error fetching nominee:", error);
    return res.status(500).json({ success: false, message: "Internal server error" });
  }
});


// ==========================================
// Phase 4: GTT (Good Till Triggered) Engine
// ==========================================

app.get("/allGtt", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const gtts = await GttModel.find({ userId }).sort({ createdAt: -1 });
    res.status(200).json(gtts);
  } catch (error) {
    console.error("Error fetching GTTs:", error);
    res.status(500).json({ error: "Failed to fetch GTT orders" });
  }
});

app.post("/newGtt", requireAuth, async (req, res) => {
  try {
    const {
      userId = getAuthenticatedUserId(req),
      symbol,
      exchange = "NSE",
      type = "SINGLE",
      transactionType = "BUY",
      product = "CNC",
      qty,
      triggerPrice,
      orderPrice,
      stoplossTrigger,
      stoplossPrice,
      targetTrigger,
      targetPrice,
    } = req.body;

    if (!symbol || !qty || Number(qty) <= 0) {
      return res.status(400).json({
        success: false,
        message: "Valid symbol and quantity are required for GTT order.",
      });
    }

    if (type === "SINGLE" && (!triggerPrice || !orderPrice)) {
      return res.status(400).json({
        success: false,
        message: "Trigger price and limit order price are required for Single GTT.",
      });
    }

    if (type === "OCO" && (!stoplossTrigger || !targetTrigger)) {
      return res.status(400).json({
        success: false,
        message: "Both Stop-loss and Target triggers are required for OCO GTT.",
      });
    }

    const newGtt = new GttModel({
      userId,
      symbol: symbol.toUpperCase(),
      exchange: exchange.toUpperCase(),
      type: type.toUpperCase(),
      transactionType: transactionType.toUpperCase(),
      product: product.toUpperCase(),
      qty: Number(qty),
      triggerPrice: triggerPrice ? Number(triggerPrice) : undefined,
      orderPrice: orderPrice ? Number(orderPrice) : undefined,
      stoplossTrigger: stoplossTrigger ? Number(stoplossTrigger) : undefined,
      stoplossPrice: stoplossPrice ? Number(stoplossPrice) : undefined,
      targetTrigger: targetTrigger ? Number(targetTrigger) : undefined,
      targetPrice: targetPrice ? Number(targetPrice) : undefined,
      status: "ACTIVE",
    });

    const savedGtt = await newGtt.save();
    console.log(`🎯 [GTT CREATED] ${type} on ${symbol} for ${userId}`);

    res.status(201).json({
      success: true,
      message: `GTT trigger order created for ${symbol}`,
      gtt: savedGtt,
    });
  } catch (error) {
    console.error("Error creating GTT:", error);
    res.status(500).json({ success: false, message: "Internal server error creating GTT" });
  }
});

app.post("/cancelGtt", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    const { id } = req.body;
    if (!id) {
      return res.status(400).json({ success: false, message: "GTT ID required" });
    }
    const updated = await GttModel.findOneAndUpdate(
      { _id: id, userId },
      { status: "CANCELLED" },
      { new: true }
    );
    if (!updated) {
      return res.status(404).json({ success: false, message: "GTT order not found" });
    }
    res.status(200).json({ success: true, message: "GTT order cancelled", gtt: updated });
  } catch (error) {
    console.error("Error cancelling GTT:", error);
    res.status(500).json({ success: false, message: "Internal server error cancelling GTT" });
  }
});

app.post("/triggerGtt", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    const { id } = req.body;
    const gtt = await GttModel.findOne({ _id: id, userId });
    if (!gtt || gtt.status !== "ACTIVE") {
      return res.status(404).json({ success: false, message: "GTT not found or already triggered" });
    }

    // Place the order
    const priceToExecute = gtt.type === "SINGLE" ? gtt.orderPrice : (gtt.targetPrice || gtt.stoplossPrice);
    const orderRes = await executeOrderInternal({
      name: gtt.symbol,
      qty: gtt.qty,
      price: priceToExecute,
      mode: gtt.transactionType,
      product: gtt.product,
      userId: gtt.userId,
    });

    if (orderRes.success) {
      gtt.status = "TRIGGERED";
      gtt.triggeredAt = new Date();
      await gtt.save();
      return res.status(200).json({ success: true, message: "GTT triggered and executed successfully!", order: orderRes.order });
    } else {
      gtt.status = "REJECTED";
      await gtt.save();
      return res.status(400).json({ success: false, message: "GTT execution rejected: " + orderRes.message });
    }
  } catch (error) {
    console.error("Error triggering GTT:", error);
    res.status(500).json({ success: false, message: "Internal server error triggering GTT" });
  }
});

// ==========================================
// Phase 4: Basket Orders Engine
// ==========================================

const strategyBasketTemplates = [
  {
    code: "TMPL_NIFTY_IT",
    name: "Nifty IT Trio",
    category: "Sector Growth",
    description: "Core market-cap weighted allocation in India's top 3 IT outsourcing powerhouses.",
    tag: "High Growth",
    items: [
      { symbol: "INFY", name: "Infosys Ltd.", mode: "BUY", product: "CNC", qty: 5, price: 1845.50 },
      { symbol: "TCS", name: "Tata Consultancy Services", mode: "BUY", product: "CNC", qty: 2, price: 3982.75 },
      { symbol: "WIPRO", name: "Wipro Ltd.", mode: "BUY", product: "CNC", qty: 15, price: 546.80 },
    ],
    marginRequired: 25395.00,
  },
  {
    code: "TMPL_BANKING_TITANS",
    name: "Banking Titans",
    category: "Financials",
    description: "Pillars of Indian credit expansion covering premier private and PSU banking lenders.",
    tag: "Bluechip",
    items: [
      { symbol: "HDFCBANK", name: "HDFC Bank Ltd.", mode: "BUY", product: "CNC", qty: 8, price: 1728.15 },
      { symbol: "ICICIBANK", name: "ICICI Bank Ltd.", mode: "BUY", product: "CNC", qty: 6, price: 1242.00 },
      { symbol: "SBIN", name: "State Bank of India", mode: "BUY", product: "CNC", qty: 12, price: 814.65 },
    ],
    marginRequired: 31053.00,
  },
  {
    code: "TMPL_ALL_WEATHER",
    name: "All-Weather Balanced Wealth",
    category: "Multi-Asset",
    description: "Portfolio combining Nifty 50 equity benchmark with Sovereign Gold hedge.",
    tag: "Low Risk",
    items: [
      { symbol: "NIFTYBEES", name: "Nippon India Nifty 50 BeES ETF", mode: "BUY", product: "CNC", qty: 25, price: 264.50 },
      { symbol: "GOLDBEES", name: "Nippon India ETF Gold BeES", mode: "BUY", product: "CNC", qty: 30, price: 68.50 },
    ],
    marginRequired: 8667.50,
  },
  {
    code: "TMPL_AUTO_MOMENTUM",
    name: "Automobile Momentum",
    category: "Consumption",
    description: "Riding the EV transition, domestic passenger vehicle demand, and commercial vehicle cycles.",
    tag: "Momentum",
    items: [
      { symbol: "TATAMOTORS", name: "Tata Motors Ltd.", mode: "BUY", product: "CNC", qty: 10, price: 884.20 },
      { symbol: "MARUTI", name: "Maruti Suzuki India", mode: "BUY", product: "CNC", qty: 1, price: 11240.50 },
    ],
    marginRequired: 20082.50,
  },
  {
    code: "TMPL_INFRA_POWER",
    name: "Energy & Infrastructure",
    category: "Infra & Energy",
    description: "Strategic investment in India's logistics gateways, retail telecom, and energy revolution.",
    tag: "Capex Cycle",
    items: [
      { symbol: "RELIANCE", name: "Reliance Industries Ltd.", mode: "BUY", product: "CNC", qty: 4, price: 2712.40 },
      { symbol: "ADANIPORTS", name: "Adani Ports & SEZ Ltd.", mode: "BUY", product: "CNC", qty: 6, price: 1340.00 },
    ],
    marginRequired: 18889.60,
  },
  {
    code: "TMPL_FMCG_SHIELD",
    name: "FMCG Cash Flow Shield",
    category: "Defensive",
    description: "Essential consumer staples with bulletproof balance sheets and consistent high dividend yield.",
    tag: "High Dividend",
    items: [
      { symbol: "ITC", name: "ITC Ltd.", mode: "BUY", product: "CNC", qty: 25, price: 478.40 },
      { symbol: "HINDUNILVR", name: "Hindustan Unilever Ltd.", mode: "BUY", product: "CNC", qty: 3, price: 2382.40 },
    ],
    marginRequired: 19107.20,
  },
];

app.get("/basketTemplates", (req, res) => {
  res.status(200).json(strategyBasketTemplates);
});

app.post("/addTemplateToBaskets", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "User authentication required." });
    }
    const { templateCode } = req.body;
    const tmpl = strategyBasketTemplates.find((t) => t.code === templateCode);
    if (!tmpl) {
      return res.status(404).json({ success: false, message: "Strategy template not found." });
    }

    const newBasket = new BasketModel({
      userId,
      name: tmpl.name,
      items: tmpl.items.map((i) => ({
        symbol: i.symbol,
        mode: i.mode || "BUY",
        product: i.product || "CNC",
        qty: i.qty || 1,
        price: i.price || 100,
        orderType: "MARKET",
      })),
      marginRequired: tmpl.marginRequired,
    });

    const saved = await newBasket.save();
    try {
      await createNotification({
        userId,
        type: "ORDER",
        category: "EXECUTION",
        title: `Strategy Basket Added - ${tmpl.name}`,
        description: `Strategy template "${tmpl.name}" with ${tmpl.items.length} order legs added to your baskets.`,
        metadata: { actionUrl: "/orders" },
      });
    } catch (e) {}

    res.status(201).json({ success: true, message: `"${tmpl.name}" added to your Demat baskets!`, basket: saved });
  } catch (err) {
    console.error("Error adding template to baskets:", err);
    res.status(500).json({ success: false, message: "Failed to add strategy basket." });
  }
});

app.get("/allBaskets", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(200).json([]);
    }
    const baskets = await BasketModel.find({ userId }).sort({ createdAt: -1 });
    res.status(200).json(baskets);
  } catch (error) {
    console.error("Error fetching baskets:", error);
    res.status(500).json({ error: "Failed to fetch baskets" });
  }
});

app.post("/saveBasket", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const { id, name, items = [] } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ success: false, message: "Basket name is required." });
    }

    let marginRequired = 0;
    items.forEach((item) => {
      const cost = Number(item.qty || 1) * Number(item.price || 0);
      marginRequired += (item.product === "MIS" ? cost * 0.2 : cost);
    });

    if (id) {
      const updated = await BasketModel.findOneAndUpdate(
        { _id: id, userId },
        {
          name: name.trim(),
          items,
          marginRequired: Number(marginRequired.toFixed(2)),
        },
        { new: true }
      );
      if (updated) {
        return res.status(200).json({ success: true, message: "Basket updated successfully", basket: updated });
      }
    }

    const newBasket = new BasketModel({
      userId,
      name: name.trim(),
      items,
      marginRequired: Number(marginRequired.toFixed(2)),
    });

    const saved = await newBasket.save();
    res.status(201).json({ success: true, message: "Basket saved successfully", basket: saved });
  } catch (error) {
    console.error("Error saving basket:", error);
    res.status(500).json({ success: false, message: "Internal server error saving basket" });
  }
});

app.delete("/deleteBasket/:id", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    const { id } = req.params;
    const deleted = await BasketModel.findOneAndDelete({ _id: id, userId });
    if (!deleted) {
      return res.status(404).json({ success: false, message: "Basket not found" });
    }
    res.status(200).json({ success: true, message: "Basket deleted successfully" });
  } catch (error) {
    console.error("Error deleting basket:", error);
    res.status(500).json({ success: false, message: "Internal server error deleting basket" });
  }
});

app.post("/executeBasket", requireAuth, tradeFundsLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const { items = [], basketName = "Basket" } = req.body;
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ success: false, message: "Basket contains no orders to execute." });
    }

    // 1. Calculate total margin requirement
    let totalMarginRequired = 0;
    for (const item of items) {
      const qty = Number(item.qty || 0);
      const price = Number(item.price || 0);
      const cost = qty * price;
      const margin = (item.product || "CNC") === "MIS" ? cost * 0.2 : cost;
      if ((item.mode || item.type || "BUY").toUpperCase() === "BUY") {
        totalMarginRequired += margin;
      }
    }

    // 2. Check total margin against user's funds
    let funds = await getOrCreateUserFunds(userId);
    const currentAvailable = parseFloat(funds?.equity?.availableMargin?.replace(/,/g, "") || "0");

    if (currentAvailable < totalMarginRequired) {
      return res.status(400).json({
        success: false,
        code: "INSUFFICIENT_MARGIN",
        message: `Insufficient margin to execute basket "${basketName}"! Required: ₹${formatIndianCurrency(totalMarginRequired)}, Available: ₹${formatIndianCurrency(currentAvailable)}.`,
      });
    }

    // 3. Execute each order in sequence
    const executedOrders = [];
    for (const item of items) {
      const result = await executeOrderInternal({
        name: item.symbol || item.name,
        qty: item.qty,
        price: item.price,
        mode: item.mode || item.type || "BUY",
        product: item.product || "CNC",
        userId,
      });

      if (!result.success) {
        return res.status(400).json({
          success: false,
          message: `Execution failed on leg ${item.symbol}: ${result.message}`,
          executedSoFar: executedOrders,
        });
      }
      executedOrders.push(result.order);
    }

    console.log(`📦 [BASKET EXECUTED] "${basketName}" with ${executedOrders.length} legs for ${userId}`);
    try {
      await createNotification({
        userId,
        type: "ORDER",
        category: "EXECUTION",
        title: `Basket Executed - ${basketName}`,
        description: `Basket "${basketName}" executed successfully with ${executedOrders.length} order legs at NSE.`,
        metadata: { actionUrl: "/orders" },
      });
    } catch (e) {}

    return res.status(200).json({
      success: true,
      message: `Basket "${basketName}" executed successfully! All ${executedOrders.length} orders placed.`,
      executedCount: executedOrders.length,
      orders: executedOrders,
    });
  } catch (error) {
    console.error("Error executing basket:", error);
    res.status(500).json({ success: false, message: "Internal server error executing basket" });
  }
});


// ============================================================================
// REAL-TIME NOTIFICATIONS ENGINE ROUTES
// ============================================================================

// 1. Fetch user notifications with optional category filtering
app.get("/notifications", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const limit = parseInt(req.query.limit) || 50;
    const type = req.query.type;
    const unreadOnly = req.query.unreadOnly === "true";

    const filter = { userId };
    if (type && type !== "ALL") {
      filter.type = type.toUpperCase();
    }
    if (unreadOnly) {
      filter.unread = true;
    }

    const notifications = await NotificationModel.find(filter)
      .sort({ createdAt: -1 })
      .limit(limit);

    res.status(200).json(notifications);
  } catch (error) {
    console.error("Error fetching notifications:", error);
    res.status(500).json({ error: "Failed to fetch notifications" });
  }
});

// 2. High-speed unread count aggregation
app.get("/notifications/unreadCount", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const unreadCount = await NotificationModel.countDocuments({ userId, unread: true });
    res.status(200).json({ unreadCount });
  } catch (error) {
    console.error("Error counting unread notifications:", error);
    res.status(500).json({ unreadCount: 0 });
  }
});

// 3. Mark single notification as read (tenant-scoped)
app.patch("/notifications/:id/read", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid notification ID" });
    }
    const updated = await NotificationModel.findOneAndUpdate(
      { _id: id, userId },
      { $set: { unread: false } },
      { new: true }
    );
    if (!updated) {
      return res.status(404).json({ success: false, message: "Notification not found" });
    }
    res.status(200).json({ success: true, notification: updated });
  } catch (error) {
    console.error("Error marking notification read:", error);
    res.status(500).json({ success: false, error: "Failed to update notification" });
  }
});

// 4. Mark all notifications as read (Atomic bulk update)
app.post("/notifications/markAllRead", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    await NotificationModel.updateMany({ userId, unread: true }, { $set: { unread: false } });
    res.status(200).json({ success: true, message: "All notifications marked as read." });
  } catch (error) {
    console.error("Error marking all notifications read:", error);
    res.status(500).json({ success: false, error: "Failed to mark all as read" });
  }
});

// 5. Delete single notification (tenant-scoped)
app.delete("/notifications/:id", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid notification ID" });
    }
    const deleted = await NotificationModel.findOneAndDelete({ _id: id, userId });
    if (!deleted) {
      return res.status(404).json({ success: false, message: "Notification not found" });
    }
    res.status(200).json({ success: true, message: "Notification deleted." });
  } catch (error) {
    console.error("Error deleting notification:", error);
    res.status(500).json({ success: false, error: "Failed to delete notification" });
  }
});

// 6. Clear all notifications
app.post("/notifications/clearAll", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    await NotificationModel.deleteMany({ userId });
    res.status(200).json({ success: true, message: "All notifications cleared." });
  } catch (error) {
    console.error("Error clearing notifications:", error);
    res.status(500).json({ success: false, error: "Failed to clear notifications" });
  }
});

// ============================================================================
// FUNDS TREASURY & INTERACTIVE UPI EMAIL COLLECT ENGINE
// ============================================================================

// 1. Initiate Fund Deposit (Dispatches Interactive UPI Collect Email)
app.post("/fundDeposit/initiate", requireAuth, tradeFundsLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const { amount, upiId } = req.body;
    const validation = validatePositiveAmount(amount, { min: 1, max: 100000000 });
    if (!validation.valid) {
      return res.status(400).json({ success: false, message: validation.message });
    }
    const numAmount = validation.amount;

    const cleanUpi = typeof upiId === "string" ? upiId.trim() : "";
    if (!cleanUpi || !/^[\w.\-]{2,256}@[a-zA-Z]{2,64}$/.test(cleanUpi)) {
      return res.status(400).json({ success: false, message: "Please provide a valid UPI ID (e.g. yourname@okhdfcbank)." });
    }

    const user = await UserModel.findOne({ userId });
    const userEmail = user?.email;
    if (!userEmail) {
      return res.status(400).json({ success: false, message: "Registered user email not found for this account." });
    }

    const idempotencyKey =
      typeof req.body.idempotencyKey === "string" && req.body.idempotencyKey.trim()
        ? req.body.idempotencyKey.trim()
        : typeof req.headers["idempotency-key"] === "string" && req.headers["idempotency-key"].trim()
        ? req.headers["idempotency-key"].trim()
        : undefined;

    if (idempotencyKey) {
      const existingTx = await FundsTransactionModel.findOne({ userId, idempotencyKey });
      if (existingTx) {
        const safeExisting = existingTx.toObject();
        delete safeExisting.approvalToken;
        return res.status(200).json({
          success: true,
          message: "Existing deposit request retrieved (idempotent replay).",
          transaction: safeExisting,
        });
      }
    }

    const approvalToken = crypto.randomBytes(32).toString("hex");
    const approvalExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    const referenceId = "UPI" + crypto.randomInt(10000000000, 99999999999);

    const newTx = new FundsTransactionModel({
      userId,
      type: "PAYIN",
      amount: numAmount,
      paymentMethod: "UPI",
      upiId: cleanUpi,
      status: "PENDING_APPROVAL",
      referenceId,
      approvalToken,
      approvalExpiresAt,
      idempotencyKey,
      remarks: `Instant UPI Payin via ${cleanUpi}`,
    });
    await newTx.save();

    const approveUrl = `${PUBLIC_BACKEND_URL}/fundDeposit/action?token=${approvalToken}&decision=APPROVE`;
    const declineUrl = `${PUBLIC_BACKEND_URL}/fundDeposit/action?token=${approvalToken}&decision=REJECT`;

    await sendFundDepositEmail({
      toEmail: userEmail,
      amount: numAmount,
      upiId: cleanUpi,
      referenceId,
      approveUrl,
      declineUrl,
    });

    try {
      await createNotification({
        userId,
        type: "FUNDS",
        category: "MARGIN",
        title: "UPI Payin Initiated",
        description: `UPI collect request for ₹${formatIndianCurrency(numAmount)} sent to ${cleanUpi}. Please approve via email. Ref: ${referenceId}.`,
        metadata: {
          amount: numAmount,
          referenceId,
          actionUrl: "/funds",
        },
      });
    } catch (e) {}

    const safeTx = newTx.toObject();
    delete safeTx.approvalToken;

    res.status(201).json({
      success: true,
      message: `UPI Collect Request sent to ${cleanUpi}! Please approve the payment via the authorization email sent to ${userEmail}.`,
      transaction: safeTx,
    });
  } catch (error) {
    logger.error("fund_deposit_initiate_error", { error: error.message });
    res.status(500).json({ success: false, message: "Failed to initiate fund deposit." });
  }
});

// 2a. Confirmation GET page (does not mutate state on GET pre-fetch / link scan)
app.get("/fundDeposit/action", async (req, res) => {
  try {
    const token = typeof req.query.token === "string" ? req.query.token.trim() : "";
    const decision = typeof req.query.decision === "string" ? req.query.decision.trim().toUpperCase() : "";
    if (!token || !["APPROVE", "REJECT"].includes(decision)) {
      return res.status(400).send("<h3>Invalid or missing deposit action parameters.</h3>");
    }

    const tx = await FundsTransactionModel.findOne({ approvalToken: token });
    if (!tx || (tx.approvalExpiresAt && new Date(tx.approvalExpiresAt) < new Date())) {
      return res.status(404).send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Request Expired</title></head><body style="font-family:sans-serif;text-align:center;padding:50px;"><h2>Transfer Link Expired or Invalid</h2><p>We could not find an active deposit request for this token.</p><a href="${escapeHtml(PUBLIC_FRONTEND_URL)}/funds">Return to Zerodha Kite</a></body></html>`);
    }

    if (tx.status !== "PENDING_APPROVAL") {
      return res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Already Processed</title></head><body style="font-family:sans-serif;text-align:center;padding:50px;"><h2>Transfer Already Processed</h2><p>Deposit request <strong>${escapeHtml(tx.referenceId)}</strong> has already been marked as <strong>${escapeHtml(tx.status)}</strong>.</p><a href="${escapeHtml(PUBLIC_FRONTEND_URL)}/funds">View in Zerodha Kite</a></body></html>`);
    }

    return res.send(
      renderConfirmationPage({
        title: decision === "APPROVE" ? "Confirm UPI Fund Deposit" : "Decline UPI Fund Deposit",
        subtitle: "Please confirm your deposit authorization decision below to proceed.",
        actionUrl: `${PUBLIC_BACKEND_URL}/fundDeposit/action`,
        token,
        decision,
        details: [
          ["Amount", `₹${formatIndianCurrency(tx.amount)}`],
          ["Reference ID", tx.referenceId],
          ["Payer UPI ID", tx.upiId],
        ],
        returnUrl: `${PUBLIC_FRONTEND_URL}/funds`,
      })
    );
  } catch (error) {
    logger.error("fund_deposit_get_action_error", { error: error.message });
    res.status(500).send("<h3>Server error validating deposit authorization.</h3>");
  }
});

// 2b. Atomic state-changing POST endpoint for deposit approval / rejection
app.post("/fundDeposit/action", authLimiter, async (req, res) => {
  try {
    const token = typeof req.body.token === "string" ? req.body.token.trim() : "";
    const decision = typeof req.body.decision === "string" ? req.body.decision.trim().toUpperCase() : "";
    if (!token || !["APPROVE", "REJECT"].includes(decision)) {
      return res.status(400).send("<h3>Invalid or missing deposit action parameters.</h3>");
    }

    const now = new Date();
    const isApprove = decision === "APPROVE";

    const outcome = await runInTransaction(async (session) => {
      const sOpt = session ? { session } : undefined;
      const tx = await FundsTransactionModel.findOneAndUpdate(
        {
          approvalToken: token,
          status: "PENDING_APPROVAL",
          $or: [{ approvalExpiresAt: { $gt: now } }, { approvalExpiresAt: null }, { approvalExpiresAt: { $exists: false } }],
        },
        {
          $set: {
            status: isApprove ? "COMPLETED" : "REJECTED",
            completedAt: now,
            approvalToken: null,
          },
        },
        { new: true, ...(sOpt || {}) }
      );

      if (!tx) {
        return { found: false };
      }

      if (isApprove) {
        const funds = await getOrCreateUserFunds(tx.userId, session);
        const amountPaise = toPaise(tx.amount);
        const newAvailPaise = addPaise(toPaise(funds.equity.availableMargin), amountPaise);
        const newPayinPaise = addPaise(toPaise(funds.equity.payin || "0"), amountPaise);

        funds.equity.availableMargin = formatPaiseINR(newAvailPaise);
        funds.equity.availableCash = formatPaiseINR(newAvailPaise);
        funds.equity.payin = formatPaiseINR(newPayinPaise);
        await funds.save(sOpt);
      }

      return { found: true, tx };
    });

    if (!outcome.found) {
      return res.status(409).send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Request Invalid or Already Processed</title></head><body style="font-family:sans-serif;text-align:center;padding:50px;"><h2>Deposit Request Invalid, Expired, or Already Processed</h2><a href="${escapeHtml(PUBLIC_FRONTEND_URL)}/funds">View in Zerodha Kite</a></body></html>`);
    }

    const { tx } = outcome;
    try {
      await createNotification({
        userId: tx.userId,
        type: "FUNDS",
        category: "MARGIN",
        title: isApprove ? "Funds Credited Successfully" : "UPI Transfer Declined",
        description: isApprove
          ? `₹${formatIndianCurrency(tx.amount)} credited to your trading account via UPI (${tx.upiId}). Margin available immediately. Ref: ${tx.referenceId}.`
          : `UPI deposit request of ₹${formatIndianCurrency(tx.amount)} was declined. Ref: ${tx.referenceId}.`,
        metadata: { amount: tx.amount, referenceId: tx.referenceId, actionUrl: "/funds" },
      });
    } catch (e) {}

    logger.info("fund_deposit_processed", { userId: tx.userId, status: tx.status, referenceId: tx.referenceId });

    if (isApprove) {
      return res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Payment Approved - Zerodha Kite</title></head><body style="font-family:sans-serif;background:#f8fafc;padding:40px 20px;text-align:center;"><div style="max-width:500px;margin:0 auto;background:#fff;padding:36px 28px;border-radius:8px;border:1px solid #e2e8f0;"><h2 style="color:#16a34a;">Funds Credited Successfully!</h2><p>Amount: <strong>₹${escapeHtml(formatIndianCurrency(tx.amount))}</strong></p><p>Ref: <code>${escapeHtml(tx.referenceId)}</code> &bull; UPI: ${escapeHtml(tx.upiId)}</p><a href="${escapeHtml(PUBLIC_FRONTEND_URL)}/funds" style="display:inline-block;background:#16a34a;color:#fff;padding:12px 24px;border-radius:4px;text-decoration:none;">View in Zerodha Kite Dashboard</a></div></body></html>`);
    }
    return res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Transfer Declined - Zerodha Kite</title></head><body style="font-family:sans-serif;background:#f8fafc;padding:40px 20px;text-align:center;"><div style="max-width:500px;margin:0 auto;background:#fff;padding:36px 28px;border-radius:8px;border:1px solid #e2e8f0;"><h2 style="color:#dc2626;">UPI Transfer Declined</h2><p>Declined request for <strong>₹${escapeHtml(formatIndianCurrency(tx.amount))}</strong>. No funds transferred.</p><a href="${escapeHtml(PUBLIC_FRONTEND_URL)}/funds">Return to Dashboard</a></div></body></html>`);
  } catch (error) {
    logger.error("fund_deposit_post_action_error", { error: error.message });
    res.status(500).send("<h3>Server error processing deposit authorization.</h3>");
  }
});

// 3. Fetch User's Funds Transaction Ledger
app.get("/fundsTransactions", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) return res.status(200).json([]);
    const transactions = await FundsTransactionModel.find({ userId }).sort({ createdAt: -1 });
    res.status(200).json(transactions);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch funds transactions" });
  }
});

// ============================================================================
// DYNAMIC LINKED BANK ACCOUNTS (SEBI PENNY-DROP VERIFIED)
// ============================================================================

// 1. Get User's Linked Bank Accounts
app.get("/userBankAccounts", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) return res.status(200).json([]);

    const accounts = await BankAccountModel.find({ userId }).sort({ isPrimary: -1, createdAt: 1 });
    res.status(200).json(accounts);
  } catch (error) {
    console.error("Error fetching bank accounts:", error);
    res.status(500).json({ error: "Failed to fetch bank accounts" });
  }
});

// 2. Add New Bank Account (Dynamic Linking & Penny Drop Simulation)
app.post("/addBankAccount", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "User authentication required" });
    }

    const { bankName, accountNumber, ifscCode, accountType = "SAVINGS", branch = "Main Branch", isPrimary = false } = req.body;

    if (!bankName || !accountNumber || !ifscCode) {
      return res.status(400).json({ success: false, message: "Bank name, account number, and IFSC code are required." });
    }

    const cleanAcc = accountNumber.toString().trim();
    if (cleanAcc.length < 8) {
      return res.status(400).json({ success: false, message: "Please provide a valid bank account number (min 8 digits)." });
    }

    const cleanIfsc = ifscCode.toString().trim().toUpperCase();
    const ifscRegex = /^[A-Z]{4}0[A-Z0-9]{6}$/;
    if (!ifscRegex.test(cleanIfsc)) {
      return res.status(400).json({ success: false, message: "Invalid IFSC Code format. E.g. HDFC0000060 or SBIN0001234." });
    }

    const masked = "····" + cleanAcc.slice(-4);
    const existingCount = await BankAccountModel.countDocuments({ userId });
    const shouldBePrimary = isPrimary || existingCount === 0;

    // If setting as primary, unset any existing primary
    if (shouldBePrimary) {
      await BankAccountModel.updateMany({ userId }, { $set: { isPrimary: false } });
    }

    const pennyDropRef = "PD" + crypto.randomInt(100000000, 1000000000);

    const newAccount = new BankAccountModel({
      userId,
      bankName: bankName.trim(),
      accountNumber: cleanAcc,
      maskedAccountNumber: masked,
      ifscCode: cleanIfsc,
      branch: branch.trim(),
      accountType: accountType.toUpperCase() === "CURRENT" ? "CURRENT" : "SAVINGS",
      isPrimary: shouldBePrimary,
      status: "VERIFIED",
      pennyDropRef,
    });
    await newAccount.save();

    try {
      await createNotification({
        userId,
        type: "COMPLIANCE",
        category: "BANK_ACCOUNT",
        title: "Bank Account Linked Successfully",
        description: `${bankName.trim()} A/C (${masked}) successfully verified via NPCI Penny Drop and linked to your Zerodha trading account.`,
        metadata: {
          accountNumber: masked,
          actionUrl: "/funds",
        },
      });
    } catch (e) {}

    res.status(201).json({
      success: true,
      message: `${bankName.trim()} A/C (${masked}) linked and verified successfully!`,
      account: newAccount,
    });
  } catch (error) {
    console.error("Error adding bank account:", error);
    res.status(500).json({ success: false, message: "Failed to link bank account." });
  }
});

// 3. Set Primary Bank Account
app.put("/setPrimaryBankAccount/:id", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const { id } = req.params;

    await BankAccountModel.updateMany({ userId }, { $set: { isPrimary: false } });
    const account = await BankAccountModel.findOneAndUpdate(
      { _id: id, userId },
      { $set: { isPrimary: true } },
      { new: true }
    );

    if (!account) {
      return res.status(404).json({ success: false, message: "Bank account not found." });
    }

    res.status(200).json({
      success: true,
      message: `${account.bankName} (${account.maskedAccountNumber}) is now your Primary bank account for withdrawals.`,
      account,
    });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to update primary bank account." });
  }
});

// 4. Delete Bank Account
app.delete("/deleteBankAccount/:id", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const { id } = req.params;

    const account = await BankAccountModel.findOne({ _id: id, userId });
    if (!account) {
      return res.status(404).json({ success: false, message: "Bank account not found." });
    }

    if (account.isPrimary) {
      return res.status(400).json({
        success: false,
        message: "Cannot delete your Primary bank account. Please set another account as primary first.",
      });
    }

    await BankAccountModel.deleteOne({ _id: id, userId });
    res.status(200).json({ success: true, message: "Bank account unlinked successfully." });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to delete bank account." });
  }
});

// Per-user in-flight lock to prevent concurrent withdrawal race conditions (TOCTOU)

// 4. Withdraw Funds Endpoint (SEBI Clearance Cycle + ACID Transaction + Paise Math)
app.post("/withdrawFunds", requireAuth, tradeFundsLimiter, async (req, res) => {
  const userId = getAuthenticatedUserId(req);
  try {
    const { amount, bankAccount = "HDFC Bank ····4821", upiId } = req.body;
    const validation = validatePositiveAmount(amount, { min: 1, max: 100000000 });
    if (!validation.valid) {
      return res.status(400).json({ success: false, message: validation.message });
    }
    const { amount: numAmount, paise: reqPaise } = validation;

    const txResult = await withUserLock(`funds:${userId}`, async () =>
      runInTransaction(async (session) => {
        const sOpt = session ? { session } : undefined;
        const funds = await getOrCreateUserFunds(userId, session);
        const previousCashStr = funds.equity.availableCash;
        const currentAvailPaise = toPaise(funds.equity.availableMargin);
        const currentCashPaise = toPaise(previousCashStr);
        const currentPayoutPaise = toPaise(funds.equity.payout || "0");

        if (reqPaise > currentCashPaise) {
          return {
            status: 400,
            payload: {
              success: false,
              message: `Insufficient withdrawable cash balance! You can withdraw up to ₹${formatPaiseINR(currentCashPaise)}.`,
            },
          };
        }

        const updatedFunds = await FundsModel.findOneAndUpdate(
          { _id: funds._id, "equity.availableCash": previousCashStr },
          {
            $set: {
              "equity.availableMargin": formatPaiseINR(subPaise(currentAvailPaise, reqPaise)),
              "equity.availableCash": formatPaiseINR(subPaise(currentCashPaise, reqPaise)),
              "equity.payout": formatPaiseINR(addPaise(currentPayoutPaise, reqPaise)),
            },
          },
          { new: true, ...(sOpt || {}) }
        );
        if (!updatedFunds) {
          return {
            status: 409,
            payload: { success: false, message: "Balance changed concurrently. Please retry withdrawal." },
          };
        }

        const referenceId = "PAYOUT" + crypto.randomInt(10000000000, 99999999999);
        const newTx = new FundsTransactionModel({
          userId,
          type: "PAYOUT",
          amount: numAmount,
          paymentMethod: upiId ? "UPI" : "NEFT/RTGS",
          upiId: upiId || null,
          bankAccount,
          status: "COMPLETED",
          referenceId,
          remarks: `Withdrawal to ${bankAccount}`,
          completedAt: new Date(),
        });
        await newTx.save(sOpt);

        return { status: 200, funds: updatedFunds.equity, newTx, referenceId };
      })
    );

    if (txResult.status !== 200) {
      return res.status(txResult.status).json(txResult.payload);
    }

    try {
      await createNotification({
        userId,
        type: "FUNDS",
        category: "MARGIN",
        title: "Funds Withdrawal Requested",
        description: `Withdrawal request for ₹${formatIndianCurrency(numAmount)} submitted. Crediting to ${bankAccount} by 06:00 IST tomorrow. Ref: ${txResult.referenceId}.`,
        metadata: { amount: numAmount, referenceId: txResult.referenceId, actionUrl: "/funds" },
      });
    } catch (e) {}

    return res.status(200).json({
      success: true,
      message: `₹${formatIndianCurrency(numAmount)} withdrawal processed! Funds will be credited to ${bankAccount}.`,
      funds: txResult.funds,
      transaction: txResult.newTx,
    });
  } catch (error) {
    if (error?.status === 429) {
      return res.status(429).json({ success: false, message: error.message });
    }
    logger.error("withdraw_funds_error", { error: error.message });
    return res.status(500).json({ success: false, message: "Failed to process withdrawal request." });
  }
});

// 5. Margin Pledging: Pledge Demat Holdings for Trading Collateral
app.post("/pledgeHolding", requireAuth, tradeFundsLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const { symbol, companyName, quantity, marketPrice } = req.body;
    if (!symbol || typeof symbol !== "string") {
      return res.status(400).json({ success: false, message: "Valid stock symbol is required." });
    }
    const numQty = parseInt(quantity, 10);
    const priceValidation = validatePositiveAmount(marketPrice || 100, { min: 0.01, max: 10000000 });
    if (!Number.isInteger(numQty) || numQty <= 0 || !priceValidation.valid) {
      return res.status(400).json({ success: false, message: "Valid positive quantity and market price are required." });
    }
    const numPrice = priceValidation.amount;

    const sym = symbol.trim().toUpperCase();
    let haircutPercent = 20;
    if (sym === "RELIANCE" || sym === "TCS") haircutPercent = 12.5;
    else if (sym === "INFY" || sym === "HDFCBANK" || sym === "ICICIBANK") haircutPercent = 15;

    const txResult = await withUserLock(`funds:${userId}`, async () =>
      runInTransaction(async (session) => {
        const sOpt = session ? { session } : undefined;
        const holdingQuery = HoldingsModel.findOne({ userId, $or: [{ name: symbol }, { instrument: symbol }] });
        if (session) holdingQuery.session(session);
        const holding = await holdingQuery;

        const ownedQty = holding ? holding.qty : 0;
        if (ownedQty < numQty) {
          return {
            status: 400,
            payload: {
              success: false,
              message: `Insufficient Demat shares! You hold ${ownedQty} shares of ${symbol}, but attempted to pledge ${numQty} shares.`,
            },
          };
        }

        const totalValPaise = Math.round(numQty * toPaise(numPrice));
        const collateralPaise = Math.round(totalValPaise * (1 - haircutPercent / 100));
        const collateralValue = fromPaise(collateralPaise);
        const pledgeRef = "PLG" + crypto.randomInt(10000000000, 99999999999);

        const newPledge = new PledgedCollateralModel({
          userId,
          symbol,
          companyName: companyName || symbol,
          pledgedQty: numQty,
          marketPrice: numPrice,
          haircutPercent,
          collateralValue,
          status: "PLEDGED",
          pledgeRef,
        });
        await newPledge.save(sOpt);

        const funds = await getOrCreateUserFunds(userId, session);
        funds.equity.availableMargin = formatPaiseINR(addPaise(toPaise(funds.equity.availableMargin), collateralPaise));
        funds.equity.collateralEquity = formatPaiseINR(addPaise(toPaise(funds.equity.collateralEquity || "0"), collateralPaise));
        funds.equity.totalCollateral = formatPaiseINR(addPaise(toPaise(funds.equity.totalCollateral || "0"), collateralPaise));
        await funds.save(sOpt);

        const newTx = new FundsTransactionModel({
          userId,
          type: "PLEDGE_MARGIN",
          amount: collateralValue,
          paymentMethod: "COLLATERAL",
          status: "COMPLETED",
          referenceId: pledgeRef,
          remarks: `Pledged ${numQty} sh of ${symbol} (${haircutPercent}% haircut)`,
          completedAt: new Date(),
        });
        await newTx.save(sOpt);

        return { status: 201, newPledge, collateralValue, pledgeRef, equity: funds.equity };
      })
    );

    if (txResult.status !== 201) {
      return res.status(txResult.status).json(txResult.payload);
    }

    try {
      await createNotification({
        userId,
        type: "FUNDS",
        category: "MARGIN_PLEDGE",
        title: `Margin Pledged - ${symbol}`,
        description: `Pledged ${numQty} shares of ${symbol}. Generated ₹${formatIndianCurrency(txResult.collateralValue)} trading collateral (Haircut: ${haircutPercent}%). Ref: ${txResult.pledgeRef}.`,
        metadata: { symbol, amount: txResult.collateralValue, actionUrl: "/funds" },
      });
    } catch (e) {}

    res.status(201).json({
      success: true,
      message: `Successfully pledged ${numQty} shares of ${symbol}! ₹${formatIndianCurrency(txResult.collateralValue)} added to available margin.`,
      pledge: txResult.newPledge,
      collateralValue: txResult.collateralValue,
      funds: txResult.equity,
    });
  } catch (error) {
    if (error?.status === 429) {
      return res.status(429).json({ success: false, message: error.message });
    }
    logger.error("pledge_holding_error", { error: error.message });
    res.status(500).json({ success: false, message: "Failed to pledge shares for margin." });
  }
});

// 6. Unpledge Holding
app.post("/unpledgeHolding", requireAuth, tradeFundsLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const { pledgeId } = req.body;
    if (!mongoose.Types.ObjectId.isValid(pledgeId)) {
      return res.status(400).json({ success: false, message: "Valid pledgeId is required." });
    }

    const txResult = await withUserLock(`funds:${userId}`, async () =>
      runInTransaction(async (session) => {
        const sOpt = session ? { session } : undefined;
        const pledgeQuery = PledgedCollateralModel.findOne({ _id: pledgeId, userId, status: "PLEDGED" });
        if (session) pledgeQuery.session(session);
        const pledge = await pledgeQuery;
        if (!pledge) {
          return { status: 404, payload: { success: false, message: "Active pledged record not found." } };
        }

        const funds = await getOrCreateUserFunds(userId, session);
        const availPaise = toPaise(funds.equity.availableMargin);
        const colEqPaise = toPaise(funds.equity.collateralEquity || "0");
        const colTotPaise = toPaise(funds.equity.totalCollateral || "0");
        const releasePaise = toPaise(pledge.collateralValue);

        if (availPaise < releasePaise) {
          return {
            status: 400,
            payload: {
              success: false,
              message: `Cannot unpledge! You have open positions utilizing this collateral. Free up at least ₹${formatPaiseINR(releasePaise)} margin before unpledging.`,
            },
          };
        }

        pledge.status = "RELEASED";
        pledge.releasedAt = new Date();
        await pledge.save(sOpt);

        funds.equity.availableMargin = formatPaiseINR(subPaise(availPaise, releasePaise));
        funds.equity.collateralEquity = formatPaiseINR(Math.max(0, subPaise(colEqPaise, releasePaise)));
        funds.equity.totalCollateral = formatPaiseINR(Math.max(0, subPaise(colTotPaise, releasePaise)));
        await funds.save(sOpt);

        const unpledgeRef = "UNPLG" + crypto.randomInt(10000000000, 99999999999);
        const newTx = new FundsTransactionModel({
          userId,
          type: "UNPLEDGE_MARGIN",
          amount: pledge.collateralValue,
          paymentMethod: "COLLATERAL",
          status: "COMPLETED",
          referenceId: unpledgeRef,
          remarks: `Unpledged ${pledge.pledgedQty} sh of ${pledge.symbol}`,
          completedAt: new Date(),
        });
        await newTx.save(sOpt);

        return { status: 200, pledge, equity: funds.equity };
      })
    );

    if (txResult.status !== 200) {
      return res.status(txResult.status).json(txResult.payload);
    }

    res.status(200).json({
      success: true,
      message: `Successfully unpledged ${txResult.pledge.pledgedQty} shares of ${txResult.pledge.symbol}! Demat lock released.`,
      funds: txResult.equity,
    });
  } catch (error) {
    if (error?.status === 429) {
      return res.status(429).json({ success: false, message: error.message });
    }
    logger.error("unpledge_holding_error", { error: error.message });
    res.status(500).json({ success: false, message: "Failed to unpledge shares." });
  }
});

// 7. Get User's Pledged Holdings
app.get("/myPledgedHoldings", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) return res.status(200).json([]);
    const pledges = await PledgedCollateralModel.find({ userId, status: "PLEDGED" }).sort({ pledgedAt: -1 });
    res.status(200).json(pledges);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch pledged holdings" });
  }
});

// 8. Test notification trigger (for rapid dev testing / simulation)
app.post("/notifications/test", requireAuth, async (req, res) => {
  try {
    if (IS_PROD) {
      return res.status(403).json({ success: false, message: "Test endpoint is disabled in production." });
    }
    const userId = getAuthenticatedUserId(req);
    const { type = "ORDER", title, description, metadata } = req.body;
    const notification = await createNotification({
      userId,
      type,
      title: title || "Test Notification",
      description: description || "This is a real-time notification generated dynamically.",
      metadata: metadata || { actionUrl: "/orders" },
    });
    res.status(201).json({ success: true, notification });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});



// ============================================================================
// DYNAMIC IPO & ASBA APPLICATION ENGINE (OPTION C EMAIL MANDATES)
// ============================================================================

// 1. Submit IPO Application & Dispatch Live Email UPI Mandate
app.post("/applyIpo", requireAuth, tradeFundsLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(400).json({ success: false, message: "userId is required to apply for IPO" });
    }
    const {
      userEmail,
      ipoSymbol,
      companyName,
      category = "INDIVIDUAL",
      upiId,
      lots = 1,
      lotSize = 38,
      bidPrice = 390,
      isCutOff = true,
      dematBoId = "1208160081236464",
      pan = "ABCDE1234F",
    } = req.body;

    if (!ipoSymbol || !companyName || !upiId) {
      return res.status(400).json({
        success: false,
        message: "IPO symbol, company name, and UPI ID are required.",
      });
    }

    const upiRegex = /^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$/;
    if (!upiRegex.test(upiId.trim())) {
      return res.status(400).json({
        success: false,
        message: "Invalid UPI ID format. E.g. trader@okhdfcbank or trader@okaxis.",
      });
    }

    const numLots = Math.max(1, parseInt(lots) || 1);
    const numLotSize = Math.max(1, parseInt(lotSize) || 1);
    const numTotalQty = numLots * numLotSize;
    const numBidPrice = parseFloat(bidPrice) || 100;
    const totalAmount = Number((numTotalQty * numBidPrice).toFixed(2));

    // Enforce SEBI retail limit
    if (category === "INDIVIDUAL" && totalAmount > 200000) {
      return res.status(400).json({
        success: false,
        message: "Retail investment cannot exceed ₹2,00,000 under SEBI regulations. Please select HNI category for bids above ₹2 Lakhs.",
      });
    }
    if (category === "HNI" && totalAmount > 500000) {
      return res.status(400).json({
        success: false,
        message: "HNI UPI bid limit cannot exceed ₹5,00,000 via ASBA UPI.",
      });
    }

    // Check if user already applied
    const existing = await IpoApplicationModel.findOne({
      userId,
      ipoSymbol: ipoSymbol.toUpperCase(),
      status: { $in: ["MANDATE_PENDING", "APPLIED", "ALLOTTED"] },
    });
    if (existing) {
      return res.status(400).json({
        success: false,
        message: `You already have an active application (${existing.applicationNumber}) for ${companyName}.`,
      });
    }

    // Resolve registered user email strictly from DB (prevent client email override)
    const userDoc = await UserModel.findOne({ userId });
    const targetEmail = userDoc?.email;
    if (!targetEmail) {
      return res.status(400).json({ success: false, message: "Registered user email not found for this account." });
    }

    const randomSuffix = crypto.randomInt(10000, 100000);
    const applicationNumber = `IPO-${new Date().getFullYear()}-${ipoSymbol.toUpperCase()}-${randomSuffix}`;
    const mandateToken = crypto.randomBytes(24).toString("hex");
    const mandateExpiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000);

    const newApplication = new IpoApplicationModel({
      userId,
      userEmail: targetEmail,
      ipoSymbol: ipoSymbol.toUpperCase(),
      companyName,
      applicationNumber,
      investorCategory: category,
      upiId: upiId.trim(),
      lots: numLots,
      lotSize: numLotSize,
      totalQty: numTotalQty,
      bidPrice: numBidPrice,
      isCutOff: Boolean(isCutOff),
      totalAmount,
      dematBoId,
      pan: pan.toUpperCase(),
      mandateToken,
      mandateExpiresAt,
      status: "MANDATE_PENDING",
      mandateStatus: "PENDING_APPROVAL",
      appliedAt: new Date(),
    });

    const savedApp = await newApplication.save();

    const approveUrl = `${PUBLIC_BACKEND_URL}/ipoMandate/action?token=${mandateToken}&decision=APPROVE`;
    const declineUrl = `${PUBLIC_BACKEND_URL}/ipoMandate/action?token=${mandateToken}&decision=REJECT`;

    // Send real interactive email
    await sendIpoMandateEmail({
      toEmail: targetEmail,
      companyName,
      ipoSymbol: ipoSymbol.toUpperCase(),
      applicationNumber,
      lots: numLots,
      totalQty: numTotalQty,
      bidPrice: numBidPrice,
      totalAmount,
      upiId: upiId.trim(),
      category,
      dematBoId,
      approveUrl,
      declineUrl,
    });

    // In-app notification
    try {
      await createNotification({
        userId,
        type: "COMPLIANCE",
        category: "IPO",
        title: `IPO Bid Submitted - ${companyName}`,
        description: `Application #${applicationNumber} submitted. UPI Mandate for ₹${totalAmount.toLocaleString("en-IN")} sent to ${targetEmail}.`,
        metadata: {
          symbol: ipoSymbol,
          amount: totalAmount,
          actionUrl: "/bids",
        },
      });
    } catch (e) {}

    console.log(`📋 [IPO APPLIED] ${userId} applied for ${companyName} (${numLots} lot) - Mandate sent to ${targetEmail}`);

    const safeApp = savedApp.toObject();
    delete safeApp.mandateToken;

    res.status(201).json({
      success: true,
      message: `IPO application submitted! UPI Mandate authorization email sent to ${targetEmail}.`,
      application: safeApp,
    });
  } catch (error) {
    console.error("Error applying for IPO:", error);
    res.status(500).json({ success: false, message: "Internal server error processing IPO application" });
  }
});

// 2. Fetch User's Submitted IPO Applications
app.get("/myIpoApplications", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const applications = await IpoApplicationModel.find({ userId }).sort({ appliedAt: -1 });
    res.status(200).json(applications);
  } catch (error) {
    console.error("Error fetching user IPO applications:", error);
    res.status(500).json({ error: "Failed to fetch IPO applications" });
  }
});

// 3a. Confirmation GET page (prevents CSRF / GET pre-fetcher from mutating IPO mandate)
app.get("/ipoMandate/action", async (req, res) => {
  try {
    const token = typeof req.query.token === "string" ? req.query.token.trim() : "";
    const decision = typeof req.query.decision === "string" ? req.query.decision.trim().toUpperCase() : "";
    if (!token || !["APPROVE", "REJECT"].includes(decision)) {
      return res.status(400).send("<h3>Invalid or missing mandate action parameters.</h3>");
    }

    const application = await IpoApplicationModel.findOne({ mandateToken: token });
    if (!application || (application.mandateExpiresAt && new Date(application.mandateExpiresAt) < new Date())) {
      return res.status(404).send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Mandate Expired</title></head><body style="font-family:sans-serif;text-align:center;padding:50px;"><h2 style="color:#ef4444;">Mandate Link Invalid or Expired</h2><p>We could not find an active IPO mandate for this authorization link.</p><a href="${escapeHtml(PUBLIC_FRONTEND_URL)}/bids">Return to Zerodha Kite</a></body></html>`);
    }

    if (application.mandateStatus !== "PENDING_APPROVAL") {
      return res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Mandate Already Processed</title></head><body style="font-family:sans-serif;text-align:center;padding:50px;"><h2>Mandate Already Processed</h2><p>Mandate for <strong>${escapeHtml(application.companyName)}</strong> has already been marked as <strong>${escapeHtml(application.mandateStatus)}</strong>.</p><a href="${escapeHtml(PUBLIC_FRONTEND_URL)}/bids">View in Zerodha Kite</a></body></html>`);
    }

    return res.send(
      renderConfirmationPage({
        title: decision === "APPROVE" ? "Confirm IPO UPI Mandate" : "Decline IPO UPI Mandate",
        subtitle: `Authorize or decline the ASBA block for ${application.companyName}.`,
        actionUrl: `${PUBLIC_BACKEND_URL}/ipoMandate/action`,
        token,
        decision,
        details: [
          ["Application No.", application.applicationNumber],
          ["Company", application.companyName],
          ["Amount Blocked", `₹${formatIndianCurrency(application.totalAmount)}`],
          ["UPI ID", application.upiId],
        ],
        returnUrl: `${PUBLIC_FRONTEND_URL}/bids`,
      })
    );
  } catch (error) {
    logger.error("ipo_mandate_get_action_error", { error: error.message });
    res.status(500).send("<h3>Internal server error validating mandate decision.</h3>");
  }
});

// 3b. Atomic state-changing POST action for IPO mandate
app.post("/ipoMandate/action", authLimiter, async (req, res) => {
  try {
    const token = typeof req.body.token === "string" ? req.body.token.trim() : "";
    const decision = typeof req.body.decision === "string" ? req.body.decision.trim().toUpperCase() : "";
    if (!token || !["APPROVE", "REJECT"].includes(decision)) {
      return res.status(400).send("<h3>Invalid or missing mandate action parameters.</h3>");
    }

    const now = new Date();
    const isApprove = decision === "APPROVE";
    const application = await IpoApplicationModel.findOneAndUpdate(
      {
        mandateToken: token,
        mandateStatus: "PENDING_APPROVAL",
        $or: [{ mandateExpiresAt: { $gt: now } }, { mandateExpiresAt: null }, { mandateExpiresAt: { $exists: false } }],
      },
      {
        $set: {
          status: isApprove ? "APPLIED" : "CANCELLED",
          mandateStatus: isApprove ? "ACCEPTED" : "REJECTED",
          mandateDecidedAt: now,
          mandateToken: null,
        },
      },
      { new: true }
    );

    if (!application) {
      return res.status(409).send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Mandate Invalid or Already Processed</title></head><body style="font-family:sans-serif;text-align:center;padding:50px;"><h2>IPO Mandate Invalid, Expired, or Already Processed</h2><a href="${escapeHtml(PUBLIC_FRONTEND_URL)}/bids">View in Zerodha Kite</a></body></html>`);
    }

    try {
      await createNotification({
        userId: application.userId,
        type: isApprove ? "FUNDS" : "COMPLIANCE",
        category: "IPO",
        title: isApprove ? `Mandate Approved - ${application.companyName}` : `Mandate Declined - ${application.companyName}`,
        description: isApprove
          ? `UPI Mandate for ${application.companyName} (${application.lots} Lot, ₹${formatIndianCurrency(application.totalAmount)}) has been approved. Funds lien marked under ASBA.`
          : `UPI Mandate for ${application.companyName} was declined. Application #${application.applicationNumber} has been revoked.`,
        metadata: { symbol: application.ipoSymbol, amount: application.totalAmount, actionUrl: "/bids" },
      });
    } catch (e) {}

    if (isApprove) {
      return res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>UPI Mandate Approved - Zerodha Kite</title></head><body style="font-family:sans-serif;background:#f8fafc;padding:40px 20px;text-align:center;"><div style="max-width:500px;margin:0 auto;background:#fff;padding:36px 28px;border-radius:8px;border:1px solid #e2e8f0;"><h2 style="color:#15803d;">UPI Mandate Approved!</h2><p>ASBA block registered for <strong>${escapeHtml(application.companyName)}</strong>.</p><p>App No: <code>${escapeHtml(application.applicationNumber)}</code> &bull; Amount: ₹${escapeHtml(formatIndianCurrency(application.totalAmount))}</p><a href="${escapeHtml(PUBLIC_FRONTEND_URL)}/bids" style="display:inline-block;background:#387ed1;color:#fff;padding:12px 24px;border-radius:4px;text-decoration:none;">View in Zerodha Kite Dashboard</a></div></body></html>`);
    }
    return res.send(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Mandate Declined - Zerodha Kite</title></head><body style="font-family:sans-serif;background:#f8fafc;padding:40px 20px;text-align:center;"><div style="max-width:500px;margin:0 auto;background:#fff;padding:36px 28px;border-radius:8px;border:1px solid #e2e8f0;"><h2 style="color:#dc2626;">UPI Mandate Declined</h2><p>You declined the mandate for <strong>${escapeHtml(application.companyName)}</strong>.</p><a href="${escapeHtml(PUBLIC_FRONTEND_URL)}/bids">Return to Dashboard</a></div></body></html>`);
  } catch (error) {
    logger.error("ipo_mandate_post_action_error", { error: error.message });
    res.status(500).send("<h3>Internal server error processing mandate decision.</h3>");
  }
});

// 4. Cancel / Revoke Submitted IPO Application
app.delete("/cancelIpoApplication/:id", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    const { id } = req.params;
    const appDoc = await IpoApplicationModel.findOneAndUpdate(
      { _id: id, userId },
      { status: "CANCELLED", mandateStatus: "REJECTED" },
      { new: true }
    );
    if (!appDoc) {
      return res.status(404).json({ success: false, message: "IPO application not found" });
    }
    if (appDoc) {
      try {
        await createNotification({
          userId: appDoc.userId,
          type: "COMPLIANCE",
          category: "IPO",
          title: `IPO Bid Cancelled - ${appDoc.companyName}`,
          description: `Application #${appDoc.applicationNumber} was cancelled. ASBA bank lien released.`,
          metadata: { symbol: appDoc.ipoSymbol, actionUrl: "/bids" },
        });
      } catch (e) {}
    }
    res.status(200).json({ success: true, message: "IPO application cancelled successfully" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to cancel IPO application" });
  }
});

// 5. Modify Existing IPO Bid (Lots / Price / Cut-off / UPI)
app.put("/modifyIpoBid/:id", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    const { id } = req.params;
    const { lots, bidPrice, isCutOff, upiId } = req.body;

    const appDoc = await IpoApplicationModel.findOne({ _id: id, userId });
    if (!appDoc) {
      return res.status(404).json({ success: false, message: "IPO application not found." });
    }

    if (appDoc.status === "CANCELLED") {
      return res.status(400).json({ success: false, message: "Cancelled applications cannot be modified. Please submit a new bid." });
    }

    const numLots = Math.max(1, parseInt(lots) || appDoc.lots);
    const numLotSize = appDoc.lotSize || 1;
    const numTotalQty = numLots * numLotSize;
    const numBidPrice = parseFloat(bidPrice) || appDoc.bidPrice;
    const newTotalAmount = Number((numTotalQty * numBidPrice).toFixed(2));

    // SEBI Category Retail Check
    if (appDoc.investorCategory === "INDIVIDUAL" && newTotalAmount > 200000) {
      return res.status(400).json({
        success: false,
        message: "Retail investment cannot exceed ₹2,00,000 under SEBI ASBA rules. Switch to HNI for higher allocations.",
      });
    }

    appDoc.lots = numLots;
    appDoc.bidPrice = numBidPrice;
    appDoc.isCutOff = isCutOff !== undefined ? isCutOff : appDoc.isCutOff;
    appDoc.totalQty = numTotalQty;
    appDoc.totalAmount = newTotalAmount;
    if (upiId && upiId.trim()) {
      appDoc.upiId = upiId.trim();
    }
    appDoc.status = "APPLIED";
    appDoc.mandateStatus = "ACCEPTED";
    await appDoc.save();

    try {
      await createNotification({
        userId: appDoc.userId,
        type: "COMPLIANCE",
        category: "IPO",
        title: `IPO Bid Modified - ${appDoc.companyName}`,
        description: `Bid updated to ${numLots} Lot (${numTotalQty} shares) @ ₹${numBidPrice}. New ASBA blocked lien: ₹${newTotalAmount.toLocaleString("en-IN")}.`,
        metadata: { symbol: appDoc.ipoSymbol, actionUrl: "/bids" },
      });
    } catch (e) {}

    res.status(200).json({
      success: true,
      message: `IPO application for ${appDoc.companyName} modified successfully!`,
      application: appDoc,
    });
  } catch (error) {
    console.error("Error modifying IPO bid:", error);
    res.status(500).json({ success: false, message: "Failed to modify IPO application." });
  }
});

// ============================================================================
// GOVT. SECURITIES (G-SEC & T-BILLS) NON-COMPETITIVE BIDDING DESK
// ============================================================================

const curatedGsecs = [
  {
    symbol: "91D_TBILL",
    name: "91-Day Treasury Bill (RBI Auction)",
    category: "T-BILL",
    yield: "6.82% p.a.",
    biddingRange: "Live till 17:00 IST",
    pricePerUnit: 1000,
    minQty: 10,
    minAmount: "₹10,000",
    settlementDate: "T+1 Clearing",
    maturityDate: "91 Days from Allotment",
    status: "Bidding Open",
  },
  {
    symbol: "182D_TBILL",
    name: "182-Day Treasury Bill (RBI Auction)",
    category: "T-BILL",
    yield: "6.98% p.a.",
    biddingRange: "Live till 17:00 IST",
    pricePerUnit: 1000,
    minQty: 10,
    minAmount: "₹10,000",
    settlementDate: "T+1 Clearing",
    maturityDate: "182 Days from Allotment",
    status: "Bidding Open",
  },
  {
    symbol: "364D_TBILL",
    name: "364-Day Treasury Bill (RBI Auction)",
    category: "T-BILL",
    yield: "7.05% p.a.",
    biddingRange: "Live till 17:00 IST",
    pricePerUnit: 1000,
    minQty: 10,
    minAmount: "₹10,000",
    settlementDate: "T+1 Clearing",
    maturityDate: "364 Days from Allotment",
    status: "Bidding Open",
  },
  {
    symbol: "GS2033_718",
    name: "7.18% GS 2033 (10-Yr Benchmark Govt Bond)",
    category: "G-SEC",
    yield: "7.18% p.a.",
    biddingRange: "Live till 17:00 IST",
    pricePerUnit: 1000,
    minQty: 10,
    minAmount: "₹10,000",
    settlementDate: "Semi-Annual Coupon",
    maturityDate: "15 Oct 2033",
    status: "Bidding Open",
  },
  {
    symbol: "SGB_2024_25",
    name: "Sovereign Gold Bond (2024-25 Series)",
    category: "SGB",
    yield: "2.50% p.a. + Gold Returns",
    biddingRange: "RBI Issue Window",
    pricePerUnit: 6260,
    minQty: 1,
    minAmount: "₹6,260",
    settlementDate: "RBI Sovereign Guarantee",
    maturityDate: "8 Years (Exit option after 5th yr)",
    status: "Bidding Open",
  },
];

app.get("/allGsecs", catalogLimiter, async (req, res) => {
  res.status(200).json(curatedGsecs);
});

app.post("/applyGsecBid", requireAuth, tradeFundsLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "User authentication required" });
    }
    const { symbol, instrumentName, units, pricePerUnit, category, indicativeYield } = req.body;
    const numUnits = Math.max(1, parseInt(units) || 10);
    const numPrice = parseFloat(pricePerUnit) || 1000;
    const totalAmount = numUnits * numPrice;

    const bidNumber = `GSEC-${new Date().getFullYear()}-${symbol}-${crypto.randomInt(10000, 100000)}`;

    const newBid = new GsecBidModel({
      userId,
      symbol,
      instrumentName,
      category: category || "T-BILL",
      units: numUnits,
      indicativeYield: indicativeYield || "7.05%",
      pricePerUnit: numPrice,
      totalAmount,
      status: "BID_PLACED",
      bidNumber,
    });
    await newBid.save();

    try {
      await createNotification({
        userId,
        type: "ORDER",
        category: "GSEC",
        title: `RBI Bidding Placed - ${symbol}`,
        description: `Non-competitive bid for ${numUnits} units of ${instrumentName} (₹${totalAmount.toLocaleString("en-IN")}) placed successfully.`,
        metadata: { symbol, actionUrl: "/bids" },
      });
    } catch (e) {}

    res.status(201).json({
      success: true,
      message: `G-Sec / T-Bill non-competitive bid for ${instrumentName} placed successfully!`,
      bid: newBid,
    });
  } catch (error) {
    console.error("Error applying G-Sec bid:", error);
    res.status(500).json({ success: false, message: "Failed to place G-Sec bid." });
  }
});

app.get("/myGsecApplications", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) return res.status(200).json([]);
    const bids = await GsecBidModel.find({ userId }).sort({ createdAt: -1 });
    res.status(200).json(bids);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch user G-Sec bids" });
  }
});

// ============================================================================
// CORPORATE ACTIONS & SHARE BUYBACKS TENDER DESK
// ============================================================================

const curatedCorporateActions = [
  {
    symbol: "TCS",
    companyName: "Tata Consultancy Services Ltd.",
    actionType: "BUYBACK",
    tenderPrice: 4150.00,
    currentMarketPrice: 3982.75,
    premiumPercent: "+4.20%",
    issueSize: "₹17,000 Cr",
    windowDates: "10 Nov - 22 Nov 2024",
    status: "Tender Open",
    description: "Tender offer share buyback through proportionate tender offer route.",
  },
  {
    symbol: "WIPRO",
    companyName: "Wipro Limited",
    actionType: "BUYBACK",
    tenderPrice: 445.00,
    currentMarketPrice: 546.80,
    premiumPercent: "Tender Offer",
    issueSize: "₹12,000 Cr",
    windowDates: "15 Nov - 28 Nov 2024",
    status: "Tender Open",
    description: "Share buyback through tender offer route for retail and general shareholders.",
  },
  {
    symbol: "INFY",
    companyName: "Infosys Limited",
    actionType: "BUYBACK",
    tenderPrice: 1850.00,
    currentMarketPrice: 1845.50,
    premiumPercent: "+0.24%",
    issueSize: "₹9,300 Cr",
    windowDates: "01 Dec - 15 Dec 2024",
    status: "Upcoming",
    description: "Open market buyback program on recognized stock exchanges.",
  },
];

app.get("/allCorporateActions", catalogLimiter, async (req, res) => {
  res.status(200).json(curatedCorporateActions);
});

app.post("/tenderCorporateAction", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "User authentication required" });
    }
    const { symbol, companyName, tenderedQty, tenderPrice } = req.body;
    const numQty = Math.max(1, parseInt(tenderedQty) || 1);
    const numPrice = parseFloat(tenderPrice) || 100;
    const totalAmount = numQty * numPrice;

    // Verify user owns sufficient shares in Demat holdings
    const holding = await HoldingsModel.findOne({
      userId,
      $or: [{ name: symbol }, { instrument: symbol }],
    });

    const ownedQty = holding ? holding.qty : 0;
    if (ownedQty < numQty) {
      return res.status(400).json({
        success: false,
        message: `Insufficient Demat shares! You hold ${ownedQty} shares of ${symbol}, but attempted to tender ${numQty} shares.`,
      });
    }

    const tenderRef = `CORP-${new Date().getFullYear()}-${symbol}-${crypto.randomInt(10000, 100000)}`;

    const newTender = new CorporateActionModel({
      userId,
      symbol,
      companyName,
      actionType: "BUYBACK",
      tenderPrice: numPrice,
      tenderedQty: numQty,
      totalAmount,
      status: "TENDERED",
      tenderRef,
    });
    await newTender.save();

    try {
      await createNotification({
        userId,
        type: "COMPLIANCE",
        category: "CORPORATE_ACTION",
        title: `Buyback Tender Placed - ${symbol}`,
        description: `Successfully tendered ${numQty} shares of ${companyName} @ ₹${numPrice} (Total: ₹${totalAmount.toLocaleString("en-IN")}). Ref: ${tenderRef}.`,
        metadata: { symbol, actionUrl: "/bids" },
      });
    } catch (e) {}

    res.status(201).json({
      success: true,
      message: `Successfully tendered ${numQty} shares of ${companyName} for buyback!`,
      tender: newTender,
    });
  } catch (error) {
    console.error("Error tendering corporate action:", error);
    res.status(500).json({ success: false, message: "Failed to tender shares for corporate action." });
  }
});

app.get("/myCorporateActionTenders", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) return res.status(200).json([]);
    const tenders = await CorporateActionModel.find({ userId }).sort({ createdAt: -1 });
    res.status(200).json(tenders);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch corporate action tenders" });
  }
});

// ============================================================================
// AUCTIONS (EXCHANGE SETTLEMENT AUCTIONS FOR SHORT DELIVERIES)
// ============================================================================

app.get("/allAuctions", catalogLimiter, async (req, res) => {
  try {
    let count = await AuctionModel.countDocuments();
    if (count === 0) {
      const defaultAuctions = [
        {
          symbol: "HDFCBANK",
          name: "HDFC Bank Limited",
          exchange: "NSE",
          settlementType: "T+1 Short Delivery",
          shortQtyRequired: 150,
          basePrice: 1728.15,
          maxAllowedPrice: 2073.78, // +20% upper cap
          auctionWindow: "14:00 - 14:45 IST",
          status: "OPEN",
          settlementDate: "Tomorrow (T+1)",
        },
        {
          symbol: "TATAMOTORS",
          name: "Tata Motors Limited",
          exchange: "NSE",
          settlementType: "T+1 Short Delivery",
          shortQtyRequired: 400,
          basePrice: 884.20,
          maxAllowedPrice: 1061.04,
          auctionWindow: "14:00 - 14:45 IST",
          status: "OPEN",
          settlementDate: "Tomorrow (T+1)",
        },
        {
          symbol: "ZOMATO",
          name: "Zomato Limited",
          exchange: "NSE",
          settlementType: "T+1 Short Delivery",
          shortQtyRequired: 1200,
          basePrice: 262.40,
          maxAllowedPrice: 314.88,
          auctionWindow: "14:00 - 14:45 IST",
          status: "OPEN",
          settlementDate: "Tomorrow (T+1)",
        },
        {
          symbol: "RELIANCE",
          name: "Reliance Industries Limited",
          exchange: "NSE",
          settlementType: "T+1 Short Delivery",
          shortQtyRequired: 80,
          basePrice: 2710.40,
          maxAllowedPrice: 3252.48,
          auctionWindow: "14:00 - 14:45 IST",
          status: "OPEN",
          settlementDate: "Tomorrow (T+1)",
        },
      ];
      await AuctionModel.insertMany(defaultAuctions);
    }
    const auctions = await AuctionModel.find();
    res.status(200).json(auctions);
  } catch (error) {
    console.error("Error fetching auctions:", error);
    res.status(500).json({ error: "Failed to fetch exchange auctions" });
  }
});

app.post("/submitAuctionOffer", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "User authentication required" });
    }

    const { symbol, companyName, quantity, offerPrice } = req.body;
    const numQty = Math.max(1, parseInt(quantity) || 1);
    const numPrice = parseFloat(offerPrice);

    if (!numPrice || numPrice <= 0) {
      return res.status(400).json({ success: false, message: "Please provide a valid offer price" });
    }

    // Verify auction exists and price within +20% circuit
    const auction = await AuctionModel.findOne({ symbol });
    if (!auction) {
      return res.status(404).json({ success: false, message: `No active auction found for ${symbol}` });
    }

    if (numPrice > auction.maxAllowedPrice) {
      return res.status(400).json({
        success: false,
        message: `Offer price ₹${numPrice} exceeds the maximum exchange cap of ₹${auction.maxAllowedPrice.toFixed(2)} (+20% upper penalty limit).`,
      });
    }

    // Verify user owns sufficient shares in Demat holdings
    const holding = await HoldingsModel.findOne({
      userId,
      $or: [{ name: symbol }, { instrument: symbol }],
    });

    const ownedQty = holding ? holding.qty : 0;
    if (ownedQty < numQty) {
      return res.status(400).json({
        success: false,
        message: `Insufficient Demat shares! You hold ${ownedQty} shares of ${symbol}, but attempted to offer ${numQty} shares in the auction.`,
      });
    }

    const totalAmount = numQty * numPrice;
    const premiumVal = ((numPrice - auction.basePrice) / auction.basePrice) * 100;
    const premiumPercent = `${premiumVal >= 0 ? "+" : ""}${premiumVal.toFixed(2)}%`;
    const orderId = `AUC-${new Date().getFullYear()}-${symbol}-${crypto.randomInt(10000, 100000)}`;

    const newOffer = new AuctionOfferModel({
      userId,
      symbol,
      companyName: companyName || auction.name,
      exchange: auction.exchange || "NSE",
      quantity: numQty,
      basePrice: auction.basePrice,
      offerPrice: numPrice,
      totalAmount,
      premiumPercent,
      status: "OFFERED",
      orderId,
      settlementDate: auction.settlementDate,
    });
    await newOffer.save();

    try {
      await createNotification({
        userId,
        type: "ORDER",
        category: "AUCTION",
        title: `Auction Offer Submitted - ${symbol}`,
        description: `Offered ${numQty} shares of ${companyName || auction.name} @ ₹${numPrice.toFixed(2)} (${premiumPercent} premium). Settlement credit: ₹${totalAmount.toLocaleString("en-IN")}. Ref: ${orderId}.`,
        metadata: { symbol, actionUrl: "/bids" },
      });
    } catch (e) {}

    res.status(201).json({
      success: true,
      message: `Auction offer placed for ${numQty} shares of ${companyName || auction.name} @ ₹${numPrice.toFixed(2)}!`,
      offer: newOffer,
    });
  } catch (error) {
    console.error("Error submitting auction offer:", error);
    res.status(500).json({ success: false, message: "Failed to place auction sell offer." });
  }
});

app.get("/myAuctionOffers", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) return res.status(200).json([]);
    const offers = await AuctionOfferModel.find({ userId }).sort({ createdAt: -1 });
    res.status(200).json(offers);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch auction offers" });
  }
});

// ============================================================================
// SOCIAL STOCK EXCHANGE (SSE IPO - ZERO COUPON ZERO PRINCIPAL / ZCZP)
// ============================================================================

app.get("/allSseIpos", catalogLimiter, async (req, res) => {
  try {
    let count = await SseIpoModel.countDocuments();
    if (count === 0) {
      const defaultSse = [
        {
          symbol: "UNNATI",
          orgName: "SGBS Unnati Foundation",
          focusArea: "Youth Vocational Training & Employment",
          issueDates: "04 Nov - 15 Nov 2024",
          targetAmount: "₹2.00 Cr",
          unitPrice: 100,
          minUnits: 100,
          minInvestment: 10000,
          taxExemption: "100% Tax Exempt u/s 80G",
          impactGoal: "Provide skill training and secure formal sector job placements for 10,000 underprivileged rural youth across 8 states",
          socialAuditor: "KPMG Social Audit Services",
          sebiRegNo: "SSE-NPO-2024-0019",
          status: "Apply",
          rhpUrl: "https://www.bseindia.com/markets/social-stock-exchange",
        },
        {
          symbol: "GOONJ",
          orgName: "Goonj Welfare Foundation",
          focusArea: "Rural Livelihood & Flood Relief Infrastructure",
          issueDates: "08 Nov - 20 Nov 2024",
          targetAmount: "₹3.50 Cr",
          unitPrice: 100,
          minUnits: 100,
          minInvestment: 10000,
          taxExemption: "100% Tax Exempt u/s 80G",
          impactGoal: "Reconstruct 45 flood-resilient community bridges, water wells, and livelihood centers in flood-prone districts of Assam and Bihar",
          socialAuditor: "PwC India Social Audit",
          sebiRegNo: "SSE-NPO-2024-0024",
          status: "Apply",
          rhpUrl: "https://www.bseindia.com/markets/social-stock-exchange",
        },
        {
          symbol: "PRATHAM",
          orgName: "Pratham Education Foundation",
          focusArea: "Primary Child Literacy & Digital Learning",
          issueDates: "12 Nov - 25 Nov 2024",
          targetAmount: "₹5.00 Cr",
          unitPrice: 100,
          minUnits: 100,
          minInvestment: 10000,
          taxExemption: "100% Tax Exempt u/s 80G",
          impactGoal: "Deliver foundational literacy and interactive tablet-based numeracy kits to 50,000 primary school children in rural government schools",
          socialAuditor: "Deloitte Social Advisory",
          sebiRegNo: "SSE-NPO-2024-0031",
          status: "Apply",
          rhpUrl: "https://www.bseindia.com/markets/social-stock-exchange",
        },
        {
          symbol: "DEEPAKFDN",
          orgName: "Deepak Foundation",
          focusArea: "Maternal Health & Mobile Tribal Clinics",
          issueDates: "18 Nov - 30 Nov 2024",
          targetAmount: "₹1.75 Cr",
          unitPrice: 100,
          minUnits: 100,
          minInvestment: 10000,
          taxExemption: "100% Tax Exempt u/s 80G",
          impactGoal: "Operate 12 specialized mobile medical care units serving 75,000 expectant mothers and infants in remote tribal areas",
          socialAuditor: "EY India Social Assurance",
          sebiRegNo: "SSE-NPO-2024-0042",
          status: "Apply",
          rhpUrl: "https://www.bseindia.com/markets/social-stock-exchange",
        },
      ];
      await SseIpoModel.insertMany(defaultSse);
    }
    const sseIpos = await SseIpoModel.find();
    res.status(200).json(sseIpos);
  } catch (error) {
    console.error("Error fetching SSE IPOs:", error);
    res.status(500).json({ error: "Failed to fetch Social Stock Exchange IPOs" });
  }
});

app.post("/applySseIpo", requireAuth, tradeFundsLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "User authentication required" });
    }

    const { symbol, orgName, units, panNumber, upiId, taxReceiptRequested } = req.body;
    const numUnits = Math.max(100, parseInt(units) || 100);
    const unitPrice = 100;
    const totalAmount = numUnits * unitPrice;

    if (!panNumber || panNumber.trim().length < 10) {
      return res.status(400).json({ success: false, message: "Valid 10-character PAN is required for Section 80G compliance" });
    }

    if (!upiId || !upiId.includes("@")) {
      return res.status(400).json({ success: false, message: "Valid UPI Virtual Payment Address (VPA) is required for ASBA lien" });
    }

    const taxCertificateNo = `80G-SSE-${symbol}-${Date.now().toString().slice(-6)}`;
    const asbaReference = `ASBA-SSE-${crypto.randomInt(100000, 1000000)}`;

    const newApp = new SseApplicationModel({
      userId,
      symbol,
      orgName,
      units: numUnits,
      unitPrice,
      totalAmount,
      panNumber: panNumber.trim().toUpperCase(),
      taxReceiptRequested: taxReceiptRequested !== false,
      taxCertificateNo,
      upiId: upiId.trim(),
      status: "APPLIED",
      mandateStatus: "ACCEPTED",
      asbaReference,
    });
    await newApp.save();

    try {
      await createNotification({
        userId,
        type: "COMPLIANCE",
        category: "SSE_IPO",
        title: `SSE Contribution Placed - ${orgName}`,
        description: `Subscribed to ${numUnits} ZCZP units of ${orgName} (Total: ₹${totalAmount.toLocaleString("en-IN")}). 80G Certificate: ${taxCertificateNo}. ASBA Ref: ${asbaReference}.`,
        metadata: { symbol, actionUrl: "/bids" },
      });
    } catch (e) {}

    res.status(201).json({
      success: true,
      message: `Successfully contributed ₹${totalAmount.toLocaleString("en-IN")} (${numUnits} units) to ${orgName}!`,
      application: newApp,
    });
  } catch (error) {
    console.error("Error applying to SSE IPO:", error);
    res.status(500).json({ success: false, message: "Failed to place Social Stock Exchange contribution." });
  }
});

app.get("/mySseApplications", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) return res.status(200).json([]);
    const apps = await SseApplicationModel.find({ userId }).sort({ createdAt: -1 });
    res.status(200).json(apps);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch SSE applications" });
  }
});



// ============================================================================
// STOCK SIP (SYSTEMATIC INVESTMENT PLAN) ENGINE
// ============================================================================

// Helper: Calculate Next Trigger Date based on frequency, day, and time
function calculateNextTriggerDate(frequency, scheduleDay, scheduleTime) {
  const [hours, minutes] = (scheduleTime || "09:30").split(":").map(Number);
  const now = new Date();
  let next = new Date();
  next.setHours(hours, minutes, 0, 0);

  if (frequency === "WEEKLY") {
    const targetDay = Math.min(Math.max(1, scheduleDay || 1), 5); // 1=Mon...5=Fri
    const currentDay = now.getDay();
    let daysUntil = targetDay - currentDay;
    if (daysUntil < 0 || (daysUntil === 0 && now >= next)) {
      daysUntil += 7;
    }
    next.setDate(now.getDate() + daysUntil);
  } else if (frequency === "DAILY") {
    if (now >= next) {
      next.setDate(now.getDate() + 1);
    }
    if (next.getDay() === 6) next.setDate(next.getDate() + 2);
    if (next.getDay() === 0) next.setDate(next.getDate() + 1);
  } else {
    // MONTHLY
    const targetDay = Math.min(Math.max(1, scheduleDay || 5), 28);
    next.setDate(targetDay);
    if (now >= next) {
      next.setMonth(next.getMonth() + 1);
      next.setDate(targetDay);
    }
  }
  return next;
}

// Helper: Advance to the Next Execution Cycle (used when an installment is executed)
function advanceNextTriggerDate(frequency, scheduleDay, scheduleTime, currentTrigger) {
  const [hours, minutes] = (scheduleTime || "09:30").split(":").map(Number);
  const now = new Date();
  let base = currentTrigger ? new Date(currentTrigger) : new Date();

  // If the previous trigger was in the past or today, ensure forward advancement
  if (base <= now) {
    base = new Date(now);
  }

  let next = new Date(base);
  next.setHours(hours, minutes, 0, 0);

  if (frequency === "WEEKLY") {
    next.setDate(next.getDate() + 7);
  } else if (frequency === "DAILY") {
    next.setDate(next.getDate() + 1);
    if (next.getDay() === 6) next.setDate(next.getDate() + 2); // Saturday -> Monday
    if (next.getDay() === 0) next.setDate(next.getDate() + 1); // Sunday -> Monday
  } else {
    // MONTHLY
    const targetDay = Math.min(Math.max(1, scheduleDay || 5), 28);
    next.setMonth(next.getMonth() + 1);
    next.setDate(targetDay);
  }
  return next;
}

// 0. Catalog of 50 Real Market SIPs (Stored in & Fetched directly from MongoDB Atlas!)
app.get("/marketSipsCatalog", catalogLimiter, async (req, res) => {
  try {
    let catalog = await MarketSipCatalogModel.find({}).sort({ code: 1 }).lean();
    if (!catalog || catalog.length === 0) {
      catalog = marketSips50;
    }
    return res.status(200).json(catalog);
  } catch (err) {
    console.error("Error fetching market SIP catalog from DB:", err.message);
    return res.status(200).json(marketSips50);
  }
});

// 1. Fetch all user SIPs (with default seeding from real market catalog if empty)
app.get("/allSips", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(200).json([]);
    }
    const sips = await SipModel.find({ userId }).sort({ createdAt: -1 });
    res.status(200).json(sips);
  } catch (error) {
    console.error("Error fetching SIPs:", error);
    res.status(500).json({ error: "Failed to fetch SIPs" });
  }
});

// 2. Create New Stock SIP (Supports 50 Real Market SIPs directly without a basket!)
app.post("/createSip", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(400).json({ success: false, message: "userId is required to create SIP" });
    }
    const {
      name,
      sipType = "STOCK",
      marketSipCode,
      basketId,
      instruments: customInstruments,
      frequency = "MONTHLY",
      scheduleDay = 5,
      scheduleTime = "09:30",
    } = req.body;

    let finalName = name;
    let finalInstruments = [];
    let finalBasketId = basketId || null;
    let finalBasketName = null;
    let finalSymbol = null;
    let finalMinAmount = 0;
    let finalSipType = sipType;

    // Mode A: Direct from 50 Real Market SIPs (Zero Basket dependency!)
    if (marketSipCode) {
      let marketPlan = await MarketSipCatalogModel.findOne({ code: marketSipCode }).lean();
      if (!marketPlan) {
        marketPlan = marketSips50.find((m) => m.code === marketSipCode);
      }
      if (!marketPlan) {
        return res.status(404).json({ success: false, message: "Market SIP plan not found." });
      }
      finalName = finalName || marketPlan.name;
      finalInstruments = marketPlan.instruments;
      finalSymbol = marketPlan.symbol;
      finalMinAmount = marketPlan.minAmount;
      finalSipType = marketPlan.category.includes("ETF")
        ? "ETF"
        : marketPlan.category.includes("Thematic")
        ? "THEMATIC"
        : "STOCK";
    }
    // Mode B: Direct custom instruments
    else if (Array.isArray(customInstruments) && customInstruments.length > 0) {
      finalInstruments = customInstruments;
      finalSymbol = customInstruments[0].symbol;
      finalMinAmount = customInstruments.reduce(
        (acc, i) => acc + (i.price || 100) * (i.qty || 1),
        0
      );
    }
    // Mode C: Legacy user basket (strictly tenant-scoped)
    else if (basketId) {
      if (!isValidObjectId(String(basketId))) {
        return res.status(400).json({ success: false, message: "Invalid basket ID." });
      }
      const basket = await BasketModel.findOne({ _id: String(basketId).trim(), userId });
      if (!basket) {
        return res.status(404).json({ success: false, message: "Selected basket does not exist." });
      }
      finalBasketId = basket._id;
      finalBasketName = basket.name;
      finalInstruments = basket.items;
      finalName = finalName || `${basket.name} SIP`;
      finalMinAmount = basket.marginRequired;
      finalSipType = "BASKET";
    } else {
      return res.status(400).json({
        success: false,
        message: "Please choose a market SIP or stock to start your SIP.",
      });
    }

    if (!finalName || !finalName.trim()) {
      return res.status(400).json({ success: false, message: "SIP name is required." });
    }

    const nextTriggerAt = calculateNextTriggerDate(frequency, Number(scheduleDay), scheduleTime);

    const newSip = new SipModel({
      userId,
      name: finalName.trim(),
      sipType: finalSipType,
      symbol: finalSymbol,
      basketId: finalBasketId,
      basketName: finalBasketName,
      instruments: finalInstruments,
      minAmount: finalMinAmount,
      frequency,
      scheduleDay: Number(scheduleDay),
      scheduleTime,
      status: "ACTIVE",
      nextTriggerAt,
      totalInstallmentsExecuted: 0,
      totalCapitalInvested: 0,
      executionLogs: [],
    });

    const savedSip = await newSip.save();

    try {
      await createNotification({
        userId,
        type: "ORDER",
        category: "EXECUTION",
        title: `Stock SIP Started - ${finalName}`,
        description: `Scheduled ${frequency.toLowerCase()} SIP on ${finalSymbol || finalName}. Next installment: ${nextTriggerAt.toLocaleDateString("en-IN")}.`,
        metadata: { actionUrl: "/orders" },
      });
    } catch (e) {}

    res.status(201).json({
      success: true,
      message: `Stock SIP "${finalName}" started successfully!`,
      sip: savedSip,
    });
  } catch (error) {
    console.error("Error creating SIP:", error);
    res.status(500).json({ success: false, message: "Failed to create Stock SIP" });
  }
});

// 3. Toggle Status (Active / Paused)
app.patch("/toggleSipStatus/:id", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    const { id } = req.params;
    const sip = await SipModel.findOne({ _id: id, userId });
    if (!sip) return res.status(404).json({ success: false, message: "SIP not found" });

    sip.status = sip.status === "ACTIVE" ? "PAUSED" : "ACTIVE";
    if (sip.status === "ACTIVE") {
      sip.nextTriggerAt = calculateNextTriggerDate(sip.frequency, sip.scheduleDay, sip.scheduleTime);
    }
    await sip.save();

    try {
      await createNotification({
        userId: sip.userId,
        type: "ORDER",
        category: "EXECUTION",
        title: `SIP ${sip.status === "ACTIVE" ? "Resumed" : "Paused"} - ${sip.name}`,
        description: `Stock SIP "${sip.name}" is now ${sip.status.toLowerCase()}.`,
        metadata: { actionUrl: "/orders" },
      });
    } catch (e) {}

    res.status(200).json({ success: true, message: `SIP "${sip.name}" is now ${sip.status}.`, sip });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to toggle SIP status" });
  }
});

// 3b. Rename SIP Endpoint
app.patch("/updateSipName/:id", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    const { id } = req.params;
    const { name } = req.body;
    if (!name || !name.trim()) {
      return res.status(400).json({ success: false, message: "Valid SIP name is required." });
    }
    const sip = await SipModel.findOne({ _id: id, userId });
    if (!sip) return res.status(404).json({ success: false, message: "SIP not found." });

    const oldName = sip.name;
    sip.name = name.trim();
    await sip.save();

    try {
      await createNotification({
        userId: sip.userId,
        type: "ORDER",
        category: "EXECUTION",
        title: `SIP Renamed - ${sip.name}`,
        description: `Stock SIP "${oldName}" was renamed to "${sip.name}".`,
        metadata: { actionUrl: "/orders" },
      });
    } catch (e) {}

    return res.status(200).json({ success: true, message: `SIP renamed to "${sip.name}".`, sip });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Failed to rename SIP." });
  }
});

// 4. Internal Executor function (Supports direct instruments or linked baskets!)
async function executeSipInternal(sipId) {
  const sip = await SipModel.findById(sipId);
  if (!sip) throw new Error("SIP not found");

  // Resolve order legs: direct instruments preferred, fallback to basket
  let orderLegs = Array.isArray(sip.instruments) && sip.instruments.length > 0 ? sip.instruments : [];
  if (orderLegs.length === 0 && sip.basketId) {
    const basket = await BasketModel.findById(sip.basketId);
    if (basket && Array.isArray(basket.items)) {
      orderLegs = basket.items;
    }
  }

  if (orderLegs.length === 0) {
    throw new Error(`SIP "${sip.name}" has no investment instruments configured`);
  }

  const userId = sip.userId;

  // Check user email
  let userEmail = process.env.EMAIL_USER;
  const userDoc = await UserModel.findOne({ userId });
  if (userDoc?.email) userEmail = userDoc.email;

  // Calculate required margin
  let totalMarginRequired = 0;
  for (const item of orderLegs) {
    const cost = (Number(item.qty) || 1) * (Number(item.price) || 100);
    totalMarginRequired += item.product === "MIS" ? cost * 0.2 : cost;
  }

  let funds = await getOrCreateUserFunds(userId);
  const availableMargin = parseFloat(funds?.equity?.availableMargin?.replace(/,/g, "") || "0");

  const nextCycleDate = advanceNextTriggerDate(sip.frequency, sip.scheduleDay, sip.scheduleTime, sip.nextTriggerAt);
  const formattedNextDate = nextCycleDate.toLocaleDateString("en-IN", {
    day: "numeric",
    month: "short",
    year: "numeric",
  });

  // 1. INSUFFICIENT MARGIN CASE (Option A + Email Alert)
  if (availableMargin < totalMarginRequired) {
    sip.executionLogs.push({
      executedAt: new Date(),
      ordersCount: 0,
      amountDebited: 0,
      status: "FAILED_INSUFFICIENT_FUNDS",
      failureReason: `Required: ₹${totalMarginRequired.toLocaleString("en-IN")}, Available: ₹${availableMargin.toLocaleString("en-IN")}`,
    });
    sip.nextTriggerAt = nextCycleDate;
    await sip.save();

    try {
      await createNotification({
        userId,
        type: "FUNDS",
        category: "MARGIN",
        title: `SIP Skipped - ${sip.name}`,
        description: `Installment skipped due to insufficient margin. Required: ₹${formatIndianCurrency(totalMarginRequired)}, Available: ₹${formatIndianCurrency(availableMargin)}.`,
        metadata: { actionUrl: "/funds" },
      });
    } catch (e) {}

    await sendSipFailureEmail({
      toEmail: userEmail,
      sipName: sip.name,
      basketName: sip.basketName || sip.symbol || sip.name,
      requiredAmount: totalMarginRequired,
      availableAmount: availableMargin,
      nextDate: formattedNextDate,
    });

    return {
      success: false,
      code: "INSUFFICIENT_MARGIN",
      message: `Insufficient margin! Required: ₹${formatIndianCurrency(totalMarginRequired)}, Available: ₹${formatIndianCurrency(availableMargin)}. Failure alert sent to ${userEmail}.`,
      sip,
    };
  }

  // 2. SUFFICIENT MARGIN: Execute order legs concurrently
  const executedOrders = [];
  let totalDebited = 0;

  for (const item of orderLegs) {
    const result = await executeOrderInternal({
      name: item.symbol || item.name,
      qty: item.qty || 1,
      price: item.price,
      mode: item.mode || "BUY",
      product: item.product || "CNC",
      userId,
    });

    if (!result.success) {
      throw new Error(`Failed to execute leg ${item.symbol}: ${result.message}`);
    }
    executedOrders.push(result.order);
    totalDebited += (Number(item.qty) || 1) * (Number(item.price) || 100);
  }

  sip.totalInstallmentsExecuted += 1;
  sip.totalCapitalInvested += totalDebited;
  sip.lastExecutedAt = new Date();
  sip.nextTriggerAt = nextCycleDate;
  sip.executionLogs.push({
    executedAt: new Date(),
    ordersCount: executedOrders.length,
    amountDebited: totalDebited,
    status: "SUCCESS",
  });
  await sip.save();

  try {
    await createNotification({
      userId,
      type: "ORDER",
      category: "EXECUTION",
      title: `Stock SIP Executed - ${sip.name}`,
      description: `SIP installment executed with ${executedOrders.length} orders totaling ₹${formatIndianCurrency(totalDebited)}.`,
      metadata: { actionUrl: "/orders" },
    });
  } catch (e) {}

  await sendSipSuccessEmail({
    toEmail: userEmail,
    sipName: sip.name,
    basketName: sip.basketName || sip.symbol || sip.name,
    executedOrdersCount: executedOrders.length,
    totalAmount: totalDebited,
    nextDate: formattedNextDate,
  });

  return {
    success: true,
    message: `Stock SIP "${sip.name}" executed successfully! ${executedOrders.length} orders placed.`,
    sip,
    executedOrders,
  };
}

// 5. Route to trigger SIP immediately (Option 1 - Interactive Pro Mode)
app.post("/executeSipNow/:id", requireAuth, tradeFundsLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    const { id } = req.params;
    const ownedSip = await SipModel.findOne({ _id: id, userId });
    if (!ownedSip) {
      return res.status(404).json({ success: false, message: "SIP not found" });
    }
    const result = await executeSipInternal(id);
    if (!result.success) {
      const status = result.code === "CDSL_AUTH_REQUIRED" ? 403 : 400;
      return res.status(status).json(result);
    }
    return res.status(200).json(result);
  } catch (error) {
    console.error("Error executing SIP:", error);
    return res.status(500).json({ success: false, message: error.message || "Failed to execute SIP" });
  }
});

// 6. Delete SIP
app.delete("/deleteSip/:id", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    const { id } = req.params;
    const deleted = await SipModel.findOneAndDelete({ _id: id, userId });
    if (!deleted) {
      return res.status(404).json({ success: false, message: "SIP not found" });
    }
    try {
      await createNotification({
        userId: deleted.userId,
        type: "ORDER",
        category: "EXECUTION",
        title: `SIP Deleted - ${deleted.name}`,
        description: `Stock SIP "${deleted.name}" has been permanently cancelled.`,
        metadata: { actionUrl: "/orders" },
      });
    } catch (e) {}
    res.status(200).json({ success: true, message: "SIP deleted successfully" });
  } catch (error) {
    res.status(500).json({ success: false, message: "Failed to delete SIP" });
  }
});

// 7. Background Heartbeat Worker for SIPs (Runs every 45s with distributed lock)
let sipWorkerInterval = null;
async function runSipWorkerCycle() {
  if (mongoose.connection.readyState !== 1) return;
  const lockOwner = await acquireDistributedLock("sip-heartbeat-worker", 40000);
  if (!lockOwner) return;
  try {
    const now = new Date();
    const dueSips = await SipModel.find({
      status: "ACTIVE",
      nextTriggerAt: { $lte: now },
    });

    for (const sip of dueSips) {
      logger.info("sip_cron_triggered", { sipId: String(sip._id), name: sip.name });
      try {
        await executeSipInternal(sip._id);
      } catch (err) {
        logger.error("sip_cron_execution_error", { sipId: String(sip._id), error: err.message });
      }
    }
  } catch (e) {
    logger.error("sip_worker_error", { error: e.message });
  } finally {
    await releaseDistributedLock("sip-heartbeat-worker", lockOwner);
  }
}


// ============================================================================
// REAL-TIME PRICE ALERTS (SENTINEL ENGINE) ROUTES & EVALUATION WORKER
// ============================================================================

// 1. Fetch user alerts with dynamic live LTP & proximity calculations
app.get("/alerts", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const statusFilter = req.query.status; // "ALL", "ACTIVE", "TRIGGERED", "DISABLED"

    const query = { userId };
    if (statusFilter && statusFilter !== "ALL") {
      query.status = statusFilter.toUpperCase();
    }

    const alerts = await AlertModel.find(query).sort({ createdAt: -1 }).lean();

    // Attach latest live LTP from instruments collection
    const allInstruments = await InstrumentModel.find({}).lean();
    const priceMap = new Map();
    allInstruments.forEach((i) => {
      if (i.name) priceMap.set(i.name.toUpperCase(), i.price || i.ltp || 100);
      if (i.symbol) priceMap.set(i.symbol.toUpperCase(), i.price || i.ltp || 100);
    });

    const enrichedAlerts = alerts.map((a) => {
      const sym = a.symbol?.toUpperCase();
      const currentLtp = priceMap.get(sym) || a.initialLtp || a.targetPrice;

      // Calculate distance to target
      let distancePct = 0;
      let distanceValue = 0;
      if (a.conditionType === "GTE") {
        distanceValue = a.targetPrice - currentLtp;
        distancePct = currentLtp > 0 ? ((a.targetPrice - currentLtp) / currentLtp) * 100 : 0;
      } else if (a.conditionType === "LTE") {
        distanceValue = currentLtp - a.targetPrice;
        distancePct = currentLtp > 0 ? ((currentLtp - a.targetPrice) / currentLtp) * 100 : 0;
      } else if (a.conditionType === "PCT_UP" || a.conditionType === "PCT_DOWN") {
        distancePct = a.targetPercentage;
      }

      return {
        ...a,
        currentLtp,
        distancePct: Number(distancePct.toFixed(2)),
        distanceValue: Number(distanceValue.toFixed(2)),
      };
    });

    res.status(200).json(enrichedAlerts);
  } catch (error) {
    console.error("Error fetching alerts:", error);
    res.status(500).json({ success: false, message: "Failed to fetch alerts" });
  }
});

// 2. Create Price Alert
app.post("/createAlert", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(400).json({ success: false, message: "userId is required to create alert" });
    }
    const {
      symbol,
      name,
      conditionType = "GTE",
      targetPrice,
      targetPercentage,
      notes,
    } = req.body;

    if (!symbol) {
      return res.status(400).json({ success: false, message: "Symbol is required" });
    }

    // Get current LTP for symbol
    const cleanSym = symbol.toUpperCase().trim();
    const inst = await InstrumentModel.findOne({ name: cleanSym });
    const currentPrice = inst ? (inst.price || inst.ltp) : 1000;
    const stockName = inst ? (inst.instrument || inst.name) : (name || cleanSym);

    const newAlert = new AlertModel({
      userId,
      symbol: cleanSym,
      name: stockName,
      conditionType,
      targetPrice: Number(targetPrice) || currentPrice,
      targetPercentage: Number(targetPercentage) || 0,
      initialLtp: currentPrice,
      notes: notes || "",
      status: "ACTIVE",
    });

    const savedAlert = await newAlert.save();

    try {
      await createNotification({
        userId,
        type: "ORDER",
        category: "EXECUTION",
        title: `Alert Set - ${cleanSym}`,
        description: `Price alert activated: ${conditionType === "GTE" ? "≥" : "≤"} ₹${Number(targetPrice).toLocaleString("en-IN")}.`,
        metadata: { actionUrl: "/orders" },
      });
    } catch (e) {}

    res.status(201).json({ success: true, alert: savedAlert });
  } catch (error) {
    console.error("Error creating alert:", error);
    res.status(500).json({ success: false, message: "Failed to create alert" });
  }
});

// 3. Update Price Alert
app.put("/updateAlert/:id", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    const { id } = req.params;
    const { conditionType, targetPrice, targetPercentage, notes } = req.body;

    const alert = await AlertModel.findOne({ _id: id, userId });
    if (!alert) return res.status(404).json({ success: false, message: "Alert not found" });

    if (conditionType) alert.conditionType = conditionType;
    if (targetPrice !== undefined) alert.targetPrice = Number(targetPrice);
    if (targetPercentage !== undefined) alert.targetPercentage = Number(targetPercentage);
    if (notes !== undefined) alert.notes = notes;

    await alert.save();
    res.status(200).json({ success: true, alert });
  } catch (error) {
    console.error("Error updating alert:", error);
    res.status(500).json({ success: false, message: "Failed to update alert" });
  }
});

// 4. Toggle Status (Active <-> Disabled)
app.patch("/toggleAlertStatus/:id", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    const { id } = req.params;
    const alert = await AlertModel.findOne({ _id: id, userId });
    if (!alert) return res.status(404).json({ success: false, message: "Alert not found" });

    alert.status = alert.status === "ACTIVE" ? "DISABLED" : "ACTIVE";
    await alert.save();

    res.status(200).json({ success: true, alert });
  } catch (error) {
    console.error("Error toggling alert status:", error);
    res.status(500).json({ success: false, message: "Failed to toggle alert status" });
  }
});

// 5. Reset Triggered Alert back to Active
app.post("/resetAlert/:id", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    const { id } = req.params;
    const alert = await AlertModel.findOne({ _id: id, userId });
    if (!alert) return res.status(404).json({ success: false, message: "Alert not found" });

    alert.status = "ACTIVE";
    alert.triggeredAt = undefined;
    alert.triggeredPrice = undefined;
    await alert.save();

    res.status(200).json({ success: true, message: `Alert for ${alert.symbol} re-armed!`, alert });
  } catch (error) {
    console.error("Error resetting alert:", error);
    res.status(500).json({ success: false, message: "Failed to reset alert" });
  }
});

// 6. Delete Alert
app.delete("/deleteAlert/:id", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    const { id } = req.params;
    const deleted = await AlertModel.findOneAndDelete({ _id: id, userId });
    if (!deleted) return res.status(404).json({ success: false, message: "Alert not found" });
    if (deleted) {
      try {
        await createNotification({
          userId: deleted.userId,
          type: "ORDER",
          category: "EXECUTION",
          title: `Alert Deleted - ${deleted.symbol}`,
          description: `Price alert for ${deleted.symbol} was removed.`,
          metadata: { actionUrl: "/orders" },
        });
      } catch (e) {}
    }
    res.status(200).json({ success: true, message: "Alert deleted successfully" });
  } catch (error) {
    console.error("Error deleting alert:", error);
    res.status(500).json({ success: false, message: "Failed to delete alert" });
  }
});

// 7. Background Sentinel Price Alert Evaluation Engine (Runs every 15s)
async function evaluatePriceAlerts() {
  try {
    const activeAlerts = await AlertModel.find({ status: "ACTIVE" });
    if (activeAlerts.length === 0) return;

    const allInstruments = await InstrumentModel.find({}).lean();
    const priceMap = new Map();
    allInstruments.forEach((i) => {
      if (i.name) priceMap.set(i.name.toUpperCase(), i.price || i.ltp || 100);
      if (i.symbol) priceMap.set(i.symbol.toUpperCase(), i.price || i.ltp || 100);
    });

    for (const alert of activeAlerts) {
      const sym = alert.symbol?.toUpperCase();
      const currentPrice = priceMap.get(sym);
      if (!currentPrice) continue;

      let triggered = false;
      let conditionText = "";

      if (alert.conditionType === "GTE" && currentPrice >= alert.targetPrice) {
        triggered = true;
        conditionText = `LTP crossed above or reached ₹${Number(alert.targetPrice).toLocaleString("en-IN")}`;
      } else if (alert.conditionType === "LTE" && currentPrice <= alert.targetPrice) {
        triggered = true;
        conditionText = `LTP dropped below or reached ₹${Number(alert.targetPrice).toLocaleString("en-IN")}`;
      } else if (alert.conditionType === "PCT_UP") {
        const changePct = alert.initialLtp > 0 ? ((currentPrice - alert.initialLtp) / alert.initialLtp) * 100 : 0;
        if (changePct >= alert.targetPercentage) {
          triggered = true;
          conditionText = `Day change gained +${alert.targetPercentage}% (current: +${changePct.toFixed(2)}%)`;
        }
      } else if (alert.conditionType === "PCT_DOWN") {
        const changePct = alert.initialLtp > 0 ? ((currentPrice - alert.initialLtp) / alert.initialLtp) * 100 : 0;
        if (changePct <= -alert.targetPercentage) {
          triggered = true;
          conditionText = `Day change dipped -${alert.targetPercentage}% (current: ${changePct.toFixed(2)}%)`;
        }
      }

      if (triggered) {
        console.log(`🚨 [ALERT TRIGGERED] ${alert.symbol}: ${conditionText} (LTP: ₹${currentPrice})`);
        alert.status = "TRIGGERED";
        alert.triggeredAt = new Date();
        alert.triggeredPrice = currentPrice;
        await alert.save();

        const user = await UserModel.findOne({ userId: alert.userId });
        const userEmail = user?.email;
        if (!userEmail) continue;

        // Dispatch In-App Notification
        try {
          await createNotification({
            userId: alert.userId,
            type: "ORDER",
            category: "EXECUTION",
            title: `🚨 Alert Triggered: ${alert.symbol} @ ₹${currentPrice.toLocaleString("en-IN")}`,
            description: `${alert.symbol} ${conditionText}. ${alert.notes ? `Note: "${alert.notes}"` : ""}`,
            metadata: { actionUrl: "/orders", symbol: alert.symbol },
          });
        } catch (e) {}

        // Dispatch Nodemailer Email Alert
        await sendAlertTriggeredEmail({
          toEmail: userEmail,
          symbol: alert.symbol,
          name: alert.name,
          conditionText,
          targetValue: alert.targetPrice || alert.targetPercentage,
          triggeredPrice: currentPrice,
          notes: alert.notes,
        });
      }
    }
  } catch (err) {
    console.error("Error evaluating price alerts:", err.message);
  }
}

let alertsWorkerInterval = null;
async function runAlertsWorkerCycle() {
  if (mongoose.connection.readyState !== 1) return;
  const lockOwner = await acquireDistributedLock("price-alerts-worker", 13000);
  if (!lockOwner) return;
  try {
    await evaluatePriceAlerts();
  } finally {
    await releaseDistributedLock("price-alerts-worker", lockOwner);
  }
}



// ============================================================================
// 8. SEGMENT SETTINGS & KILL SWITCH SUBSYSTEM (SEBI / ZERODHA RISK CONTROLS)
// ============================================================================

app.get("/userSegments", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    let user = await UserModel.findOne({ userId });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (!user.segments || !user.segments.equity) {
      user.segments = {
        equity: {
          name: "NSE & BSE Equity (Cash)",
          exchange: "NSE, BSE",
          active: true,
          deactivatedAt: null,
          activatedAt: new Date(),
        },
        futuresAndOptions: {
          name: "Futures & Options (F&O)",
          exchange: "NFO, BFO",
          active: true,
          deactivatedAt: null,
          activatedAt: new Date(),
        },
        currency: {
          name: "Currency Derivatives (CDS)",
          exchange: "CDS, BCD",
          active: false,
          deactivatedAt: null,
          activatedAt: null,
        },
        commodity: {
          name: "Commodity Derivatives",
          exchange: "MCX",
          active: false,
          deactivatedAt: null,
          activatedAt: null,
        },
      };
      user.markModified("segments");
      await user.save();
    }

    const now = Date.now();
    const twelveHoursMs = 12 * 60 * 60 * 1000;
    const enrichedSegments = {};

    for (const [key, seg] of Object.entries(user.segments)) {
      let cooldownRemainingMs = 0;
      let canReactivate = true;
      if (!seg.active && seg.deactivatedAt) {
        const elapsed = now - new Date(seg.deactivatedAt).getTime();
        if (elapsed < twelveHoursMs) {
          cooldownRemainingMs = twelveHoursMs - elapsed;
          canReactivate = false;
        }
      }
      enrichedSegments[key] = {
        ...seg,
        cooldownRemainingMs,
        canReactivate,
      };
    }

    res.status(200).json({
      success: true,
      segments: enrichedSegments,
      userDemat: user.demat,
      annualIncome: user.annualIncome,
    });
  } catch (err) {
    console.error("Error fetching user segments:", err);
    res.status(500).json({ success: false, message: "Failed to fetch segments" });
  }
});

app.post("/updateSegments", requireAuth, authLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    const { segmentKey, targetState, annualIncome } = req.body;
    if (!segmentKey || typeof targetState !== "boolean") {
      return res.status(400).json({ success: false, message: "Valid segmentKey and boolean targetState required." });
    }

    const user = await UserModel.findOne({ userId });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (!user.segments) user.segments = {};

    const defaultNames = {
      equity: { name: "NSE & BSE Equity (Cash)", exchange: "NSE, BSE" },
      futuresAndOptions: { name: "Futures & Options (F&O)", exchange: "NFO, BFO" },
      currency: { name: "Currency Derivatives (CDS)", exchange: "CDS, BCD" },
      commodity: { name: "Commodity Derivatives", exchange: "MCX" },
    };

    const currentSeg = user.segments[segmentKey] || {
      name: defaultNames[segmentKey]?.name || segmentKey,
      exchange: defaultNames[segmentKey]?.exchange || "NSE",
      active: false,
      deactivatedAt: null,
      activatedAt: null,
    };

    const now = new Date();
    const twelveHoursMs = 12 * 60 * 60 * 1000;

    // Reactivation Check against 12-Hour Kill Switch
    if (targetState === true) {
      if (currentSeg.deactivatedAt) {
        const elapsed = now.getTime() - new Date(currentSeg.deactivatedAt).getTime();
        if (elapsed < twelveHoursMs) {
          const hoursLeft = ((twelveHoursMs - elapsed) / (1000 * 60 * 60)).toFixed(1);
          return res.status(403).json({
            success: false,
            code: "KILL_SWITCH_ACTIVE",
            message: `Kill Switch Cooldown Active! This segment was deactivated to prevent overtrading and cannot be reactivated for another ${hoursLeft} hours.`,
          });
        }
      }
      currentSeg.active = true;
      currentSeg.activatedAt = now;
      currentSeg.deactivatedAt = null;
      if (annualIncome) {
        user.annualIncome = annualIncome;
      }
    } else {
      // Deactivating via Kill Switch
      currentSeg.active = false;
      currentSeg.deactivatedAt = now;
    }

    user.segments[segmentKey] = currentSeg;
    user.markModified("segments");
    await user.save();

    // Audit Notification
    try {
      await createNotification({
        userId,
        type: "RISK",
        category: "SYSTEM",
        title: targetState
          ? `Segment Activated - ${currentSeg.name}`
          : `🛑 Kill Switch Active - ${currentSeg.name} Deactivated`,
        description: targetState
          ? `Trading is now active for ${currentSeg.name} (${currentSeg.exchange}).`
          : `Trading in ${currentSeg.name} is disabled. Reactivation is locked for 12 hours as per SEBI Kill Switch risk rules.`,
        metadata: { actionUrl: "/orders", segmentKey },
      });
    } catch (e) {}

    res.status(200).json({
      success: true,
      message: targetState
        ? `${currentSeg.name} activated successfully!`
        : `${currentSeg.name} deactivated via Kill Switch. Locked for 12 hours.`,
      segments: user.segments,
    });
  } catch (err) {
    console.error("Error updating segment:", err);
    res.status(500).json({ success: false, message: "Failed to update segment" });
  }
});

// Segment Activation Verification OTP
app.post("/sendSegmentOtp", requireAuth, otpLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const user = await UserModel.findOne({ userId });
    const userEmail = user?.email;
    if (!userEmail) {
      return res.status(400).json({ success: false, message: "No registered email address found for this user account." });
    }
    const { segmentKey } = req.body;
    if (!["equity", "futuresAndOptions", "currency", "commodity"].includes(segmentKey)) {
      return res.status(400).json({ success: false, message: "Invalid trading segment requested." });
    }

    const generatedOtp = crypto.randomInt(100000, 1000000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await OtpModel.findOneAndUpdate(
      { email: `${userEmail.toLowerCase()}_seg_otp` },
      {
        otp: generatedOtp,
        attempts: 0,
        expiresAt,
        createdAt: new Date(),
      },
      { upsert: true, returnDocument: "after", setDefaultsOnInsert: true }
    );

    const emailResult = await sendOtpEmail(userEmail, generatedOtp);
    logger.info("segment_otp_dispatched", { userId, delivered: emailResult.delivered });

    res.status(200).json({
      success: true,
      message: `Verification OTP sent to ${userEmail}`,
      isLiveEmail: emailResult.delivered,
      devOtp: IS_TEST ? generatedOtp : undefined,
    });
  } catch (err) {
    logger.error("segment_otp_send_error", { error: err.message });
    res.status(500).json({ success: false, message: "Failed to send verification code" });
  }
});

app.post("/verifySegmentOtp", requireAuth, authLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const user = await UserModel.findOne({ userId });
    if (!user || !user.email) {
      return res.status(400).json({ success: false, message: "Registered user account not found." });
    }
    const userEmail = user.email.toLowerCase();
    const { otp, segmentKey, annualIncome } = req.body;
    if (!["equity", "futuresAndOptions", "currency", "commodity"].includes(segmentKey)) {
      return res.status(400).json({ success: false, message: "Invalid trading segment specified." });
    }

    const otpKey = `${userEmail}_seg_otp`;
    const otpRecord = await OtpModel.findOne({ email: otpKey });
    if (!otpRecord) {
      return res.status(400).json({ success: false, message: "No OTP found or expired. Please request a new code." });
    }
    if (new Date() > otpRecord.expiresAt) {
      await OtpModel.deleteOne({ _id: otpRecord._id });
      return res.status(400).json({ success: false, message: "OTP has expired. Please request a new one." });
    }
    if (otpRecord.attempts >= 5) {
      await OtpModel.deleteOne({ _id: otpRecord._id });
      return res.status(429).json({ success: false, message: "Too many failed verification attempts. Please request a new OTP." });
    }

    const cleanOtp = String(otp || "").trim();
    if (!constantTimeEquals(String(otpRecord.otp), cleanOtp)) {
      otpRecord.attempts += 1;
      await otpRecord.save();
      const remaining = Math.max(0, 5 - otpRecord.attempts);
      return res.status(400).json({
        success: false,
        message: `Invalid verification code entered. ${remaining} attempt${remaining === 1 ? "" : "s"} remaining.`,
      });
    }

    // Activate segment
    if (!user.segments) user.segments = {};
    const defaultNames = {
      equity: { name: "NSE & BSE Equity (Cash)", exchange: "NSE, BSE" },
      futuresAndOptions: { name: "Futures & Options (F&O)", exchange: "NFO, BFO" },
      currency: { name: "Currency Derivatives (CDS)", exchange: "CDS, BCD" },
      commodity: { name: "Commodity Derivatives", exchange: "MCX" },
    };

    const currentSeg = user.segments[segmentKey] || {
      name: defaultNames[segmentKey]?.name || segmentKey,
      exchange: defaultNames[segmentKey]?.exchange || "NSE",
      active: true,
      deactivatedAt: null,
      activatedAt: new Date(),
    };
    currentSeg.active = true;
    currentSeg.activatedAt = new Date();
    currentSeg.deactivatedAt = null;

    user.segments[segmentKey] = currentSeg;
    if (annualIncome) user.annualIncome = annualIncome;
    user.markModified("segments");
    await user.save();

    await OtpModel.deleteOne({ _id: otpRecord._id });

    try {
      await createNotification({
        userId,
        type: "RISK",
        category: "SYSTEM",
        title: `Segment Activated - ${currentSeg.name}`,
        description: `Trading is now active for ${currentSeg.name} (${currentSeg.exchange}) with verified income declaration.`,
        metadata: { actionUrl: "/orders", segmentKey },
      });
    } catch (e) {}

    res.status(200).json({
      success: true,
      message: `${currentSeg.name} verified and activated!`,
      segments: user.segments,
    });
  } catch (err) {
    console.error("Error verifying segment OTP:", err);
    res.status(500).json({ success: false, message: "Verification failed." });
  }
});


// ============================================================================
// 9. CDSL E-DIS DEMAT AUTHORIZATION (TPIN & TRANSACTION OTP VIA EMAIL)
// ============================================================================

app.post("/cdsl/generate-tpin", requireAuth, otpLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const user = await UserModel.findOne({ userId });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const toEmail = user.email;
    if (!toEmail) {
      return res.status(400).json({ success: false, message: "No registered email found for this user account. Please update your profile email." });
    }

    const generatedTpin = crypto.randomInt(100000, 1000000).toString();
    user.cdslTpin = hashPassword(generatedTpin);
    user.cdslAttempts = 0;
    user.cdslLockedUntil = null;
    await user.save();

    const emailResult = await sendCdslTpinEmail(toEmail, generatedTpin, user.demat);
    logger.info("cdsl_tpin_dispatched", { userId, delivered: emailResult.delivered });

    res.status(200).json({
      success: true,
      message: `Your 6-digit CDSL TPIN has been sent to ${toEmail}`,
      isLiveEmail: emailResult.delivered,
    });
  } catch (err) {
    logger.error("cdsl_generate_tpin_error", { error: err.message });
    res.status(500).json({ success: false, message: "Failed to dispatch CDSL TPIN" });
  }
});

app.post("/cdsl/verify-tpin", requireAuth, authLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const { tpin, stockName, stockQty } = req.body;
    const user = await UserModel.findOne({ userId });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (user.cdslLockedUntil && new Date(user.cdslLockedUntil) > new Date()) {
      return res.status(429).json({
        success: false,
        message: "CDSL TPIN locked due to multiple failed attempts. Please try again later or generate a new TPIN.",
      });
    }

    if (!user.cdslTpin) {
      return res.status(400).json({
        success: false,
        message: "No CDSL TPIN found for this account. Please click 'Generate New TPIN' to receive one on your registered email.",
      });
    }

    const cleanTpin = String(tpin || "").trim();
    if (!cleanTpin || !verifyPassword(cleanTpin, user.cdslTpin)) {
      user.cdslAttempts = (user.cdslAttempts || 0) + 1;
      if (user.cdslAttempts >= 5) {
        user.cdslLockedUntil = new Date(Date.now() + 15 * 60 * 1000);
      }
      await user.save();
      if (user.cdslAttempts >= 5) {
        return res.status(429).json({
          success: false,
          message: "Too many invalid TPIN attempts. CDSL authorization temporarily locked for 15 minutes.",
        });
      }
      const remaining = 5 - user.cdslAttempts;
      return res.status(400).json({
        success: false,
        message: `Invalid CDSL TPIN entered. ${remaining} attempt${remaining === 1 ? "" : "s"} remaining.`,
      });
    }

    // Re-hash legacy plaintext TPIN upon successful verification + reset counters
    if (!user.cdslTpin.includes(":")) {
      user.cdslTpin = hashPassword(cleanTpin);
    }
    user.cdslAttempts = 0;
    user.cdslLockedUntil = null;
    await user.save();

    // TPIN is valid -> Generate Transaction OTP
    const generatedOtp = crypto.randomInt(100000, 1000000).toString();
    const toEmail = (user.email || "").toLowerCase();
    if (!toEmail) {
      return res.status(400).json({ success: false, message: "No registered email address found for this user account." });
    }

    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
    await OtpModel.findOneAndUpdate(
      { email: `${toEmail}_cdsl_otp` },
      {
        otp: generatedOtp,
        attempts: 0,
        expiresAt,
        createdAt: new Date(),
      },
      { upsert: true, returnDocument: "after", setDefaultsOnInsert: true }
    );

    const emailResult = await sendCdslTransactionOtpEmail(toEmail, generatedOtp, stockName, stockQty);
    logger.info("cdsl_otp_dispatched", { userId, delivered: emailResult.delivered });

    res.status(200).json({
      success: true,
      message: `Transaction OTP sent to ${toEmail}`,
      isLiveEmail: emailResult.delivered,
      devOtp: IS_TEST ? generatedOtp : undefined,
    });
  } catch (err) {
    logger.error("cdsl_verify_tpin_error", { error: err.message });
    res.status(500).json({ success: false, message: "Failed to verify TPIN" });
  }
});

app.post("/cdsl/verify-otp", requireAuth, authLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const { otp } = req.body;
    const user = await UserModel.findOne({ userId });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const toEmail = (user.email || "").toLowerCase();
    const otpRecord = await OtpModel.findOne({ email: `${toEmail}_cdsl_otp` });

    if (!otpRecord) {
      return res.status(400).json({
        success: false,
        message: "No active CDSL transaction OTP found or expired. Please re-enter your TPIN.",
      });
    }

    if (new Date() > otpRecord.expiresAt) {
      await OtpModel.deleteOne({ _id: otpRecord._id });
      return res.status(400).json({
        success: false,
        message: "CDSL transaction OTP has expired. Please request a new code.",
      });
    }

    if (otpRecord.attempts >= 5) {
      await OtpModel.deleteOne({ _id: otpRecord._id });
      return res.status(429).json({
        success: false,
        message: "Too many failed CDSL OTP attempts. Please re-verify your TPIN.",
      });
    }

    const cleanOtp = String(otp || "").trim();
    if (!constantTimeEquals(String(otpRecord.otp), cleanOtp)) {
      otpRecord.attempts += 1;
      await otpRecord.save();
      const remaining = Math.max(0, 5 - otpRecord.attempts);
      return res.status(400).json({
        success: false,
        message: `Invalid transaction OTP entered. ${remaining} attempt${remaining === 1 ? "" : "s"} remaining.`,
      });
    }

    await OtpModel.deleteOne({ _id: otpRecord._id });

    // Persist server-side CDSL E-DIS authorization expiry in IST (valid for rest of IST trading/AMO day)
    const IST_OFFSET_MS = 5.5 * 60 * 60 * 1000;
    const nowUtc = new Date();
    const nowIst = new Date(nowUtc.getTime() + IST_OFFSET_MS);
    const eodIst = new Date(nowIst);
    eodIst.setUTCHours(23, 59, 59, 999);
    const cdslAuthorizedUntil = new Date(eodIst.getTime() - IST_OFFSET_MS);
    user.cdslAuthorizedUntil = cdslAuthorizedUntil;
    await user.save();

    // In-App Notification
    try {
      await createNotification({
        userId,
        type: "ORDER",
        category: "SYSTEM",
        title: "CDSL Demat Authorized",
        description: `Demat account authorized via CDSL E-DIS for exit transactions today.`,
        metadata: { actionUrl: "/holdings" },
      });
    } catch (e) {}

    res.status(200).json({
      success: true,
      cdslAuthorizedUntil: cdslAuthorizedUntil.toISOString(),
      message: "Demat holdings authorized successfully for today's trading session!",
    });
  } catch (err) {
    console.error("Error verifying CDSL OTP:", err);
    res.status(500).json({ success: false, message: "Failed to verify OTP" });
  }
});


// ==========================================
// SUPPORT TICKET ECOSYSTEM
// ==========================================

// 1. Register New Support Ticket
app.post("/createSupportTicket", requireAuth, tradeFundsLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const {
      category = "ORDERS",
      categoryLabel,
      subject,
      description,
      priority = "NORMAL",
    } = req.body;

    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    const dbUser = await UserModel.findOne({ userId }).select("fullName email").lean();
    if (!dbUser) {
      return res.status(404).json({ success: false, message: "Authenticated user not found" });
    }
    const userName = dbUser.fullName || "Trader";
    const userEmail = dbUser.email || "";

    if (!subject || typeof subject !== "string" || !subject.trim() || subject.trim().length > 200) {
      return res.status(400).json({ success: false, message: "Subject is required (max 200 characters)" });
    }
    if (!description || typeof description !== "string" || !description.trim() || description.trim().length > 4000) {
      return res.status(400).json({ success: false, message: "Description is required (max 4000 characters)" });
    }

    const categoryLabels = {
      FUNDS: "Funds, Payouts & Margins",
      ORDERS: "Order Placement & Fills",
      DEMAT: "Demat, Pledging & Holdings",
      ACCOUNT: "Account Settings & KYC",
      TECH: "Technical & Platform Query",
      OTHER: "General Support Inquiry",
    };

    const finalCategoryLabel = categoryLabel || categoryLabels[category] || "General Support Inquiry";
    const randomNum = crypto.randomInt(100000, 1000000);
    const ticketId = `TKT-${randomNum}`;

    const newTicket = new SupportTicketModel({
      ticketId,
      userId,
      userName,
      userEmail,
      category,
      categoryLabel: finalCategoryLabel,
      subject: subject.trim(),
      description: description.trim(),
      priority,
      status: "OPEN",
      slaHours: priority === "URGENT" ? 1 : 2,
      assignedTo: "Kite Customer Helpdesk",
      createdAt: new Date(),
    });

    await newTicket.save();

    // Trigger in-app notification for the user
    try {
      await createNotification({
        userId,
        type: "SYSTEM",
        category: "SUPPORT_TICKET",
        title: `Support Ticket #${ticketId} Registered`,
        description: `Your ticket regarding '${subject.trim()}' has been registered under ${finalCategoryLabel}. Priority: ${priority}. Expected SLA: 2 business hours.`,
        metadata: {
          referenceId: ticketId,
          actionUrl: "/support",
        },
        priority: priority === "URGENT" ? "HIGH" : "NORMAL",
      });
    } catch (notifErr) {
      console.warn("Could not dispatch ticket notification:", notifErr.message);
    }

    return res.status(201).json({
      success: true,
      message: `Support Ticket #${ticketId} created successfully. Our team will resolve it within 2 business hours.`,
      ticket: newTicket,
    });
  } catch (err) {
    console.error("Error creating support ticket:", err);
    return res.status(500).json({ success: false, message: "Failed to create support ticket" });
  }
});

// 2. Fetch User's Registered Support Tickets
app.get("/mySupportTickets", requireAuth, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }

    const tickets = await SupportTicketModel.find({ userId }).sort({ createdAt: -1 });
    return res.status(200).json({
      success: true,
      count: tickets.length,
      tickets,
    });
  } catch (err) {
    console.error("Error fetching support tickets:", err);
    return res.status(500).json({ success: false, message: "Failed to fetch support tickets" });
  }
});

// Global Error Handler (prevents stack trace leakage in production)
app.use((err, req, res, next) => {
  console.error("Unhandled Express Error:", err?.message || err);
  if (err && err.type === "entity.parse.failed") {
    return res.status(400).json({ success: false, message: "Malformed JSON payload" });
  }
  if (err && err.name === "CastError") {
    return res.status(400).json({ success: false, message: "Invalid identifier format" });
  }
  if (err && typeof err.message === "string" && err.message.startsWith("CORS origin blocked")) {
    return res.status(403).json({ success: false, message: "Origin not allowed by CORS policy" });
  }
  return res.status(err?.status || 500).json({
    success: false,
    message: process.env.NODE_ENV === "production" ? "Internal server error" : err?.message || "Internal server error",
  });
});

let serverInstance = null;

function startBackgroundWorkers() {
  if (!sipWorkerInterval) {
    sipWorkerInterval = setInterval(runSipWorkerCycle, 45000);
    if (sipWorkerInterval.unref) sipWorkerInterval.unref();
  }
  if (!alertsWorkerInterval) {
    alertsWorkerInterval = setInterval(runAlertsWorkerCycle, 15000);
    if (alertsWorkerInterval.unref) alertsWorkerInterval.unref();
  }
}

function stopBackgroundWorkers() {
  if (sipWorkerInterval) {
    clearInterval(sipWorkerInterval);
    sipWorkerInterval = null;
  }
  if (alertsWorkerInterval) {
    clearInterval(alertsWorkerInterval);
    alertsWorkerInterval = null;
  }
}

function startServer(port = PORT) {
  startBackgroundWorkers();
  serverInstance = app.listen(port, () => {
    logger.info("server_started", { port, env: NODE_ENV });
  });
  serverInstance.setTimeout(30000);
  return serverInstance;
}

async function shutdown(signal) {
  logger.info("shutdown_initiated", { signal });
  stopBackgroundWorkers();
  if (serverInstance) {
    await new Promise((resolve) => serverInstance.close(resolve));
    serverInstance = null;
  }
  await mongoose.connection.close().catch(() => {});
  process.exit(0);
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

if (require.main === module) {
  startServer();
}

module.exports = { app, startServer, shutdown };
