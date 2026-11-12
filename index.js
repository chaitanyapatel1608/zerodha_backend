const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, ".env") });
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const {
  hashPassword,
  verifyPassword,
  escapeRegex,
  resolveAuthenticatedUserId,
} = require("./utils/security");

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
const PORT = process.env.PORT || 3002;
const uri = process.env.MONGO_URL;

if (process.env.NODE_ENV === "production" && !process.env.JWT_SECRET) {
  console.error("FATAL: JWT_SECRET environment variable must be set in production.");
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET || "zerodha_jwt_super_secret_key_2026_finance_kite";

// Environment & Host Configuration
const PUBLIC_FRONTEND_URL = process.env.PUBLIC_FRONTEND_URL || "http://localhost:3001";
const PUBLIC_BACKEND_URL = process.env.PUBLIC_BACKEND_URL || "http://localhost:3002";


// Middlewares & Security Headers
app.disable("x-powered-by");
app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  })
);

const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:3001",
  process.env.FRONTEND_URL,
  process.env.PUBLIC_FRONTEND_URL,
].filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin) || process.env.NODE_ENV !== "production") {
        return callback(null, true);
      }
      return callback(new Error("CORS origin blocked by policy: " + origin));
    },
    credentials: true,
  })
);
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// Rate Limiters
const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 15,
  message: { success: false, message: "Too many OTP requests. Please wait a few minutes before trying again." },
  standardHeaders: true,
  legacyHeaders: false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  message: { success: false, message: "Too many authentication attempts. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

const tradeFundsLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  message: { success: false, message: "Rate limit exceeded for sensitive actions. Please slow down." },
  standardHeaders: true,
  legacyHeaders: false,
});

// MongoDB Connection
mongoose
  .connect(uri)
  .then(() => {
    console.log("DB connected successfully!");
    seedCatalogsToDb();
  })
  .catch((err) => console.error("DB connection error:", err));

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

    // Compare OTP
    if (otpRecord.otp !== cleanOtp) {
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
      const randomId = Math.floor(1000 + Math.random() * 9000);
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
      console.log(`👤 [NEW USER PROVISIONED] ${user.userId} (${user.email}) - PAN: ${user.pan}`);
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

    // Sign stateless JWT
    const token = jwt.sign(
      {
        userId: user.userId,
        email: user.email,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    return res.status(200).json({
      success: true,
      message: "Authentication successful!",
      token,
      user: {
        userId: user.userId,
        email: user.email,
        fullName: user.fullName,
        phone: user.phone || "",
        pan: user.pan || "",
        dob: user.dob || "",
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

// 2.5 Kite Direct / Password Login & Lookup Endpoint
app.post("/kite-login", authLimiter, async (req, res) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !identifier.trim()) {
      return res.status(400).json({ success: false, message: "User ID, Phone number, or Email is required" });
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
      return res.status(404).json({
        success: false,
        code: "USER_NOT_FOUND",
        message: `No Zerodha account registered with '${cleanId}'. Please open a new account to continue.`,
      });
    }

    if (user.password && password) {
      const isValid = verifyPassword(password, user.password);
      if (!isValid) {
        return res.status(401).json({ success: false, message: "Incorrect password. Please try again." });
      }
      // Upgrade plaintext to scrypt hash if needed
      if (!user.password.includes(":")) {
        user.password = hashPassword(password);
        await user.save();
      }
    } else if (password && !user.password) {
      user.password = hashPassword(password);
      await user.save();
    }

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign(
      {
        userId: user.userId,
        email: user.email,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    console.log(`🚀 [KITE LOGIN SUCCESS] ${user.userId} (${user.email}) - Terminal Launched`);

    return res.status(200).json({
      success: true,
      message: "Login successful!",
      token,
      user: {
        userId: user.userId,
        email: user.email,
        fullName: user.fullName,
        phone: user.phone || "",
        pan: user.pan || "",
        dob: user.dob || "",
        demat: user.demat || "1208160012345678",
        annualIncome: user.annualIncome || "₹1L - ₹5L",
        tradingExp: user.tradingExp || "1-3 Years",
        broker: user.broker || "Zerodha Broking Ltd.",
        avatarText: user.avatarText,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Error in kite-login:", error);
    return res.status(500).json({ success: false, message: "Internal server error during login" });
  }
});

// 3. Verify Active Session Token

// Helper: Resolve dynamic userId from verified JWT token
function getAuthenticatedUserId(req) {
  return resolveAuthenticatedUserId(req, JWT_SECRET, process.env.NODE_ENV);
}

app.get("/verifyUser", async (req, res) => {
  try {
    let resolvedUserId = null;
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      try {
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        resolvedUserId = decoded?.userId;
      } catch (e) {}
    }
    if (!resolvedUserId && req.query?.userId) {
      resolvedUserId = req.query.userId.trim();
    }
    if (!resolvedUserId) {
      return res.status(401).json({ success: false, message: "User identity or token required" });
    }

    const user = await UserModel.findOne({ userId: resolvedUserId }).select("-__v");
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    return res.status(200).json({
      success: true,
      user: {
        userId: user.userId,
        email: user.email,
        fullName: user.fullName,
        phone: user.phone || "",
        pan: user.pan || "",
        dob: user.dob || "",
        demat: user.demat || ("12081600" + Math.floor(10000000 + Math.random() * 90000000)),
        annualIncome: user.annualIncome || "₹1L - ₹5L",
        tradingExp: user.tradingExp || "1-3 Years",
        broker: user.broker || "Zerodha Broking Ltd.",
        avatarText: user.avatarText,
        role: user.role,
        nomineeStatus: user.nomineeStatus || "PENDING",
        nominees: user.nominees || [],
      },
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: "Error verifying user profile" });
  }
});

// ==========================================
// Core Trading & Market Data Routes
// ==========================================

app.get("/allHoldings", async (req, res) => {
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

app.get("/allPositions", async (req, res) => {
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
app.post("/squareOffPosition", async (req, res) => {
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
app.post("/squareOffAllPositions", async (req, res) => {
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
app.post("/convertPosition", async (req, res) => {
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

app.get("/allOrders", async (req, res) => {
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

// Helper: Strictly isolate user funds per tenant/user account
async function getOrCreateUserFunds(userId) {
  if (!userId) return null;
  let funds = await FundsModel.findOne({ userId });
  if (!funds) {
    funds = new FundsModel({
      userId,
      equity: {
        availableMargin: "1,24,500.00",
        usedMargin: "0.00",
        availableCash: "1,24,500.00",
        openingBalance: "1,24,500.00",
      },
      commodity: {
        availableMargin: "0.00",
        usedMargin: "0.00",
        availableCash: "0.00",
        openingBalance: "0.00",
      },
    });
    await funds.save();
    console.log(`💰 [USER FUNDS INITIALIZED] Initialized fresh margin for user: ${userId}`);
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
  const orderCost = numQty * numPrice;
  const marginRequired = orderProduct === "MIS" ? orderCost * 0.2 : orderCost;

  let funds = await getOrCreateUserFunds(userId);
  if (!funds) {
    return {
      success: false,
      code: "FUNDS_UNAVAILABLE",
      message: "Unable to retrieve or initialize trading funds for this user account.",
    };
  }

  let currentAvailable = parseFloat(funds.equity.availableMargin.replace(/,/g, "")) || 0;
  let currentUsed = parseFloat(funds.equity.usedMargin.replace(/,/g, "")) || 0;

  if (orderMode === "BUY") {
    if (currentAvailable < marginRequired) {
      return {
        success: false,
        code: "INSUFFICIENT_MARGIN",
        message: `Insufficient margin! Margin required: ₹${formatIndianCurrency(marginRequired)}, but available margin is only ₹${formatIndianCurrency(currentAvailable)}.`,
      };
    }

    currentAvailable -= marginRequired;
    currentUsed += marginRequired;
    funds.equity.availableMargin = formatIndianCurrency(currentAvailable);
    funds.equity.usedMargin = formatIndianCurrency(currentUsed);
    funds.equity.availableCash = formatIndianCurrency(currentAvailable);
    await funds.save();

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

      const proceeds = numQty * numPrice;
      currentAvailable += proceeds;
      currentUsed = Math.max(0, currentUsed - proceeds);
      funds.equity.availableMargin = formatIndianCurrency(currentAvailable);
      funds.equity.usedMargin = formatIndianCurrency(currentUsed);
      funds.equity.availableCash = formatIndianCurrency(currentAvailable);
      await funds.save();
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

      currentAvailable += marginRequired;
      currentUsed = Math.max(0, currentUsed - marginRequired);
      funds.equity.availableMargin = formatIndianCurrency(currentAvailable);
      funds.equity.usedMargin = formatIndianCurrency(currentUsed);
      funds.equity.availableCash = formatIndianCurrency(currentAvailable);
      await funds.save();
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
  const savedOrder = await newOrder.save();

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
}

// Helper to format Indian Currency
const formatIndianCurrency = (num) => {
  return Number(num).toLocaleString("en-IN", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
};

// 1. Transactional Order Engine with Portfolio & Funds Synchronization
app.post("/newOrder", tradeFundsLimiter, async (req, res) => {
  try {
    const { name, qty, price, mode = "BUY", product = "CNC" } = req.body;
    const userId = getAuthenticatedUserId(req);
    const result = await executeOrderInternal({ name, qty, price, mode, product, userId });
    if (!result.success) {
      return res.status(400).json(result);
    }
    console.log(`⚡ [ORDER EXECUTED] ${mode} ${qty} ${name} @ ₹${price} (${product}) for ${userId}`);
    return res.status(201).json({
      success: true,
      message: `Order executed: ${mode} ${qty} ${name} @ ₹${price} (${product})`,
      order: result.order,
      funds: result.funds,
    });
  } catch (error) {
    console.error("Order engine execution error:", error);
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
    const q = (req.query.q || "").trim();
    const sector = (req.query.sector || "").trim();
    const limit = parseInt(req.query.limit) || 50;

    const query = {};
    if (sector) {
      query.sector = new RegExp("^" + sector + "$", "i");
    }
    if (q) {
      query.$or = [
        { symbol: new RegExp(q, "i") },
        { name: new RegExp(q, "i") },
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
app.get("/allInstruments", async (req, res) => {
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
app.get("/userWatchlistTabs", async (req, res) => {
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
        // Tab 1 auto-initializes with default stocks, Tabs 2-7 start empty
        if (id === 1) {
          try {
            const newTab1 = new UserWatchlistModel({
              userId,
              tabId: 1,
              tabName: "Watchlist 1",
              stocks: defaultTab1Stocks,
            });
            await newTab1.save();
            tabs.push({ tabId: 1, tabName: "Watchlist 1", count: defaultTab1Stocks.length });
          } catch (err) {
            tabs.push({ tabId: 1, tabName: "Watchlist 1", count: defaultTab1Stocks.length });
          }
        } else {
          tabs.push({ tabId: id, tabName: `Watchlist ${id}`, count: 0 });
        }
      }
    }

    return res.status(200).json(tabs);
  } catch (error) {
    console.error("Error fetching user watchlist tabs:", error);
    return res.status(500).json({ error: "Failed to fetch user watchlist tabs" });
  }
});

// GET /userWatchlist - Get a specific tab's stocks and metadata
app.get("/userWatchlist", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const tabId = parseInt(req.query.tabId) || 1;

    let tabDoc = await UserWatchlistModel.findOne({ userId, tabId });
    if (!tabDoc) {
      if (tabId === 1) {
        tabDoc = new UserWatchlistModel({
          userId,
          tabId: 1,
          tabName: "Watchlist 1",
          stocks: defaultTab1Stocks,
        });
        await tabDoc.save();
      } else {
        tabDoc = new UserWatchlistModel({
          userId,
          tabId,
          tabName: `Watchlist ${tabId}`,
          stocks: [],
        });
        await tabDoc.save();
      }
    }

    return res.status(200).json(tabDoc);
  } catch (error) {
    console.error("Error fetching user watchlist:", error);
    return res.status(500).json({ error: "Failed to fetch user watchlist" });
  }
});

// POST /addWatchlistStock - Add a stock to active tab
app.post("/addWatchlistStock", async (req, res) => {
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
        stocks: tabId === 1 ? defaultTab1Stocks : [],
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
app.post("/removeWatchlistStock", async (req, res) => {
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
app.post("/renameWatchlistTab", async (req, res) => {
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
        stocks: tabId === 1 ? defaultTab1Stocks : [],
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

app.get("/userFunds", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.query.userId;
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

app.get("/allIpos", async (req, res) => {
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
app.post("/addNominee", async (req, res) => {
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
app.get("/getNominee", async (req, res) => {
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
      user.demat = "12081600" + Math.floor(10000000 + Math.random() * 90000000);
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

app.get("/allGtt", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const gtts = await GttModel.find({ userId }).sort({ createdAt: -1 });
    res.status(200).json(gtts);
  } catch (error) {
    console.error("Error fetching GTTs:", error);
    res.status(500).json({ error: "Failed to fetch GTT orders" });
  }
});

app.post("/newGtt", async (req, res) => {
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

app.post("/cancelGtt", async (req, res) => {
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

app.post("/triggerGtt", async (req, res) => {
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

app.post("/addTemplateToBaskets", async (req, res) => {
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

app.get("/allBaskets", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(200).json([]);
    }
    let baskets = await BasketModel.find({ userId }).sort({ createdAt: -1 });

    // Auto-seed default baskets for user if empty so they have realistic dynamic constituents
    if (baskets.length === 0) {
      const defaultBaskets = [
        {
          userId,
          name: "Nifty Bull Spread",
          items: [
            { symbol: "INFY", mode: "BUY", product: "CNC", qty: 10, price: 1845.5, orderType: "LIMIT" },
            { symbol: "TCS", mode: "BUY", product: "CNC", qty: 5, price: 3982.75, orderType: "LIMIT" },
          ],
          marginRequired: 38368.75,
        },
        {
          userId,
          name: "IT Long Term SIP",
          items: [
            { symbol: "INFY", mode: "BUY", product: "CNC", qty: 5, price: 1845.5, orderType: "LIMIT" },
            { symbol: "WIPRO", mode: "BUY", product: "CNC", qty: 15, price: 546.8, orderType: "LIMIT" },
            { symbol: "TCS", mode: "BUY", product: "CNC", qty: 2, price: 3982.75, orderType: "LIMIT" },
          ],
          marginRequired: 25395.0,
        },
      ];
      baskets = await BasketModel.insertMany(defaultBaskets);
      console.log(`📦 [BASKETS SEEDED] Initialized 2 real constituent baskets for user ${userId}`);
    }

    res.status(200).json(baskets);
  } catch (error) {
    console.error("Error fetching baskets:", error);
    res.status(500).json({ error: "Failed to fetch baskets" });
  }
});

app.post("/saveBasket", async (req, res) => {
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

app.delete("/deleteBasket/:id", async (req, res) => {
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

app.post("/executeBasket", async (req, res) => {
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
app.get("/notifications", async (req, res) => {
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
app.get("/notifications/unreadCount", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const unreadCount = await NotificationModel.countDocuments({ userId, unread: true });
    res.status(200).json({ unreadCount });
  } catch (error) {
    console.error("Error counting unread notifications:", error);
    res.status(500).json({ unreadCount: 0 });
  }
});

// 3. Mark single notification as read
app.patch("/notifications/:id/read", async (req, res) => {
  try {
    const { id } = req.params;
    const updated = await NotificationModel.findByIdAndUpdate(
      id,
      { $set: { unread: false } },
      { new: true }
    );
    res.status(200).json({ success: true, notification: updated });
  } catch (error) {
    console.error("Error marking notification read:", error);
    res.status(500).json({ success: false, error: "Failed to update notification" });
  }
});

// 4. Mark all notifications as read (Atomic bulk update)
app.post("/notifications/markAllRead", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    await NotificationModel.updateMany({ userId, unread: true }, { $set: { unread: false } });
    res.status(200).json({ success: true, message: "All notifications marked as read." });
  } catch (error) {
    console.error("Error marking all notifications read:", error);
    res.status(500).json({ success: false, error: "Failed to mark all as read" });
  }
});

// 5. Delete single notification
app.delete("/notifications/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await NotificationModel.findByIdAndDelete(id);
    res.status(200).json({ success: true, message: "Notification deleted." });
  } catch (error) {
    console.error("Error deleting notification:", error);
    res.status(500).json({ success: false, error: "Failed to delete notification" });
  }
});

// 6. Clear all notifications
app.post("/notifications/clearAll", async (req, res) => {
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
app.post("/fundDeposit/initiate", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.body.userId;
    if (!userId) {
      return res.status(401).json({ success: false, message: "User authentication required" });
    }

    const { amount, upiId } = req.body;
    const numAmount = parseFloat(amount);
    if (!numAmount || numAmount <= 0) {
      return res.status(400).json({ success: false, message: "Please enter a valid deposit amount." });
    }

    if (!upiId || !upiId.includes("@")) {
      return res.status(400).json({ success: false, message: "Please provide a valid UPI ID (e.g. yourname@okhdfcbank)." });
    }

    // Resolve user email
    let userEmail = req.body.userEmail;
    if (!userEmail) {
      const user = await UserModel.findOne({ userId });
      userEmail = user?.email || "chaitanya.expound@gmail.com";
    }

    const approvalToken = crypto.randomBytes(32).toString("hex");
    const referenceId = "UPI" + Math.floor(10000000000 + Math.random() * 90000000000);

    const newTx = new FundsTransactionModel({
      userId,
      type: "PAYIN",
      amount: numAmount,
      paymentMethod: "UPI",
      upiId: upiId.trim(),
      status: "PENDING_APPROVAL",
      referenceId,
      approvalToken,
      remarks: `Instant UPI Payin via ${upiId.trim()}`,
    });
    await newTx.save();

    const approveUrl = `${PUBLIC_BACKEND_URL}/fundDeposit/action?token=${approvalToken}&decision=APPROVE`;
    const declineUrl = `${PUBLIC_BACKEND_URL}/fundDeposit/action?token=${approvalToken}&decision=REJECT`;

    // Send interactive approval email via Nodemailer
    await sendFundDepositEmail({
      toEmail: userEmail,
      amount: numAmount,
      upiId: upiId.trim(),
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
        description: `UPI collect request for ₹${formatIndianCurrency(numAmount)} sent to ${upiId}. Please approve via email. Ref: ${referenceId}.`,
        metadata: {
          amount: numAmount,
          referenceId,
          actionUrl: "/funds",
        },
      });
    } catch (e) {}

    res.status(201).json({
      success: true,
      message: `UPI Collect Request sent to ${upiId}! Please approve the payment via the authorization email sent to ${userEmail}.`,
      transaction: newTx,
      approveUrl, // Included for seamless 1-click in-app simulation testing
    });
  } catch (error) {
    console.error("Error initiating fund deposit:", error);
    res.status(500).json({ success: false, message: "Failed to initiate fund deposit." });
  }
});

// 2. Interactive Email Action (Approve / Decline from Gmail or direct link)
app.get("/fundDeposit/action", async (req, res) => {
  try {
    const { token, decision } = req.query;
    if (!token || !decision) {
      return res.status(400).send("<h3>Invalid or missing deposit action parameters.</h3>");
    }

    const tx = await FundsTransactionModel.findOne({ approvalToken: token });
    if (!tx) {
      return res.status(404).send(`
        <!DOCTYPE html>
        <html>
        <head><title>Request Expired</title><style>body { font-family: -apple-system, sans-serif; text-align: center; padding: 50px; background: #f8fafc; color: #1e293b; }</style></head>
        <body>
          <h2 style="color: #ef4444;">Transfer Link Expired or Invalid</h2>
          <p>We could not find an active deposit request associated with this token.</p>
          <a href="${PUBLIC_FRONTEND_URL}/funds" style="display: inline-block; margin-top: 16px; padding: 10px 20px; background: #387ed1; color: #fff; text-decoration: none; border-radius: 4px;">Return to Zerodha Kite</a>
        </body>
        </html>
      `);
    }

    if (tx.status !== "PENDING_APPROVAL") {
      return res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>Transfer Already Processed</title><style>body { font-family: -apple-system, sans-serif; text-align: center; padding: 50px; background: #f8fafc; color: #1e293b; }</style></head>
        <body>
          <h2>Transfer Already Processed</h2>
          <p>This deposit request (Ref: <strong>${tx.referenceId}</strong>) has already been marked as <strong>${tx.status}</strong>.</p>
          <a href="${PUBLIC_FRONTEND_URL}/funds" style="display: inline-block; margin-top: 16px; padding: 10px 20px; background: #387ed1; color: #fff; text-decoration: none; border-radius: 4px;">View in Zerodha Kite</a>
        </body>
        </html>
      `);
    }

    const isApprove = decision.toUpperCase() === "APPROVE";
    if (isApprove) {
      tx.status = "COMPLETED";
      tx.completedAt = new Date();
      await tx.save();

      // Credit funds to user account
      const funds = await getOrCreateUserFunds(tx.userId);
      let currentAvailable = parseFloat(funds.equity.availableMargin.replace(/,/g, "")) || 0;
      let currentPayin = parseFloat((funds.equity.payin || "0").replace(/,/g, "")) || 0;

      currentAvailable += tx.amount;
      currentPayin += tx.amount;

      funds.equity.availableMargin = formatIndianCurrency(currentAvailable);
      funds.equity.availableCash = formatIndianCurrency(currentAvailable);
      funds.equity.payin = formatIndianCurrency(currentPayin);
      await funds.save();

      // Dispatch in-app notification
      try {
        await createNotification({
          userId: tx.userId,
          type: "FUNDS",
          category: "MARGIN",
          title: "Funds Credited Successfully",
          description: `₹${formatIndianCurrency(tx.amount)} credited to your trading account via UPI (${tx.upiId}). Margin available immediately. Ref: ${tx.referenceId}.`,
          metadata: {
            amount: tx.amount,
            referenceId: tx.referenceId,
            actionUrl: "/funds",
          },
        });
      } catch (e) {}

      console.log(`✅ [FUNDS CREDITED] Credited ₹${tx.amount} to user ${tx.userId} (Ref: ${tx.referenceId})`);

      return res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Payment Approved - Zerodha Kite</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; margin: 0; padding: 40px 20px; color: #0f172a; text-align: center; }
            .receipt-card { max-width: 500px; margin: 0 auto; background: #fff; padding: 36px 28px; border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 10px 25px rgba(0,0,0,0.06); }
            .success-icon { width: 64px; height: 64px; line-height: 64px; border-radius: 50%; background: #dcfce7; color: #16a34a; font-size: 32px; margin: 0 auto 16px auto; }
            h2 { margin: 0 0 8px 0; color: #0f172a; font-size: 24px; }
            p { color: #64748b; font-size: 14px; line-height: 1.5; margin: 0 0 24px 0; }
            .details-table { width: 100%; border-collapse: collapse; margin-bottom: 24px; font-size: 13.5px; text-align: left; }
            .details-table td { padding: 10px 0; border-bottom: 1px solid #f1f5f9; }
            .details-table .label { color: #64748b; }
            .details-table .val { font-weight: 600; text-align: right; color: #0f172a; }
            .btn-return { display: inline-block; background: #16a34a; color: #fff; text-decoration: none; padding: 12px 28px; border-radius: 4px; font-weight: 600; font-size: 14px; }
          </style>
        </head>
        <body>
          <div class="receipt-card">
            <div class="success-icon">✓</div>
            <h2>Funds Credited Successfully!</h2>
            <p>Your UPI payment has been confirmed. The funds are immediately available for trading on Zerodha Kite.</p>
            <table class="details-table">
              <tr><td class="label">Amount Credited</td><td class="val" style="color: #16a34a; font-size: 18px;">₹${formatIndianCurrency(tx.amount)}</td></tr>
              <tr><td class="label">Reference ID</td><td class="val" style="font-family: monospace;">${tx.referenceId}</td></tr>
              <tr><td class="label">Payer UPI ID</td><td class="val">${tx.upiId}</td></tr>
              <tr><td class="label">Target Segment</td><td class="val">Equity & F&O Margin</td></tr>
              <tr><td class="label">Status</td><td class="val" style="color: #16a34a;">Completed</td></tr>
            </table>
            <a href="${PUBLIC_FRONTEND_URL}/funds" class="btn-return">View in Zerodha Kite Dashboard &rsaquo;</a>
          </div>
        </body>
        </html>
      `);
    } else {
      tx.status = "REJECTED";
      tx.completedAt = new Date();
      await tx.save();

      try {
        await createNotification({
          userId: tx.userId,
          type: "FUNDS",
          category: "MARGIN",
          title: "UPI Transfer Declined",
          description: `UPI deposit request of ₹${formatIndianCurrency(tx.amount)} was declined. Ref: ${tx.referenceId}.`,
          metadata: {
            amount: tx.amount,
            referenceId: tx.referenceId,
            actionUrl: "/funds",
          },
        });
      } catch (e) {}

      return res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Transfer Declined - Zerodha Kite</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; margin: 0; padding: 40px 20px; color: #0f172a; text-align: center; }
            .receipt-card { max-width: 500px; margin: 0 auto; background: #fff; padding: 36px 28px; border-radius: 8px; border: 1px solid #e2e8f0; }
            .decline-icon { width: 56px; height: 56px; line-height: 56px; border-radius: 50%; background: #fee2e2; color: #dc2626; font-size: 28px; margin: 0 auto 16px auto; }
            h2 { margin: 0 0 8px 0; color: #dc2626; font-size: 22px; }
            p { color: #64748b; font-size: 14px; line-height: 1.5; margin: 0 0 24px 0; }
            .btn-return { display: inline-block; background: #64748b; color: #fff; text-decoration: none; padding: 12px 28px; border-radius: 4px; font-weight: 500; font-size: 14px; }
          </style>
        </head>
        <body>
          <div class="receipt-card">
            <div class="decline-icon">✕</div>
            <h2>UPI Transfer Declined</h2>
            <p>You have declined the fund deposit request for <strong>₹${formatIndianCurrency(tx.amount)}</strong>. No money was transferred.</p>
            <a href="${PUBLIC_FRONTEND_URL}/funds" class="btn-return">Return to Dashboard</a>
          </div>
        </body>
        </html>
      `);
    }
  } catch (error) {
    console.error("Error processing fund deposit action:", error);
    res.status(500).send("<h3>Server error processing deposit authorization.</h3>");
  }
});

// 3. Fetch User's Funds Transaction Ledger
app.get("/fundsTransactions", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.query.userId;
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
app.get("/userBankAccounts", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.query.userId;
    if (!userId) return res.status(200).json([]);

    let accounts = await BankAccountModel.find({ userId }).sort({ isPrimary: -1, createdAt: 1 });

    // Seed default verified account if user has none
    if (accounts.length === 0) {
      const defaultAccount = new BankAccountModel({
        userId,
        bankName: "HDFC Bank",
        accountNumber: "50100482194821",
        maskedAccountNumber: "····4821",
        ifscCode: "HDFC0000060",
        branch: "Fort, Mumbai",
        accountType: "SAVINGS",
        isPrimary: true,
        status: "VERIFIED",
        pennyDropRef: "PD" + Math.floor(100000000 + Math.random() * 900000000),
      });
      await defaultAccount.save();
      accounts = [defaultAccount];
    }

    res.status(200).json(accounts);
  } catch (error) {
    console.error("Error fetching bank accounts:", error);
    res.status(500).json({ error: "Failed to fetch bank accounts" });
  }
});

// 2. Add New Bank Account (Dynamic Linking & Penny Drop Simulation)
app.post("/addBankAccount", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.body.userId;
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

    const pennyDropRef = "PD" + Math.floor(100000000 + Math.random() * 900000000);

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
app.put("/setPrimaryBankAccount/:id", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.body.userId;
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
app.delete("/deleteBankAccount/:id", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.query.userId;
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
const withdrawalLocks = new Set();

// 4. Withdraw Funds Endpoint (SEBI Clearance Cycle)
app.post("/withdrawFunds", tradeFundsLimiter, async (req, res) => {
  const userId = getAuthenticatedUserId(req);
  if (!userId) {
    return res.status(401).json({ success: false, message: "User authentication required" });
  }
  if (withdrawalLocks.has(userId)) {
    return res.status(429).json({ success: false, message: "A withdrawal request is already in progress. Please wait." });
  }
  withdrawalLocks.add(userId);
  try {
    const { amount, bankAccount = "HDFC Bank ····4821", upiId } = req.body;
    const numAmount = Number(amount);
    if (!Number.isFinite(numAmount) || numAmount <= 0 || numAmount > 100000000) {
      return res.status(400).json({ success: false, message: "Please enter a valid withdrawal amount between ₹1 and ₹10,00,00,000." });
    }

    const funds = await getOrCreateUserFunds(userId);
    const previousCashStr = funds.equity.availableCash;
    let currentAvailable = parseFloat(funds.equity.availableMargin.replace(/,/g, "")) || 0;
    let currentCash = parseFloat(previousCashStr.replace(/,/g, "")) || 0;
    let currentPayout = parseFloat((funds.equity.payout || "0").replace(/,/g, "")) || 0;

    if (numAmount > currentCash) {
      return res.status(400).json({
        success: false,
        message: `Insufficient withdrawable cash balance! You can withdraw up to ₹${formatIndianCurrency(currentCash)}.`,
      });
    }

    currentAvailable -= numAmount;
    currentCash -= numAmount;
    currentPayout += numAmount;

    const updatedFunds = await FundsModel.findOneAndUpdate(
      { _id: funds._id, "equity.availableCash": previousCashStr },
      {
        $set: {
          "equity.availableMargin": formatIndianCurrency(currentAvailable),
          "equity.availableCash": formatIndianCurrency(currentCash),
          "equity.payout": formatIndianCurrency(currentPayout),
        },
      },
      { new: true }
    );
    if (!updatedFunds) {
      return res.status(409).json({ success: false, message: "Balance changed concurrently. Please retry withdrawal." });
    }

    const referenceId = "PAYOUT" + Math.floor(10000000000 + Math.random() * 90000000000);
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
    await newTx.save();

    try {
      await createNotification({
        userId,
        type: "FUNDS",
        category: "MARGIN",
        title: "Funds Withdrawal Requested",
        description: `Withdrawal request for ₹${formatIndianCurrency(numAmount)} submitted. Crediting to ${bankAccount} by 06:00 IST tomorrow. Ref: ${referenceId}.`,
        metadata: {
          amount: numAmount,
          referenceId,
          actionUrl: "/funds",
        },
      });
    } catch (e) {}

    res.status(200).json({
      success: true,
      message: `₹${formatIndianCurrency(numAmount)} withdrawal processed! Funds will be credited to ${bankAccount}.`,
      funds: updatedFunds.equity,
      transaction: newTx,
    });
  } catch (error) {
    console.error("Error withdrawing funds:", error);
    res.status(500).json({ success: false, message: "Failed to process withdrawal request." });
  } finally {
    withdrawalLocks.delete(userId);
  }
});

// 5. Margin Pledging: Pledge Demat Holdings for Trading Collateral
app.post("/pledgeHolding", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.body.userId;
    if (!userId) {
      return res.status(401).json({ success: false, message: "User authentication required" });
    }

    const { symbol, companyName, quantity, marketPrice } = req.body;
    const numQty = Math.max(1, parseInt(quantity) || 1);
    const numPrice = parseFloat(marketPrice) || 100;

    // Verify holding
    const holding = await HoldingsModel.findOne({
      userId,
      $or: [{ name: symbol }, { instrument: symbol }],
    });

    const ownedQty = holding ? holding.qty : 0;
    if (ownedQty < numQty) {
      return res.status(400).json({
        success: false,
        message: `Insufficient Demat shares! You hold ${ownedQty} shares of ${symbol}, but attempted to pledge ${numQty} shares.`,
      });
    }

    // Standard SEBI Haircuts: Bluechips 12.5%, Large-cap 15%, Others 20%
    let haircutPercent = 20;
    const sym = symbol.toUpperCase();
    if (sym === "RELIANCE" || sym === "TCS") haircutPercent = 12.5;
    else if (sym === "INFY" || sym === "HDFCBANK" || sym === "ICICIBANK") haircutPercent = 15;

    const totalVal = numQty * numPrice;
    const collateralValue = Number((totalVal * (1 - haircutPercent / 100)).toFixed(2));
    const pledgeRef = "PLG" + Math.floor(10000000000 + Math.random() * 90000000000);

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
    await newPledge.save();

    // Update user funds with pledged collateral
    const funds = await getOrCreateUserFunds(userId);
    let currentAvailable = parseFloat(funds.equity.availableMargin.replace(/,/g, "")) || 0;
    let currentCollateralEquity = parseFloat((funds.equity.collateralEquity || "0").replace(/,/g, "")) || 0;
    let currentTotalCollateral = parseFloat((funds.equity.totalCollateral || "0").replace(/,/g, "")) || 0;

    currentAvailable += collateralValue;
    currentCollateralEquity += collateralValue;
    currentTotalCollateral += collateralValue;

    funds.equity.availableMargin = formatIndianCurrency(currentAvailable);
    funds.equity.collateralEquity = formatIndianCurrency(currentCollateralEquity);
    funds.equity.totalCollateral = formatIndianCurrency(currentTotalCollateral);
    await funds.save();

    // Record in ledger
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
    await newTx.save();

    try {
      await createNotification({
        userId,
        type: "FUNDS",
        category: "MARGIN_PLEDGE",
        title: `Margin Pledged - ${symbol}`,
        description: `Pledged ${numQty} shares of ${symbol}. Generated ₹${formatIndianCurrency(collateralValue)} trading collateral (Haircut: ${haircutPercent}%). Ref: ${pledgeRef}.`,
        metadata: {
          symbol,
          amount: collateralValue,
          actionUrl: "/funds",
        },
      });
    } catch (e) {}

    res.status(201).json({
      success: true,
      message: `Successfully pledged ${numQty} shares of ${symbol}! ₹${formatIndianCurrency(collateralValue)} added to available margin.`,
      pledge: newPledge,
      collateralValue: newPledge.collateralValue,
      funds: funds.equity,
    });
  } catch (error) {
    console.error("Error pledging holding:", error);
    res.status(500).json({ success: false, message: "Failed to pledge shares for margin." });
  }
});

// 6. Unpledge Holding
app.post("/unpledgeHolding", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.body.userId;
    if (!userId) {
      return res.status(401).json({ success: false, message: "User authentication required" });
    }

    const { pledgeId } = req.body;
    const pledge = await PledgedCollateralModel.findOne({ _id: pledgeId, userId, status: "PLEDGED" });
    if (!pledge) {
      return res.status(404).json({ success: false, message: "Active pledged record not found." });
    }

    const funds = await getOrCreateUserFunds(userId);
    let currentAvailable = parseFloat(funds.equity.availableMargin.replace(/,/g, "")) || 0;
    let currentCollateralEquity = parseFloat((funds.equity.collateralEquity || "0").replace(/,/g, "")) || 0;
    let currentTotalCollateral = parseFloat((funds.equity.totalCollateral || "0").replace(/,/g, "")) || 0;

    if (currentAvailable < pledge.collateralValue) {
      return res.status(400).json({
        success: false,
        message: `Cannot unpledge! You have open positions utilizing this collateral. Free up at least ₹${formatIndianCurrency(pledge.collateralValue)} margin before unpledging.`,
      });
    }

    pledge.status = "RELEASED";
    pledge.releasedAt = new Date();
    await pledge.save();

    currentAvailable -= pledge.collateralValue;
    currentCollateralEquity = Math.max(0, currentCollateralEquity - pledge.collateralValue);
    currentTotalCollateral = Math.max(0, currentTotalCollateral - pledge.collateralValue);

    funds.equity.availableMargin = formatIndianCurrency(currentAvailable);
    funds.equity.collateralEquity = formatIndianCurrency(currentCollateralEquity);
    funds.equity.totalCollateral = formatIndianCurrency(currentTotalCollateral);
    await funds.save();

    const unpledgeRef = "UNPLG" + Math.floor(10000000000 + Math.random() * 90000000000);
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
    await newTx.save();

    res.status(200).json({
      success: true,
      message: `Successfully unpledged ${pledge.pledgedQty} shares of ${pledge.symbol}! Demat lock released.`,
      funds: funds.equity,
    });
  } catch (error) {
    console.error("Error unpledging holding:", error);
    res.status(500).json({ success: false, message: "Failed to unpledge shares." });
  }
});

// 7. Get User's Pledged Holdings
app.get("/myPledgedHoldings", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.query.userId;
    if (!userId) return res.status(200).json([]);
    const pledges = await PledgedCollateralModel.find({ userId, status: "PLEDGED" }).sort({ pledgedAt: -1 });
    res.status(200).json(pledges);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch pledged holdings" });
  }
});

// 8. Test notification trigger (for rapid dev testing / simulation)
app.post("/notifications/test", async (req, res) => {
  try {
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
app.post("/applyIpo", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.body.userId;
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

    // Resolve user email
    let targetEmail = userEmail;
    if (!targetEmail) {
      const userDoc = await UserModel.findOne({ userId });
      targetEmail = userDoc?.email || process.env.EMAIL_USER || "trader@example.com";
    }

    const randomSuffix = Math.floor(10000 + Math.random() * 90000);
    const applicationNumber = `IPO-${new Date().getFullYear()}-${ipoSymbol.toUpperCase()}-${randomSuffix}`;
    const mandateToken = crypto.randomBytes(24).toString("hex");

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

    res.status(201).json({
      success: true,
      message: `IPO application submitted! UPI Mandate authorization email sent to ${targetEmail}.`,
      application: savedApp,
    });
  } catch (error) {
    console.error("Error applying for IPO:", error);
    res.status(500).json({ success: false, message: "Internal server error processing IPO application" });
  }
});

// 2. Fetch User's Submitted IPO Applications
app.get("/myIpoApplications", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const applications = await IpoApplicationModel.find({ userId }).sort({ appliedAt: -1 });
    res.status(200).json(applications);
  } catch (error) {
    console.error("Error fetching user IPO applications:", error);
    res.status(500).json({ error: "Failed to fetch IPO applications" });
  }
});

// 3. One-Click Email Action Endpoint (Approve / Decline from Gmail)
app.get("/ipoMandate/action", async (req, res) => {
  try {
    const { token, decision } = req.query;
    if (!token || !decision) {
      return res.status(400).send("<h3>Invalid or missing mandate action parameters.</h3>");
    }

    const application = await IpoApplicationModel.findOne({ mandateToken: token });
    if (!application) {
      return res.status(404).send(`
        <!DOCTYPE html>
        <html>
        <head><title>Mandate Expired</title><style>body { font-family: -apple-system, sans-serif; text-align: center; padding: 50px; background: #f8fafc; color: #1e293b; }</style></head>
        <body>
          <h2 style="color: #ef4444;">Mandate Link Invalid or Expired</h2>
          <p>We could not find an active IPO mandate associated with this authorization link.</p>
          <a href="${PUBLIC_FRONTEND_URL}/bids" style="display: inline-block; margin-top: 16px; padding: 10px 20px; background: #387ed1; color: #fff; text-decoration: none; border-radius: 4px;">Return to Zerodha Kite</a>
        </body>
        </html>
      `);
    }

    if (application.mandateStatus !== "PENDING_APPROVAL") {
      return res.send(`
        <!DOCTYPE html>
        <html>
        <head><title>Mandate Already Processed</title><style>body { font-family: -apple-system, sans-serif; text-align: center; padding: 50px; background: #f8fafc; color: #1e293b; }</style></head>
        <body>
          <h2>Mandate Already Processed</h2>
          <p>This mandate for <strong>${application.companyName}</strong> has already been marked as <strong>${application.mandateStatus}</strong>.</p>
          <a href="${PUBLIC_FRONTEND_URL}/bids" style="display: inline-block; margin-top: 16px; padding: 10px 20px; background: #387ed1; color: #fff; text-decoration: none; border-radius: 4px;">View in Zerodha Kite</a>
        </body>
        </html>
      `);
    }

    const isApprove = decision.toUpperCase() === "APPROVE";
    if (isApprove) {
      application.status = "APPLIED";
      application.mandateStatus = "ACCEPTED";
      application.mandateDecidedAt = new Date();
      await application.save();

      // Dispatch in-app notification
      try {
        await createNotification({
          userId: application.userId,
          type: "FUNDS",
          category: "IPO",
          title: `Mandate Approved - ${application.companyName}`,
          description: `UPI Mandate for ${application.companyName} (${application.lots} Lot, ₹${application.totalAmount.toLocaleString("en-IN")}) has been approved. Funds lien marked under ASBA.`,
          metadata: {
            symbol: application.ipoSymbol,
            amount: application.totalAmount,
            actionUrl: "/bids",
          },
        });
      } catch (e) {}

      return res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>UPI Mandate Approved - Zerodha Kite</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; margin: 0; padding: 40px 20px; color: #0f172a; text-align: center; }
            .receipt-card { max-width: 500px; margin: 0 auto; background: #fff; padding: 36px 28px; border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 10px 25px rgba(0,0,0,0.06); }
            .success-icon { width: 56px; height: 56px; line-height: 56px; border-radius: 50%; background: #dcfce7; color: #16a34a; font-size: 28px; margin: 0 auto 16px auto; }
            h2 { margin: 0 0 8px 0; color: #15803d; font-size: 22px; }
            p { color: #64748b; font-size: 14px; line-height: 1.5; margin: 0 0 24px 0; }
            .details-table { width: 100%; border-collapse: collapse; margin-bottom: 24px; text-align: left; font-size: 13px; }
            .details-table td { padding: 8px 12px; border-bottom: 1px solid #f1f5f9; }
            .details-table td.label { color: #64748b; }
            .details-table td.val { font-weight: 600; color: #0f172a; text-align: right; }
            .btn-return { display: inline-block; background: #387ed1; color: #fff; text-decoration: none; padding: 12px 28px; border-radius: 4px; font-weight: 500; font-size: 14px; }
            .btn-return:hover { background: #2b6cb0; }
          </style>
        </head>
        <body>
          <div class="receipt-card">
            <div class="success-icon">✓</div>
            <h2>UPI Mandate Approved!</h2>
            <p>Your UPI ASBA block for <strong>${application.companyName}</strong> has been successfully authorized and registered with the exchange.</p>
            <table class="details-table">
              <tr><td class="label">Application No.</td><td class="val">${application.applicationNumber}</td></tr>
              <tr><td class="label">Bid Quantity</td><td class="val">${application.lots} Lot (${application.totalQty} Shares)</td></tr>
              <tr><td class="label">Amount Blocked</td><td class="val">₹${application.totalAmount.toLocaleString("en-IN", { minimumFractionDigits: 2 })}</td></tr>
              <tr><td class="label">UPI ID</td><td class="val">${application.upiId}</td></tr>
              <tr><td class="label">Status</td><td class="val" style="color: #16a34a;">Lien Marked (Active)</td></tr>
            </table>
            <a href="${PUBLIC_FRONTEND_URL}/bids" class="btn-return">View in Zerodha Kite Dashboard &rsaquo;</a>
          </div>
        </body>
        </html>
      `);
    } else {
      application.status = "CANCELLED";
      application.mandateStatus = "REJECTED";
      application.mandateDecidedAt = new Date();
      await application.save();

      try {
        await createNotification({
          userId: application.userId,
          type: "COMPLIANCE",
          category: "IPO",
          title: `Mandate Declined - ${application.companyName}`,
          description: `UPI Mandate for ${application.companyName} was declined. Application #${application.applicationNumber} has been revoked.`,
          metadata: {
            symbol: application.ipoSymbol,
            actionUrl: "/bids",
          },
        });
      } catch (e) {}

      return res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Mandate Declined - Zerodha Kite</title>
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; margin: 0; padding: 40px 20px; color: #0f172a; text-align: center; }
            .receipt-card { max-width: 500px; margin: 0 auto; background: #fff; padding: 36px 28px; border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 10px 25px rgba(0,0,0,0.06); }
            .decline-icon { width: 56px; height: 56px; line-height: 56px; border-radius: 50%; background: #fee2e2; color: #dc2626; font-size: 28px; margin: 0 auto 16px auto; }
            h2 { margin: 0 0 8px 0; color: #dc2626; font-size: 22px; }
            p { color: #64748b; font-size: 14px; line-height: 1.5; margin: 0 0 24px 0; }
            .btn-return { display: inline-block; background: #64748b; color: #fff; text-decoration: none; padding: 12px 28px; border-radius: 4px; font-weight: 500; font-size: 14px; }
          </style>
        </head>
        <body>
          <div class="receipt-card">
            <div class="decline-icon">✕</div>
            <h2>UPI Mandate Declined</h2>
            <p>You have declined the UPI mandate for <strong>${application.companyName}</strong>. No funds have been blocked and your application has been cancelled.</p>
            <a href="${PUBLIC_FRONTEND_URL}/bids" class="btn-return">Return to Dashboard</a>
          </div>
        </body>
        </html>
      `);
    }
  } catch (error) {
    console.error("Error processing mandate decision:", error);
    res.status(500).send("<h3>Internal server error processing mandate decision.</h3>");
  }
});

// 4. Cancel / Revoke Submitted IPO Application
app.delete("/cancelIpoApplication/:id", async (req, res) => {
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
app.put("/modifyIpoBid/:id", async (req, res) => {
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

app.get("/allGsecs", async (req, res) => {
  res.status(200).json(curatedGsecs);
});

app.post("/applyGsecBid", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.body.userId;
    if (!userId) {
      return res.status(401).json({ success: false, message: "User authentication required" });
    }
    const { symbol, instrumentName, units, pricePerUnit, category, indicativeYield } = req.body;
    const numUnits = Math.max(1, parseInt(units) || 10);
    const numPrice = parseFloat(pricePerUnit) || 1000;
    const totalAmount = numUnits * numPrice;

    const bidNumber = `GSEC-${new Date().getFullYear()}-${symbol}-${Math.floor(10000 + Math.random() * 90000)}`;

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

app.get("/myGsecApplications", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.query.userId;
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

app.get("/allCorporateActions", async (req, res) => {
  res.status(200).json(curatedCorporateActions);
});

app.post("/tenderCorporateAction", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.body.userId;
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

    const tenderRef = `CORP-${new Date().getFullYear()}-${symbol}-${Math.floor(10000 + Math.random() * 90000)}`;

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

app.get("/myCorporateActionTenders", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.query.userId;
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

app.get("/allAuctions", async (req, res) => {
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

app.post("/submitAuctionOffer", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.body.userId;
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
    const orderId = `AUC-${new Date().getFullYear()}-${symbol}-${Math.floor(10000 + Math.random() * 90000)}`;

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

app.get("/myAuctionOffers", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.query.userId;
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

app.get("/allSseIpos", async (req, res) => {
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

app.post("/applySseIpo", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.body.userId;
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
    const asbaReference = `ASBA-SSE-${Math.floor(100000 + Math.random() * 900000)}`;

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

app.get("/mySseApplications", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.query.userId;
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
app.get("/marketSipsCatalog", async (req, res) => {
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
app.get("/allSips", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(200).json([]);
    }
    let sips = await SipModel.find({ userId }).sort({ createdAt: -1 });

    if (sips.length === 0) {
      // Seed with top real market SIPs (e.g. Nifty BeES and Reliance)
      const relianceMarket = marketSips50.find((m) => m.code === "SIP_RELIANCE");
      const niftyBeesMarket = marketSips50.find((m) => m.code === "SIP_NIFTYBEES");

      const seedSips = [];
      if (relianceMarket) {
        seedSips.push({
          userId,
          name: relianceMarket.name,
          sipType: "STOCK",
          symbol: "RELIANCE",
          instruments: relianceMarket.instruments,
          minAmount: relianceMarket.minAmount,
          frequency: "MONTHLY",
          scheduleDay: 5,
          scheduleTime: "09:30",
          status: "ACTIVE",
          nextTriggerAt: calculateNextTriggerDate("MONTHLY", 5, "09:30"),
          totalInstallmentsExecuted: 0,
          totalCapitalInvested: 0,
          executionLogs: [],
        });
      }
      if (niftyBeesMarket) {
        seedSips.push({
          userId,
          name: niftyBeesMarket.name,
          sipType: "ETF",
          symbol: "NIFTYBEES",
          instruments: niftyBeesMarket.instruments,
          minAmount: niftyBeesMarket.minAmount,
          frequency: "WEEKLY",
          scheduleDay: 1, // Monday
          scheduleTime: "09:30",
          status: "ACTIVE",
          nextTriggerAt: calculateNextTriggerDate("WEEKLY", 1, "09:30"),
          totalInstallmentsExecuted: 0,
          totalCapitalInvested: 0,
          executionLogs: [],
        });
      }

      if (seedSips.length > 0) {
        sips = await SipModel.insertMany(seedSips);
      }
    }

    res.status(200).json(sips);
  } catch (error) {
    console.error("Error fetching SIPs:", error);
    res.status(500).json({ error: "Failed to fetch SIPs" });
  }
});

// 2. Create New Stock SIP (Supports 50 Real Market SIPs directly without a basket!)
app.post("/createSip", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.body.userId;
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
    // Mode C: Legacy user basket
    else if (basketId) {
      const basket = await BasketModel.findById(basketId);
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
app.patch("/toggleSipStatus/:id", async (req, res) => {
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
app.patch("/updateSipName/:id", async (req, res) => {
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
app.post("/executeSipNow/:id", async (req, res) => {
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
      return res.status(400).json(result);
    }
    return res.status(200).json(result);
  } catch (error) {
    console.error("Error executing SIP:", error);
    return res.status(500).json({ success: false, message: error.message || "Failed to execute SIP" });
  }
});

// 6. Delete SIP
app.delete("/deleteSip/:id", async (req, res) => {
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

// 7. Background Heartbeat Worker for SIPs (Runs every 45s)
setInterval(async () => {
  try {
    const now = new Date();
    const dueSips = await SipModel.find({
      status: "ACTIVE",
      nextTriggerAt: { $lte: now },
    });

    for (const sip of dueSips) {
      console.log(`⏰ [SIP CRON TRIGGERED] Executing due SIP: "${sip.name}" (ID: ${sip._id})`);
      try {
        await executeSipInternal(sip._id);
      } catch (err) {
        console.error(`Error in automated SIP execution for ${sip.name}:`, err.message);
      }
    }
  } catch (e) {}
}, 45000);


// ============================================================================
// REAL-TIME PRICE ALERTS (SENTINEL ENGINE) ROUTES & EVALUATION WORKER
// ============================================================================

// 1. Fetch user alerts with dynamic live LTP & proximity calculations
app.get("/alerts", async (req, res) => {
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
app.post("/createAlert", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req) || req.body.userId;
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
app.put("/updateAlert/:id", async (req, res) => {
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
app.patch("/toggleAlertStatus/:id", async (req, res) => {
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
app.post("/resetAlert/:id", async (req, res) => {
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
app.delete("/deleteAlert/:id", async (req, res) => {
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

setInterval(evaluatePriceAlerts, 15000);



// ============================================================================
// 8. SEGMENT SETTINGS & KILL SWITCH SUBSYSTEM (SEBI / ZERODHA RISK CONTROLS)
// ============================================================================

app.get("/userSegments", async (req, res) => {
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

app.post("/updateSegments", async (req, res) => {
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
app.post("/sendSegmentOtp", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const user = await UserModel.findOne({ userId });
    const userEmail = user?.email || req.body.email;
    if (!userEmail) {
      return res.status(400).json({ success: false, message: "No registered email address found for this user account." });
    }
    const segmentKey = req.body.segmentKey;

    const generatedOtp = crypto.randomInt(100000, 1000000).toString();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await OtpModel.findOneAndUpdate(
      { email: userEmail.toLowerCase() },
      {
        otp: generatedOtp,
        attempts: 0,
        expiresAt,
        createdAt: new Date(),
      },
      { upsert: true, returnDocument: "after", setDefaultsOnInsert: true }
    );

    const emailResult = await sendOtpEmail(userEmail, generatedOtp);
    res.status(200).json({
      success: true,
      message: `Verification OTP sent to ${userEmail}`,
      isLiveEmail: emailResult.delivered,
      devOtp: emailResult.delivered ? undefined : generatedOtp,
    });
  } catch (err) {
    console.error("Error sending segment OTP:", err);
    res.status(500).json({ success: false, message: "Failed to send verification code" });
  }
});

app.post("/verifySegmentOtp", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const user = await UserModel.findOne({ userId });
    const userEmail = (user?.email || req.body.email || "").toLowerCase();
    const { otp, segmentKey, annualIncome } = req.body;

    const otpRecord = await OtpModel.findOne({ email: userEmail });
    if (!otpRecord) {
      return res.status(400).json({ success: false, message: "No OTP found or expired. Please request a new code." });
    }
    if (new Date() > otpRecord.expiresAt) {
      return res.status(400).json({ success: false, message: "OTP has expired. Please request a new one." });
    }
    if (otpRecord.otp !== otp?.toString().trim()) {
      return res.status(400).json({ success: false, message: "Invalid verification code entered." });
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

app.post("/cdsl/generate-tpin", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "User authentication required" });
    }
    const user = await UserModel.findOne({ userId });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const generatedTpin = crypto.randomInt(100000, 1000000).toString();
    user.cdslTpin = generatedTpin;
    await user.save();

    const toEmail = user.email;
    if (!toEmail) {
      return res.status(400).json({ success: false, message: "No registered email found for this user account. Please update your profile email." });
    }
    const emailResult = await sendCdslTpinEmail(toEmail, generatedTpin, user.demat);

    console.log(`🔐 [CDSL TPIN DISPATCHED] TPIN for user ${userId} (${toEmail}): ${generatedTpin}`);

    res.status(200).json({
      success: true,
      message: `Your 6-digit CDSL TPIN has been sent to ${toEmail}`,
      isLiveEmail: emailResult.delivered,
      devTpin: emailResult.delivered ? undefined : generatedTpin,
    });
  } catch (err) {
    console.error("Error generating CDSL TPIN:", err);
    res.status(500).json({ success: false, message: "Failed to dispatch CDSL TPIN" });
  }
});

app.post("/cdsl/verify-tpin", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "User authentication required" });
    }
    const { tpin, stockName, stockQty } = req.body;
    const user = await UserModel.findOne({ userId });
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (!user.cdslTpin) {
      return res.status(400).json({
        success: false,
        message: "No CDSL TPIN found for this account. Please click 'Generate New TPIN' to receive one on your registered email.",
      });
    }

    if (tpin !== user.cdslTpin) {
      return res.status(400).json({
        success: false,
        message: "Invalid CDSL TPIN entered. Please check the code sent to your registered email.",
      });
    }

    // TPIN is valid -> Generate Transaction OTP
    const generatedOtp = crypto.randomInt(100000, 1000000).toString();
    const toEmail = (user.email || "").toLowerCase();
    if (!toEmail) {
      return res.status(400).json({ success: false, message: "No registered email address found for this user account." });
    }

    // Store in OtpModel with cdsl identifier
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

    console.log(`🔐 [CDSL OTP DISPATCHED] Transaction OTP for ${userId} (${toEmail}): ${generatedOtp}`);

    res.status(200).json({
      success: true,
      message: `Transaction OTP sent to ${toEmail}`,
      isLiveEmail: emailResult.delivered,
      devOtp: emailResult.delivered ? undefined : generatedOtp,
    });
  } catch (err) {
    console.error("Error verifying CDSL TPIN:", err);
    res.status(500).json({ success: false, message: "Failed to verify TPIN" });
  }
});

app.post("/cdsl/verify-otp", async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    if (!userId) {
      return res.status(401).json({ success: false, message: "User authentication required" });
    }
    const { otp, stockName } = req.body;
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
      return res.status(400).json({
        success: false,
        message: "CDSL transaction OTP has expired. Please request a new code.",
      });
    }

    if (otpRecord.otp !== otp?.toString().trim()) {
      return res.status(400).json({
        success: false,
        message: "Invalid transaction OTP entered. Please check the code sent to your email.",
      });
    }

    await OtpModel.deleteOne({ _id: otpRecord._id });

    // In-App Notification
    try {
      await createNotification({
        userId,
        type: "ORDER",
        category: "SYSTEM",
        title: "CDSL Demat Authorized",
        description: `Demat account authorized via CDSL E-DIS for exit transactions today until 3:30 PM.`,
        metadata: { actionUrl: "/holdings" },
      });
    } catch (e) {}

    res.status(200).json({
      success: true,
      message: "Demat holdings authorized successfully! Valid until 3:30 PM today.",
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
app.post("/createSupportTicket", tradeFundsLimiter, async (req, res) => {
  try {
    const userId = getAuthenticatedUserId(req);
    const {
      userName = "Trader",
      userEmail = "",
      category = "ORDERS",
      categoryLabel,
      subject,
      description,
      priority = "NORMAL",
    } = req.body;

    if (!userId) {
      return res.status(401).json({ success: false, message: "Authentication required" });
    }
    if (!subject || !subject.trim()) {
      return res.status(400).json({ success: false, message: "Subject is required" });
    }
    if (!description || !description.trim()) {
      return res.status(400).json({ success: false, message: "Description is required" });
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
    const randomNum = Math.floor(100000 + Math.random() * 900000);
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
app.get("/mySupportTickets", async (req, res) => {
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
  if (err && typeof err.message === "string" && err.message.startsWith("CORS origin blocked")) {
    return res.status(403).json({ success: false, message: "Origin not allowed by CORS policy" });
  }
  return res.status(err?.status || 500).json({
    success: false,
    message: process.env.NODE_ENV === "production" ? "Internal server error" : err?.message || "Internal server error",
  });
});

app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}!`);
});
