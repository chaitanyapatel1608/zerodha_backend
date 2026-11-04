const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, ".env") });
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");

const { HoldingsModel } = require("./model/HoldingsModel");
const { PositionsModel } = require("./model/PositionsModel");
const { OrdersModel } = require("./model/OrdersModel");
const { WatchlistModel } = require("./model/WatchlistModel");
const { FundsModel } = require("./model/FundsModel");
const { IpoModel } = require("./model/IpoModel");
const { IpoApplicationModel } = require("./model/IpoApplicationModel");
const { UserModel } = require("./model/UserModel");
const { GttModel } = require("./model/GttModel");
const { BasketModel } = require("./model/BasketModel");
const { UserWatchlistModel } = require("./model/UserWatchlistModel");
const { NotificationModel } = require("./model/NotificationModel");
const { masterInstruments } = require("./data/masterInstruments");
const { OtpModel } = require("./model/OtpModel");
const { sendOtpEmail, sendIpoMandateEmail } = require("./utils/emailService");
const { ipoData50 } = require("./data/ipoData50");

const app = express();
const PORT = process.env.PORT || 3002;
const uri = process.env.MONGO_URL;
const JWT_SECRET = process.env.JWT_SECRET || "zerodha_jwt_super_secret_key_2026_finance_kite";

// Middlewares
app.use(cors());
app.use(bodyParser.json());

// Rate Limiter for OTP requests (15 requests per 10 minutes per IP)
const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 15,
  message: { success: false, message: "Too many OTP requests. Please wait a few minutes before trying again." },
  standardHeaders: true,
  legacyHeaders: false,
});

// MongoDB Connection
mongoose
  .connect(uri)
  .then(() => console.log("DB connected successfully!"))
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
          { userId: { $regex: new RegExp(`^${cleanId}$`, "i") } },
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
      devOtp: emailResult.delivered ? undefined : generatedOtp,
    });
  } catch (error) {
    console.error("Error sending OTP:", error);
    return res.status(500).json({ success: false, message: "Internal server error while dispatching OTP" });
  }
});

// 2. Verify OTP Endpoint (Unified Signup & Login)
app.post("/verify-otp", async (req, res) => {
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
app.post("/kite-login", async (req, res) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !identifier.trim()) {
      return res.status(400).json({ success: false, message: "User ID, Phone number, or Email is required" });
    }
    const cleanId = identifier.trim();
    const user = await UserModel.findOne({
      $or: [
        { userId: { $regex: new RegExp(`^${cleanId}$`, "i") } },
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
      if (user.password !== password) {
        return res.status(401).json({ success: false, message: "Incorrect password. Please try again." });
      }
    } else if (password && !user.password) {
      user.password = password;
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
app.get("/verifyUser", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ success: false, message: "Access token missing or malformed" });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await UserModel.findOne({ userId: decoded.userId }).select("-__v");
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
        demat: user.demat || "1208160012345678",
        annualIncome: user.annualIncome || "₹1L - ₹5L",
        tradingExp: user.tradingExp || "1-3 Years",
        broker: user.broker || "Zerodha Broking Ltd.",
        avatarText: user.avatarText,
        role: user.role,
      },
    });
  } catch (error) {
    return res.status(401).json({ success: false, message: "Invalid or expired token" });
  }
});

// ==========================================
// Core Trading & Market Data Routes
// ==========================================

app.get("/allHoldings", async (req, res) => {
  try {
    const allHoldings = await HoldingsModel.find({});
    res.status(200).json(allHoldings);
  } catch (error) {
    console.error("Error fetching holdings:", error);
    res.status(500).json({ error: "Failed to fetch holdings" });
  }
});

app.get("/allPositions", async (req, res) => {
  try {
    const allPositions = await PositionsModel.find({});
    res.status(200).json(allPositions);
  } catch (error) {
    console.error("Error fetching positions:", error);
    res.status(500).json({ error: "Failed to fetch positions" });
  }
});

app.get("/allOrders", async (req, res) => {
  try {
    const allOrders = await OrdersModel.find({}).sort({ createdAt: -1 });
    res.status(200).json(allOrders);
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Failed to fetch orders" });
  }
});


// Dynamic Real-Time Notification Dispatcher
async function createNotification({
  userId = "ZU9344",
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

// Unified Order Execution Helper
async function executeOrderInternal({ name, qty, price, mode = "BUY", product = "CNC", userId = "ZU9344" }) {
  const numQty = Number(qty);
  const numPrice = Number(price);

  if (!name || isNaN(numQty) || numQty <= 0 || isNaN(numPrice) || numPrice <= 0) {
    return { success: false, message: "Valid instrument name, positive quantity, and price are required." };
  }

  const orderMode = mode.toUpperCase();
  const orderProduct = product.toUpperCase();
  const orderCost = numQty * numPrice;
  const marginRequired = orderProduct === "MIS" ? orderCost * 0.2 : orderCost;

  let funds = await FundsModel.findOne({ userId });
  if (!funds) funds = await FundsModel.findOne({});
  if (!funds) {
    funds = new FundsModel({
      userId,
      equity: {
        availableMargin: "1,24,500.00",
        usedMargin: "0.00",
        availableCash: "1,24,500.00",
        openingBalance: "1,24,500.00",
      },
    });
    await funds.save();
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
        $or: [{ name }, { instrument: name }],
        product: "MIS",
      });

      if (existingPosition) {
        const totalShares = existingPosition.qty + numQty;
        const totalCost = existingPosition.qty * (existingPosition.avg || existingPosition.price) + numQty * numPrice;
        existingPosition.avg = Number((totalCost / totalShares).toFixed(2));
        existingPosition.qty = totalShares;
        existingPosition.price = numPrice;
        existingPosition.ltp = numPrice;
        await existingPosition.save();
      } else {
        const newPosition = new PositionsModel({
          userId,
          product: "MIS",
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
        });
        await newPosition.save();
      }
    }
  } else if (orderMode === "SELL") {
    if (orderProduct === "CNC") {
      let existingHolding = await HoldingsModel.findOne({
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
        $or: [{ name }, { instrument: name }],
        product: "MIS",
      });

      if (existingPosition) {
        existingPosition.qty = Math.max(0, existingPosition.qty - numQty);
        if (existingPosition.qty === 0) {
          await PositionsModel.deleteOne({ _id: existingPosition._id });
        } else {
          await existingPosition.save();
        }
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
app.post("/newOrder", async (req, res) => {
  try {
    const { name, qty, price, mode = "BUY", product = "CNC", userId = "ZU9344" } = req.body;
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

// GET /masterInstruments - Omnisearch across catalog
app.get("/masterInstruments", (req, res) => {
  try {
    const q = (req.query.q || "").trim().toLowerCase();
    const sector = (req.query.sector || "").trim().toLowerCase();
    const limit = parseInt(req.query.limit) || 50;

    let results = masterInstruments;
    if (sector) {
      results = results.filter((item) => (item.sector || "").toLowerCase() === sector);
    }
    if (q) {
      results = results.filter((item) => {
        const sym = (item.symbol || "").toLowerCase();
        const nm = (item.name || "").toLowerCase();
        return sym.includes(q) || nm.includes(q);
      });
    }

    return res.status(200).json(results.slice(0, limit));
  } catch (error) {
    console.error("Error searching master instruments:", error);
    return res.status(500).json({ error: "Failed to search master instruments" });
  }
});

// GET /userWatchlistTabs - Get all 7 tabs metadata (id, name, stock count)
app.get("/userWatchlistTabs", async (req, res) => {
  try {
    const userId = req.query.userId || "ZU9344";
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
    const userId = req.query.userId || "ZU9344";
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
    const { userId = "ZU9344", tabId = 1, stock } = req.body;
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
    const { userId = "ZU9344", tabId = 1, symbol } = req.body;
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
    const { userId = "ZU9344", tabId = 1, tabName } = req.body;
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
    const userId = req.query.userId;
    let funds = null;
    if (userId) {
      funds = await FundsModel.findOne({ userId });
    }
    if (!funds) {
      funds = await FundsModel.findOne({});
    }
    if (!funds) {
      funds = new FundsModel({
        userId: userId || "ZU9344",
        equity: {
          availableMargin: "1,24,500.00",
          usedMargin: "42,180.00",
          availableCash: "1,24,500.00",
          openingBalance: "1,66,680.00",
        },
      });
      await funds.save();
    }
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
    const { userId, nominees, optOut } = req.body;

    if (!userId) {
      return res.status(400).json({ success: false, message: "User ID is required." });
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
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ success: false, message: "User ID is required" });
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
    const userId = req.query.userId || "ZU9344";
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
      userId = "ZU9344",
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
    const { id } = req.body;
    if (!id) {
      return res.status(400).json({ success: false, message: "GTT ID required" });
    }
    const updated = await GttModel.findByIdAndUpdate(
      id,
      { status: "CANCELLED" },
      { new: true }
    );
    res.status(200).json({ success: true, message: "GTT order cancelled", gtt: updated });
  } catch (error) {
    console.error("Error cancelling GTT:", error);
    res.status(500).json({ success: false, message: "Internal server error cancelling GTT" });
  }
});

app.post("/triggerGtt", async (req, res) => {
  try {
    const { id } = req.body;
    const gtt = await GttModel.findById(id);
    if (!gtt || gtt.status !== "ACTIVE") {
      return res.status(400).json({ success: false, message: "GTT not found or already triggered" });
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

app.get("/allBaskets", async (req, res) => {
  try {
    const userId = req.query.userId || "ZU9344";
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
    const { id, userId = "ZU9344", name, items = [] } = req.body;
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
    const { id } = req.params;
    await BasketModel.findByIdAndDelete(id);
    res.status(200).json({ success: true, message: "Basket deleted successfully" });
  } catch (error) {
    console.error("Error deleting basket:", error);
    res.status(500).json({ success: false, message: "Internal server error deleting basket" });
  }
});

app.post("/executeBasket", async (req, res) => {
  try {
    const { userId = "ZU9344", items = [], basketName = "Basket" } = req.body;
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
    let funds = await FundsModel.findOne({ userId });
    if (!funds) funds = await FundsModel.findOne({});
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
    const userId = req.query.userId || "ZU9344";
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
    const userId = req.query.userId || "ZU9344";
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
    const userId = req.body.userId || "ZU9344";
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
    const userId = req.body.userId || "ZU9344";
    await NotificationModel.deleteMany({ userId });
    res.status(200).json({ success: true, message: "All notifications cleared." });
  } catch (error) {
    console.error("Error clearing notifications:", error);
    res.status(500).json({ success: false, error: "Failed to clear notifications" });
  }
});

// 7. Dynamic Funds deposit endpoint with automatic ledger & notification synchronization
app.post("/addFunds", async (req, res) => {
  try {
    const { userId = "ZU9344", amount = 10000, method = "UPI" } = req.body;
    let funds = await FundsModel.findOne({ userId });
    if (!funds) funds = await FundsModel.findOne({});
    if (!funds) {
      funds = new FundsModel({ userId });
    }
    const numAmount = parseFloat(amount);
    let currentAvailable = parseFloat(funds.equity.availableMargin.replace(/,/g, "")) || 0;
    currentAvailable += numAmount;
    funds.equity.availableMargin = formatIndianCurrency(currentAvailable);
    funds.equity.availableCash = formatIndianCurrency(currentAvailable);
    await funds.save();

    const refId = "UPI" + Math.floor(10000000000 + Math.random() * 90000000000);
    await createNotification({
      userId,
      type: "FUNDS",
      category: "MARGIN",
      title: "Funds Credited",
      description: `₹${formatIndianCurrency(numAmount)} added via ${method} (Ref: ${refId}). Margin updated.`,
      metadata: {
        amount: numAmount,
        referenceId: refId,
        actionUrl: "/funds",
      },
    });

    res.status(200).json({
      success: true,
      message: `₹${formatIndianCurrency(numAmount)} deposited successfully.`,
      funds: funds.equity,
    });
  } catch (err) {
    console.error("Add funds error:", err);
    res.status(500).json({ success: false, message: "Failed to add funds" });
  }
});

// 8. Test notification trigger (for rapid dev testing / simulation)
app.post("/notifications/test", async (req, res) => {
  try {
    const { userId = "ZU9344", type = "ORDER", title, description, metadata } = req.body;
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
    const {
      userId = "ZU9344",
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

    const approveUrl = `http://localhost:3002/ipoMandate/action?token=${mandateToken}&decision=APPROVE`;
    const declineUrl = `http://localhost:3002/ipoMandate/action?token=${mandateToken}&decision=REJECT`;

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
    const userId = req.query.userId || "ZU9344";
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
          <a href="http://localhost:3001/bids" style="display: inline-block; margin-top: 16px; padding: 10px 20px; background: #387ed1; color: #fff; text-decoration: none; border-radius: 4px;">Return to Zerodha Kite</a>
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
          <a href="http://localhost:3001/bids" style="display: inline-block; margin-top: 16px; padding: 10px 20px; background: #387ed1; color: #fff; text-decoration: none; border-radius: 4px;">View in Zerodha Kite</a>
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
            <a href="http://localhost:3001/bids" class="btn-return">View in Zerodha Kite Dashboard &rsaquo;</a>
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
            <a href="http://localhost:3001/bids" class="btn-return">Return to Dashboard</a>
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
    const { id } = req.params;
    const appDoc = await IpoApplicationModel.findByIdAndUpdate(
      id,
      { status: "CANCELLED", mandateStatus: "REJECTED" },
      { new: true }
    );
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


app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}!`);
});
