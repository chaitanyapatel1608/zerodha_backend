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
const { UserModel } = require("./model/UserModel");
const { OtpModel } = require("./model/OtpModel");
const { sendOtpEmail } = require("./utils/emailService");

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

app.post("/newOrder", async (req, res) => {
  try {
    const { name, qty, price, mode, product } = req.body;
    const newOrder = new OrdersModel({
      name,
      qty: Number(qty),
      price: Number(price),
      mode: mode || "BUY",
      product: product || "CNC",
    });

    const savedOrder = await newOrder.save();
    console.log("New order saved to MongoDB:", savedOrder);
    res.status(201).json({ message: "Order placed successfully!", order: savedOrder });
  } catch (error) {
    console.error("Error creating order:", error);
    res.status(500).json({ error: "Failed to place order" });
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

app.get("/userFunds", async (req, res) => {
  try {
    let funds = await FundsModel.findOne({ userId: "ZU8842" });
    if (!funds) {
      funds = await FundsModel.findOne({});
    }
    res.status(200).json(funds);
  } catch (error) {
    console.error("Error fetching funds:", error);
    res.status(500).json({ error: "Failed to fetch user funds" });
  }
});

app.get("/allIpos", async (req, res) => {
  try {
    const allIpos = await IpoModel.find({});
    res.status(200).json(allIpos);
  } catch (error) {
    console.error("Error fetching IPOs:", error);
    res.status(500).json({ error: "Failed to fetch IPOs" });
  }
});

app.listen(PORT, () => {
  console.log(`Backend server running on port ${PORT}!`);
});
