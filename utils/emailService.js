const nodemailer = require("nodemailer");

/**
 * Sends a branded Zerodha Kite OTP email to the user.
 * Supports Gmail App Passwords, Custom SMTP, or falls back gracefully to console delivery.
 */
async function sendOtpEmail(toEmail, otp) {
  const emailUser = process.env.EMAIL_USER;
  const emailPass = process.env.EMAIL_PASS;

  if (!emailUser || !emailPass) {
    console.log(
      `⚠️ [EMAIL SERVICE] EMAIL_USER / EMAIL_PASS not set in backend/.env. Simulated OTP for ${toEmail}: ${otp}`
    );
    return {
      delivered: false,
      reason: "CREDENTIALS_NOT_CONFIGURED",
      devOtp: otp,
    };
  }

  try {
    const transporter = nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE || "gmail",
      auth: {
        user: emailUser,
        pass: emailPass,
      },
    });

    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f7f9fc; margin: 0; padding: 20px; color: #424242; }
          .container { max-width: 500px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #e0e0e0; overflow: hidden; }
          .header { background: #ffffff; padding: 24px; text-align: center; border-bottom: 1px solid #f0f0f0; }
          .content { padding: 32px 24px; text-align: center; }
          .otp-box { display: inline-block; background: #f0f7ff; border: 2px dashed #387ed1; border-radius: 8px; padding: 14px 28px; font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #387ed1; margin: 24px 0; }
          .footer { background: #fafafa; padding: 16px 24px; font-size: 12px; color: #888888; text-align: center; border-top: 1px solid #f0f0f0; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h2 style="color: #387ed1; margin: 0; font-weight: 700; letter-spacing: 1px;">ZERODHA</h2>
          </div>
          <div class="content">
            <h3 style="margin-top: 0; color: #222;">Login / Signup Verification</h3>
            <p style="color: #666; font-size: 14px; line-height: 1.6;">
              Please use the verification code below to complete your login or registration on Zerodha Kite.
            </p>
            <div class="otp-box">${otp}</div>
            <p style="color: #999; font-size: 13px; margin-bottom: 0;">
              This OTP is valid for <strong>5 minutes</strong>. Do not share this code with anyone.
            </p>
          </div>
          <div class="footer">
            If you did not request this verification code, please ignore this email.<br>
            Zerodha Broking Limited • Bengaluru, India
          </div>
        </div>
      </body>
      </html>
    `;

    const info = await transporter.sendMail({
      from: `"Zerodha Kite" <${emailUser}>`,
      to: toEmail,
      subject: `${otp} is your Zerodha verification code`,
      text: `Your Zerodha verification code is ${otp}. Valid for 5 minutes.`,
      html: htmlContent,
    });

    console.log(`✉️ [LIVE EMAIL DELIVERED] OTP sent to ${toEmail} (MessageId: ${info.messageId})`);
    return {
      delivered: true,
      messageId: info.messageId,
    };
  } catch (error) {
    console.error(`❌ [EMAIL DELIVERY FAILED] Could not send email to ${toEmail}:`, error.message);
    return {
      delivered: false,
      reason: error.message,
      devOtp: otp,
    };
  }
}

/**
 * Sends a real-time interactive UPI Mandate Authorization email for IPO applications.
 * Includes one-click [Approve] and [Decline] links with secure tokens.
 */
async function sendIpoMandateEmail({
  toEmail,
  companyName,
  ipoSymbol,
  applicationNumber,
  lots,
  totalQty,
  bidPrice,
  totalAmount,
  upiId,
  category = "INDIVIDUAL",
  dematBoId = "1208160081236464",
  approveUrl,
  declineUrl,
}) {
  const emailUser = process.env.EMAIL_USER;
  const emailPass = process.env.EMAIL_PASS;

  if (!emailUser || !emailPass) {
    console.log(
      `⚠️ [EMAIL SERVICE] EMAIL_USER / EMAIL_PASS not set. Simulated IPO Mandate for ${toEmail}: ${companyName} (${totalAmount})`
    );
    return {
      delivered: false,
      reason: "CREDENTIALS_NOT_CONFIGURED",
      approveUrl,
      declineUrl,
    };
  }

  try {
    const transporter = nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE || "gmail",
      auth: {
        user: emailUser,
        pass: emailPass,
      },
    });

    const formattedAmount = Number(totalAmount).toLocaleString("en-IN", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    });

    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Authorize IPO UPI Mandate</title>
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f1f5f9; margin: 0; padding: 24px; color: #1e293b; }
          .container { max-width: 540px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.06); }
          .header { background: #ffffff; padding: 24px; text-align: center; border-bottom: 2px solid #387ed1; }
          .header-brand { font-size: 22px; font-weight: 700; color: #387ed1; letter-spacing: 1px; margin: 0; }
          .header-tag { font-size: 11px; text-transform: uppercase; letter-spacing: 1.5px; color: #64748b; margin-top: 4px; font-weight: 600; }
          .content { padding: 28px 24px; }
          .alert-banner { background: #eff6ff; border-left: 4px solid #387ed1; padding: 12px 16px; border-radius: 4px; margin-bottom: 24px; }
          .alert-banner p { margin: 0; font-size: 13px; color: #1e40af; line-height: 1.5; }
          .summary-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 18px; margin-bottom: 24px; }
          .summary-title { font-size: 18px; font-weight: 700; color: #0f172a; margin: 0 0 14px 0; }
          .summary-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #e2e8f0; font-size: 13px; }
          .summary-row:last-child { border-bottom: none; }
          .summary-label { color: #64748b; }
          .summary-value { font-weight: 600; color: #0f172a; text-align: right; }
          .amount-highlight { background: #ecfdf5; border: 1px solid #a7f3d0; border-radius: 6px; padding: 14px; text-align: center; margin-bottom: 28px; }
          .amount-label { font-size: 11px; text-transform: uppercase; color: #047857; font-weight: 600; letter-spacing: 0.5px; }
          .amount-value { font-size: 28px; font-weight: 700; color: #065f46; margin: 4px 0 0 0; }
          .action-buttons-wrap { text-align: center; margin: 28px 0 12px 0; }
          .btn { display: inline-block; padding: 14px 28px; font-size: 14px; font-weight: 600; text-decoration: none; border-radius: 5px; transition: background 0.15s ease; margin: 6px 8px; }
          .btn-approve { background-color: #16a34a; color: #ffffff !important; box-shadow: 0 2px 6px rgba(22, 163, 74, 0.35); }
          .btn-decline { background-color: #ffffff; color: #dc2626 !important; border: 1px solid #fca5a5; }
          .info-note { font-size: 11.5px; color: #64748b; line-height: 1.5; margin-top: 20px; text-align: center; padding: 0 12px; }
          .footer { background: #fafafa; padding: 18px 24px; font-size: 11.5px; color: #94a3b8; text-align: center; border-top: 1px solid #e2e8f0; line-height: 1.6; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1 class="header-brand">ZERODHA</h1>
            <div class="header-tag">SEBI ASBA &bull; UPI 2.0 Mandate Authorization</div>
          </div>
          <div class="content">
            <div class="alert-banner">
              <p>
                <strong>Action Required:</strong> A UPI Mandate request has been initiated for your IPO bid on <strong>${companyName}</strong>. Please authorize or decline the blocking request below.
              </p>
            </div>

            <div class="summary-card">
              <div class="summary-title">${companyName} (${ipoSymbol})</div>
              <div class="summary-row">
                <span class="summary-label">Application Number</span>
                <span class="summary-value" style="font-family: monospace; font-size: 13px;">${applicationNumber}</span>
              </div>
              <div class="summary-row">
                <span class="summary-label">Investor Category</span>
                <span class="summary-value">${category === "HNI" ? "Non-Institutional (HNI)" : "Individual (Retail)"}</span>
              </div>
              <div class="summary-row">
                <span class="summary-label">Bid Lots</span>
                <span class="summary-value">${lots} Lot (${totalQty} Shares)</span>
              </div>
              <div class="summary-row">
                <span class="summary-label">Bid Price</span>
                <span class="summary-value">₹${Number(bidPrice).toFixed(2)} (Cut-off)</span>
              </div>
              <div class="summary-row">
                <span class="summary-label">CDSL Demat BO ID</span>
                <span class="summary-value" style="font-family: monospace;">${dematBoId}</span>
              </div>
              <div class="summary-row">
                <span class="summary-label">UPI ID</span>
                <span class="summary-value">${upiId}</span>
              </div>
            </div>

            <div class="amount-highlight">
              <div class="amount-label">Amount to Block under ASBA</div>
              <div class="amount-value">₹${formattedAmount}</div>
            </div>

            <div class="action-buttons-wrap">
              <a href="${approveUrl}" class="btn btn-approve">
                ✓ Approve UPI Mandate
              </a>
              <a href="${declineUrl}" class="btn btn-decline">
                ✕ Decline Mandate
              </a>
            </div>

            <p class="info-note">
              <strong>ASBA Safety Guarantee:</strong> Funds remain in your bank account and earn interest. They are only held as a lien and will never be debited unless shares are successfully allotted to you.
            </p>
          </div>

          <div class="footer">
            Zerodha Broking Ltd. &bull; SEBI Registration No.: INZ000031633 &bull; CDSL DP ID: 12081600<br>
            If you did not submit this IPO bid, please decline this mandate immediately.
          </div>
        </div>
      </body>
      </html>
    `;

    const info = await transporter.sendMail({
      from: `"Zerodha Kite" <${emailUser}>`,
      to: toEmail,
      subject: `Action Required: Authorize UPI Mandate for ${companyName} (${applicationNumber})`,
      text: `Action Required: Authorize UPI Mandate of ₹${formattedAmount} for ${companyName} (${applicationNumber}). Approve here: ${approveUrl} or Decline here: ${declineUrl}`,
      html: htmlContent,
    });

    console.log(
      `✉️ [LIVE IPO MANDATE EMAIL SENT] Sent to ${toEmail} for ${companyName} (MessageId: ${info.messageId})`
    );
    return {
      delivered: true,
      messageId: info.messageId,
    };
  } catch (error) {
    console.error(
      `❌ [EMAIL DELIVERY FAILED] Could not send IPO mandate email to ${toEmail}:`,
      error.message
    );
    return {
      delivered: false,
      reason: error.message,
    };
  }
}

module.exports = { sendOtpEmail, sendIpoMandateEmail };
