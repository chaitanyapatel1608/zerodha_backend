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

/**
 * Sends an email notification when a Stock SIP execution fails due to insufficient margin.
 */
async function sendSipFailureEmail({
  toEmail,
  sipName,
  basketName,
  requiredAmount,
  availableAmount,
  nextDate,
}) {
  const emailUser = process.env.EMAIL_USER;
  const emailPass = process.env.EMAIL_PASS;

  if (!emailUser || !emailPass) {
    console.log(
      `⚠️ [EMAIL SERVICE] EMAIL_USER / EMAIL_PASS not set. Simulated SIP failure alert for ${toEmail}: ${sipName}`
    );
    return { delivered: false, reason: "CREDENTIALS_NOT_CONFIGURED" };
  }

  try {
    const transporter = nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE || "gmail",
      auth: { user: emailUser, pass: emailPass },
    });

    const formattedReq = Number(requiredAmount).toLocaleString("en-IN", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    });
    const formattedAvail = Number(availableAmount).toLocaleString("en-IN", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    });

    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f7f9fc; margin: 0; padding: 24px; color: #1e293b; }
          .container { max-width: 520px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
          .header { background: #ffffff; padding: 20px 24px; border-bottom: 1px solid #f1f5f9; display: flex; align-items: center; justify-content: space-between; }
          .badge-alert { background: #fee2e2; color: #dc2626; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
          .content { padding: 28px 24px; }
          .alert-title { margin: 0 0 10px 0; color: #0f172a; font-size: 18px; font-weight: 600; }
          .alert-desc { color: #64748b; font-size: 14px; line-height: 1.5; margin: 0 0 20px 0; }
          .details-card { background: #fafafa; border: 1px solid #f1f5f9; border-radius: 6px; padding: 16px; margin-bottom: 24px; }
          .row { display: flex; justify-content: space-between; padding: 6px 0; font-size: 13px; }
          .row .label { color: #64748b; }
          .row .value { font-weight: 600; color: #0f172a; text-align: right; }
          .row .danger { color: #dc2626; }
          .btn-deposit { display: inline-block; background: #387ed1; color: #ffffff !important; padding: 12px 24px; border-radius: 4px; text-decoration: none; font-size: 14px; font-weight: 500; text-align: center; }
          .footer { background: #fafafa; padding: 16px 24px; font-size: 11px; color: #94a3b8; border-top: 1px solid #f1f5f9; text-align: center; line-height: 1.5; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h2 style="color: #387ed1; margin: 0; font-weight: 700; letter-spacing: 1px; font-size: 20px;">ZERODHA</h2>
            <span class="badge-alert">Margin Shortfall</span>
          </div>
          <div class="content">
            <h3 class="alert-title">Stock SIP Execution Skipped</h3>
            <p class="alert-desc">
              Your scheduled Stock SIP <strong>${sipName}</strong> could not be executed today because your equity account had insufficient available margin. Per broker risk guidelines, your SIP remains <strong>Active</strong> and has not been cancelled.
            </p>
            <div class="details-card">
              <div class="row"><span class="label">SIP Name:</span><span class="value">${sipName}</span></div>
              <div class="row"><span class="label">Linked Basket:</span><span class="value">${basketName}</span></div>
              <div class="row"><span class="label">Required Funds:</span><span class="value danger">₹${formattedReq}</span></div>
              <div class="row"><span class="label">Available Margin:</span><span class="value">₹${formattedAvail}</span></div>
              <div class="row"><span class="label">Next Scheduled Trigger:</span><span class="value">${nextDate}</span></div>
            </div>
            <div style="text-align: center; margin-top: 24px;">
              <a href="http://localhost:3001/funds" class="btn-deposit">Add Funds to Equity Margin &rarr;</a>
            </div>
          </div>
          <div class="footer">
            Zerodha Broking Ltd. &bull; SEBI Registration No.: INZ000031633 &bull; NSE / BSE / MCX<br>
            Please ensure adequate cash margin is maintained in your account prior to your next SIP trigger date.
          </div>
        </div>
      </body>
      </html>
    `;

    const info = await transporter.sendMail({
      from: `"Zerodha Kite" <${emailUser}>`,
      to: toEmail,
      subject: `Alert: Stock SIP Skipped due to Insufficient Margin (${sipName})`,
      text: `Alert: Stock SIP ${sipName} skipped. Required margin: ₹${formattedReq}, available: ₹${formattedAvail}. Please add funds before next trigger on ${nextDate}.`,
      html: htmlContent,
    });

    console.log(`✉️ [SIP FAILURE EMAIL SENT] Sent to ${toEmail} for ${sipName} (MessageId: ${info.messageId})`);
    return { delivered: true, messageId: info.messageId };
  } catch (error) {
    console.error(`❌ [SIP FAILURE EMAIL ERROR] Failed to send email to ${toEmail}:`, error.message);
    return { delivered: false, reason: error.message };
  }
}

/**
 * Sends an email notification when a Stock SIP executes successfully.
 */
async function sendSipSuccessEmail({
  toEmail,
  sipName,
  basketName,
  executedOrdersCount,
  totalAmount,
  nextDate,
}) {
  const emailUser = process.env.EMAIL_USER;
  const emailPass = process.env.EMAIL_PASS;

  if (!emailUser || !emailPass) {
    return { delivered: false, reason: "CREDENTIALS_NOT_CONFIGURED" };
  }

  try {
    const transporter = nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE || "gmail",
      auth: { user: emailUser, pass: emailPass },
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
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f7f9fc; margin: 0; padding: 24px; color: #1e293b; }
          .container { max-width: 520px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
          .header { background: #ffffff; padding: 20px 24px; border-bottom: 1px solid #f1f5f9; display: flex; align-items: center; justify-content: space-between; }
          .badge-success { background: #dcfce7; color: #15803d; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
          .content { padding: 28px 24px; }
          .title { margin: 0 0 10px 0; color: #0f172a; font-size: 18px; font-weight: 600; }
          .desc { color: #64748b; font-size: 14px; line-height: 1.5; margin: 0 0 20px 0; }
          .details-card { background: #fafafa; border: 1px solid #f1f5f9; border-radius: 6px; padding: 16px; margin-bottom: 24px; }
          .row { display: flex; justify-content: space-between; padding: 6px 0; font-size: 13px; }
          .row .label { color: #64748b; }
          .row .value { font-weight: 600; color: #0f172a; text-align: right; }
          .btn-view { display: inline-block; background: #387ed1; color: #ffffff !important; padding: 12px 24px; border-radius: 4px; text-decoration: none; font-size: 14px; font-weight: 500; text-align: center; }
          .footer { background: #fafafa; padding: 16px 24px; font-size: 11px; color: #94a3b8; border-top: 1px solid #f1f5f9; text-align: center; line-height: 1.5; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h2 style="color: #387ed1; margin: 0; font-weight: 700; letter-spacing: 1px; font-size: 20px;">ZERODHA</h2>
            <span class="badge-success">Executed</span>
          </div>
          <div class="content">
            <h3 class="title">Stock SIP Installment Executed</h3>
            <p class="desc">
              Your Stock SIP <strong>${sipName}</strong> executed successfully on the exchange. All <strong>${executedOrdersCount} orders</strong> in the linked basket <strong>${basketName}</strong> have been routed to NSE and added to your portfolio.
            </p>
            <div class="details-card">
              <div class="row"><span class="label">SIP Name:</span><span class="value">${sipName}</span></div>
              <div class="row"><span class="label">Linked Basket:</span><span class="value">${basketName}</span></div>
              <div class="row"><span class="label">Capital Invested:</span><span class="value" style="color: #16a34a;">₹${formattedAmount}</span></div>
              <div class="row"><span class="label">Orders Executed:</span><span class="value">${executedOrdersCount} legs</span></div>
              <div class="row"><span class="label">Next Scheduled Run:</span><span class="value">${nextDate}</span></div>
            </div>
            <div style="text-align: center; margin-top: 24px;">
              <a href="http://localhost:3001/orders" class="btn-view">View Orders in Kite &rarr;</a>
            </div>
          </div>
          <div class="footer">
            Zerodha Broking Ltd. &bull; SEBI Registration No.: INZ000031633 &bull; NSE / BSE / MCX<br>
            Trade details are available in your Kite console and daily contract notes.
          </div>
        </div>
      </body>
      </html>
    `;

    const info = await transporter.sendMail({
      from: `"Zerodha Kite" <${emailUser}>`,
      to: toEmail,
      subject: `Order Executed: Stock SIP ${sipName} (₹${formattedAmount})`,
      text: `Stock SIP ${sipName} executed successfully. Capital invested: ₹${formattedAmount}. Next run: ${nextDate}.`,
      html: htmlContent,
    });

    console.log(`✉️ [SIP SUCCESS EMAIL SENT] Sent to ${toEmail} for ${sipName} (MessageId: ${info.messageId})`);
    return { delivered: true, messageId: info.messageId };
  } catch (error) {
    console.error(`❌ [SIP SUCCESS EMAIL ERROR] Failed to send email to ${toEmail}:`, error.message);
    return { delivered: false, reason: error.message };
  }
}

/**
 * Sends a Price Alert Triggered email to the user.
 */
async function sendAlertTriggeredEmail({
  toEmail,
  symbol,
  name,
  conditionText,
  targetValue,
  triggeredPrice,
  notes,
}) {
  const emailUser = process.env.EMAIL_USER;
  const emailPass = process.env.EMAIL_PASS;

  if (!emailUser || !emailPass) {
    console.log(`⚠️ [EMAIL SERVICE] No email credentials. Simulated Alert for ${symbol} @ ₹${triggeredPrice}`);
    return { delivered: false, reason: "CREDENTIALS_NOT_CONFIGURED" };
  }

  try {
    const transporter = nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE || "gmail",
      auth: {
        user: emailUser,
        pass: emailPass,
      },
    });

    const formattedTriggeredPrice = Number(triggeredPrice).toLocaleString("en-IN", {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    });

    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f7f9fc; margin: 0; padding: 24px; color: #1e293b; }
          .container { max-width: 520px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
          .header { background: #ffffff; padding: 20px 24px; border-bottom: 1px solid #f1f5f9; display: flex; align-items: center; justify-content: space-between; }
          .badge-alert { background: #fef3c7; color: #b45309; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
          .content { padding: 28px 24px; }
          .title { margin: 0 0 10px 0; color: #0f172a; font-size: 18px; font-weight: 600; }
          .desc { color: #64748b; font-size: 14px; line-height: 1.5; margin: 0 0 20px 0; }
          .details-card { background: #fafafa; border: 1px solid #f1f5f9; border-radius: 6px; padding: 16px; margin-bottom: 24px; }
          .row { display: flex; justify-content: space-between; padding: 6px 0; font-size: 13px; }
          .row .label { color: #64748b; }
          .row .value { font-weight: 600; color: #0f172a; text-align: right; }
          .price-highlight { font-size: 20px; font-weight: 700; color: #2563eb; }
          .notes-box { background: #f8fafc; border-left: 3px solid #387ed1; padding: 10px 14px; font-size: 12.5px; color: #334155; margin-top: 12px; font-style: italic; }
          .btn-view { display: inline-block; background: #387ed1; color: #ffffff !important; padding: 12px 24px; border-radius: 4px; text-decoration: none; font-size: 14px; font-weight: 500; text-align: center; }
          .footer { background: #fafafa; padding: 16px 24px; font-size: 11px; color: #94a3b8; border-top: 1px solid #f1f5f9; text-align: center; line-height: 1.5; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h2 style="color: #387ed1; margin: 0; font-weight: 700; letter-spacing: 1px; font-size: 20px;">ZERODHA</h2>
            <span class="badge-alert">Alert Triggered</span>
          </div>
          <div class="content">
            <h3 class="title">Price Alert Triggered: ${symbol}</h3>
            <p class="desc">
              Your Sentinel price alert for <strong>${symbol}</strong> (${name || symbol}) has crossed the defined boundary on the National Stock Exchange (NSE).
            </p>
            <div class="details-card">
              <div class="row"><span class="label">Instrument:</span><span class="value">${symbol} (NSE)</span></div>
              <div class="row"><span class="label">Condition:</span><span class="value" style="color: #2563eb;">${conditionText}</span></div>
              <div class="row"><span class="label">Triggered At Price:</span><span class="value price-highlight">₹${formattedTriggeredPrice}</span></div>
              <div class="row"><span class="label">Triggered Time:</span><span class="value">${new Date().toLocaleTimeString("en-IN", { hour: "2-digit", minute: "2-digit", second: "2-digit" })} IST</span></div>
              ${notes ? `<div class="notes-box"><strong>Note:</strong> ${notes}</div>` : ""}
            </div>
            <div style="text-align: center; margin-top: 24px;">
              <a href="http://localhost:3001/orders" class="btn-view">Trade ${symbol} on Kite &rarr;</a>
            </div>
          </div>
          <div class="footer">
            Zerodha Broking Ltd. &bull; Sentinel Real-Time Market Intelligence &bull; NSE / BSE / MCX<br>
            This alert has been deactivated per single-trigger rules. You can re-arm it in your Kite console anytime.
          </div>
        </div>
      </body>
      </html>
    `;

    const info = await transporter.sendMail({
      from: `"Zerodha Sentinel" <${emailUser}>`,
      to: toEmail,
      subject: `🚨 Price Alert Triggered: ${symbol} is now ₹${formattedTriggeredPrice}`,
      text: `Price alert for ${symbol} has been triggered. Condition: ${conditionText}. Last Traded Price: ₹${formattedTriggeredPrice}.`,
      html: htmlContent,
    });

    console.log(`✉️ [ALERT EMAIL SENT] Sent to ${toEmail} for ${symbol} (MessageId: ${info.messageId})`);
    return { delivered: true, messageId: info.messageId };
  } catch (error) {
    console.error(`❌ [ALERT EMAIL ERROR] Failed to send email to ${toEmail}:`, error.message);
    return { delivered: false, reason: error.message };
  }
}

/**
 * Sends CDSL E-DIS TPIN Email
 */
async function sendCdslTpinEmail(toEmail, tpin, dematBoId) {
  const emailUser = process.env.EMAIL_USER;
  const emailPass = process.env.EMAIL_PASS;

  if (!emailUser || !emailPass) {
    console.log(`⚠️ [EMAIL SERVICE] Simulated CDSL TPIN for ${toEmail}: ${tpin}`);
    return { delivered: false, devTpin: tpin };
  }

  try {
    const transporter = nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE || "gmail",
      auth: { user: emailUser, pass: emailPass },
    });

    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f7f9fc; margin: 0; padding: 20px; color: #1e293b; }
          .container { max-width: 520px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; overflow: hidden; }
          .header { background: #1e3a8a; padding: 22px; text-align: center; color: #ffffff; }
          .cdsl-logo { font-size: 20px; font-weight: 800; letter-spacing: 2px; }
          .content { padding: 30px 24px; text-align: center; }
          .tpin-box { display: inline-block; background: #eff6ff; border: 2px dashed #2563eb; border-radius: 8px; padding: 14px 32px; font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #1e3a8a; margin: 20px 0; }
          .demat-pill { display: inline-block; background: #f1f5f9; padding: 4px 12px; border-radius: 4px; font-family: monospace; font-size: 13px; font-weight: bold; color: #334155; margin-bottom: 12px; }
          .footer { background: #fafafa; padding: 16px; font-size: 11px; color: #94a3b8; text-align: center; border-top: 1px solid #f1f5f9; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="cdsl-logo">CDSL &bull; E-DIS</div>
            <p style="margin: 4px 0 0 0; font-size: 12px; opacity: 0.9;">Central Depository Services (India) Limited</p>
          </div>
          <div class="content">
            <h3 style="margin-top: 0; color: #0f172a;">Your CDSL Demat TPIN</h3>
            <p style="color: #64748b; font-size: 13.5px; line-height: 1.5;">
              Use the 6-digit TPIN below to authorize electronic debit of shares from your Demat account on Zerodha Kite.
            </p>
            <div class="demat-pill">Demat BO ID: ${dematBoId || "1208160012345678"}</div>
            <div>
              <div class="tpin-box">${tpin}</div>
            </div>
            <p style="color: #64748b; font-size: 12.5px;">
              Keep your TPIN confidential. It is required for all Demat holdings exit transactions.
            </p>
          </div>
          <div class="footer">
            Central Depository Services (India) Ltd. &bull; Zerodha Broking Ltd. DP ID: 12081600<br>
            Automated regulatory email. Please do not reply.
          </div>
        </div>
      </body>
      </html>
    `;

    const info = await transporter.sendMail({
      from: `"CDSL E-DIS Depository" <${emailUser}>`,
      to: toEmail,
      subject: `🔐 Your CDSL Demat E-DIS TPIN: ${tpin} (BO ID: ${dematBoId || "12081600..."})`,
      text: `Your CDSL Demat TPIN for E-DIS authorization is: ${tpin}. BO ID: ${dematBoId}`,
      html: htmlContent,
    });

    console.log(`✉️ [CDSL TPIN EMAIL SENT] Sent to ${toEmail} (MessageId: ${info.messageId})`);
    return { delivered: true, messageId: info.messageId };
  } catch (error) {
    console.error(`❌ [CDSL TPIN EMAIL ERROR] Failed to send email to ${toEmail}:`, error.message);
    return { delivered: false, reason: error.message };
  }
}

/**
 * Sends CDSL Transaction Authorization OTP Email
 */
async function sendCdslTransactionOtpEmail(toEmail, otp, stockName, stockQty) {
  const emailUser = process.env.EMAIL_USER;
  const emailPass = process.env.EMAIL_PASS;

  if (!emailUser || !emailPass) {
    console.log(`⚠️ [EMAIL SERVICE] Simulated CDSL OTP for ${toEmail}: ${otp}`);
    return { delivered: false, devOtp: otp };
  }

  try {
    const transporter = nodemailer.createTransport({
      service: process.env.EMAIL_SERVICE || "gmail",
      auth: { user: emailUser, pass: emailPass },
    });

    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #f7f9fc; margin: 0; padding: 20px; color: #1e293b; }
          .container { max-width: 520px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; overflow: hidden; }
          .header { background: #1e3a8a; padding: 20px; text-align: center; color: #ffffff; }
          .cdsl-logo { font-size: 20px; font-weight: 800; letter-spacing: 2px; }
          .content { padding: 30px 24px; text-align: center; }
          .otp-box { display: inline-block; background: #ecfdf5; border: 2px dashed #10b981; border-radius: 8px; padding: 14px 32px; font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #065f46; margin: 20px 0; }
          .stock-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px 14px; font-size: 13px; color: #334155; margin: 12px 0; }
          .footer { background: #fafafa; padding: 16px; font-size: 11px; color: #94a3b8; text-align: center; border-top: 1px solid #f1f5f9; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="cdsl-logo">CDSL &bull; TRANSACTION OTP</div>
            <p style="margin: 4px 0 0 0; font-size: 12px; opacity: 0.9;">E-DIS Demat Holding Debit Authorization</p>
          </div>
          <div class="content">
            <h3 style="margin-top: 0; color: #0f172a;">Authorize Share Sale</h3>
            <p style="color: #64748b; font-size: 13.5px; line-height: 1.5;">
              Enter the OTP below to authorize debit of Demat shares on Zerodha Kite.
            </p>
            <div class="stock-box">
              <strong>Asset Authorizing:</strong> ${stockQty || 1} shares of <strong>${stockName || "Holdings"}</strong>
            </div>
            <div>
              <div class="otp-box">${otp}</div>
            </div>
            <p style="color: #ef4444; font-size: 12px; font-weight: 600;">
              Valid for 5 minutes. Do not share this OTP with anyone.
            </p>
          </div>
          <div class="footer">
            Central Depository Services (India) Ltd. &bull; Zerodha Broking Ltd.<br>
            Once authorized, Demat holdings remain authorized for exit until 3:30 PM today.
          </div>
        </div>
      </body>
      </html>
    `;

    const info = await transporter.sendMail({
      from: `"CDSL E-DIS Depository" <${emailUser}>`,
      to: toEmail,
      subject: `🔐 CDSL E-DIS Transaction OTP: ${otp} for ${stockName || "Shares"} Sale`,
      text: `Your CDSL Transaction OTP is: ${otp}. Valid for ${stockQty} shares of ${stockName}.`,
      html: htmlContent,
    });

    console.log(`✉️ [CDSL OTP EMAIL SENT] Sent to ${toEmail} (MessageId: ${info.messageId})`);
    return { delivered: true, messageId: info.messageId };
  } catch (error) {
    console.error(`❌ [CDSL OTP EMAIL ERROR] Failed to send email to ${toEmail}:`, error.message);
    return { delivered: false, reason: error.message };
  }
}


/**
 * Interactive UPI Collect Request Email for Adding Funds
 */
async function sendFundDepositEmail({
  toEmail,
  amount,
  upiId,
  referenceId,
  approveUrl,
  declineUrl,
}) {
  const emailUser = process.env.EMAIL_USER;
  const emailPass = process.env.EMAIL_PASS;
  const formattedAmount = Number(amount).toLocaleString("en-IN", { minimumFractionDigits: 2 });

  if (!emailUser || !emailPass) {
    console.log(
      `⚠️ [EMAIL SERVICE] EMAIL_USER / EMAIL_PASS not set. Simulated UPI deposit email for ${toEmail}: Amount ₹${formattedAmount}, Approve: ${approveUrl}`
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

    const htmlContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <style>
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8fafc; margin: 0; padding: 24px; color: #0f172a; }
          .container { max-width: 520px; margin: 0 auto; background: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
          .header { background: #ffffff; padding: 24px; text-align: center; border-bottom: 2px solid #16a34a; }
          .header-brand { font-size: 22px; font-weight: 700; color: #387ed1; letter-spacing: 1px; margin: 0; }
          .header-tag { font-size: 11px; text-transform: uppercase; letter-spacing: 1.5px; color: #64748b; margin-top: 4px; font-weight: 600; }
          .content { padding: 28px 24px; }
          .alert-banner { background: #f0fdf4; border-left: 4px solid #16a34a; padding: 12px 16px; border-radius: 4px; margin-bottom: 24px; }
          .alert-banner p { margin: 0; font-size: 13px; color: #166534; line-height: 1.5; }
          .summary-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 18px; margin-bottom: 24px; }
          .summary-row { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #e2e8f0; font-size: 13px; }
          .summary-row:last-child { border-bottom: none; }
          .summary-label { color: #64748b; }
          .summary-value { font-weight: 600; color: #0f172a; text-align: right; }
          .amount-highlight { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 16px; text-align: center; margin-bottom: 28px; }
          .amount-label { font-size: 11px; text-transform: uppercase; color: #15803d; font-weight: 700; letter-spacing: 0.5px; }
          .amount-value { font-size: 32px; font-weight: 700; color: #166534; margin: 4px 0 0 0; }
          .action-buttons-wrap { text-align: center; margin: 28px 0 12px 0; }
          .btn { display: inline-block; padding: 14px 28px; font-size: 14px; font-weight: 600; text-decoration: none; border-radius: 5px; margin: 6px 8px; }
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
            <div class="header-tag">Instant Funds Payin &bull; UPI Collect Request</div>
          </div>
          <div class="content">
            <div class="alert-banner">
              <p>
                <strong>Payment Authorization Required:</strong> An instant fund transfer request of <strong>₹${formattedAmount}</strong> has been initiated via UPI for your Zerodha trading account.
              </p>
            </div>

            <div class="amount-highlight">
              <div class="amount-label">Deposit Amount to Credit</div>
              <div class="amount-value">₹${formattedAmount}</div>
            </div>

            <div class="summary-card">
              <div class="summary-row">
                <span class="summary-label">Reference ID</span>
                <span class="summary-value" style="font-family: monospace;">${referenceId}</span>
              </div>
              <div class="summary-row">
                <span class="summary-label">Target Trading Account</span>
                <span class="summary-value">Equity & F&O Margin</span>
              </div>
              <div class="summary-row">
                <span class="summary-label">Payer UPI ID</span>
                <span class="summary-value">${upiId}</span>
              </div>
              <div class="summary-row">
                <span class="summary-label">Transfer Type</span>
                <span class="summary-value">Instant Zero-Cost UPI</span>
              </div>
            </div>

            <div class="action-buttons-wrap">
              <a href="${approveUrl}" class="btn btn-approve">
                ✓ Approve Payment (₹${formattedAmount})
              </a>
              <a href="${declineUrl}" class="btn btn-decline">
                ✕ Decline Transfer
              </a>
            </div>

            <p class="info-note">
              Once approved, funds will be instantly credited to your trading margin and available for immediate equity and intraday trading.
            </p>
          </div>

          <div class="footer">
            Zerodha Broking Ltd. &bull; SEBI Registration No.: INZ000031633<br>
            If you did not initiate this deposit, click Decline to reject the transfer request immediately.
          </div>
        </div>
      </body>
      </html>
    `;

    const info = await transporter.sendMail({
      from: `"Zerodha Kite" <${emailUser}>`,
      to: toEmail,
      subject: `Action Required: Approve UPI Fund Transfer of ₹${formattedAmount} (Ref: ${referenceId})`,
      text: `Action Required: Approve UPI Fund Transfer of ₹${formattedAmount} to your Zerodha trading account. Approve here: ${approveUrl} or Decline here: ${declineUrl}`,
      html: htmlContent,
    });

    console.log(`✉️ [FUND DEPOSIT EMAIL SENT] Sent to ${toEmail} (Ref: ${referenceId})`);
    return { delivered: true, messageId: info.messageId };
  } catch (error) {
    console.error(`❌ [FUND DEPOSIT EMAIL ERROR] Failed to send email to ${toEmail}:`, error.message);
    return { delivered: false, reason: error.message };
  }
}

module.exports = {
  sendFundDepositEmail,
  sendOtpEmail,
  sendIpoMandateEmail,
  sendSipFailureEmail,
  sendSipSuccessEmail,
  sendAlertTriggeredEmail,
  sendCdslTpinEmail,
  sendCdslTransactionOtpEmail,
};
