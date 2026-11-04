const nodemailer = require("nodemailer");

/**
 * Sends a branded Zerodha Kite OTP email to the user.
 * Supports Gmail App Passwords, Custom SMTP, or falls back gracefully to console delivery.
 */
async function sendOtpEmail(toEmail, otp) {
  const emailUser = process.env.EMAIL_USER;
  const emailPass = process.env.EMAIL_PASS;

  // If credentials are not configured yet in .env, gracefully fallback
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

module.exports = { sendOtpEmail };
