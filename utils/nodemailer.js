import nodemailer from "nodemailer";

export async function sendToOtp({ subject, html, text, to, user, otp }) {
  const { EMAIL_USER, EMAIL_PASSWORD } = process.env;

  try {
    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 465,
      secure: true,
      auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASSWORD,
      },
    });

    const result = await transporter.sendMail({
      from: `RAKSHIT <${EMAIL_USER}>`,
      to: to || user?.email,
      subject: subject || "RAKSHIT - OTP ✔",
      text,
      html:
        html ||
        `<p>Dear ${user?.name || "User"},</p>
         <p>Your OTP is: <b>${otp}</b></p>
         <p>This OTP will expire in 10 minutes.</p>`,
    });

    console.log("✅ Mail Sent:", result.messageId);
    return result;
  } catch (error) {
    console.error("❌ Email Error:", error);
    throw new Error("Failed to send email");
  }
}
