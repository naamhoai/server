import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import nodemailer from 'nodemailer';
import { PrismaClient } from '@prisma/client';
import {
  validatePhoneOrEmail,
  validateEmail,
  validateStrongPassword,
} from '../utils/authValidation.js';

const prisma = new PrismaClient();
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'secret_key';
const CLIENT_URL = process.env.CLIENT_URL || 'http://localhost:5173';
const VERIFICATION_TTL_MINUTES = Number(process.env.VERIFICATION_TOKEN_TTL_MINUTES || 10);
const IS_DEV = (process.env.NODE_ENV || 'development') !== 'production';
const OTP_MAX_PER_ACCOUNT = 5;
const OTP_ACCOUNT_WINDOW_MINUTES = 10;

const sha256 = (value) =>
  crypto.createHash('sha256').update(String(value)).digest('hex');

function getEmailTransporter() {
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS } = process.env;
  if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) {
    if (IS_DEV) console.warn('[DEV] Missing SMTP_* env vars. Using mock email transporter.');
    return {
      sendMail: async (mailOptions) => {
        if (IS_DEV) {
          const otpMatch = mailOptions.text?.match(/code is:\s*(\d{6})/);
          const otp = otpMatch ? otpMatch[1] : '(see text)';
          console.info(`\n[DEV-MOCK Email] To: ${mailOptions.to}`);
          console.info(`[DEV-MOCK Email] OTP: ${otp}\n`);
        }
      }
    };
  }

  const port = Number(SMTP_PORT);
  return nodemailer.createTransport({
    host: SMTP_HOST,
    port,
    secure: port === 465,
    auth: { user: SMTP_USER, pass: SMTP_PASS },
  });
}

async function sendVerificationEmail(toEmail, otp) {
  const from = process.env.SMTP_FROM || 'noreply@localhost';
  const transporter = getEmailTransporter();
  await transporter.sendMail({
    from,
    to: toEmail,
    subject: 'Your Verification Code',
    text: `Your account verification code is: ${otp}\n\nThis code expires in ${VERIFICATION_TTL_MINUTES} minutes.`,
    html: `<p>Your account verification code is:</p><h2>${otp}</h2><p>This code expires in ${VERIFICATION_TTL_MINUTES} minutes.</p>`,
  });
}

// SMS không dùng Twilio trên server này — log mock, OTP vẫn lưu DB
async function sendVerificationSms(toPhoneDigits, countryCode, otp) {
  console.info(`[MOCK SMS] To: ${countryCode}${toPhoneDigits} | OTP: ${IS_DEV ? otp : '(hidden)'}`);
}

function minutesAgo(minutes) {
  const d = new Date();
  d.setMinutes(d.getMinutes() - minutes);
  return d.toISOString();
}

function minutesFromNow(minutes) {
  const d = new Date();
  d.setMinutes(d.getMinutes() + minutes);
  return d.toISOString();
}

// ─── GET /api/auth/me — thông tin user hiện tại (refresh plan/xp sau thanh toán) ───
router.get('/me', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await prisma.user.findUnique({
      where: { id: decoded.userId || decoded.id },
      select: { id: true, fullName: true, email: true, phone: true, username: true, role: true, plan: true, planExpiresAt: true, requestDailyCount: true, xp: true, avatar: true }
    });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true, user });
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ─── POST /api/auth/register ───
router.post('/register', async (req, res) => {
  try {
    const { phoneOrEmail, fullName, password, countryCode } = req.body;

    if (!phoneOrEmail || !fullName || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const idResult = validatePhoneOrEmail(phoneOrEmail);
    if (!idResult.ok) return res.status(400).json({ error: idResult.message });

    const passResult = validateStrongPassword(password);
    if (!passResult.ok) return res.status(400).json({ error: passResult.message });

    const isEmail = phoneOrEmail.includes('@');
    const channel = isEmail ? 'email' : 'phone';

    const existing = await prisma.user.findUnique({ where: { username: phoneOrEmail } });

    if (existing && existing.isActive) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Rate limit OTP theo account
    const windowStart = minutesAgo(OTP_ACCOUNT_WINDOW_MINUTES);
    let recentOtpCount = 0;
    if (existing?.id) {
      recentOtpCount = await prisma.verificationToken.count({
        where: { userId: existing.id, channel, createdAt: { gte: new Date(windowStart) } },
      });
    }

    if (recentOtpCount >= OTP_MAX_PER_ACCOUNT) {
      return res.status(429).json({
        error: `Too many verification code requests. Please wait ${OTP_ACCOUNT_WINDOW_MINUTES} minutes before trying again.`
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const tokenHash = sha256(otp);
    let targetUser;

    await prisma.$transaction(async (tx) => {
      if (existing && !existing.isActive) {
        const passwordHash = await bcrypt.hash(password, 10);
        targetUser = await tx.user.update({
          where: { id: existing.id },
          data: { passwordHash, fullName, countryCode: countryCode || '+84' },
        });
        await tx.verificationToken.deleteMany({ where: { userId: existing.id } });
      } else {
        const passwordHash = await bcrypt.hash(password, 10);
        targetUser = await tx.user.create({
          data: {
            username: phoneOrEmail,
            email: isEmail ? phoneOrEmail : null,
            phone: isEmail ? null : phoneOrEmail,
            passwordHash,
            fullName,
            countryCode: countryCode || '+84',
            role: 'student',
            isActive: false,
          },
        });
      }

      await tx.verificationToken.create({
        data: {
          userId: targetUser.id,
          channel,
          tokenHash,
          expiresAt: new Date(minutesFromNow(VERIFICATION_TTL_MINUTES)),
        },
      });
    });

    if (isEmail) {
      sendVerificationEmail(phoneOrEmail, otp).catch(e => console.error('Email send failed:', e));
    } else {
      sendVerificationSms(phoneOrEmail, countryCode || '+84', otp).catch(e => console.error('SMS send failed:', e));
    }

    res.status(201).json({
      message: 'Verification sent. Please check your email/SMS to activate your account.',
      channel,
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: IS_DEV ? (error?.message || 'Registration failed') : 'Registration failed' });
  }
});

// ─── POST /api/auth/login ───
router.post('/login', async (req, res) => {
  try {
    const { email, phoneOrEmail, password } = req.body;
    const loginEmail = (email || phoneOrEmail || '').trim();

    if (!loginEmail || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const emailResult = validateEmail(loginEmail);
    if (!emailResult.ok) return res.status(400).json({ error: emailResult.message });

    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const user = await prisma.user.findFirst({ where: { email: loginEmail } });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    if (!user.isActive) {
      return res.status(403).json({
        error: 'Account not verified. Please verify your email via the link first.',
      });
    }

    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.email || user.phone || user.username,
        full_name: user.fullName,
        email: user.email,
        role: user.role,
        xp: user.xp,
        level: user.level,
        streak: user.streak,
      },
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ─── POST /api/auth/google-login ───
router.post('/google-login', async (req, res) => {
  try {
    const { email, name, avatar, googleId } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const user = await prisma.$transaction(async (tx) => {
      let u = await tx.user.findFirst({ where: { OR: [{ email }, { username: email }] } });

      if (!u) {
        u = await tx.user.create({
          data: {
            username: email,
            email,
            passwordHash: await bcrypt.hash(googleId || Math.random().toString(36), 10),
            fullName: name || 'Google User',
            avatar: avatar || null,
            role: 'student',
            isActive: true,
          },
        });
      } else if (!u.isActive) {
        u = await tx.user.update({ where: { id: u.id }, data: { isActive: true } });
      }

      return u;
    });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Google login successful',
      token,
      user: {
        id: user.id,
        username: user.email,
        full_name: user.fullName,
        email: user.email,
        role: user.role,
        xp: user.xp,
        level: user.level,
        streak: user.streak,
      },
    });
  } catch (error) {
    console.error('Google login error:', error);
    res.status(500).json({ error: 'Google login failed' });
  }
});

// ─── GET /api/auth/verify — kiểm tra JWT còn hạn ───
router.get('/verify', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await prisma.user.findUnique({ where: { id: decoded.id } });
    if (!user) return res.status(401).json({ error: 'User not found' });

    res.json({
      user: {
        id: user.id,
        username: user.email,
        full_name: user.fullName,
        email: user.email,
        role: user.role,
        xp: user.xp,
        level: user.level,
        streak: user.streak,
      },
    });
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ─── POST /api/auth/verify-otp — xác thực OTP kích hoạt tài khoản ───
router.post('/verify-otp', async (req, res) => {
  try {
    const { phoneOrEmail, otp } = req.body;
    if (!phoneOrEmail || !otp) {
      return res.status(400).json({ error: 'Phone/Email and OTP are required' });
    }

    const tokenHash = sha256(otp);
    const isEmailInput = phoneOrEmail.includes('@');
    let user = await prisma.user.findUnique({ where: { username: phoneOrEmail } });
    if (!user && isEmailInput) user = await prisma.user.findFirst({ where: { email: phoneOrEmail } });
    if (!user && !isEmailInput) user = await prisma.user.findFirst({ where: { phone: phoneOrEmail } });

    if (!user) return res.status(400).json({ error: 'User not found' });

    const channel = isEmailInput ? 'email' : 'phone';
    const MAX_OTP_ATTEMPTS = 5;
    const windowStart = minutesAgo(OTP_ACCOUNT_WINDOW_MINUTES);

    const attemptRows = await prisma.verificationToken.aggregate({
      where: { userId: user.id, channel, createdAt: { gte: new Date(windowStart) } },
      _sum: { attempts: true },
    });
    const totalAttempts = attemptRows._sum.attempts || 0;

    if (totalAttempts >= MAX_OTP_ATTEMPTS) {
      return res.status(429).json({
        error: `Too many incorrect attempts. Please wait ${OTP_ACCOUNT_WINDOW_MINUTES} minutes before trying again.`,
      });
    }

    const latestToken = await prisma.verificationToken.findFirst({
      where: { userId: user.id, channel, usedAt: null, expiresAt: { gt: new Date() } },
      orderBy: { createdAt: 'desc' },
    });

    if (!latestToken) {
      return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
    }

    if (latestToken.tokenHash !== tokenHash) {
      await prisma.verificationToken.update({
        where: { id: latestToken.id },
        data: { attempts: latestToken.attempts + 1 },
      });
      const remaining = MAX_OTP_ATTEMPTS - totalAttempts - 1;
      return res.status(400).json({ error: `Incorrect OTP code. ${remaining} attempt(s) remaining.` });
    }

    await prisma.$transaction(async (tx) => {
      await tx.verificationToken.deleteMany({ where: { userId: user.id, channel } });
      await tx.user.update({ where: { id: user.id }, data: { isActive: true } });
    });

    res.json({ message: 'Account verified successfully' });
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// ─── POST /api/auth/forgot-password — bước 1: gửi OTP reset ───
router.post('/forgot-password', async (req, res) => {
  try {
    const { phoneOrEmail } = req.body;
    if (!phoneOrEmail) {
      return res.status(400).json({ error: 'Phone number or email is required.' });
    }

    const idResult = validatePhoneOrEmail(phoneOrEmail);
    if (!idResult.ok) return res.status(400).json({ error: idResult.message });

    const isEmail = phoneOrEmail.includes('@');

    let user = await prisma.user.findUnique({ where: { username: phoneOrEmail } });
    if (!user && isEmail) user = await prisma.user.findFirst({ where: { email: phoneOrEmail } });
    if (!user && !isEmail) user = await prisma.user.findFirst({ where: { phone: phoneOrEmail } });

    // Không tiết lộ account có tồn tại hay không
    if (!user || !user.isActive) {
      return res.json({ message: 'If your account exists, a reset code has been sent.' });
    }

    const resetChannel = 'reset_' + (isEmail ? 'email' : 'phone');
    const windowStart = minutesAgo(OTP_ACCOUNT_WINDOW_MINUTES);

    const recentOtpCount = await prisma.verificationToken.count({
      where: { userId: user.id, channel: resetChannel, createdAt: { gte: new Date(windowStart) } },
    });

    if (recentOtpCount >= OTP_MAX_PER_ACCOUNT) {
      return res.status(429).json({
        error: `Too many reset code requests. Please wait ${OTP_ACCOUNT_WINDOW_MINUTES} minutes before trying again.`
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const tokenHash = sha256(otp);

    await prisma.$transaction(async (tx) => {
      await tx.verificationToken.deleteMany({
        where: { userId: user.id, channel: resetChannel, usedAt: { not: null } },
      });
      await tx.verificationToken.updateMany({
        where: { userId: user.id, channel: resetChannel, usedAt: null },
        data: { expiresAt: new Date() },
      });
      await tx.verificationToken.create({
        data: {
          userId: user.id,
          channel: resetChannel,
          tokenHash,
          expiresAt: new Date(minutesFromNow(VERIFICATION_TTL_MINUTES)),
          attempts: 0,
        },
      });
    });

    if (isEmail) {
      sendResetEmail(phoneOrEmail, otp).catch(e => console.error('Reset email failed:', e));
    } else {
      sendVerificationSms(phoneOrEmail, user.countryCode || '+84', otp).catch(e => console.error('Reset SMS failed:', e));
    }

    res.json({ message: 'If your account exists, a reset code has been sent.', channel: isEmail ? 'email' : 'phone' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Failed to send reset code.' });
  }
});

// ─── POST /api/auth/verify-reset-otp — bước 2: xác thực OTP, trả resetToken ───
router.post('/verify-reset-otp', async (req, res) => {
  try {
    const { phoneOrEmail, otp } = req.body;
    if (!phoneOrEmail || !otp) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    const isEmail = phoneOrEmail.includes('@');
    const channel = 'reset_' + (isEmail ? 'email' : 'phone');
    const tokenHash = sha256(otp);
    const MAX_ATTEMPTS = 5;
    const windowStart = minutesAgo(OTP_ACCOUNT_WINDOW_MINUTES);

    let user = await prisma.user.findUnique({ where: { username: phoneOrEmail } });
    if (!user && isEmail) user = await prisma.user.findFirst({ where: { email: phoneOrEmail } });
    if (!user && !isEmail) user = await prisma.user.findFirst({ where: { phone: phoneOrEmail } });

    if (!user) return res.status(400).json({ error: 'Invalid request.' });

    const attemptRows = await prisma.verificationToken.aggregate({
      where: { userId: user.id, channel, createdAt: { gte: new Date(windowStart) } },
      _sum: { attempts: true },
    });
    const totalAttempts = attemptRows._sum.attempts || 0;

    if (totalAttempts >= MAX_ATTEMPTS) {
      return res.status(429).json({
        error: `Too many incorrect attempts. Please wait ${OTP_ACCOUNT_WINDOW_MINUTES} minutes before trying again.`,
      });
    }

    const tokenRow = await prisma.verificationToken.findFirst({
      where: {
        userId: user.id,
        channel,
        usedAt: null,
        resetTokenHash: null,
        expiresAt: { gt: new Date() },
      },
      orderBy: { createdAt: 'desc' },
    });

    if (!tokenRow) {
      return res.status(400).json({ error: 'Code has expired or already used. Please request a new one.' });
    }

    if (tokenRow.tokenHash !== tokenHash) {
      await prisma.verificationToken.update({
        where: { id: tokenRow.id },
        data: { attempts: tokenRow.attempts + 1 },
      });
      const remaining = MAX_ATTEMPTS - totalAttempts - 1;
      return res.status(400).json({ error: `Incorrect code. ${remaining} attempt(s) remaining.` });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHash = sha256(resetToken);

    await prisma.verificationToken.update({
      where: { id: tokenRow.id },
      data: {
        usedAt: new Date(),
        resetTokenHash,
        expiresAt: new Date(minutesFromNow(5)),
      },
    });

    res.json({ message: 'Code verified. You may now set a new password.', resetToken });
  } catch (error) {
    console.error('Verify reset OTP error:', error);
    res.status(500).json({ error: 'Verification failed.' });
  }
});

// ─── POST /api/auth/reset-password — bước 3: đặt mật khẩu mới ───
router.post('/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    if (!resetToken || !newPassword) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    const passResult = validateStrongPassword(newPassword);
    if (!passResult.ok) return res.status(400).json({ error: passResult.message });

    const resetTokenHash = sha256(resetToken);

    const tokenRow = await prisma.verificationToken.findFirst({
      where: { resetTokenHash, expiresAt: { gt: new Date() } },
    });

    if (!tokenRow) {
      return res.status(400).json({ error: 'Reset session has expired. Please start over.' });
    }

    const newHash = await bcrypt.hash(newPassword, 10);

    await prisma.$transaction(async (tx) => {
      await tx.verificationToken.delete({ where: { id: tokenRow.id } });
      await tx.user.update({
        where: { id: tokenRow.userId },
        data: { passwordHash: newHash },
      });
    });

    res.json({ message: 'Password has been reset successfully. You can now log in.' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password.' });
  }
});

// Email đặt lại mật khẩu (template đầy đủ)
async function sendResetEmail(toEmail, otp) {
  const from = process.env.SMTP_FROM || 'noreply@localhost';
  const transporter = getEmailTransporter();

  const [localPart, domain] = toEmail.split('@');
  const maskedLocal = localPart.length <= 3 ? localPart[0] + '***' : localPart.slice(0, 3) + '***';
  const maskedEmail = `${maskedLocal}@${domain}`;
  const year = new Date().getFullYear();

  await transporter.sendMail({
    from: `"Excel Tutor" <${from}>`,
    to: toEmail,
    subject: '[Excel Tutor] Reset Your Password',
    text: `You requested to reset your password for Excel Tutor.\n\nYour reset code is: ${otp}\n\nExpires in ${VERIFICATION_TTL_MINUTES} minutes. Do not share this code with anyone.\n\nIf you did not request this, please ignore this email.`,
    html: `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f4f6f9;font-family:'Segoe UI',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f9;padding:32px 0;">
<tr><td align="center">
<table width="520" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">
<tr><td style="background:linear-gradient(135deg,#10b981,#0d9488);padding:32px;text-align:center;">
  <h1 style="margin:0;color:#fff;font-size:24px;font-weight:700;">📊 Excel Tutor</h1>
  <p style="margin:8px 0 0;color:rgba(255,255,255,0.85);font-size:14px;">Password Reset Request</p>
</td></tr>
<tr><td style="padding:36px 40px;">
  <p style="margin:0 0 8px;color:#374151;font-size:16px;font-weight:600;">Hello,</p>
  <p style="margin:0 0 24px;color:#6b7280;font-size:14px;line-height:1.6;">You requested to <strong>reset the password</strong> for your Excel Tutor account associated with <strong style="color:#374151;">${maskedEmail}</strong>.</p>
  <div style="background:#f0fdf4;border:2px dashed #10b981;border-radius:12px;padding:24px;text-align:center;margin-bottom:24px;">
    <p style="margin:0 0 8px;color:#6b7280;font-size:12px;text-transform:uppercase;letter-spacing:1px;font-weight:600;">Your Reset Code</p>
    <p style="margin:0;font-size:42px;font-weight:700;letter-spacing:12px;color:#10b981;">${otp}</p>
    <p style="margin:12px 0 0;color:#9ca3af;font-size:12px;">⏱ Expires in <strong>${VERIFICATION_TTL_MINUTES} minutes</strong></p>
  </div>
  <p style="margin:0 0 16px;color:#6b7280;font-size:14px;line-height:1.6;">Enter this code on the reset password page. <strong>Do not share this code with anyone.</strong></p>
  <div style="background:#fef9ec;border-left:4px solid #f59e0b;border-radius:4px;padding:12px 16px;">
    <p style="margin:0;color:#92400e;font-size:12px;line-height:1.5;">⚠️ <strong>Security notice:</strong> Excel Tutor will never ask for your full password. If you did not request this, please ignore this email — your account remains safe.</p>
  </div>
</td></tr>
<tr><td style="background:#f9fafb;padding:20px 40px;border-top:1px solid #e5e7eb;">
  <p style="margin:0;color:#9ca3af;font-size:12px;text-align:center;">© ${year} Excel Tutor. This is an automated message, please do not reply.</p>
</td></tr>
</table>
</td></tr></table>
</body></html>`,
  });
}

export default router;
