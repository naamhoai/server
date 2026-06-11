import express from 'express';
import crypto from 'crypto';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const router = express.Router();

// ─── Middleware: API key cho admin routes ───
function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'] || req.query.api_key;
  if (!process.env.ADMIN_API_KEY || key !== process.env.ADMIN_API_KEY) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }
  next();
}

// =============================================================================
// ROUTE 0: Danh sách gói plan (public)
// GET /api/sepay/packages
// =============================================================================
router.get('/packages', async (_req, res) => {
  try {
    let packages = await prisma.planPackage.findMany({
      where: { isActive: true },
      orderBy: { price: 'asc' },
    });

    if (packages.length === 0) {
      await prisma.planPackage.createMany({
        data: [
          { name: 'Gói Thường', plan: 'regular', dailyRequestLimit: 50, durationDays: 30, price: 29000, badge: 'popular' },
          { name: 'Gói Pro', plan: 'pro', dailyRequestLimit: 200, durationDays: 30, price: 89000, badge: null },
        ],
      });
      packages = await prisma.planPackage.findMany({ where: { isActive: true }, orderBy: { price: 'asc' } });
    }

    res.json({ success: true, data: packages });
  } catch (err) {
    console.error('[SePay] List packages error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// =============================================================================
// ROUTE 1: Webhook nhận thông báo thanh toán (public, xác thực qua HMAC)
// POST /api/sepay/webhook
//
// SePay gọi endpoint này khi có biến động số dư ngân hàng.
// Luồng: Khách CK → Ngân hàng → SePay → POST /webhook → xử lý async
// =============================================================================
router.post('/webhook', async (req, res) => {
  try {
    const sig = req.headers['x-sepay-signature'];
    const timestamp = req.headers['x-sepay-timestamp'] || '';

    if (!sig) {
      console.error('[SePay] Missing x-sepay-signature');
      return res.status(401).json({ success: false, error: 'Missing signature' });
    }

    const SECRET_KEY = process.env.SEPAY_WEBHOOK_SECRET;
    if (!SECRET_KEY) {
      console.error('[SePay] SEPAY_WEBHOOK_SECRET not set');
      return res.status(500).json({ success: false, error: 'Server misconfigured' });
    }

    // req.body là Buffer (raw) do express.raw() trong index.js
    // Parse thủ công để có cả raw bytes (cho HMAC chính xác) lẫn JSON object
    const rawBody = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : JSON.stringify(req.body);
    let payload;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      return res.status(400).json({ success: false, error: 'Invalid JSON body' });
    }

    // SePay hỗ trợ nhiều format HMAC — thử tất cả
    const hmac1 = crypto.createHmac('sha256', SECRET_KEY).update(rawBody).digest('hex');
    const hmac2 = 'sha256=' + hmac1;
    const hmac3 = 'sha256=' + crypto.createHmac('sha256', SECRET_KEY).update(timestamp + '.' + rawBody).digest('hex');

    const validSig = sig === hmac1 || sig === hmac2 || sig === hmac3;

    console.log('[SePay] Webhook received:', {
      sig, timestamp, body: payload,
      hmac1, hmac2, hmac3, valid: validSig
    });

    if (!validSig) {
      console.error('[SePay] Invalid HMAC signature');
      return res.status(401).json({ success: false, error: 'Invalid signature' });
    }

    // Trả về NGAY trong 30s (yêu cầu của SePay), xử lý bất đồng bộ sau
    res.json({ success: true });

    setImmediate(async () => {
      const { id, transferType, transferAmount, content, accountNumber, transactionDate, gateway } = payload;
      let { code } = payload;

      if (transferType !== 'in') {
        console.log(`[SePay] Ignoring transferType: ${transferType}`);
        return;
      }

      // Extract code từ content nếu SePay chưa parse
      if (!code && content) {
        const match = content.match(/SEVQR\s+(U\d+P?\d*)/i);
        if (match) {
          code = `SEVQR ${match[1]}`;
          console.log(`[SePay] Extracted code from content: ${code}`);
        }
      }

      // Chống trùng lặp bằng sepayId
      const existing = await prisma.sepayTransaction.findUnique({ where: { sepayId: id } });
      if (existing) {
        console.log(`[SePay] Duplicate ignored: sepayId=${id}`);
        return;
      }

      const created = await prisma.sepayTransaction.create({
        data: {
          sepayId: id,
          amount: transferAmount,
          code: code || null,
          content: content || null,
          accountNumber: accountNumber || null,
          transactionDate: new Date(transactionDate),
          status: 'received',
        },
      });

      console.log(`[SePay] Transaction saved: id=${created.id}, amount=${transferAmount}, code=${code}`);

      if (code) {
        await processOrder(code, transferAmount, created.id, gateway);
      }
    });
  } catch (err) {
    console.error('[SePay] Webhook error:', err);
  }
});

// Xử lý đơn hàng mua gói
// Code format: "SEVQR U{userId}P{packageId}" hoặc "U{userId}P{packageId}"
async function processOrder(code, amount, transactionId, gateway) {
  try {
    const cleanCode = code.replace(/^SEVQR\s*/i, '').trim();

    let userId = null;
    let packageId = null;

    const upMatch = cleanCode.match(/^U(\d+)P(\d+)$/);
    if (upMatch) {
      userId = parseInt(upMatch[1]);
      packageId = parseInt(upMatch[2]);
    } else {
      const uMatch = cleanCode.match(/^U(\d+)$/);
      if (uMatch) userId = parseInt(uMatch[1]);
    }

    if (!userId) {
      console.warn(`[SePay] Cannot resolve userId from code: ${code}`);
      return;
    }

    const pkg = packageId
      ? await prisma.planPackage.findUnique({ where: { id: packageId } })
      : await prisma.planPackage.findFirst({ where: { price: amount, isActive: true } });

    if (!pkg) {
      console.warn(`[SePay] Package not found: code=${code}, packageId=${packageId}`);
      return;
    }

    if (amount < pkg.price) {
      console.warn(`[SePay] Insufficient amount: received=${amount}, required=${pkg.price}`);
      await prisma.sepayTransaction.update({ where: { id: transactionId }, data: { status: 'failed' } });
      return;
    }

    const now = new Date();
    const currentUser = await prisma.user.findUnique({
      where: { id: userId },
      select: { planExpiresAt: true },
    });

    const baseDate = currentUser?.planExpiresAt && new Date(currentUser.planExpiresAt) > now
      ? new Date(currentUser.planExpiresAt)
      : now;
    const newExpiresAt = new Date(baseDate.getTime() + pkg.durationDays * 86400000);

    const xpReward = Math.floor(pkg.price / 1000);

    await prisma.user.update({
      where: { id: userId },
      data: {
        plan: pkg.plan,
        planExpiresAt: newExpiresAt,
        requestDailyCount: 0,
        xp: { increment: xpReward },
      },
    });

    await prisma.planTransaction.create({
      data: {
        userId,
        type: 'plan_purchase',
        planType: pkg.plan,
        expiresAt: newExpiresAt,
        amount: Math.round(amount),
        description: `Mua ${pkg.name} (${pkg.dailyRequestLimit} req/ngày × ${pkg.durationDays} ngày) qua ${gateway || 'Vietinbank'}`,
      },
    });

    await prisma.sepayTransaction.update({
      where: { id: transactionId },
      data: { status: 'processed', userId, planPackageId: pkg.id },
    });

    const expiryStr = newExpiresAt.toLocaleDateString('vi-VN', { day: '2-digit', month: '2-digit', year: 'numeric' });

    await prisma.notification.create({
      data: {
        userId,
        type: 'plan_purchase',
        icon: '🎉',
        title: `Kích hoạt ${pkg.name} thành công!`,
        message: `Bạn đã nâng cấp lên ${pkg.name} — ${pkg.dailyRequestLimit} lượt AI/ngày. Hạn dùng: ${expiryStr}. Bạn nhận được +${xpReward} XP!`,
      },
    });

    await sendTelegramNotification(
      `💰 Thanh toán mới!\n` +
      `👤 User ID: ${userId}\n` +
      `📦 Gói: ${pkg.name}\n` +
      `💵 Số tiền: ${new Intl.NumberFormat('vi-VN').format(amount)}đ\n` +
      `📅 Hạn dùng: ${expiryStr}\n` +
      `⭐ XP: +${xpReward}`
    );

    console.log(`[SePay] Order processed: userId=${userId}, plan=${pkg.plan}, expires=${newExpiresAt.toISOString()}`);
  } catch (err) {
    console.error('[SePay] processOrder error:', err);
  }
}

async function sendTelegramNotification(message) {
  try {
    const token = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;
    if (!token || !chatId) return;

    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: message }),
    });
  } catch (err) {
    console.error('[Telegram] Error:', err.message);
  }
}

// =============================================================================
// Từ đây: admin routes — yêu cầu ADMIN_API_KEY header
// =============================================================================

// GET /api/sepay/transactions — danh sách giao dịch
router.get('/transactions', requireApiKey, async (req, res) => {
  try {
    const { since_id, limit = 100, from, to } = req.query;
    const where = {};
    if (since_id) where.sepayId = { gt: parseInt(since_id) };
    if (from || to) {
      where.transactionDate = {};
      if (from) where.transactionDate.gte = new Date(from);
      if (to) where.transactionDate.lte = new Date(to + ' 23:59:59');
    }

    const transactions = await prisma.sepayTransaction.findMany({
      where,
      take: Math.min(parseInt(limit), 5000),
      orderBy: { sepayId: 'asc' },
      include: {
        user: { select: { id: true, fullName: true, email: true } },
        planPackage: { select: { id: true, name: true, plan: true, dailyRequestLimit: true, durationDays: true } },
      },
    });

    res.json({ success: true, data: transactions, count: transactions.length });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/sepay/balance — số dư tài khoản qua SePay API
router.get('/balance', requireApiKey, async (req, res) => {
  try {
    const token = process.env.SEPAY_API_TOKEN;
    if (!token) return res.status(500).json({ success: false, error: 'SEPAY_API_TOKEN not configured' });

    const response = await fetch('https://my.sepay.vn/userapi/transactions/list', {
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    });

    if (!response.ok) {
      return res.status(response.status).json({ success: false, error: `SePay API error: ${response.status}` });
    }

    res.json({ success: true, data: await response.json() });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/sepay/qr?amount=50000&code=SEVQR+U3P2 — tạo QR thanh toán
router.get('/qr', async (req, res) => {
  try {
    const { amount, code = '', account: accountOverride } = req.query;

    const bankAccount = await prisma.sepayBankAccount.findFirst({ where: { isActive: true } });

    const bankCode = bankAccount?.bankCode || 'ICB';
    const bankName = bankAccount?.bankName || process.env.SEPAY_BANK_NAME || 'Vietinbank';
    const accountNumber = accountOverride || bankAccount?.accountNumber || process.env.SEPAY_ACCOUNT_NUMBER || '';
    const accountName = bankAccount?.accountName || process.env.SEPAY_ACCOUNT_NAME || '';

    if (!accountNumber) {
      return res.status(400).json({ success: false, error: 'No bank account configured' });
    }

    const params = new URLSearchParams({
      acc: accountNumber,
      bank: bankCode === 'ICB' ? 'Vietinbank' : bankName,
      ...(amount && { amount: amount.toString() }),
      des: code || 'SEVQR',
    });

    const qrUrl = `https://qr.sepay.vn/img?${params.toString()}`;
    res.json({ success: true, data: { qrUrl, bankName, accountNumber, accountName, amount: amount || null, code: code || null } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/sepay/order/:code/status — kiểm tra trạng thái thanh toán
router.get('/order/:code/status', async (req, res) => {
  try {
    const { code } = req.params;
    if (!code) return res.status(400).json({ success: false, error: 'code is required' });

    const transaction = await prisma.sepayTransaction.findFirst({
      where: { code },
      include: {
        user: { select: { id: true, fullName: true, plan: true, planExpiresAt: true } },
        planPackage: { select: { id: true, name: true, plan: true, dailyRequestLimit: true, durationDays: true } },
      },
    });

    if (!transaction) {
      return res.json({ success: true, data: { paid: false, message: 'Chưa có giao dịch' } });
    }
    if (transaction.status === 'received') {
      return res.json({ success: true, data: { paid: false, status: 'pending', message: 'Đang chờ xử lý' } });
    }
    if (transaction.status === 'processed') {
      return res.json({
        success: true,
        data: {
          paid: true,
          plan: transaction.planPackage?.plan || transaction.user?.plan || null,
          dailyLimit: transaction.planPackage?.dailyRequestLimit || null,
          packageName: transaction.planPackage?.name || null,
          durationDays: transaction.planPackage?.durationDays || null,
          expiresAt: transaction.user?.planExpiresAt || null,
        },
      });
    }

    res.json({ success: true, data: { paid: false, status: transaction.status } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/sepay/order — tạo mã đơn hàng cho user (cần userId từ client)
// Trong standalone server, userId được truyền qua body (client tự authenticate với Excel_trainer)
router.post('/order', async (req, res) => {
  try {
    const { userId, packageId } = req.body;
    if (!userId) return res.status(400).json({ success: false, error: 'userId is required' });

    const packageInfo = packageId
      ? await prisma.planPackage.findUnique({ where: { id: packageId } })
      : null;

    const orderCode = packageId ? `SEVQR U${userId}P${packageId}` : `SEVQR U${userId}`;

    res.json({
      success: true,
      data: {
        orderCode,
        userId,
        packageId: packageId || null,
        amount: packageInfo?.price || null,
        plan: packageInfo?.plan || null,
        dailyLimit: packageInfo?.dailyRequestLimit || null,
        durationDays: packageInfo?.durationDays || null,
        packageName: packageInfo?.name || null,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// CRUD tài khoản ngân hàng (admin)
router.get('/bank-accounts', requireApiKey, async (_req, res) => {
  try {
    res.json({ success: true, data: await prisma.sepayBankAccount.findMany({ orderBy: { id: 'asc' } }) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.post('/bank-accounts', requireApiKey, async (req, res) => {
  try {
    const { bankName, bankCode, accountNumber, accountName } = req.body;
    if (!bankName || !bankCode || !accountNumber || !accountName) {
      return res.status(400).json({ success: false, error: 'Missing required fields' });
    }
    res.json({ success: true, data: await prisma.sepayBankAccount.create({ data: { bankName, bankCode, accountNumber, accountName } }) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.put('/bank-accounts/:id', requireApiKey, async (req, res) => {
  try {
    const { bankName, bankCode, accountNumber, accountName, isActive } = req.body;
    res.json({
      success: true,
      data: await prisma.sepayBankAccount.update({
        where: { id: parseInt(req.params.id) },
        data: { bankName, bankCode, accountNumber, accountName, isActive },
      }),
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

router.delete('/bank-accounts/:id', requireApiKey, async (req, res) => {
  try {
    await prisma.sepayBankAccount.delete({ where: { id: parseInt(req.params.id) } });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

export default router;
