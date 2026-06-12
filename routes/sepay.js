import express from 'express';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'secret_key';

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
    // ── Log ngay khi nhận request, trước mọi kiểm tra ──
    console.log('\n' + '─'.repeat(50));
    console.log('📨 WEBHOOK REQUEST NHẬN ĐƯỢC');
    console.log(`   Thời gian : ${new Date().toLocaleString('vi-VN')}`);
    console.log(`   Headers   :`, {
      'content-type': req.headers['content-type'],
      'x-sepay-signature': req.headers['x-sepay-signature'] || '(không có)',
      'x-sepay-timestamp': req.headers['x-sepay-timestamp'] || '(không có)',
    });
    console.log('─'.repeat(50));

    const sig = req.headers['x-sepay-signature'];
    const timestamp = req.headers['x-sepay-timestamp'] || '';

    if (!sig) {
      console.error('❌ Thiếu header x-sepay-signature — SePay chưa cấu hình HMAC?');
      // Vẫn tiếp tục xử lý nếu chưa bật HMAC trên SePay dashboard
    }

    const SECRET_KEY = process.env.SEPAY_WEBHOOK_SECRET;
    if (!SECRET_KEY) {
      console.error('❌ SEPAY_WEBHOOK_SECRET chưa set trong .env');
      return res.status(500).json({ success: false, error: 'Server misconfigured' });
    }

    // req.body là Buffer (raw) do express.raw() trong index.js
    const rawBody = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : JSON.stringify(req.body);
    console.log('   Raw body  :', rawBody);

    let payload;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      console.error('❌ Body không phải JSON hợp lệ');
      return res.status(400).json({ success: false, error: 'Invalid JSON body' });
    }

    // Kiểm tra HMAC nếu SePay có gửi signature
    let validSig = true; // mặc định pass nếu không có sig (SePay chưa bật HMAC)
    if (sig) {
      // SePay hỗ trợ nhiều format — thử tất cả
      // Lưu ý: nếu secret có prefix "whsec_" thì thử cả 2 (có và không có prefix)
      const secrets = [SECRET_KEY];
      if (SECRET_KEY.startsWith('whsec_')) {
        secrets.push(SECRET_KEY.slice(6)); // thử bỏ prefix whsec_
      }

      validSig = false;
      for (const secret of secrets) {
        const h1 = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
        const h2 = 'sha256=' + h1;
        const h3 = 'sha256=' + crypto.createHmac('sha256', secret).update(timestamp + '.' + rawBody).digest('hex');
        console.log(`   HMAC check (secret=${secret.slice(0, 8)}...): sig=${sig}`);
        console.log(`     hmac plain  : ${h1}`);
        console.log(`     hmac sha256=: ${h2}`);
        console.log(`     hmac ts.body: ${h3}`);
        if (sig === h1 || sig === h2 || sig === h3) {
          validSig = true;
          console.log('   ✅ HMAC hợp lệ');
          break;
        }
      }

      if (!validSig) {
        console.error('❌ HMAC không khớp — kiểm tra lại SEPAY_WEBHOOK_SECRET trong .env');
        return res.status(401).json({ success: false, error: 'Invalid signature' });
      }
    } else {
      console.warn('⚠️  Không có signature — tiếp tục xử lý (chế độ không HMAC)');
    }

    // Trả về NGAY trong 30s (yêu cầu của SePay), xử lý bất đồng bộ sau
    res.json({ success: true });

    setImmediate(async () => {
      // QUAN TRỌNG: phải try/catch toàn bộ — lỗi trong setImmediate không được
      // route handler bắt, unhandled rejection sẽ crash cả server
      try {
        const { id, transferType, transferAmount, content, accountNumber, transactionDate, gateway } = payload;
        let { code } = payload;

        // In rõ thông tin chuyển khoản ra console
        console.log('\n' + '═'.repeat(50));
        console.log('💰 CHUYỂN KHOẢN MỚI TỪ SEPAY');
        console.log('═'.repeat(50));
        console.log(`  SePay ID   : ${id}`);
        console.log(`  Loại       : ${transferType === 'in' ? '📥 Tiền vào' : '📤 Tiền ra'}`);
        console.log(`  Số tiền    : ${new Intl.NumberFormat('vi-VN').format(transferAmount)}đ`);
        console.log(`  Ngân hàng  : ${gateway || 'N/A'}`);
        console.log(`  Tài khoản  : ${accountNumber || 'N/A'}`);
        console.log(`  Nội dung   : ${content || '(trống)'}`);
        console.log(`  Mã đơn     : ${code || '(chưa extract)'}`);
        console.log(`  Thời gian  : ${transactionDate}`);
        console.log('═'.repeat(50) + '\n');

        if (transferType !== 'in') {
          console.log(`[SePay] Bỏ qua — tiền ra (${transferType})`);
          return;
        }

        // Extract code từ content nếu SePay chưa parse
        // Hỗ trợ cả format mới (EX + 6 ký tự) lẫn format cũ (U{id}P{id})
        if (!code && content) {
          const newFmt = content.match(/SEVQR\s+(EX[A-Z0-9]{6})/i);
          const oldFmt = content.match(/SEVQR\s+(U\d+P?\d*)/i);
          const match = newFmt || oldFmt;
          if (match) {
            code = match[1].toUpperCase();
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
      } catch (err) {
        // P2002 = trùng sepayId do race 2 webhook đến cùng lúc — an toàn bỏ qua
        if (err?.code === 'P2002') {
          console.log(`[SePay] Duplicate (race) ignored: sepayId=${payload?.id}`);
        } else {
          console.error('[SePay] Async processing error:', err);
        }
      }
    });
  } catch (err) {
    console.error('[SePay] Webhook error:', err);
  }
});

// Xử lý đơn hàng mua gói
// Ưu tiên tra cứu Order table (code mới EX...) → fallback code cũ U{id}P{id}
async function processOrder(code, amount, transactionId, gateway) {
  try {
    const cleanCode = code.replace(/^SEVQR\s*/i, '').trim().toUpperCase();

    let userId = null;
    let packageId = null;
    let orderId = null;

    // Format mới: tra cứu Order table theo code random
    const order = await prisma.order.findUnique({ where: { code: cleanCode } });
    if (order) {
      // Kiểm tra Order chưa hết hạn và chưa paid
      if (order.status === 'paid') {
        console.warn(`[SePay] Order already paid: code=${cleanCode}`);
        return;
      }
      if (order.status === 'expired' || new Date() > new Date(order.expiresAt)) {
        console.warn(`[SePay] Order expired: code=${cleanCode}`);
        await prisma.sepayTransaction.update({ where: { id: transactionId }, data: { status: 'failed' } });
        return;
      }
      userId = order.userId;
      packageId = order.packageId;
      orderId = order.id;
    } else {
      // Fallback: format cũ U{userId}P{packageId}
      const upMatch = cleanCode.match(/^U(\d+)P(\d+)$/);
      if (upMatch) {
        userId = parseInt(upMatch[1]);
        packageId = parseInt(upMatch[2]);
      } else {
        const uMatch = cleanCode.match(/^U(\d+)$/);
        if (uMatch) userId = parseInt(uMatch[1]);
      }
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
      select: { plan: true, planExpiresAt: true },
    });

    // Còn hạn → cộng dồn ngày vào hạn cũ; hết hạn → tính từ hôm nay
    const stillActive = currentUser?.planExpiresAt && new Date(currentUser.planExpiresAt) > now;
    const baseDate = stillActive ? new Date(currentUser.planExpiresAt) : now;
    const newExpiresAt = new Date(baseDate.getTime() + pkg.durationDays * 86400000);

    // KHÔNG hạ cấp: giữ gói CAO NHẤT giữa gói đang còn hạn và gói vừa mua.
    // VD: đang Pro mà mua thêm Thường → vẫn Pro (+ ngày), không bị tụt xuống Thường.
    const RANK = { free: 0, regular: 1, pro: 2 };
    const currentPlan = stillActive ? (currentUser.plan || 'free') : 'free';
    const resultPlan = (RANK[pkg.plan] ?? 0) >= (RANK[currentPlan] ?? 0) ? pkg.plan : currentPlan;

    const xpReward = Math.floor(pkg.price / 1000);

    await prisma.user.update({
      where: { id: userId },
      data: {
        plan: resultPlan,
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
      data: { status: 'processed', userId, planPackageId: pkg.id, orderId: orderId || undefined },
    });

    // Đánh dấu Order đã thanh toán
    if (orderId) {
      await prisma.order.update({ where: { id: orderId }, data: { status: 'paid' } });
    }

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

// GET /api/sepay/order/:code/status — kiểm tra user đã nạp tiền thành công chưa
// Frontend polling mỗi 3-5s sau khi hiện QR
// code: raw code của order (VD: "EXA3F7K2"), không cần prefix SEVQR
router.get('/order/:code/status', async (req, res) => {
  try {
    const code = (req.params.code || '').replace(/^SEVQR\s*/i, '').trim().toUpperCase();
    if (!code) return res.status(400).json({ success: false, error: 'code is required' });

    // ─── Ưu tiên tra bảng orders (format mới EX...) ───
    const order = await prisma.order.findUnique({
      where: { code },
      include: {
        user: { select: { id: true, fullName: true, plan: true, planExpiresAt: true } },
        package: { select: { id: true, name: true, plan: true, dailyRequestLimit: true, durationDays: true } },
        sepayTransaction: { select: { sepayId: true, amount: true, transactionDate: true } },
      },
    });

    if (order) {
      if (order.status === 'paid') {
        return res.json({
          success: true,
          data: {
            paid: true,
            status: 'paid',
            message: 'Thanh toán thành công',
            plan: order.package?.plan || order.user?.plan || null,
            dailyLimit: order.package?.dailyRequestLimit || null,
            packageName: order.package?.name || null,
            durationDays: order.package?.durationDays || null,
            expiresAt: order.user?.planExpiresAt || null,
            paidAmount: order.sepayTransaction?.amount || null,
            paidAt: order.sepayTransaction?.transactionDate || null,
          },
        });
      }
      if (order.status === 'refunded') {
        return res.json({ success: true, data: { paid: false, status: 'refunded', message: 'Đơn đã được hoàn tiền' } });
      }
      if (order.status === 'expired' || new Date() > new Date(order.expiresAt)) {
        return res.json({ success: true, data: { paid: false, status: 'expired', message: 'Đơn hàng đã hết hạn, vui lòng tạo đơn mới' } });
      }
      // pending
      return res.json({
        success: true,
        data: { paid: false, status: 'pending', message: 'Đang chờ thanh toán', amount: order.amount, expiresAt: order.expiresAt },
      });
    }

    // ─── Fallback: tra sepay_transactions (format cũ U{id}P{id}) ───
    const transaction = await prisma.sepayTransaction.findFirst({
      where: { code },
      include: {
        user: { select: { id: true, fullName: true, plan: true, planExpiresAt: true } },
        planPackage: { select: { id: true, name: true, plan: true, dailyRequestLimit: true, durationDays: true } },
      },
    });

    if (!transaction) {
      return res.json({ success: true, data: { paid: false, status: 'not_found', message: 'Không tìm thấy đơn hàng' } });
    }
    if (transaction.status === 'processed') {
      return res.json({
        success: true,
        data: {
          paid: true,
          status: 'paid',
          plan: transaction.planPackage?.plan || transaction.user?.plan || null,
          dailyLimit: transaction.planPackage?.dailyRequestLimit || null,
          packageName: transaction.planPackage?.name || null,
          durationDays: transaction.planPackage?.durationDays || null,
          expiresAt: transaction.user?.planExpiresAt || null,
        },
      });
    }

    res.json({ success: true, data: { paid: false, status: transaction.status, message: 'Đang chờ xử lý' } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Helper: tạo random code 8 ký tự (EX + 6 random)
function generateOrderCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // bỏ I,O,0,1 dễ nhầm
  let result = 'EX';
  for (let i = 0; i < 6; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

// POST /api/sepay/order — tạo đơn hàng với random code
// userId lấy từ JWT (ưu tiên) hoặc body (fallback cho service nội bộ)
router.post('/order', async (req, res) => {
  try {
    const { packageId } = req.body;

    // Ưu tiên userId từ JWT để chống spoof
    let userId = null;
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token) {
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        userId = decoded.id || decoded.userId;
      } catch { /* token sai → thử body */ }
    }
    if (!userId && req.body.userId) userId = parseInt(req.body.userId);

    if (!userId) return res.status(400).json({ success: false, error: 'userId is required' });

    const packageInfo = packageId
      ? await prisma.planPackage.findUnique({ where: { id: packageId } })
      : null;

    if (packageId && !packageInfo) {
      return res.status(404).json({ success: false, error: 'Package not found' });
    }

    // Tạo code unique, retry nếu trùng (cực kỳ hiếm)
    let code;
    for (let attempt = 0; attempt < 5; attempt++) {
      code = generateOrderCode();
      const exists = await prisma.order.findUnique({ where: { code } });
      if (!exists) break;
    }

    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // hết hạn sau 24h
    const order = await prisma.order.create({
      data: {
        code,
        userId: parseInt(userId),
        packageId: packageId ? parseInt(packageId) : null,
        amount: packageInfo?.price || 0,
        expiresAt,
      },
    });

    res.json({
      success: true,
      data: {
        orderId: order.id,
        orderCode: `SEVQR ${code}`,  // Nội dung CK user phải nhập
        code,
        userId: parseInt(userId),
        packageId: packageId ? parseInt(packageId) : null,
        amount: packageInfo?.price || null,
        plan: packageInfo?.plan || null,
        dailyLimit: packageInfo?.dailyRequestLimit || null,
        durationDays: packageInfo?.durationDays || null,
        packageName: packageInfo?.name || null,
        expiresAt,
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
