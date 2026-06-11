import express from 'express';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const router = express.Router();

function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'] || req.query.api_key;
  if (!process.env.ADMIN_API_KEY || key !== process.env.ADMIN_API_KEY) {
    return res.status(401).json({ success: false, error: 'Unauthorized' });
  }
  next();
}

router.use(requireApiKey);

// =============================================================================
// GET /admin/stats — tổng quan hệ thống
// =============================================================================
router.get('/stats', async (_req, res) => {
  try {
    const now = new Date();
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const startOf7Days = new Date(now.getTime() - 7 * 86400000);
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

    const [
      totalUsers,
      activeToday,
      activeLast7Days,
      planBreakdown,
      totalRevenue,
      revenueThisMonth,
      recentTransactions,
      newUsersToday,
      newUsersThisMonth,
    ] = await Promise.all([
      // Tổng users
      prisma.user.count({ where: { isActive: true } }),

      // Active hôm nay (có activity log hôm nay)
      prisma.activityLog.count({
        where: { activityDate: { gte: startOfToday } },
      }),

      // Active 7 ngày
      prisma.activityLog.count({
        where: { activityDate: { gte: startOf7Days } },
      }),

      // Phân bổ theo plan
      prisma.user.groupBy({
        by: ['plan'],
        _count: { id: true },
        where: { isActive: true },
      }),

      // Tổng doanh thu (giao dịch processed)
      prisma.sepayTransaction.aggregate({
        _sum: { amount: true },
        where: { status: 'processed' },
      }),

      // Doanh thu tháng này
      prisma.sepayTransaction.aggregate({
        _sum: { amount: true },
        where: { status: 'processed', transactionDate: { gte: startOfMonth } },
      }),

      // 10 giao dịch gần nhất
      prisma.sepayTransaction.findMany({
        take: 10,
        orderBy: { transactionDate: 'desc' },
        where: { status: 'processed' },
        include: {
          user: { select: { id: true, fullName: true, email: true, username: true } },
          planPackage: { select: { name: true, plan: true } },
        },
      }),

      // Users mới hôm nay
      prisma.user.count({ where: { createdAt: { gte: startOfToday } } }),

      // Users mới tháng này
      prisma.user.count({ where: { createdAt: { gte: startOfMonth } } }),
    ]);

    // Chuyển planBreakdown thành object { free: n, regular: n, pro: n }
    const plans = { free: 0, regular: 0, pro: 0 };
    for (const row of planBreakdown) {
      plans[row.plan] = row._count.id;
    }

    res.json({
      success: true,
      data: {
        users: {
          total: totalUsers,
          newToday: newUsersToday,
          newThisMonth: newUsersThisMonth,
          activeToday,
          activeLast7Days,
          byPlan: plans,
        },
        revenue: {
          total: Math.round(totalRevenue._sum.amount || 0),
          thisMonth: Math.round(revenueThisMonth._sum.amount || 0),
          recentTransactions: recentTransactions.map(t => ({
            id: t.id,
            sepayId: t.sepayId,
            amount: Math.round(t.amount),
            transactionDate: t.transactionDate,
            userId: t.userId,
            userName: t.user?.fullName || t.user?.username || null,
            userEmail: t.user?.email || null,
            package: t.planPackage?.name || null,
            plan: t.planPackage?.plan || null,
            content: t.content,
          })),
        },
      },
    });
  } catch (err) {
    console.error('[Admin] Stats error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// =============================================================================
// GET /admin/users — danh sách users kèm plan + lịch sử thanh toán
// Query: ?page=1&limit=20&plan=pro&search=name
// =============================================================================
router.get('/users', async (req, res) => {
  try {
    const { page = 1, limit = 20, plan, search } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const where = { isActive: true };
    if (plan) where.plan = plan;
    if (search) {
      where.OR = [
        { fullName: { contains: search } },
        { email: { contains: search } },
        { username: { contains: search } },
      ];
    }

    const [users, total] = await Promise.all([
      prisma.user.findMany({
        where,
        skip,
        take: parseInt(limit),
        orderBy: { createdAt: 'desc' },
        select: {
          id: true,
          username: true,
          fullName: true,
          email: true,
          phone: true,
          plan: true,
          planExpiresAt: true,
          xp: true,
          level: true,
          createdAt: true,
          requestDailyCount: true,
          // Đếm số lần đã mua gói
          sepayTransactions: {
            where: { status: 'processed' },
            select: { amount: true, transactionDate: true, planPackageId: true },
            orderBy: { transactionDate: 'desc' },
          },
        },
      }),
      prisma.user.count({ where }),
    ]);

    res.json({
      success: true,
      data: users.map(u => ({
        id: u.id,
        username: u.username,
        fullName: u.fullName,
        email: u.email,
        phone: u.phone,
        plan: u.plan,
        planExpiresAt: u.planExpiresAt,
        xp: u.xp,
        level: u.level,
        createdAt: u.createdAt,
        requestDailyCount: u.requestDailyCount,
        totalSpent: Math.round(u.sepayTransactions.reduce((s, t) => s + t.amount, 0)),
        purchaseCount: u.sepayTransactions.length,
        lastPurchase: u.sepayTransactions[0]?.transactionDate || null,
        // Mã QR của user — dùng để xác định ai chuyển khoản
        orderCodeFormat: `SEVQR U${u.id}P{packageId}`,
      })),
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / parseInt(limit)),
      },
    });
  } catch (err) {
    console.error('[Admin] Users error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// =============================================================================
// GET /admin/users/:id — chi tiết 1 user + toàn bộ lịch sử giao dịch
// =============================================================================
router.get('/users/:id', async (req, res) => {
  try {
    const userId = parseInt(req.params.id);

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        username: true,
        fullName: true,
        email: true,
        phone: true,
        role: true,
        plan: true,
        planExpiresAt: true,
        xp: true,
        level: true,
        streak: true,
        createdAt: true,
        requestDailyCount: true,
        requestDailyReset: true,
        sepayTransactions: {
          orderBy: { transactionDate: 'desc' },
          include: {
            planPackage: { select: { name: true, plan: true, dailyRequestLimit: true, durationDays: true } },
          },
        },
        planTransactions: {
          orderBy: { createdAt: 'desc' },
          take: 20,
        },
        activityLogs: {
          orderBy: { activityDate: 'desc' },
          take: 30,
        },
      },
    });

    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    const totalSpent = user.sepayTransactions
      .filter(t => t.status === 'processed')
      .reduce((s, t) => s + t.amount, 0);

    res.json({
      success: true,
      data: {
        ...user,
        totalSpent: Math.round(totalSpent),
        // Mã nhận diện trong nội dung chuyển khoản
        paymentCode: `SEVQR U${user.id}`,
        orderCodeExample: `SEVQR U${user.id}P1 (P1 = packageId)`,
      },
    });
  } catch (err) {
    console.error('[Admin] User detail error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// =============================================================================
// GET /admin/transactions — toàn bộ giao dịch SePay
// Query: ?status=processed&from=2026-01-01&to=2026-12-31
// =============================================================================
router.get('/transactions', async (req, res) => {
  try {
    const { status, from, to, page = 1, limit = 50 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const where = {};
    if (status) where.status = status;
    if (from || to) {
      where.transactionDate = {};
      if (from) where.transactionDate.gte = new Date(from);
      if (to) where.transactionDate.lte = new Date(to + 'T23:59:59');
    }

    const [transactions, total] = await Promise.all([
      prisma.sepayTransaction.findMany({
        where,
        skip,
        take: parseInt(limit),
        orderBy: { transactionDate: 'desc' },
        include: {
          user: { select: { id: true, fullName: true, email: true, username: true } },
          planPackage: { select: { name: true, plan: true } },
        },
      }),
      prisma.sepayTransaction.count({ where }),
    ]);

    res.json({
      success: true,
      data: transactions,
      pagination: { total, page: parseInt(page), limit: parseInt(limit), totalPages: Math.ceil(total / parseInt(limit)) },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// =============================================================================
// POST /admin/users/:id/grant-plan — admin kích hoạt gói tay cho user
// Dùng khi: webhook fail, user chuyển đúng tiền nhưng sai nội dung
// Body: { packageId, note, amount }
// =============================================================================
router.post('/users/:id/grant-plan', async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { packageId, note, amount } = req.body;

    if (!packageId) return res.status(400).json({ success: false, error: 'packageId is required' });

    const pkg = await prisma.planPackage.findUnique({ where: { id: parseInt(packageId) } });
    if (!pkg) return res.status(404).json({ success: false, error: 'Package not found' });

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    const now = new Date();
    const baseDate = user.planExpiresAt && new Date(user.planExpiresAt) > now
      ? new Date(user.planExpiresAt)
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
        amount: amount ? parseInt(amount) : pkg.price,
        description: `[Admin manual] ${note || 'Kích hoạt tay bởi admin'} — ${pkg.name}`,
      },
    });

    const expiryStr = newExpiresAt.toLocaleDateString('vi-VN');
    await prisma.notification.create({
      data: {
        userId,
        type: 'plan_purchase',
        icon: '🎉',
        title: `Kích hoạt ${pkg.name} thành công!`,
        message: `Gói của bạn đã được kích hoạt bởi admin. ${pkg.dailyRequestLimit} lượt AI/ngày, hạn dùng: ${expiryStr}.`,
      },
    });

    console.log(`[Admin] Manual plan grant: userId=${userId}, plan=${pkg.plan}, by admin`);
    res.json({
      success: true,
      message: `Đã kích hoạt ${pkg.name} cho user ${userId}`,
      data: { userId, plan: pkg.plan, expiresAt: newExpiresAt, xpRewarded: xpReward },
    });
  } catch (err) {
    console.error('[Admin] Grant plan error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// =============================================================================
// POST /admin/transactions/:sepayId/process — xử lý lại 1 transaction thủ công
// Dùng khi webhook nhận được nhưng processOrder bị lỗi
// Body: { userId } (override userId nếu cần)
// =============================================================================
router.post('/transactions/:sepayId/process', async (req, res) => {
  try {
    const sepayId = parseInt(req.params.sepayId);
    const { userId: overrideUserId } = req.body;

    const transaction = await prisma.sepayTransaction.findUnique({
      where: { sepayId },
      include: { order: true },
    });

    if (!transaction) return res.status(404).json({ success: false, error: 'Transaction not found' });
    if (transaction.status === 'processed') {
      return res.status(400).json({ success: false, error: 'Transaction already processed' });
    }

    // Xác định userId: từ override → từ order → từ transaction
    const targetUserId = overrideUserId
      ? parseInt(overrideUserId)
      : transaction.userId || transaction.order?.userId;

    if (!targetUserId) {
      return res.status(400).json({ success: false, error: 'Cannot resolve userId. Pass userId in body.' });
    }

    // Xác định package: từ order → từ transaction → match theo amount
    const packageId = transaction.order?.packageId || transaction.planPackageId;
    const pkg = packageId
      ? await prisma.planPackage.findUnique({ where: { id: packageId } })
      : await prisma.planPackage.findFirst({ where: { price: Math.round(transaction.amount), isActive: true } });

    if (!pkg) return res.status(400).json({ success: false, error: 'Cannot resolve package. No matching plan for this amount.' });

    const user = await prisma.user.findUnique({ where: { id: targetUserId } });
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    const now = new Date();
    const baseDate = user.planExpiresAt && new Date(user.planExpiresAt) > now
      ? new Date(user.planExpiresAt)
      : now;
    const newExpiresAt = new Date(baseDate.getTime() + pkg.durationDays * 86400000);
    const xpReward = Math.floor(pkg.price / 1000);

    await prisma.user.update({
      where: { id: targetUserId },
      data: { plan: pkg.plan, planExpiresAt: newExpiresAt, requestDailyCount: 0, xp: { increment: xpReward } },
    });

    await prisma.planTransaction.create({
      data: {
        userId: targetUserId,
        type: 'plan_purchase',
        planType: pkg.plan,
        expiresAt: newExpiresAt,
        amount: Math.round(transaction.amount),
        description: `[Admin reprocess] sepayId=${sepayId} — ${pkg.name}`,
      },
    });

    await prisma.sepayTransaction.update({
      where: { sepayId },
      data: { status: 'processed', userId: targetUserId, planPackageId: pkg.id },
    });

    if (transaction.order) {
      await prisma.order.update({ where: { id: transaction.order.id }, data: { status: 'paid' } });
    }

    const expiryStr = newExpiresAt.toLocaleDateString('vi-VN');
    await prisma.notification.create({
      data: {
        userId: targetUserId,
        type: 'plan_purchase',
        icon: '🎉',
        title: `Kích hoạt ${pkg.name} thành công!`,
        message: `Thanh toán của bạn đã được xác nhận. ${pkg.dailyRequestLimit} lượt AI/ngày, hạn dùng: ${expiryStr}.`,
      },
    });

    console.log(`[Admin] Reprocessed transaction: sepayId=${sepayId}, userId=${targetUserId}`);
    res.json({
      success: true,
      message: `Đã xử lý transaction sepayId=${sepayId} cho user ${targetUserId}`,
      data: { userId: targetUserId, plan: pkg.plan, expiresAt: newExpiresAt },
    });
  } catch (err) {
    console.error('[Admin] Reprocess error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// =============================================================================
// POST /admin/transactions/:sepayId/refund — đánh dấu hoàn tiền
// Chỉ cập nhật DB + ghi chú, tiền thật admin tự chuyển khoản tay
// Body: { note }
// =============================================================================
router.post('/transactions/:sepayId/refund', async (req, res) => {
  try {
    const sepayId = parseInt(req.params.sepayId);
    const { note } = req.body;

    const transaction = await prisma.sepayTransaction.findUnique({
      where: { sepayId },
      include: { order: true, user: { select: { id: true, fullName: true, email: true } } },
    });

    if (!transaction) return res.status(404).json({ success: false, error: 'Transaction not found' });

    await prisma.sepayTransaction.update({
      where: { sepayId },
      data: { status: 'refunded' },
    });

    if (transaction.order) {
      await prisma.order.update({
        where: { id: transaction.order.id },
        data: { status: 'refunded', note: note || 'Hoàn tiền bởi admin' },
      });
    }

    if (transaction.userId) {
      await prisma.notification.create({
        data: {
          userId: transaction.userId,
          type: 'system',
          icon: '💸',
          title: 'Hoàn tiền thanh toán',
          message: `Giao dịch ${new Intl.NumberFormat('vi-VN').format(transaction.amount)}đ đã được hoàn trả. ${note || ''}`,
        },
      });
    }

    res.json({
      success: true,
      message: 'Đã đánh dấu hoàn tiền. Nhớ chuyển khoản tay cho user.',
      data: {
        sepayId,
        amount: Math.round(transaction.amount),
        user: transaction.user,
        note: note || null,
      },
    });
  } catch (err) {
    console.error('[Admin] Refund error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// =============================================================================
// GET /admin/orders — danh sách orders (pending, expired, paid)
// =============================================================================
router.get('/orders', async (req, res) => {
  try {
    const { status, page = 1, limit = 50 } = req.query;
    const skip = (parseInt(page) - 1) * parseInt(limit);

    const where = {};
    if (status) where.status = status;

    // Tự động expire các order quá hạn
    await prisma.order.updateMany({
      where: { status: 'pending', expiresAt: { lt: new Date() } },
      data: { status: 'expired' },
    });

    const [orders, total] = await Promise.all([
      prisma.order.findMany({
        where,
        skip,
        take: parseInt(limit),
        orderBy: { createdAt: 'desc' },
        include: {
          user: { select: { id: true, fullName: true, email: true, username: true } },
          package: { select: { name: true, plan: true, price: true } },
          sepayTransaction: { select: { sepayId: true, amount: true, status: true } },
        },
      }),
      prisma.order.count({ where }),
    ]);

    res.json({
      success: true,
      data: orders,
      pagination: { total, page: parseInt(page), limit: parseInt(limit), totalPages: Math.ceil(total / parseInt(limit)) },
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

export default router;
