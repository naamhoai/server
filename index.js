import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { existsSync, mkdirSync } from 'fs';
import { fileURLToPath } from 'url';
import path from 'path';

import sepayRouter from './routes/sepay.js';
import updateRouter from './routes/update.js';
import adminRouter from './routes/admin.js';
import authRouter from './routes/auth.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Đảm bảo thư mục releases tồn tại
const releasesDir = path.join(__dirname, 'releases');
if (!existsSync(releasesDir)) mkdirSync(releasesDir, { recursive: true });

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());

// Trust proxy headers từ ngrok/cloudflare/reverse proxy
app.set('trust proxy', 1);

// Rate limiting toàn server
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));

// SePay webhook cần raw body để verify HMAC chính xác
// Phải đặt TRƯỚC express.json()
app.use('/api/sepay/webhook', express.raw({ type: '*/*' }));

app.use(express.json());

// Routes
app.use('/api/auth', authRouter);
app.use('/api/sepay', sepayRouter);
app.use('/update', updateRouter);
app.use('/admin', adminRouter);

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', version: process.env.npm_package_version || '1.0.0', time: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`[Server] Running on port ${PORT} (${process.env.NODE_ENV || 'development'})`);
  console.log(`[Server] SePay webhook: POST http://localhost:${PORT}/api/sepay/webhook`);
  console.log(`[Server] Auto-update:   GET  http://localhost:${PORT}/update/latest.yml`);
  console.log(`[Server] Admin stats:   GET  http://localhost:${PORT}/admin/stats`);
});
