import express from 'express';
import { createReadStream, existsSync } from 'fs';
import { readdir, rename, stat } from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import multer from 'multer';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const RELEASES_DIR = path.join(__dirname, '..', 'releases');

const router = express.Router();

// Upload config: lưu file với tên gốc (overwrite nếu đã tồn tại)
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, RELEASES_DIR),
  filename: (_req, file, cb) => cb(null, file.originalname),
});
const upload = multer({ storage });

function requireApiKey(req, res, next) {
  const key = req.headers['x-api-key'] || req.query.api_key;
  if (!process.env.ADMIN_API_KEY || key !== process.env.ADMIN_API_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// =============================================================================
// GET /update/latest.yml
// electron-updater gọi endpoint này để kiểm tra version mới.
// File này được electron-builder tự generate khi build, rồi upload lên đây.
//
// Cấu hình electron-builder để dùng server này (thay vì GitHub):
//   "publish": { "provider": "generic", "url": "https://your-server.com/update" }
// =============================================================================
router.get('/latest.yml', (_req, res) => {
  const filePath = path.join(RELEASES_DIR, 'latest.yml');
  if (!existsSync(filePath)) {
    return res.status(404).send('No release available');
  }
  res.setHeader('Content-Type', 'text/yaml; charset=utf-8');
  createReadStream(filePath).pipe(res);
});

// =============================================================================
// GET /update/check — JSON version check (optional, cho custom logic)
// Trả về version hiện tại từ latest.yml nếu có, hoặc proxy GitHub releases
// =============================================================================
router.get('/check', async (_req, res) => {
  // Ưu tiên self-hosted nếu có latest.yml
  const localYml = path.join(RELEASES_DIR, 'latest.yml');
  if (existsSync(localYml)) {
    const content = (await import('fs')).readFileSync(localYml, 'utf8');
    const versionMatch = content.match(/^version:\s*(.+)$/m);
    const version = versionMatch?.[1]?.trim() || 'unknown';
    return res.json({ source: 'self-hosted', version, latestYmlUrl: '/update/latest.yml' });
  }

  // Fallback: GitHub releases API
  const owner = process.env.GITHUB_OWNER;
  const repo = process.env.GITHUB_REPO;
  if (!owner || !repo) {
    return res.status(404).json({ error: 'No release configured' });
  }

  try {
    const headers = { Accept: 'application/vnd.github+json' };
    if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;

    const response = await fetch(`https://api.github.com/repos/${owner}/${repo}/releases/latest`, { headers });
    if (!response.ok) {
      return res.status(response.status).json({ error: 'GitHub API error' });
    }
    const release = await response.json();
    res.json({
      source: 'github',
      version: release.tag_name?.replace(/^v/, ''),
      releaseUrl: release.html_url,
      publishedAt: release.published_at,
      assets: release.assets?.map(a => ({ name: a.name, size: a.size, downloadUrl: a.browser_download_url })),
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =============================================================================
// GET /update/:filename — serve installer file
// electron-updater tải file này sau khi đọc latest.yml
// Hỗ trợ: .exe, .dmg, .AppImage, .blockmap, v.v.
// =============================================================================
router.get('/:filename', (req, res) => {
  // path.basename ngăn path traversal (e.g. "../../etc/passwd")
  const filename = path.basename(req.params.filename);
  const filePath = path.join(RELEASES_DIR, filename);

  if (!existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }

  res.download(filePath, filename);
});

// =============================================================================
// POST /update/upload — upload release files (admin only)
// Dùng sau khi chạy: npm run build (electron-builder tạo ra file trong /release/)
//
// Upload bằng curl:
//   curl -X POST https://your-server.com/update/upload \
//     -H "x-api-key: YOUR_ADMIN_API_KEY" \
//     -F "files=@release/latest.yml" \
//     -F "files=@release/ExcelTutor Setup 1.0.0.exe"
// =============================================================================
router.post('/upload', requireApiKey, upload.array('files'), async (req, res) => {
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No files uploaded' });
  }
  const uploaded = req.files.map(f => ({ name: f.originalname, size: f.size }));
  console.log('[Update] Files uploaded:', uploaded.map(f => f.name).join(', '));
  res.json({ success: true, files: uploaded });
});

// =============================================================================
// GET /update — list release files (admin only)
// =============================================================================
router.get('/', requireApiKey, async (_req, res) => {
  try {
    const files = await readdir(RELEASES_DIR);
    const details = await Promise.all(
      files.map(async name => {
        const info = await stat(path.join(RELEASES_DIR, name));
        return { name, size: info.size, modifiedAt: info.mtime };
      })
    );
    res.json({ success: true, files: details });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =============================================================================
// DELETE /update/:filename — xóa release file (admin only)
// =============================================================================
router.delete('/:filename', requireApiKey, async (req, res) => {
  try {
    const filename = path.basename(req.params.filename);
    const filePath = path.join(RELEASES_DIR, filename);
    if (!existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }
    const { unlink } = await import('fs/promises');
    await unlink(filePath);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
