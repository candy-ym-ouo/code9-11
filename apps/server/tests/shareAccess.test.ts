import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Express } from 'express';
import request from 'supertest';
import bcrypt from 'bcryptjs';

const { shareImageForMock, raceRevocation } = vi.hoisted(() => ({
  shareImageForMock: vi.fn(),
  raceRevocation: vi.fn(),
}));

vi.mock('../src/services/assets.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/services/assets.js')>();
  return {
    ...actual,
    shareImageFor: shareImageForMock,
  };
});

let app: Express;
let tmpDir: string;
let ownerToken = '';
let libraryId = '';
let token: '' | string = '';
let cardId = '';
let assetId = '';

async function call(method: 'get' | 'post', url: string, body?: unknown, password?: string) {
  let req = request(app)[method](url);
  if (token) req = req.set('authorization', `Bearer ${token}`);
  if (password !== undefined) req = req.set('x-share-password', password);
  if (body !== undefined) req = req.send(body as object);
  return req;
}

async function getLatestLog() {
  const { getDb } = await import('../src/db.js');
  return getDb()
    .prepare('SELECT * FROM share_access_log ORDER BY at DESC, rowid DESC LIMIT 1')
    .get() as { allowed: number; deny_reason: string | null };
}

beforeAll(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'flil-share-test-'));
  process.env.DATABASE_URL = path.join(tmpDir, 'app.db');
  process.env.UPLOAD_DIR = path.join(tmpDir, 'uploads');
  process.env.THUMB_DIR = path.join(tmpDir, 'thumbs');
  process.env.SHARE_DIR = path.join(tmpDir, 'share');
  process.env.BACKUP_DIR = path.join(tmpDir, 'backups');
  process.env.JWT_SECRET = 'test-secret';
  process.env.WEATHER_PROVIDER = 'fixture';
  process.env.ENABLE_CLIMATE_BASELINE = 'false';

  const { createApp } = await import('../src/app.js');
  const { migrate, getDb, newId, nowIso } = await import('../src/db.js');
  migrate();
  app = createApp();

  const owner = await request(app).post('/api/auth/register').send({
    email: 'share-owner@test.local',
    password: 'password123',
    displayName: '分享测试',
  });
  ownerToken = owner.body.token;
  token = ownerToken;
  libraryId = owner.body.user.libraryId;
  const userId = (owner.body.user as { id: string; libraryId: string }).id;

  const card = await call('post', '/api/inspirations', { title: '分享安全测试' });
  cardId = card.body.id;

  const db = getDb();
  const ts = nowIso();
  assetId = newId();
  db.prepare(
    `INSERT INTO asset (id, library_id, inspiration_id, role, file_path, thumb_path, mime, width, height, bytes,
       sha256, shot_at, camera_model, lens, iso, aperture, shutter, has_gps_exif, palette,
       sun_elevation, sun_azimuth, weather_snapshot, created_at, updated_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(
    assetId,
    libraryId,
    cardId,
    'result',
    path.join(tmpDir, 'source-that-must-not-be-read.jpg'),
    null,
    'image/jpeg',
    1,
    1,
    1,
    null,
    null,
    null,
    null,
    null,
    null,
    null,
    0,
    '[]',
    null,
    null,
    null,
    ts,
    ts,
  );

  // 便于测试中直接构造撤销/过期/密码/非法模糊级别同时命中的边界数据。
  db.prepare(
    `INSERT INTO share_link (id, library_id, scope, scope_id, token, fuzz_level, password_hash,
       expires_at, revoked_at, created_by, view_count, created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
  ).run(
    newId(),
    libraryId,
    'inspiration',
    cardId,
    'invalid-on-all-dimensions',
    'g100',
    bcrypt.hashSync('correct-pass', 10),
    new Date(Date.now() - 60000).toISOString(),
    nowIso(),
    userId,
    0,
    ts,
  );
});

afterAll(async () => {
  const { closeDb } = await import('../src/db.js');
  closeDb();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

beforeEach(() => {
  shareImageForMock.mockReset();
  raceRevocation.mockReset();
});

describe('分享访问网关', () => {
  it('密码、过期、撤销和模糊级别在一次准入闸门中同时审计', async () => {
    const res = await request(app)
      .get('/api/share/invalid-on-all-dimensions')
      .set('x-share-password', 'wrong-pass');

    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('SHARE_REVOKED');
    const log = await getLatestLog();
    expect(log.allowed).toBe(0);
    expect(log.deny_reason?.split(',').sort()).toEqual([
      'expired',
      'fuzz_level_too_precise',
      'password_wrong',
      'revoked',
    ]);
  });

  it('并发撤销后，异步脱敏阶段恢复的请求不会发送图片', async () => {
    const created = await call(
      'post',
      '/api/share-links',
      {
        scope: 'inspiration',
        scopeId: cardId,
        fuzzLevel: 'g500',
        expiresInDays: 1,
      },
    );
    const shareTokenValue = created.body.token as string;
    const linkId = created.body.id as string;

    shareImageForMock.mockImplementation(async () => {
      await raceRevocation();
      return path.join(tmpDir, 'generated-after-revoke.jpg');
    });
    raceRevocation.mockImplementation(async () => {
      const { revokeShareLink } = await import('../src/services/share.js');
      revokeShareLink(linkId, libraryId);
    });

    token = '';
    const image = await request(app).get(`/api/share/${shareTokenValue}/assets/${assetId}`);
    token = ownerToken;

    expect(shareImageForMock).toHaveBeenCalledTimes(1);
    expect(image.status).toBe(401);
    expect(image.body.error.code).toBe('SHARE_REVOKED');
    expect(image.headers['content-type']).not.toContain('image/jpeg');
    expect(fs.existsSync(path.join(tmpDir, 'generated-after-revoke.jpg'))).toBe(false);

    const log = await getLatestLog();
    expect(log.allowed).toBe(0);
    expect(log.deny_reason).toBe('revoked');
  });

  it('有效分享图在同一次同步复查与读取后输出，并禁止缓存', async () => {
    const created = await call('post', '/api/share-links', {
      scope: 'inspiration',
      scopeId: cardId,
      fuzzLevel: 'g500',
      expiresInDays: 1,
    });
    const target = path.join(tmpDir, 'generated-valid.jpg');
    fs.writeFileSync(target, Buffer.from('valid-jpeg-bytes'));
    shareImageForMock.mockResolvedValue(target);

    token = '';
    const image = await request(app).get(`/api/share/${created.body.token}/assets/${assetId}`);

    expect(image.status).toBe(200);
    expect(image.headers['content-type']).toContain('image/jpeg');
    expect(image.headers['cache-control']).toBe('no-store');
    expect(image.body.toString()).toBe('valid-jpeg-bytes');
  });
});
