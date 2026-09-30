import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import type { FuzzLevel } from '@flil/shared';
import { getDb, newId, nowIso } from '../db.js';
import { config } from '../config.js';
import { errors } from '../http/errors.js';
import { assertShareFuzzLevel, isShareFuzzLevelAllowed } from './fuzzing.js';

export interface ShareLinkRow {
  id: string;
  library_id: string;
  scope: 'album' | 'inspiration';
  scope_id: string;
  token: string;
  fuzz_level: FuzzLevel;
  password_hash: string | null;
  expires_at: string;
  revoked_at: string | null;
  created_by: string;
  view_count: number;
  created_at: string;
}

export function createShareLink(params: {
  libraryId: string;
  scope: 'album' | 'inspiration';
  scopeId: string;
  fuzzLevel: FuzzLevel;
  expiresInDays: number;
  password?: string | null;
  userId: string;
}): ShareLinkRow {
  if (!config.enableShare) throw errors.badRequest('分享功能已被服务端关闭（ENABLE_SHARE=false）');

  // 安全底线：exact / g100 一律强制降级为 g500（不抛错，避免"手填就绕过"）
  const level = assertShareFuzzLevel(params.fuzzLevel);
  const days = Math.min(Math.max(1, params.expiresInDays), config.shareMaxExpireDays);
  const token = crypto.randomBytes(24).toString('base64url');

  const id = newId();
  getDb()
    .prepare(
      `INSERT INTO share_link (id, library_id, scope, scope_id, token, fuzz_level, password_hash,
         expires_at, created_by, view_count, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,0,?)`,
    )
    .run(
      id,
      params.libraryId,
      params.scope,
      params.scopeId,
      token,
      level,
      params.password ? bcrypt.hashSync(params.password, 10) : null,
      new Date(Date.now() + days * 86400000).toISOString(),
      params.userId,
      nowIso(),
    );

  return getDb().prepare('SELECT * FROM share_link WHERE id = ?').get(id) as ShareLinkRow;
}

export type ShareDenyReason =
  | 'revoked'
  | 'expired'
  | 'fuzz_level'
  | 'password_required'
  | 'password_wrong'
  | 'asset_out_of_scope';

/**
 * 分享访问的**唯一入口**，一次校验跑完四道关（文档 13.4）：
 * 撤销 → 过期 → 模糊级别 → 密码。
 * 任何一关不过都写访问审计（deny_reason），再抛出对应错误；绝不静默放行。
 * 顺序有意为之：先撤销/过期（链接本身已死），再模糊级别（对外安全底线），
 * 最后才核对密码，避免对一条已撤销的链接泄露"密码对不对"这类信息。
 */
export function validateShareToken(token: string, password?: string | null): ShareLinkRow {
  const row = getDb().prepare('SELECT * FROM share_link WHERE token = ?').get(token) as ShareLinkRow | undefined;
  if (!row) throw errors.notFound('分享链接');

  if (row.revoked_at) {
    logAccess(row.id, false, 'revoked');
    throw errors.shareRevoked();
  }
  if (new Date(row.expires_at).getTime() < Date.now()) {
    logAccess(row.id, false, 'expired');
    throw errors.shareExpired();
  }
  // 读时再查一次模糊级别：即使历史数据被绕过了创建期降级（exact/g100 落库），
  // 对外访问也必须在这里拒掉，而不是依赖"创建时一定拦住了"。
  if (!isShareFuzzLevelAllowed(row.fuzz_level)) {
    logAccess(row.id, false, 'fuzz_level');
    throw errors.fuzzTooPrecise();
  }
  if (row.password_hash) {
    if (!password) {
      logAccess(row.id, false, 'password_required');
      throw errors.sharePasswordRequired();
    }
    if (!bcrypt.compareSync(password, row.password_hash)) {
      logAccess(row.id, false, 'password_wrong');
      throw errors.sharePasswordRequired();
    }
  }
  return row;
}

/**
 * 读图前的最终复核（TOCTOU 兜底）。
 * validateShareToken 与真正读盘之间存在 await（如分享图转码），撤销可能在这期间发生。
 * 调用方必须在**最后一个 await 之后、读取任何图片字节之前**同步调用本函数；
 * 由于 Node 单线程，本函数返回后到同步读盘之间不会再被撤销请求插入。
 */
export function assertShareStillActive(link: ShareLinkRow): void {
  const current = getDb()
    .prepare('SELECT revoked_at, expires_at FROM share_link WHERE id = ?')
    .get(link.id) as Pick<ShareLinkRow, 'revoked_at' | 'expires_at'> | undefined;
  if (!current || current.revoked_at) {
    logAccess(link.id, false, 'revoked');
    throw errors.shareRevoked();
  }
  if (new Date(current.expires_at).getTime() < Date.now()) {
    logAccess(link.id, false, 'expired');
    throw errors.shareExpired();
  }
}

export function logAccess(shareLinkId: string, allowed: boolean, denyReason?: string): void {
  try {
    const db = getDb();
    db.prepare(
      'INSERT INTO share_access_log (id, share_link_id, ip_hash, user_agent, path, allowed, deny_reason, at) VALUES (?,?,?,?,?,?,?,?)',
    ).run(newId(), shareLinkId, null, null, null, allowed ? 1 : 0, denyReason ?? null, nowIso());
    if (allowed) db.prepare('UPDATE share_link SET view_count = view_count + 1 WHERE id = ?').run(shareLinkId);
  } catch {
    /* 审计失败不影响主流程 */
  }
}

/** 撤销即时生效：接口层每次都会重新读 revoked_at（不接受缓存兜底） */
export function revokeShareLink(id: string, libraryId: string): void {
  const res = getDb()
    .prepare('UPDATE share_link SET revoked_at = ? WHERE id = ? AND library_id = ? AND revoked_at IS NULL')
    .run(nowIso(), id, libraryId);
  if (res.changes === 0) throw errors.notFound('分享链接（可能已被撤销）');
}

export function listShareLinks(libraryId: string): ShareLinkRow[] {
  return getDb()
    .prepare('SELECT * FROM share_link WHERE library_id = ? ORDER BY created_at DESC')
    .all(libraryId) as ShareLinkRow[];
}

export function shareStatus(link: ShareLinkRow): 'active' | 'expired' | 'revoked' {
  if (link.revoked_at) return 'revoked';
  if (new Date(link.expires_at).getTime() < Date.now()) return 'expired';
  return 'active';
}

export function listAccessLogs(shareLinkId: string, libraryId: string): Record<string, unknown>[] {
  const link = getDb().prepare('SELECT library_id FROM share_link WHERE id = ?').get(shareLinkId) as
    | { library_id: string }
    | undefined;
  if (!link || link.library_id !== libraryId) throw errors.notFound('分享链接');
  return getDb()
    .prepare('SELECT * FROM share_access_log WHERE share_link_id = ? ORDER BY at DESC LIMIT 200')
    .all(shareLinkId) as Record<string, unknown>[];
}

export { isShareFuzzLevelAllowed };
