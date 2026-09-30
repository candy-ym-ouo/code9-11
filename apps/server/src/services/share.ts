import crypto from 'node:crypto';
import bcrypt from 'bcryptjs';
import type { FuzzLevel } from '@flil/shared';
import { getDb, newId, nowIso } from '../db.js';
import { config } from '../config.js';
import { errors, type ApiError } from '../http/errors.js';
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
  | 'password_required'
  | 'password_wrong'
  | 'fuzz_level_too_precise';

/**
 * 分享访问的唯一准入闸门。
 * 一次评估撤销、过期、密码和模糊级别，避免各路由各查一项导致绕过；
 * 拒绝时把全部命中的拒绝原因写入同一条审计。
 */
export function authorizeShareToken(token: string, password?: string | null): ShareLinkRow {
  const row = getDb().prepare('SELECT * FROM share_link WHERE token = ?').get(token) as ShareLinkRow | undefined;
  if (!row) throw errors.notFound('分享链接');

  const reasons = shareAccessDenialReasons(row, password);
  if (reasons.length > 0) {
    logAccess(row.id, false, reasons.join(','));
    throw shareAccessError(reasons);
  }
  return row;
}

/**
 * 异步生成分享图后必须再次调用。better-sqlite3 调用本身是同步的，因此这里与后续读图之间
 * 不会插入撤销操作，关闭“校验通过后、发图前被并发撤销”的时间窗。
 */
export function assertShareAccessCurrent(row: ShareLinkRow): void {
  const latest = getDb().prepare('SELECT * FROM share_link WHERE id = ?').get(row.id) as ShareLinkRow | undefined;
  if (!latest) {
    logAccess(row.id, false, 'revoked');
    throw errors.shareRevoked();
  }

  const reasons = shareAccessDenialReasons(latest, null).filter(
    (reason) => reason !== 'password_required' && reason !== 'password_wrong',
  );
  if (reasons.length > 0) {
    logAccess(latest.id, false, reasons.join(','));
    throw shareAccessError(reasons);
  }
}

function shareAccessDenialReasons(row: ShareLinkRow, password?: string | null): ShareDenyReason[] {
  const reasons: ShareDenyReason[] = [];
  if (row.revoked_at) reasons.push('revoked');
  if (new Date(row.expires_at).getTime() < Date.now()) reasons.push('expired');

  if (row.password_hash) {
    if (!password) reasons.push('password_required');
    else if (!bcrypt.compareSync(password, row.password_hash)) reasons.push('password_wrong');
  }

  if (!isShareFuzzLevelAllowed(row.fuzz_level)) reasons.push('fuzz_level_too_precise');
  return reasons;
}

function shareAccessError(reasons: ShareDenyReason[]): ApiError {
  if (reasons.includes('revoked')) return errors.shareRevoked();
  if (reasons.includes('expired')) return errors.shareExpired();
  if (reasons.includes('password_required') || reasons.includes('password_wrong')) {
    return errors.sharePasswordRequired();
  }
  return errors.fuzzTooPrecise();
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
