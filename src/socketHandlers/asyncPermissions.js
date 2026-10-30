'use strict';

// Async readers for the converted channel list. Legacy write handlers keep
// permissions.js synchronous so their checks and writes do not gain a yield.
const { parseRoleGate } = require('../roleGate');

// A failed read of the per-user overrides (user_role_perms) means an explicit
// deny cannot be ruled out, so callers fail closed. The read runs on every
// permission check, so the log line is limited to once a minute.
let _overrideReadWarnedAt = 0;
function warnOverrideRead(where, err) {
  const now = Date.now();
  if (now - _overrideReadWarnedAt < 60 * 1000) return;
  _overrideReadWarnedAt = now;
  console.error(`[permissions] ${where}: override read failed, denying:`, err && err.message);
}

module.exports = function createAsyncPermissions(db) {
  // ── Role inheritance: get the channel hierarchy chain for role cascading ──
  // Server roles → apply everywhere (channel_id IS NULL)
  // Channel role  → applies to that channel + all its sub-channels
  // Sub-channel role → only that sub-channel
  // This returns an array of channel IDs to check (the target + its parent if it's a sub)
  async function getChannelRoleChain(channelId) {
    if (!channelId) return [];
    const ch = await db.prepare('SELECT id, parent_channel_id FROM channels WHERE id = ?').get(channelId);
    if (!ch) return [channelId];
    if (ch.parent_channel_id) return [channelId, ch.parent_channel_id];
    return [channelId];
  }

  async function userHasPermission(userId, permission, channelId = null) {
    const user = await db.prepare('SELECT is_admin FROM users WHERE id = ?').get(userId);
    if (user && user.is_admin) return true;

    // Check per-user permission overrides first (explicit deny takes priority).
    // (#5433) Overrides written by a channel-scoped role assignment carry that
    // assignment's channel_id and must only apply within that channel (and its
    // sub-channels, via the role chain). Rows with channel_id NULL come from
    // server-wide assignments and apply everywhere. Previously this query had
    // no channel filter, so ticking e.g. "create channel" on a channel
    // assignment leaked the permission server-wide.
    try {
      const chain = channelId ? await getChannelRoleChain(channelId) : [];
      const scopeClause = chain.length > 0
        ? `(channel_id IS NULL OR channel_id IN (${chain.map(() => '?').join(',')}))`
        : 'channel_id IS NULL';
      const override = await db.prepare(`
        SELECT allowed FROM user_role_perms WHERE user_id = ? AND permission = ? AND ${scopeClause}
        ORDER BY allowed ASC LIMIT 1
      `).get(userId, permission, ...chain);
      if (override) {
        if (override.allowed === 0) return false;
        if (override.allowed === 1) return true;
      }
    } catch (err) {
      // Fail closed: carrying on to the role checks would ignore a deny.
      warnOverrideRead('userHasPermission', err);
      return false;
    }

    // Check server-scoped roles
    const serverPerm = await db.prepare(`
      SELECT rp.allowed FROM role_permissions rp
      JOIN roles r ON rp.role_id = r.id
      JOIN user_roles ur ON r.id = ur.role_id
      WHERE ur.user_id = ? AND rp.permission = ? AND r.scope = 'server' AND ur.channel_id IS NULL AND rp.allowed = 1
      LIMIT 1
    `).get(userId, permission);
    if (serverPerm) return true;

    // Check channel-scoped roles (with inheritance: parent channel roles cascade to subs)
    if (channelId) {
      const chain = await getChannelRoleChain(channelId);
      if (chain.length > 0) {
        const placeholders = chain.map(() => '?').join(',');
        const channelPerm = await db.prepare(`
          SELECT rp.allowed FROM role_permissions rp
          JOIN roles r ON rp.role_id = r.id
          JOIN user_roles ur ON r.id = ur.role_id
          WHERE ur.user_id = ? AND rp.permission = ? AND ur.channel_id IN (${placeholders}) AND rp.allowed = 1
          LIMIT 1
        `).get(userId, permission, ...chain);
        if (channelPerm) return true;
      }
    }
    return false;
  }

  async function roleGateAllows(userId, channel) {
    const gate = parseRoleGate(channel && channel.role_gate);
    if (!gate) return true;
    const rows = await db.prepare('SELECT role_id FROM user_roles WHERE user_id = ? AND (channel_id IS NULL OR channel_id = ?)')
      .all(userId, channel.id || 0);
    const held = new Set(rows.map(r => r.role_id));
    return gate.mode === 'all' ? gate.roles.every(r => held.has(r)) : gate.roles.some(r => held.has(r));
  }

  return { userHasPermission, roleGateAllows };
};
