'use strict';

// How far this person has read in some threads, for the thread mention bell.
// The bell is kept per device, so a device that was closed while the thread
// was read somewhere else asks on startup which of its remembered mentions
// are already read, and drops those instead of ringing days later.

const MAX_THREADS = 200;

module.exports = function register(socket, ctx) {
  const { db } = ctx;

  // Answers { [parentId]: lastReadReplyId } for the threads asked about,
  // leaving out any this person cannot see.
  socket.on('get-thread-read-state', (data, callback) => {
    const cb = typeof callback === 'function' ? callback : () => {};
    const ids = Array.isArray(data && data.parentIds)
      ? [...new Set(data.parentIds.filter(id => Number.isInteger(id) && id > 0))].slice(0, MAX_THREADS)
      : [];
    if (!ids.length) return cb({ reads: {} });
    try {
      const ph = ids.map(() => '?').join(',');
      const rows = db.prepare(`
        SELECT m.id AS parentId, COALESCE(tr.last_read_reply_id, 0) AS lastRead
        FROM messages m
        JOIN channel_members cm ON cm.channel_id = m.channel_id AND cm.user_id = ?
        LEFT JOIN thread_reads tr ON tr.thread_id = m.id AND tr.user_id = ?
        WHERE m.id IN (${ph}) AND m.thread_id IS NULL
      `).all(socket.user.id, socket.user.id, ...ids);
      const reads = {};
      for (const r of rows) reads[r.parentId] = r.lastRead;
      cb({ reads });
    } catch (err) {
      console.warn('[thread-read-state] lookup failed:', err.message);
      cb({ reads: {} });
    }
  });
};
