// Minimal D1 stand-in over node:sqlite so the Worker code runs under `node --test` without wrangler.
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';

export function d1() {
  const db = new DatabaseSync(':memory:');
  for (const f of fs.readdirSync(new URL('../migrations/', import.meta.url)).sort()) db.exec(fs.readFileSync(new URL('../migrations/' + f, import.meta.url), 'utf8'));
  const norm = p => p.map(v => (v === undefined ? null : typeof v === 'boolean' ? (v ? 1 : 0) : v));
  const reads = sql => /^\s*(select|with)\b/i.test(sql) || /\breturning\b/i.test(sql);
  const stmt = (sql, params = []) => ({
    bind: (...p) => stmt(sql, norm(p)),
    async all() { return { results: db.prepare(sql).all(...params), success: true, meta: {} }; },
    async first(col) { const r = db.prepare(sql).get(...params); return r == null ? null : col ? r[col] : { ...r }; },
    async run() { const r = db.prepare(sql).run(...params); return { success: true, meta: { changes: Number(r.changes), last_row_id: Number(r.lastInsertRowid) } }; },
    exec() {
      const s = db.prepare(sql);
      if (reads(sql)) return { results: s.all(...params).map(r => ({ ...r })), success: true, meta: {} };
      const r = s.run(...params);
      return { results: [], success: true, meta: { changes: Number(r.changes) } };
    },
  });
  return {
    prepare: sql => stmt(sql),
    async batch(list) {
      db.exec('BEGIN');
      try { const out = list.map(s => s.exec()); db.exec('COMMIT'); return out; } catch (e) { db.exec('ROLLBACK'); throw e; }
    },
    raw: db,
  };
}
