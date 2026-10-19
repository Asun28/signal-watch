// D1 access. Signals are not stored; they are rebuilt from items by engine.buildState on each read or run.
import { SEED_INVENTORY, productKey, normModel, normText } from '../public/engine.js';
import SOURCES_SEED from '../config/sources.json' with { type: 'json' };
import { chunk } from './util.js';

const parse = (s, d) => { try { return s ? JSON.parse(s) : d; } catch { return d; } };
const rows = r => r.results || [];

const seeded = new WeakMap();
export function ensureSeed(db) {
  if (!seeded.has(db)) seeded.set(db, (async () => {
    const done = await db.prepare("SELECT v FROM setting WHERE k = 'seeded'").first();
    if (done) return;
    const now = Date.now();
    await db.batch([
      ...SEED_INVENTORY.map((p, i) => db.prepare('INSERT OR IGNORE INTO product (id, name, vendor, cpe, version, owner, model, decoy, pos, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(p.id, p.name, p.vendor, p.cpe, p.version, p.owner, p.model, p.decoy ? 1 : 0, i, now)),
      ...SOURCES_SEED.map((s, i) => { const { enabled, ...cfg } = s; return db.prepare('INSERT OR IGNORE INTO source (id, cfg, enabled, pos, updated_at) VALUES (?,?,?,?,?)').bind(s.id, JSON.stringify(cfg), enabled === false ? 0 : 1, i, now); }),
      db.prepare("INSERT OR IGNORE INTO setting (k, v) VALUES ('settings', '{}')"),
      db.prepare("INSERT OR REPLACE INTO setting (k, v) VALUES ('seeded', ?)").bind(String(now)),
    ]);
  })().catch(e => { seeded.delete(db); throw e; }));
  return seeded.get(db);
}

export async function getKV(db, k, d = null) { const r = await db.prepare('SELECT v FROM setting WHERE k = ?').bind(k).first(); return r ? parse(r.v, d) : d; }
export const putKV = (db, k, v) => db.prepare('INSERT INTO setting (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v').bind(k, JSON.stringify(v)).run();

// Settings hold only what differs from the engine defaults. Secret values are never stored here, only env: refs
// (values entered in Settings go to the vault table as ciphertext, src/vault.js).
const SETTING_KEYS = new Set(['epss', 'cvss', 'actByDays', 'archiveDays', 'jaccard', 'windowDays', 'lookbackDays', 'perms', 'ai', 'aiGroup', 'aiExtract', 'embedMin', 'greyMin', 'aiEndpoint', 'aiModel', 'aiProvider', 'actRoute', 'ticketSys', 'schedule', 'days', 'digestTime', 'digestTeams', 'digestEmail', 'digestTo', 'mailFrom', 'teamsUrl', 'dce', 'dcr', 'stream', 'table', 'tenant', 'clientId', 'secretRef', 'ticketUrl', 'ticketAuth', 'ticketUser', 'rawDays', 'scope', 'ncscSenders', 'me', 'syncSentinel', 'syncTickets', 'wsResource', 'ticketClose']);
export const loadSettings = db => getKV(db, 'settings', {});
export function cleanSettings(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj || {})) {
    if (!SETTING_KEYS.has(k)) continue;
    if (/^(secretRef|ticketAuth|teamsUrl)$/.test(k) && v && !/^env:[A-Z0-9_]+$/.test(v)) continue; // refs only
    out[k] = v;
  }
  return out;
}
export const saveSettings = (db, obj) => putKV(db, 'settings', cleanSettings(obj));

export async function loadInventory(db) {
  return rows(await db.prepare('SELECT id, name, vendor, cpe, version, owner, model, decoy FROM product ORDER BY pos, id').all()).map(p => ({ ...p, decoy: !!p.decoy }));
}
export function validProduct(p) {
  const model = ['self', 'shared', 'vendor', 'hyper'].includes(p.model) ? p.model : normModel(p.model);
  if (!p.name || !String(p.name).trim() || !model) return null;
  if (p.cpe && !/^cpe:2\.3:[aho]:[^:]+:[^:]+/i.test(p.cpe)) return null;
  return { id: String(p.id || 'p' + Date.now().toString(36)).slice(0, 40), name: String(p.name).trim().slice(0, 120), vendor: String(p.vendor || '').trim().slice(0, 80), cpe: String(p.cpe || '').trim().slice(0, 200), version: String(p.version || '').trim().slice(0, 60), owner: String(p.owner || '').trim().slice(0, 80), model, decoy: !!p.decoy };
}
// Replace the inventory. Noise dedup keys are cleared so items that now match are picked up on the next run.
export async function saveInventory(db, list) {
  const now = Date.now(), clean = list.map(validProduct);
  if (clean.some(x => !x)) return { error: 'Invalid product' };
  const ids = new Set(), keys = new Set();
  for (const p of clean) { if (ids.has(p.id)) return { error: 'Duplicate id' }; ids.add(p.id); keys.add(normText(p.vendor + ' ' + p.name)); }
  const before = (await loadInventory(db)).map(productKey).sort().join();
  await db.batch([
    db.prepare('DELETE FROM product'),
    ...clean.map((p, i) => db.prepare('INSERT INTO product (id, name, vendor, cpe, version, owner, model, decoy, pos, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(p.id, p.name, p.vendor, p.cpe, p.version, p.owner, p.model, p.decoy ? 1 : 0, i, now)),
  ]);
  if (clean.map(productKey).sort().join() !== before) await db.prepare('DELETE FROM seen WHERE kept = 0').run();
  return { ok: true, inventory: clean };
}

export async function loadSources(db) {
  return rows(await db.prepare('SELECT id, cfg, enabled FROM source ORDER BY pos, id').all()).map(r => ({ ...parse(r.cfg, {}), id: r.id, enabled: !!r.enabled }));
}
const SRC_FIELDS = ['fam', 'name', 'icon', 'kind', 'role', 'tier', 'schedule', 'parser', 'url', 'nz', 'social', 'sample', 'optional', 'extra', 'params'];
export async function saveSource(db, s) {
  const cfg = Object.fromEntries(SRC_FIELDS.filter(k => s[k] !== undefined).map(k => [k, s[k]]));
  const pos = (await db.prepare('SELECT COALESCE(MAX(pos), 0) + 1 AS n FROM source').first()).n;
  await db.prepare('INSERT INTO source (id, cfg, enabled, pos, updated_at) VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET cfg = excluded.cfg, enabled = excluded.enabled, updated_at = excluded.updated_at')
    .bind(s.id, JSON.stringify(cfg), s.enabled === false ? 0 : 1, pos, Date.now()).run();
}

export async function loadDecisions(db) {
  return rows(await db.prepare('SELECT id, sig, at, by, act, reason, refs, via FROM decision WHERE undone_at IS NULL ORDER BY at').all())
    .map(d => ({ id: d.id, sig: d.sig, at: d.at, by: d.by, act: d.act, refs: parse(d.refs, []), ...(d.reason ? { reason: d.reason } : {}), ...(d.via ? { via: d.via } : {}) }));
}
export const insertDecision = (db, d) => db.prepare('INSERT INTO decision (id, sig, at, by, act, reason, refs, via, rev) VALUES (?,?,?,?,?,?,?,?,?)').bind(d.id, d.sig, d.at, d.by, d.act, d.reason || null, JSON.stringify(d.refs || []), d.via || null, d.rev ?? null).run();
export const undoDecision = (db, id) => db.prepare('UPDATE decision SET undone_at = ? WHERE id = ? AND undone_at IS NULL').bind(Date.now(), id).run();
export const setReason = (db, id, reason) => db.prepare('UPDATE decision SET reason = ? WHERE id = ?').bind(reason || null, id).run();

// Live dataset in the shape engine.buildState expects.
export async function liveDataset(db) {
  const [rr, ir, sr, ar, src, inc, tk, sim] = await db.batch([
    db.prepare('SELECT id, at, mode, ms, stats FROM run ORDER BY at, id'),
    db.prepare('SELECT id, run_id, src, at, title, url, fields FROM item ORDER BY id'),
    db.prepare('SELECT sig, rev, run_id, at, hash, to_sys, status FROM send ORDER BY at, rev'),
    db.prepare('SELECT k, same, conf FROM ai_pair'),
    db.prepare('SELECT id, cfg, enabled FROM source ORDER BY pos, id'),
    db.prepare('SELECT sig, name, number, status, cls, owner, ext_at FROM incident'),
    db.prepare('SELECT ref, state, ext_at FROM ticket WHERE ref IS NOT NULL'),
    db.prepare('SELECT ref, notes FROM sim'),
  ]);
  const byRun = new Map();
  for (const i of rows(ir)) {
    const raw = { ...parse(i.fields, {}), n: i.id, src: i.src, at: i.at, title: i.title, url: i.url };
    if (!byRun.has(i.run_id)) byRun.set(i.run_id, []);
    byRun.get(i.run_id).push(raw);
  }
  const runs = rows(rr).map(r => { const s = parse(r.stats, {}); return { id: r.id, at: r.at, mode: r.mode, ms: r.ms, items: byRun.get(r.id) || [], srcStat: s.srcStat || {}, epss: s.epss || {}, cvss: s.cvss || {}, noise: {}, status: {} }; });
  // Two-way sync (src/sync.js): incident and ticket state as last seen; `note` is the last note in the sandbox.
  const simNote = new Map(rows(sim).map(x => [x.ref, parse(x.notes, []).slice(-1)[0] || null]));
  const incidents = Object.fromEntries(rows(inc).map(x => [x.sig, { number: x.number, status: x.status, cls: x.cls, owner: x.owner, at: x.ext_at, sim: x.name.startsWith('SIM-'), note: simNote.get(x.name) || null }]));
  const tickets = Object.fromEntries(rows(tk).map(x => [x.ref, { state: x.state, at: x.ext_at, sim: simNote.has(x.ref), note: simNote.get(x.ref) || null }]));
  return {
    runs,
    sends: rows(sr).map(x => ({ sig: x.sig, rev: x.rev, run: x.run_id, at: x.at, hash: x.hash, to: x.to_sys, status: x.status, incident: incidents[x.sig]?.number ?? null })),
    sync: { incidents, tickets },
    aiPairs: Object.fromEntries(rows(ar).map(x => [x.k, { same: !!x.same, conf: x.conf }])),
    sources: rows(src).map(r => ({ ...parse(r.cfg, {}), id: r.id, enabled: !!r.enabled })),
  };
}

// CVEs on stored items (EPSS matching) and per-run stats (EPSS deltas), without loading the full dataset.
export async function storedCves(db) {
  const out = new Set();
  for (const r of rows(await db.prepare("SELECT fields FROM item WHERE fields LIKE '%\"cves\"%'").all())) for (const c of parse(r.fields, {}).cves || []) out.add(c);
  return out;
}
export const runStats = async db => rows(await db.prepare('SELECT stats FROM run ORDER BY at, id').all()).map(r => parse(r.stats, {}));

export async function liveStore(db) {
  await ensureSeed(db);
  const [settings, inventory, decisions, dataset] = await Promise.all([loadSettings(db), loadInventory(db), loadDecisions(db), liveDataset(db)]);
  return { store: { v: 1, replay: 'live', runIdx: 0, settings, inventory, sources: {}, extraSources: [], decisions, seq: { ticket: 0, decision: 0 } }, dataset };
}

export async function existingKeys(db, keys) {
  const out = new Set();
  for (const c of chunk([...new Set(keys)], 90)) {
    if (!c.length) continue;
    for (const r of rows(await db.prepare(`SELECT dkey FROM seen WHERE dkey IN (${c.map(() => '?').join(',')})`).bind(...c).all())) out.add(r.dkey);
  }
  return out;
}

// Multi-row inserts keep a run well under the per-invocation query limit.
export function insertSeen(db, list, at) {
  return chunk(list, 30).map(c => db.prepare(`INSERT OR IGNORE INTO seen (dkey, kept, at) VALUES ${c.map(() => '(?,?,?)').join(',')}`).bind(...c.flatMap(x => [x.dkey, x.kept ? 1 : 0, at])));
}
export function insertItems(db, runId, list) {
  return chunk(list, 12).map(c => db.prepare(`INSERT OR IGNORE INTO item (run_id, src, dkey, at, title, url, fields) VALUES ${c.map(() => '(?,?,?,?,?,?,?)').join(',')}`)
    .bind(...c.flatMap(x => [runId, x.src, x.dkey, x.at, x.title, x.url, JSON.stringify(x.fields)])));
}

export async function acquireLock(db, name, owner, ttl = 10 * 6e4) {
  const now = Date.now();
  // re-entrant for the same owner, so a retried Workflow step keeps its own lock
  const r = await db.prepare('INSERT INTO lock (name, until, owner) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET until = excluded.until, owner = excluded.owner WHERE lock.until < ? OR lock.owner = excluded.owner').bind(name, now + ttl, owner, now).run();
  return (r.meta?.changes || 0) > 0;
}
export const lockHeld = async (db, name) => ((await db.prepare('SELECT until FROM lock WHERE name = ?').bind(name).first('until')) || 0) > Date.now();
export const releaseLock = (db, name, owner) => db.prepare('DELETE FROM lock WHERE name = ? AND owner = ?').bind(name, owner).run();

export async function purge(db, rawDays) {
  const cut = Date.now() - rawDays * 864e5;
  await db.batch([
    db.prepare('DELETE FROM item WHERE run_id IN (SELECT id FROM run WHERE at < ?)').bind(cut),
    db.prepare('DELETE FROM run WHERE at < ?').bind(cut),
    db.prepare('DELETE FROM seen WHERE at < ?').bind(cut),
    db.prepare('DELETE FROM ai_pair WHERE at < ?').bind(cut),
  ]);
}
