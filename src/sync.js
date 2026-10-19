// Two-way sync with Sentinel incidents and the ticket system. Runs on the 15-minute tick, as the last job of a run,
// and right after a decision. No buildState: links, decisions and route revisions are read straight from D1.
//
// - Link rows (incident, ticket) hold the last external state seen. A fetched state that differs is an external
//   change; when it is newer than the latest decision it becomes a decision (via = 'sentinel').
// - The latest decision made outside a system gives the state wanted there. It is written once (link.pushed holds
//   its key) unless the system already shows it, so nothing is echoed back and a retry never duplicates a comment.
// - A decision older than the signal's latest route revision is stale: the update reopened the signal (and the
//   analytics rule reopens the incident), so nothing is written for it.
// - Notes and comments are labels and ids only.
// - Dry run (system not configured): the external side is the sandbox table `sim`, changed from the signal panel.
import * as db from './db.js';
import { settingsOf } from './pipeline.js';
import { sentinelConfigured, incidentsChanged, updateIncident, WS_RE } from './routes/sentinel.js';
import { ticketConfigured, ticketStates, ticketWrite } from './routes/tickets.js';

const DONE = new Set(['resolved', 'cancelled']);
const IN_NA = { BenignPositive: 'Benign', FalsePositive: 'False positive' };
const MAX_WRITES = 10, MAX_POLL = 40, RECHECK = 14 * 864e5;
const label = (...parts) => ['Signal Watch', ...parts].filter(Boolean).join(' · ');
const last = a => (a && a.length ? a[a.length - 1] : null);
const parse = (s, d) => { try { return s ? JSON.parse(s) : d; } catch { return d; } };
const rows = r => r.results || [];

export function sentinelMode(env, S) {
  if (!S.syncSentinel || S.actRoute === 'webhook') return 'off';
  if (!sentinelConfigured(env, S)) return 'sandbox';
  return WS_RE.test(S.wsResource || '') ? 'live' : 'setup';
}
export const ticketMode = (env, S) => (!S.syncTickets ? 'off' : ticketConfigured(env, S) ? 'live' : 'sandbox');
const isSim = t => t.status === 'dry-run' || /^DRY-/.test(t.ref || '');

async function load(DB, sig) {
  const w = sig ? ' AND sig = ?' : '';
  const q = sql => (sig ? DB.prepare(sql).bind(sig) : DB.prepare(sql));
  const [dr, ir, tr, sr, mr] = await DB.batch([
    q(`SELECT id, sig, at, by, act, reason, refs, via, rev FROM decision WHERE undone_at IS NULL AND act != 'auto'${w} ORDER BY at, id`),
    q(`SELECT * FROM incident WHERE 1 = 1${w}`),
    q(`SELECT * FROM ticket WHERE ref IS NOT NULL${w}`),
    q(`SELECT sig, rev, at, to_sys, status FROM send s WHERE rev = (SELECT max(rev) FROM send WHERE sig = s.sig)${w}`),
    q(`SELECT * FROM sim WHERE 1 = 1${w}`),
  ]);
  const dec = new Map();
  for (const d of rows(dr)) { if (!dec.has(d.sig)) dec.set(d.sig, []); dec.get(d.sig).push({ ...d, refs: parse(d.refs, []) }); }
  return {
    dec, inc: new Map(rows(ir).map(x => [x.sig, x])), tickets: rows(tr), sends: new Map(rows(sr).map(x => [x.sig, x])),
    sim: new Map(rows(mr).map(x => [x.ref, x])),
  };
}
// Latest decision on a signal, or null when a newer route revision made it stale.
function current(L, sig) {
  const d = last(L.dec.get(sig)), rev = L.sends.get(sig)?.rev || 0;
  return d && !(d.rev != null && rev > d.rev) ? d : null;
}

async function lock(DB, owner, wait) {
  const end = Date.now() + wait;
  for (;;) {
    if (await db.acquireLock(DB, 'sync', owner, 2 * 6e4)) return true;
    if (Date.now() >= end) return false;
    await new Promise(r => setTimeout(r, 500));
  }
}

// opts: { now, fetch, sig (one signal, after a decision), wait (ms for the lock) }
export async function syncAll(env, { now = Date.now(), fetch: f, sig = null, wait = 0 } = {}) {
  const DB = env.DB, owner = crypto.randomUUID();
  await db.ensureSeed(DB);
  if (!(await lock(DB, owner, wait))) return { busy: true };
  try {
    const S = settingsOf(await db.loadSettings(DB)), L = await load(DB, sig), budget = { n: MAX_WRITES };
    const out = { at: now, sentinel: sentinelMode(env, S), tickets: ticketMode(env, S), in: 0, out: 0, notes: 0, linked: 0, errors: 0 };
    if (out.tickets !== 'off') await readTickets(env, S, L, out, now, f);
    if (out.sentinel !== 'off' && out.sentinel !== 'setup') {
      await readIncidents(env, S, L, out, now, f, sig);
      await writeIncidents(env, S, L, out, now, f, budget);
    }
    if (out.tickets !== 'off') await writeTickets(env, S, L, out, now, f, budget);
    if (!sig) await db.putKV(DB, 'syncLast', out);
    return out;
  } finally {
    await db.releaseLock(DB, 'sync', owner);
  }
}

// ───────── Sentinel ─────────

// The analytics rule, in the sandbox: one incident per routed Act signal, reopened on a new revision.
async function simIncidents(DB, L, now) {
  let n = Math.max(1000, ...[...L.sim.values()].filter(x => x.kind === 'incident').map(x => x.number || 0));
  for (const [sig, r] of L.sends) {
    if (r.to_sys !== 'sentinel' || r.status !== 'dry-run') continue;
    const ref = 'SIM-' + sig, x = L.sim.get(ref);
    if (!x) {
      const row = { ref, kind: 'incident', sig, number: ++n, status: 'New', cls: null, owner: null, rev: r.rev, notes: '[]', at: r.at };
      await DB.prepare('INSERT OR IGNORE INTO sim (ref, kind, sig, number, status, rev, at) VALUES (?,?,?,?,?,?,?)').bind(ref, 'incident', sig, row.number, 'New', r.rev, r.at).run();
      L.sim.set(ref, row);
    } else if (r.rev > x.rev) {
      if (x.status === 'Closed') Object.assign(x, { status: 'New', cls: null, at: Math.max(r.at, x.at) });
      x.rev = r.rev;
      await DB.prepare('UPDATE sim SET status = ?, cls = ?, rev = ?, at = ? WHERE ref = ?').bind(x.status, x.cls, x.rev, x.at, ref).run();
    }
  }
  return [...L.sim.values()].filter(x => x.kind === 'incident').map(x => ({ sig: x.sig, name: x.ref, number: x.number, status: x.status, cls: x.cls, owner: x.owner, at: x.at }));
}

function inbound(e) {
  if (e.status === 'Closed') return IN_NA[e.cls] ? { act: 'na', reason: IN_NA[e.cls] } : { act: 'ack', reason: e.cls === 'TruePositive' ? 'True positive' : 'Closed' };
  return e.status === 'Active' ? { act: 'ack', reason: null } : null;
}

async function readIncidents(env, S, L, out, now, f, sig) {
  const DB = env.DB;
  let seen = [];
  if (out.sentinel === 'sandbox') seen = await simIncidents(DB, L, now);
  else if (!sig) {
    const wm = await db.getKV(DB, 'syncSentinelAt', 0), since = Math.max(wm - 5 * 6e4, now - 30 * 864e5);
    try { seen = await incidentsChanged(env, S, since, f); } catch (e) { out.errors++; console.error('sync sentinel', e?.message || e); return; }
    if (seen.length) await db.putKV(DB, 'syncSentinelAt', Math.max(wm, ...seen.map(x => x.at)));
  }
  for (const e of seen) {
    if (!L.sends.has(e.sig)) continue; // only signals this workspace routed
    const k = L.inc.get(e.sig), was = k || { status: 'New', cls: null };
    if (!k) out.linked++;
    if (was.status !== e.status || (was.cls || null) !== (e.cls || null)) {
      const m = inbound(e), d = last(L.dec.get(e.sig));
      if (m && e.at >= (d?.at || 0) && !(d && d.act === m.act && (d.reason || null) === m.reason)) {
        const nd = { id: 'D-' + crypto.randomUUID().slice(0, 8), sig: e.sig, at: Math.min(e.at, now), by: e.owner || 'Sentinel', act: m.act, refs: [], via: 'sentinel', rev: L.sends.get(e.sig)?.rev ?? null, ...(m.reason ? { reason: m.reason } : {}) };
        await db.insertDecision(DB, nd);
        if (!L.dec.has(e.sig)) L.dec.set(e.sig, []);
        L.dec.get(e.sig).push(nd);
        out.in++;
      }
    }
    const row = { sig: e.sig, name: e.name, number: e.number, status: e.status, cls: e.cls || null, owner: e.owner || null, ext_at: e.at, pushed: k?.pushed || null, synced_at: now };
    await DB.prepare('INSERT INTO incident (sig, name, number, status, cls, owner, ext_at, pushed, synced_at) VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(sig) DO UPDATE SET name = excluded.name, number = excluded.number, status = excluded.status, cls = excluded.cls, owner = excluded.owner, ext_at = excluded.ext_at, synced_at = excluded.synced_at')
      .bind(row.sig, row.name, row.number, row.status, row.cls, row.owner, row.ext_at, row.pushed, now).run();
    L.inc.set(e.sig, row);
  }
}

// State wanted in Sentinel: from the latest decision made in Signal Watch, or Closed · True positive once every
// ticket on the signal is resolved at its current revision, or Active again after an undo of what we closed.
function incidentWant(L, k) {
  const sig = k.sig, d = current(L, sig), any = last(L.dec.get(sig)), rev = L.sends.get(sig)?.rev || 0;
  const tk = L.tickets.filter(t => t.sig === sig);
  const done = tk.length && tk.every(t => DONE.has(t.state) && t.rev >= rev) ? Math.max(...tk.map(t => t.ext_at || 0)) : 0;
  let w = null;
  if (d && d.via !== 'sentinel') {
    w = d.act === 'na' ? { status: 'Closed', cls: 'BenignPositive', key: d.id, note: label('Not affected', d.reason, d.by), at: d.at }
      : { status: 'Active', cls: null, key: d.id, note: label(d.act === 'ticket' ? 'Ticketed' : 'Acknowledged', (d.refs || []).map(r => r.ref).join(' '), d.by), at: d.at };
  }
  if (done && d?.act !== 'na' && (!w || done > w.at)) w = { status: 'Closed', cls: 'TruePositive', key: 'resolved:' + done, note: label('Tickets resolved'), at: done };
  if (!w && !any && k.pushed && k.pushed !== 'undo' && k.status === 'Closed') w = { status: 'Active', cls: null, key: 'undo', note: label('Undo') };
  return w;
}

async function writeIncidents(env, S, L, out, now, f, budget) {
  const DB = env.DB;
  for (const k of L.inc.values()) {
    const w = incidentWant(L, k);
    if (!w || w.key === k.pushed) continue;
    const there = k.status === w.status && (w.status !== 'Closed' || k.cls === w.cls);
    let e = { status: k.status, cls: k.cls, at: k.ext_at };
    if (!there) {
      if (budget.n-- <= 0) return;
      try {
        if (/^SIM-/.test(k.name)) {
          const x = L.sim.get(k.name), notes = [...parse(x?.notes, []), w.note].slice(-5);
          e = { status: w.status, cls: w.status === 'Closed' ? w.cls : null, at: now };
          await DB.prepare('UPDATE sim SET status = ?, cls = ?, notes = ?, at = ? WHERE ref = ?').bind(e.status, e.cls, JSON.stringify(notes), now, k.name).run();
          if (x) Object.assign(x, e, { notes: JSON.stringify(notes) });
        } else {
          e = (await updateIncident(env, S, k.name, w, w.note, f)) || { status: w.status, cls: w.cls, at: now };
        }
      } catch (err) { out.errors++; console.error('sync incident', k.sig, err?.message || err); continue; }
      out.out++;
    }
    Object.assign(k, { status: e.status, cls: e.cls || null, ext_at: e.at || now, pushed: w.key });
    await DB.prepare('UPDATE incident SET status = ?, cls = ?, ext_at = ?, pushed = ?, synced_at = ? WHERE sig = ?').bind(k.status, k.cls, k.ext_at, k.pushed, now, k.sig).run();
  }
}

// ───────── tickets ─────────

async function readTickets(env, S, L, out, now, f) {
  const DB = env.DB;
  const due = L.tickets.filter(t => !DONE.has(t.state) || (t.ext_at || 0) > now - RECHECK).sort((a, b) => (a.synced_at || 0) - (b.synced_at || 0)).slice(0, MAX_POLL);
  const sim = due.filter(isSim), live = out.tickets === 'live' ? due.filter(t => !isSim(t)) : [];
  const seen = sim.map(t => L.sim.get(t.ref)).filter(Boolean).map(x => ({ ref: x.ref, id: null, state: x.status, at: x.at }));
  if (live.length) {
    try { seen.push(...(await ticketStates(env, S, live.map(t => t.ref), f))); } catch (e) { out.errors++; console.error('sync tickets', e?.message || e); }
  }
  const byRef = new Map(seen.map(x => [String(x.ref), x]));
  const stmts = [];
  for (const t of [...sim, ...live]) {
    const e = byRef.get(String(t.ref));
    if (e && (e.state !== t.state || (e.id && !t.ext_id))) {
      if (e.state !== t.state) Object.assign(t, { state: e.state, ext_at: e.at || now });
      t.ext_id = t.ext_id || e.id || null;
    }
    t.synced_at = now;
    stmts.push(DB.prepare('UPDATE ticket SET state = ?, ext_at = ?, ext_id = ?, synced_at = ? WHERE sig = ? AND pid = ?').bind(t.state, t.ext_at ?? null, t.ext_id ?? null, now, t.sig, t.pid));
  }
  for (let i = 0; i < stmts.length; i += 50) await DB.batch(stmts.slice(i, i + 50));
}

// Close open tickets when the latest decision is Not affected; add a note when the signal has a new revision.
async function writeTickets(env, S, L, out, now, f, budget) {
  const DB = env.DB;
  for (const t of L.tickets) {
    if (DONE.has(t.state)) continue;
    const sim = isSim(t);
    if (!sim && out.tickets !== 'live') continue;
    const d = current(L, t.sig), rev = L.sends.get(t.sig)?.rev || 0;
    let op = null, text = '';
    if (d?.act === 'na' && t.pushed !== d.id) { op = 'close'; text = label('Not affected', d.reason, d.via === 'sentinel' ? 'Sentinel' : null, d.by); }
    else if (rev > t.rev && t.ext_at != null) { op = 'note'; text = label('Updated', 'r' + rev, t.sig); }
    else if (rev > t.rev) { t.rev = rev; await DB.prepare('UPDATE ticket SET rev = ? WHERE sig = ? AND pid = ?').bind(rev, t.sig, t.pid).run(); continue; }
    if (!op) continue;
    if (budget.n-- <= 0) return;
    let closed = false;
    try {
      if (sim) {
        const x = L.sim.get(t.ref), notes = [...parse(x?.notes, []), text].slice(-5);
        closed = op === 'close';
        await DB.prepare('UPDATE sim SET status = ?, notes = ?, at = ? WHERE ref = ?').bind(closed ? 'resolved' : x?.status || 'open', JSON.stringify(notes), now, t.ref).run();
        if (x) Object.assign(x, { status: closed ? 'resolved' : x.status, notes: JSON.stringify(notes), at: now });
      } else {
        closed = op === 'close' && (await ticketWrite(env, S, 'close', t, text, f));
        if (op === 'note' || !closed) await ticketWrite(env, S, 'note', t, text, f);
      }
    } catch (e) { out.errors++; console.error('sync ticket', t.ref, e?.message || e); continue; }
    if (op === 'close') { t.pushed = d.id; if (closed) Object.assign(t, { state: 'resolved', ext_at: now }); out.out++; }
    else { t.rev = rev; out.notes++; }
    await DB.prepare('UPDATE ticket SET state = ?, ext_at = ?, rev = ?, pushed = ?, synced_at = ? WHERE sig = ? AND pid = ?').bind(t.state, t.ext_at ?? null, t.rev, t.pushed ?? null, now, t.sig, t.pid).run();
  }
}
