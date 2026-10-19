// Live pipeline: fetch → parse → dedup → match → enrich → store → group/level (engine) → route → sync → digest.
// Runs from the cron (daily, Settings → Schedule, NZ time), Run now, and email receipt. Same code path for all.
// A run is a list of small jobs (one source page, a few NCSC pages, one EPSS page, store, route) so that each fits
// the Workers Free CPU budget (10 ms) as one Workflow step (src/flow.js). runPipeline() runs the same jobs inline.
import { buildState, aliasesFor, productKey, extractKeys, routeHash, pairKey, planTickets, DEFAULT_SETTINGS, LIVE_SETTINGS, DEFAULT_SCOPE } from '../public/engine.js';
import { PARSERS, PAGED, fetchNcscDetails } from './sources/feeds.js';
import { ENRICHERS, PAGED_ENRICHERS } from './sources/epss.js';
import * as db from './db.js';
import { sha1hex, secret, chunk } from './util.js';
import { sendSentinel, sentinelConfigured, recordFor } from './routes/sentinel.js';
import { createTickets } from './routes/tickets.js';
import { syncAll } from './sync.js';
import { loadVault } from './vault.js';
import { aiAvailable, greyPair, extractProduct } from './ai.js';
import { nzParts } from './time.js';

const DOW = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

export const settingsOf = stored => ({ ...DEFAULT_SETTINGS, ...LIVE_SETTINGS, ...stored, scope: stored.scope || DEFAULT_SCOPE });

// Fields stored per item besides headline, link and date.
const FIELDS = ['cves', 'advs', 'keys', 'keysBy', 'aiKeys', 'type', 'cvss', 'kev', 'actBy', 'fix', 'affected', 'peer', 'sample'];
const pick = r => Object.fromEntries(FIELDS.filter(k => r[k] != null && !(Array.isArray(r[k]) && !r[k].length) && r[k] !== '' && r[k] !== false).map(k => [k, r[k]]));

async function pool(list, n, fn) {
  const q = list.slice();
  await Promise.all(Array.from({ length: Math.min(n, q.length) }, async () => { while (q.length) await fn(q.shift()); }));
}

async function waitLock(DB, owner, waitMs) {
  const end = Date.now() + waitMs;
  for (;;) {
    if (await db.acquireLock(DB, 'run', owner)) return true;
    if (Date.now() > end) return false;
    await new Promise(r => setTimeout(r, 1500));
  }
}

// Settings, inventory and sources, loaded per job (a Workflow step cannot share memory with the next one).
async function context(env, run) {
  const DB = env.DB;
  const [stored, inv, sources] = await Promise.all([db.loadSettings(DB), db.loadInventory(DB), db.loadSources(DB)]);
  const S = settingsOf(stored), aliases = aliasesFor(inv), invKeys = new Set(inv.map(productKey));
  await loadVault(env, S);
  const byId = Object.fromEntries(sources.map(s => [s.id, s]));
  const fam = r => byId[r.src]?.fam || r.src;
  return {
    DB, S, aliases, sources, byId,
    keep: r => r.keys.some(k => invKeys.has(k)) || (r.aiKeys || []).some(k => invKeys.has(k)) || !!r.peer || fam(r) === 'ncsc',
    ai: S.ai && S.aiExtract && aiAvailable(env, S),
    ctx: { now: run.now, settings: S, aliases, fetch: run.fetch, secret: ref => secret(env, ref) },
  };
}

// ───────── jobs ─────────

// Take the lock and list the pull sources: Daily / With run (every run), Weekly Mon (scheduled runs on that
// weekday), On receipt (push only).
export async function begin(env, run) {
  await db.ensureSeed(env.DB);
  if (!(await waitLock(env.DB, run.owner, run.wait ?? 0))) return { busy: true };
  const c = await context(env, run);
  const srcStat = {};
  if (run.push) return { t0: Date.now(), srcStat: { [run.push.src]: { status: 'ok', code: 200, items: 0, noise: 0, ms: 0 } }, pulls: [], enrich: null };
  for (const s of c.sources) if (!s.enabled) srcStat[s.id] = { status: 'off', items: 0, noise: 0 };
  const weekly = s => { const m = String(s.schedule || '').match(/^Weekly (Mon|Tue|Wed|Thu|Fri|Sat|Sun)/); return !m || run.mode !== 'Schedule' || DOW.indexOf(m[1]) === nzParts(run.now).dow; };
  const only = s => !run.only || run.only.includes(s.id);
  const pulls = c.sources.filter(s => s.enabled && s.role !== 'Enrich' && !/receipt/i.test(s.schedule || '') && weekly(s) && PARSERS[s.parser] && only(s));
  const enr = c.sources.find(s => s.enabled && s.role === 'Enrich' && ENRICHERS[s.parser] && only(s));
  return { t0: Date.now(), srcStat, pulls: pulls.map(s => ({ id: s.id, paged: !!PAGED[s.parser] })), enrich: enr ? { id: enr.id, paged: !!PAGED_ENRICHERS[enr.parser] } : null };
}

// Fetch and parse one source (or one page of it), normalise, and drop what was seen before. Seen keys are hashes
// of src + guid/url + headline. Returns kept items in full, AI candidates in full, and only the key of the rest.
export async function pull(env, run, id, page = 1) {
  const c = await context(env, run), s = c.byId[id];
  let r;
  try {
    r = run.push ? { code: 200, items: run.push.items } : PAGED[s.parser] ? await PAGED[s.parser](s, c.ctx, page) : await PARSERS[s.parser](s, c.ctx);
  } catch (e) {
    return { stat: { status: 'error', code: e?.name === 'AbortError' ? 'Timeout' : 'Error', items: 0, noise: 0 } };
  }
  if (r.push) return { push: true };
  if (!r.items) return { stat: { status: 'error', code: r.code || 'Error', items: 0, noise: 0, ms: r.ms || 0 } };
  const raws = r.items.map(i => ({ ...i, src: id }));
  for (const x of raws) {
    x.keys = x.keys ?? extractKeys(x.title, c.aliases);
    x.dkey = x.src + ':' + (await sha1hex((x.guid || x.url) + '|' + String(x.title).toLowerCase().replace(/\s+/g, ' ').trim(), 24));
  }
  const known = await db.existingKeys(c.DB, raws.map(x => x.dkey));
  const fresh = [...new Map(raws.filter(x => !known.has(x.dkey)).map(x => [x.dkey, x])).values()];
  const full = x => c.keep(x) || (c.ai && !x.keys.length && !x.peer);
  return {
    stat: { status: 'ok', code: r.code || 200, items: 0, noise: r.noise || 0, ms: r.ms || 0 }, more: !!r.more,
    items: fresh.filter(full), drop: fresh.filter(x => !full(x)).map(x => x.dkey),
  };
}

// NCSC alert pages for new alerts: IDs, CVSS and version ranges.
export async function details(env, run, items) {
  const c = await context(env, run);
  return fetchNcscDetails(items, c.ctx, items.length);
}

// Optional AI product extraction for headlines no rule matched (headline in, keys mapped locally).
export async function aiExtract(env, run, items) {
  const c = await context(env, run), out = {};
  for (const r of items) {
    try { const k = await extractProduct(env, c.S, r.title, c.aliases, run.fetch); if (k.length) out[r.dkey] = k; } catch { /* AI is optional */ }
  }
  return out;
}

// One EPSS fetch (a page for the API, the whole file for bulk), matched locally to CVEs we hold or just kept.
export async function enrich(env, run, id, page, keptCves) {
  const c = await context(env, run), s = c.byId[id];
  const wanted = new Set([...(await db.storedCves(c.DB)), ...keptCves]);
  try {
    const r = PAGED_ENRICHERS[s.parser] ? await PAGED_ENRICHERS[s.parser](s, c.ctx, wanted, page) : await ENRICHERS[s.parser](s, c.ctx, wanted);
    return r.epss ? { code: r.code, ms: r.ms, epss: r.epss, rows: r.rows, more: !!r.more } : { code: r.code, ms: r.ms || 0 };
  } catch { return { code: 'Error', ms: 0 }; }
}

// Persist the run, kept items (headline, link, date, extracted fields) and dedup keys; EPSS as a delta.
export async function store(env, run, { srcStat, items, seen, epss }) {
  const DB = env.DB, cum = {};
  for (const x of await db.runStats(DB)) Object.assign(cum, x.epss);
  const epssDelta = {};
  for (const [k, v] of Object.entries(epss || {})) if (cum[k] !== v) epssDelta[k] = v;
  const row = await DB.prepare('INSERT INTO run (at, mode, stats) VALUES (?, ?, ?) RETURNING id').bind(run.now, run.mode, JSON.stringify({ srcStat, epss: epssDelta })).first();
  const stmts = [
    ...db.insertItems(DB, row.id, items.map(r => ({ src: r.src, dkey: r.dkey, at: Math.round(r.at), title: String(r.title).slice(0, 300), url: String(r.url).slice(0, 600), fields: pick(r) }))),
    ...db.insertSeen(DB, seen, run.now),
  ];
  for (let i = 0; i < stmts.length; i += 50) await DB.batch(stmts.slice(i, i + 50));
  return row.id;
}

// Rebuild signals, route Act, and close the run record.
export async function finish(env, run, runId, t0, kept, src) {
  const out = await rebuildAndRoute(env, { runId, now: run.now, fetch: run.fetch });
  const ms = Date.now() - t0;
  await env.DB.prepare('UPDATE run SET ms = ? WHERE id = ?').bind(ms, runId).run();
  if (run.mode === 'Schedule') await db.putKV(env.DB, 'lastScheduled', run.day || null);
  const r = out.state.runs[out.state.runs.length - 1];
  return { ok: true, run: { id: runId, at: run.now, mode: run.mode, ms, fetched: r?.fetched ?? 0, items: kept, noise: r?.noise ?? 0, created: r?.created ?? 0, updated: r?.updated ?? 0, hidden: r?.hidden ?? 0, routed: out.routed, warn: Object.values(src).filter(x => x.status === 'error').length, src }, open: out.state.open };
}

// ───────── driver ─────────

// step(name, fn) runs one job: inline here, `step.do` in the Workflow. Names are stable so a Workflow can resume.
// run: { mode, now, day, push, only, owner, wait, fetch }
export async function orchestrate(env, run, step, { parallel = 4 } = {}) {
  const b = await step('begin', () => begin(env, run));
  if (b.busy) return { busy: true };
  try {
    const srcStat = { ...b.srcStat }, got = [];
    const pulls = run.push ? [{ id: run.push.src, paged: false }] : b.pulls;
    await pool(pulls, parallel, async p => {
      for (let page = 1; ; page++) {
        const r = await step(`pull ${p.id}${p.paged ? ' ' + page : ''}`, () => pull(env, run, p.id, page));
        if (r.push) return;
        if (page === 1) srcStat[p.id] = r.stat;
        else if (r.stat.status === 'error') { srcStat[p.id].code = r.stat.code; return; }
        else srcStat[p.id].ms += r.stat.ms;
        if (r.stat.status === 'error') return;
        got.push(r);
        if (!r.more) return;
      }
    });
    // one fresh list in source order; a key seen on two pages keeps its last copy
    const fresh = [...new Map(got.flatMap(r => r.items).map(x => [x.dkey, x])).values()];
    const drop = [...new Set(got.flatMap(r => r.drop))];

    const c = await context(env, run);
    const ncsc = fresh.filter(x => c.byId[x.src]?.parser === 'ncsc_alerts@2');
    if (ncsc.length) {
      const lim = c.byId[ncsc[0].src]?.params?.detail ?? 12;
      const parts = chunk(ncsc.slice(0, lim), 3);
      for (const [i, part] of parts.entries()) {
        const det = await step(`ncsc ${i + 1}`, () => details(env, run, part));
        det.forEach((d, k) => Object.assign(part[k], d));
      }
    }

    if (c.ai) {
      const ask = fresh.filter(x => !x.keys.length && !x.peer).slice(0, 20);
      if (ask.length) {
        const keys = await step('ai', () => aiExtract(env, run, ask.map(x => ({ dkey: x.dkey, title: x.title }))));
        for (const x of ask) if (keys[x.dkey]) x.aiKeys = keys[x.dkey];
      }
    }

    // keep only what matches the inventory (plus NZ peer incidents and NCSC alerts); the rest is a count
    const kept = fresh.filter(c.keep);
    const count = (src, k) => { const x = srcStat[src] || (srcStat[src] = { status: 'ok', code: 200, items: 0, noise: 0 }); x[k]++; };
    for (const x of fresh) count(x.src, c.keep(x) ? 'items' : 'noise');
    for (const k of drop) count(k.slice(0, k.indexOf(':')), 'noise');

    // enrichment from bulk data or threshold pages (no request names a CVE or product)
    const epss = {};
    if (b.enrich && !run.push) {
      const cves = [...new Set(kept.flatMap(x => x.cves || []))];
      let st = null;
      for (let page = 1; ; page++) {
        const r = await step(`epss ${page}`, () => enrich(env, run, b.enrich.id, page, cves));
        if (!r.epss) { st = page === 1 ? { status: 'error', code: r.code, items: 0, noise: 0 } : st; break; }
        if (!st) st = { status: 'ok', code: r.code, items: 0, noise: 0, ms: 0, rows: 0, matched: 0 };
        st.ms += r.ms; st.rows += r.rows; Object.assign(epss, r.epss);
        if (!b.enrich.paged || !r.more) break;
      }
      if (st?.status === 'ok') st.matched = Object.keys(epss).length;
      if (st) srcStat[b.enrich.id] = st;
    }

    const seen = [...fresh.map(x => ({ dkey: x.dkey, kept: c.keep(x) })), ...drop.map(dkey => ({ dkey, kept: false }))];
    const runId = await step('store', () => store(env, run, { srcStat, items: kept, seen, epss }));
    const done = await step('route', () => finish(env, run, runId, b.t0, kept.length, srcStat));
    // two-way sync for what this run routed or ticketed; a failure here never fails the run
    await step('sync', () => syncAll(env, { now: run.now, fetch: run.fetch }).catch(e => ({ error: String(e?.message || e) })));
    return done;
  } finally {
    await step('release', () => db.releaseLock(env.DB, 'run', run.owner).then(() => true));
  }
}

// With the RUN_FLOW binding (Workers Free) a run is queued as a Workflow instance (src/flow.js) instead.
export async function queueRun(env, params) {
  await db.ensureSeed(env.DB);
  if (await db.lockHeld(env.DB, 'run')) return { busy: true };
  const inst = await env.RUN_FLOW.create({ params: { ...params, owner: crypto.randomUUID() } });
  return { id: inst.id };
}

// opts: { mode: 'Schedule' | 'Run now' | 'Email', push: { src, items } | null, now, day, fetch, wait, only }
export function runPipeline(env, opts = {}) {
  const run = { ...opts, mode: opts.mode || 'Run now', now: opts.now || Date.now(), owner: crypto.randomUUID() };
  return orchestrate(env, run, (name, fn) => fn());
}

// Build state from D1, answer grey-zone pairs (AI flag only), and send Act signals whose state hash changed.
export async function rebuildAndRoute(env, { runId = null, now = Date.now(), fetch: fetchImpl } = {}) {
  const DB = env.DB;
  let { store, dataset } = await db.liveStore(DB);
  let state = buildState(store, dataset);
  const S = state.S;
  await loadVault(env, S);

  if (S.ai && S.aiGroup && state.pendingPairs.length && aiAvailable(env, S)) {
    const asked = [];
    for (const p of state.pendingPairs.slice(0, 10)) {
      try { const r = await greyPair(env, S, p.a, p.b, fetchImpl); asked.push(DB.prepare('INSERT OR REPLACE INTO ai_pair (k, same, conf, at) VALUES (?,?,?,?)').bind(pairKey(p.a, p.b), r.same ? 1 : 0, r.conf, now)); } catch { /* optional */ }
    }
    if (asked.length) { await DB.batch(asked); ({ store, dataset } = await db.liveStore(DB)); state = buildState(store, dataset); }
  }

  const configured = sentinelConfigured(env, S);
  const ok = x => /^2\d\d$/.test(x.status) || (x.status === 'dry-run' && !configured) || x.status === 'webhook';
  const due = state.all.filter(s => s.level === 'act').map(s => ({ s, hash: routeHash(s, 'act'), prev: state.sent[s.id] || null })).filter(x => !x.prev || x.prev.hash !== x.hash || !ok(x.prev));
  let routed = 0;
  if (due.length) {
    const rows = [];
    if (S.actRoute === 'webhook') {
      for (const x of due) {
        const need = planTickets(x.s, store.decisions);
        const refs = need.length ? await createTickets(env, S, x.s, need, fetchImpl, now) : [];
        if (refs.length) await db.insertDecision(DB, { id: 'D-' + crypto.randomUUID().slice(0, 8), sig: x.s.id, at: now, by: 'Pipeline', act: 'auto', refs, rev: x.s.route?.rev || 0 });
        x.rev = x.prev && x.prev.hash === x.hash ? x.prev.rev : (x.prev?.rev || 0) + 1;
        rows.push({ ...x, to: 'webhook', status: 'webhook' });
      }
    } else {
      for (const x of due) x.rev = x.prev && x.prev.hash === x.hash ? x.prev.rev : (x.prev?.rev || 0) + 1;
      const res = await sendSentinel(env, S, due.map(x => recordFor(x.s, now, x.rev)), fetchImpl);
      for (const x of due) rows.push({ ...x, to: 'sentinel', status: res.status });
    }
    await DB.batch(rows.map(x => DB.prepare('INSERT INTO send (sig, rev, run_id, at, hash, to_sys, status) VALUES (?,?,?,?,?,?,?) ON CONFLICT(sig, rev) DO UPDATE SET run_id = excluded.run_id, at = excluded.at, hash = excluded.hash, status = excluded.status')
      .bind(x.s.id, x.rev, runId, now, x.hash, x.to, x.status)));
    routed = rows.filter(x => ok(x)).length;
    ({ store, dataset } = await db.liveStore(DB));
    state = buildState(store, dataset);
  }
  return { state, store, dataset, routed };
}
