// JSON API for the UI. Every route sits behind auth (src/auth.js).
import { buildState, planTickets, csvImport, DECISIONS, sortSignals, digest } from '../public/engine.js';
import * as db from './db.js';
import { json, secret, clock } from './util.js';
import { runPipeline, queueRun, rebuildAndRoute, settingsOf } from './pipeline.js';
import { PARSERS, PAGED, PARSER_NAMES } from './sources/feeds.js';
import { ENRICHERS, PAGED_ENRICHERS } from './sources/epss.js';
import { parseNcscEmail } from './sources/email.js';
import { sendSentinel, sentinelConfigured, recordFor } from './routes/sentinel.js';
import { createTickets, postTicket, ticketConfigured } from './routes/tickets.js';
import { sendDigest } from './routes/digest.js';
import { aiAvailable } from './ai.js';
import { nextRunAt } from './time.js';
import { aliasesFor } from '../public/engine.js';

const bad = (msg, status = 400) => json({ error: msg }, status);

// Demo mode (AUTH_MODE=demo, public URL, sample inventory): integration targets stay as deployed, sources cannot
// be added or re-pointed, and Run now waits DEMO_GAP between runs. Triage, inventory and thresholds stay open.
const DEMO_LOCKED = ['dce', 'dcr', 'stream', 'table', 'tenant', 'clientId', 'secretRef', 'ticketUrl', 'ticketAuth', 'ticketUser', 'teamsUrl', 'digestTo', 'mailFrom', 'ncscSenders', 'aiEndpoint', 'aiModel', 'aiProvider', 'me'];
const DEMO_GAP = 10 * 6e4, DEMO_PRODUCTS = 200;

async function meta(env, store, user) {
  const S = settingsOf(store.settings);
  const last = await db.getKV(env.DB, 'lastScheduled', null);
  return {
    user: user || (env.AUTH_MODE === 'demo' ? 'Demo visitor' : S.me || 'Security owner'),
    demo: env.AUTH_MODE === 'demo', steps: !!env.RUN_FLOW,
    nextRun: nextRunAt(Date.now(), S, last),
    configured: {
      sentinel: sentinelConfigured(env, S), ticket: ticketConfigured(env, S),
      teams: !!(S.teamsUrl && (S.teamsUrl.startsWith('env:') ? secret(env, S.teamsUrl) : S.teamsUrl)),
      email: !!(S.digestTo && S.mailFrom), ai: aiAvailable(env, { ...S, ai: true }),
    },
    parsers: PARSER_NAMES,
  };
}

async function state(env) {
  const { store, dataset } = await db.liveStore(env.DB);
  return { store, dataset, st: buildState(store, dataset) };
}
function liveSig(st, id) { let s = st.byId[id]; while (s && s.dead && s.into) s = st.byId[s.into]; return s && !s.dead ? s : null; }

export async function api(request, env, ctx, user) {
  const url = new URL(request.url), path = url.pathname.replace(/\/+$/, ''), m = request.method;
  const DB = env.DB, demo = env.AUTH_MODE === 'demo';
  const body = async () => { try { return await request.json(); } catch { return null; } };
  await db.ensureSeed(DB);

  if (path === '/api/health') return json({ ok: true, at: Date.now() });

  if (path === '/api/live' && m === 'GET') {
    const { store, dataset } = await db.liveStore(DB);
    return json({ store, dataset, meta: await meta(env, store, user) });
  }

  if (path === '/api/settings' && m === 'PUT') {
    const b = await body();
    if (!b || typeof b !== 'object') return bad('Body');
    if (demo) { const cur = await db.loadSettings(DB); for (const k of DEMO_LOCKED) { if (k in cur) b[k] = cur[k]; else delete b[k]; } }
    await db.saveSettings(DB, b);
    return json({ ok: true, settings: await db.loadSettings(DB) });
  }

  if (path === '/api/inventory' && m === 'PUT') {
    const b = await body();
    if (!Array.isArray(b)) return bad('Body');
    if (demo && b.length > DEMO_PRODUCTS) return bad('Demo limit', 403);
    const r = await db.saveInventory(DB, b);
    return r.error ? bad(r.error) : json(r);
  }

  if (path === '/api/inventory/check' && m === 'POST') {
    const text = await request.text();
    return json(csvImport(text, await db.loadInventory(DB)));
  }

  if (path === '/api/sources' && m === 'POST') {
    if (demo) return bad('Demo', 403);
    const b = await body();
    if (!b?.name || !/^(https?:\/\/|mailto:)\S+$/.test(b.url || '') || !PARSER_NAMES.includes(b.parser)) return bad('Source');
    const src = { id: 'x' + Date.now().toString(36), fam: b.fam || 'x' + Date.now().toString(36), name: String(b.name).slice(0, 60), icon: b.icon || 'rss', kind: b.kind || 'RSS', role: 'Feed', tier: [1, 2, 3].includes(+b.tier) ? +b.tier : 2, schedule: b.schedule || 'Daily', parser: b.parser, url: b.url, social: !!b.social, nz: !!b.nz, sample: !!b.sample, extra: true, enabled: true };
    await db.saveSource(DB, src);
    return json({ ok: true, source: src });
  }

  let mm = path.match(/^\/api\/sources\/([\w-]+)$/);
  if (mm && m === 'PUT') {
    const cur = (await db.loadSources(DB)).find(s => s.id === mm[1]);
    if (!cur) return bad('Not found', 404);
    const b = (await body()) || {};
    if (demo && Object.keys(b).some(k => k !== 'enabled')) return bad('Demo', 403);
    const next = { ...cur };
    if ('enabled' in b) next.enabled = !!b.enabled;
    if (b.url && /^(https?:\/\/|mailto:)\S+$/.test(b.url)) next.url = b.url;
    if ([1, 2, 3].includes(+b.tier)) next.tier = +b.tier;
    if (b.schedule) next.schedule = String(b.schedule).slice(0, 40);
    if (b.parser && PARSER_NAMES.includes(b.parser)) next.parser = b.parser;
    if (b.params && typeof b.params === 'object') next.params = b.params;
    await db.saveSource(DB, next);
    return json({ ok: true, source: next });
  }

  mm = path.match(/^\/api\/sources\/([\w-]+)\/test$/);
  if (mm && m === 'POST') {
    const src = (await db.loadSources(DB)).find(s => s.id === mm[1]);
    if (!src) return bad('Not found', 404);
    const S = settingsOf(await db.loadSettings(DB));
    const ctx = { now: Date.now(), settings: S, aliases: aliasesFor(await db.loadInventory(DB)), secret: ref => secret(env, ref) };
    const t0 = Date.now();
    try {
      // paged sources: first page only, so a test stays one small request
      const probe = new Set(['CVE-2021-44228']);
      if (ENRICHERS[src.parser]) { const r = PAGED_ENRICHERS[src.parser] ? await PAGED_ENRICHERS[src.parser](src, ctx, probe, 1) : await ENRICHERS[src.parser](src, ctx, probe); return json({ code: String(r.code), n: r.rows || 0, ms: Date.now() - t0 }); }
      if (!PARSERS[src.parser]) return json({ code: 'No parser', n: 0, ms: 0 });
      const r = PAGED[src.parser] ? await PAGED[src.parser](src, ctx, 1) : await PARSERS[src.parser](src, ctx);
      if (r.push) return json({ code: 'Push', n: 0, ms: 0 });
      return json({ code: String(r.code || (r.items ? 200 : 'Error')), n: r.items ? r.items.length : 0, ms: Date.now() - t0, titles: (r.items || []).slice(0, 3).map(i => i.title) });
    } catch (e) { return json({ code: e?.name === 'AbortError' ? 'Timeout' : 'Error', n: 0, ms: Date.now() - t0 }); }
  }

  if (path === '/api/decisions' && m === 'POST') {
    const b = await body();
    if (!b || !DECISIONS[b.act] || b.act === 'auto') return bad('Decision');
    const { store, st } = await state(env);
    const s = liveSig(st, b.sig);
    if (!s || s.level === 'hidden') return bad('Signal', 404);
    let refs = [];
    if (b.act === 'ticket') {
      const need = planTickets(s, store.decisions);
      if (!need.length) return json({ exists: true, refs: s.tickets, products: s.products.length });
      refs = await createTickets(env, st.S, s, need);
      if (!refs.length) return bad('Ticket failed', 502);
    }
    const d = { id: /^D-[\w-]{4,40}$/.test(b.id || '') ? b.id : 'D-' + crypto.randomUUID().slice(0, 8), sig: s.id, at: clock(env), by: user || st.S.me || 'Security owner', act: b.act, refs, ...(b.reason ? { reason: String(b.reason).slice(0, 40) } : {}) };
    await db.insertDecision(DB, d);
    return json({ ok: true, decision: d });
  }

  mm = path.match(/^\/api\/decisions\/([\w-]+)$/);
  if (mm && m === 'DELETE') { await db.undoDecision(DB, mm[1]); return json({ ok: true }); }
  if (mm && m === 'PATCH') { const b = (await body()) || {}; await db.setReason(DB, mm[1], b.reason ? String(b.reason).slice(0, 40) : null); return json({ ok: true }); }

  if (path === '/api/run' && m === 'POST') {
    if (demo) {
      const last = (await DB.prepare("SELECT max(at) AS at FROM run WHERE mode = 'Run now'").first('at')) || 0, wait = last + DEMO_GAP - clock(env);
      if (wait > 0) return json({ error: 'Demo limit', wait: Math.ceil(wait / 6e4) }, 429);
    }
    if (env.RUN_FLOW) {
      const q = await queueRun(env, { mode: 'Run now', now: clock(env) });
      return q.busy ? json({ busy: true }, 409) : json({ queued: true, id: q.id }, 202);
    }
    const r = await runPipeline(env, { mode: 'Run now', wait: 0, now: clock(env) });
    return r.busy ? json({ busy: true }, 409) : json(r);
  }

  mm = path.match(/^\/api\/run\/([\w-]{8,128})$/);
  if (mm && m === 'GET') {
    if (!env.RUN_FLOW) return bad('Not found', 404);
    let s;
    try { s = await (await env.RUN_FLOW.get(mm[1])).status(); } catch { return bad('Not found', 404); }
    return json({ status: s.status, output: s.output ?? null, error: s.error ? String(s.error.message || s.error.name || 'Error') : null });
  }

  if (path === '/api/ingest/email' && m === 'POST') {
    if (demo) return bad('Demo', 403);
    const raw = await request.text();
    const item = parseNcscEmail(raw);
    if (!item) return bad('No NCSC alert link');
    if (env.RUN_FLOW) { const inst = await env.RUN_FLOW.create({ params: { mode: 'Email', push: { src: 'ncsc_mail', items: [item] }, now: clock(env), owner: crypto.randomUUID() } }); return json({ queued: true, id: inst.id }, 202); }
    const r = await runPipeline(env, { mode: 'Email', push: { src: 'ncsc_mail', items: [item] }, wait: 60000, now: clock(env) });
    return json(r);
  }

  if (path === '/api/digest' && m === 'GET') { const { st } = await state(env); return json(digest(st)); }

  mm = path.match(/^\/api\/test\/(sentinel|ticket|digest)$/);
  if (mm && m === 'POST') {
    const { st } = await state(env), S = st.S;
    const hero = sortSignals(st.signals.filter(s => s.level === 'act'))[0] || sortSignals(st.signals)[0];
    if (mm[1] === 'sentinel') {
      if (!hero) return json({ status: 'No signal' });
      const rec = { ...recordFor(hero, Date.now(), 0), SignalId: 'TEST-' + hero.id };
      const r = await sendSentinel(env, S, [rec]);
      return json({ status: r.status, record: rec });
    }
    if (mm[1] === 'ticket') {
      if (!hero || !hero.products[0]) return json({ status: 'No product' });
      const r = await postTicket(env, S, { ...hero, id: 'TEST-' + hero.id, title: 'TEST · ' + hero.title }, hero.products[0]);
      return json({ status: r.status, ref: r.ref || null, payload: r.payload });
    }
    const r = await sendDigest(env, S, st);
    return json(r);
  }

  if (path === '/api/rebuild' && m === 'POST' && demo) return bad('Demo', 403);
  if (path === '/api/rebuild' && m === 'POST') { const r = await rebuildAndRoute(env); return json({ ok: true, routed: r.routed }); }

  return bad('Not found', 404);
}
