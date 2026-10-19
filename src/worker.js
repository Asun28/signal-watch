// Signal Watch Worker: UI (static assets), JSON API, daily schedule (cron) and NCSC email ingest.
import { authenticate } from './auth.js';
import { api } from './api.js';
import { runPipeline, queueRun, rebuildAndRoute, settingsOf } from './pipeline.js';
import * as db from './db.js';
import { nzParts, runDue, digestDue } from './time.js';
import { sendDigest } from './routes/digest.js';
import { parseNcscEmail } from './sources/email.js';
import { syncAll } from './sync.js';

const CSP = "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

function secure(res) {
  const r = new Response(res.body, res);
  r.headers.set('content-security-policy', CSP);
  r.headers.set('x-content-type-options', 'nosniff');
  r.headers.set('referrer-policy', 'no-referrer');
  r.headers.set('permissions-policy', 'camera=(), microphone=(), geolocation=()');
  return r;
}

// Every 15 min (UTC cron): run once per NZ day at Settings → Schedule, send the digest at Settings → Digest, and
// sync with Sentinel incidents and tickets (src/sync.js).
export async function tick(env, now = Date.now(), fetchImpl) {
  await db.ensureSeed(env.DB);
  const S = settingsOf(await db.loadSettings(env.DB));
  const day = nzParts(now).date;
  const last = await db.getKV(env.DB, 'lastScheduled', null);
  const out = { day, ran: false, digest: null };
  if (runDue(now, S, last)) {
    await db.purge(env.DB, S.rawDays || 90);
    if (env.RUN_FLOW) {
      // Workflow run: lastScheduled is set when it finishes. At most 3 starts per NZ day if a run keeps failing.
      const q = await db.getKV(env.DB, 'schedQueued', {});
      const n = q.day === day ? q.n : 0;
      if (n < 3) {
        const r = await queueRun(env, { mode: 'Schedule', now, day });
        if (r.id) await db.putKV(env.DB, 'schedQueued', { day, n: n + 1 });
        out.ran = !!r.id; out.queued = r.id || null;
      }
    } else {
      const r = await runPipeline(env, { mode: 'Schedule', now, day, fetch: fetchImpl, wait: 120000 });
      out.ran = !r.busy;
      out.run = r.run;
    }
  }
  const lastDigest = await db.getKV(env.DB, 'lastDigest', null);
  const ranToday = (await db.getKV(env.DB, 'lastScheduled', null)) === day;
  if (digestDue(now, S, lastDigest, ranToday)) {
    const { state } = await rebuildAndRoute(env, { now, fetch: fetchImpl });
    const r = await sendDigest(env, S, state, fetchImpl);
    await db.putKV(env.DB, 'lastDigest', day);
    await env.DB.prepare('INSERT OR REPLACE INTO digest (day, at, teams, email) VALUES (?,?,?,?)').bind(day, now, r.teams, r.email).run();
    out.digest = { teams: r.teams, email: r.email };
  }
  try { out.sync = await syncAll(env, { now, fetch: fetchImpl }); } catch (e) { out.sync = { error: String(e?.message || e) }; }
  return out;
}

export default {
  async fetch(request, env, ctx) {
    const a = await authenticate(request, env);
    if (a instanceof Response) return a;
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      try { return await api(request, env, ctx, a.user); }
      catch (e) { console.error('api', url.pathname, e?.stack || e); return new Response(JSON.stringify({ error: 'Server error' }), { status: 500, headers: { 'content-type': 'application/json' } }); }
    }
    if (url.pathname === '/rules') return secure(await env.ASSETS.fetch(new Request(new URL('/rules.html', url), request)));
    return secure(await env.ASSETS.fetch(request));
  },

  async scheduled(controller, env, ctx) {
    ctx.waitUntil(tick(env, controller.scheduledTime).then(r => console.log('tick', JSON.stringify({ day: r.day, ran: r.ran, queued: r.queued, digest: r.digest, sync: r.sync }))).catch(e => console.error('tick', e?.stack || e)));
  },

  // Cloudflare Email Routing → this Worker: NCSC alert emails (fallback when the alerts page is down).
  async email(message, env, ctx) {
    const S = settingsOf(await db.loadSettings(env.DB));
    const allow = String(S.ncscSenders || 'ncsc.govt.nz').split(/[,\s]+/).filter(Boolean);
    if (!allow.some(d => message.from.toLowerCase().endsWith(d.toLowerCase()))) { message.setReject('Sender not allowed'); return; }
    const raw = await new Response(message.raw).text();
    const item = parseNcscEmail(raw);
    if (!item) return;
    if (env.RUN_FLOW) await env.RUN_FLOW.create({ params: { mode: 'Email', push: { src: 'ncsc_mail', items: [item] }, now: Date.now(), owner: crypto.randomUUID() } });
    else await runPipeline(env, { mode: 'Email', push: { src: 'ncsc_mail', items: [item] }, wait: 120000 });
  },
};
