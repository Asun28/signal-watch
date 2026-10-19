// Acceptance A1–A12, mapped from the brief's hard rules and "Done when". Drives the real Worker
// (fetch / scheduled code paths) over a node:sqlite D1 and recorded feed responses.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import worker, { tick } from '../src/worker.js';
import { runPipeline } from '../src/pipeline.js';
import * as db from '../src/db.js';
import * as E from '../public/engine.js';
import { d1 } from './d1.js';
import { fakeNet } from './fake-net.js';
import { teamsCard } from '../src/routes/digest.js';

const NOW = Date.parse('2026-10-19T07:30:00+13:00');
const NS_URL = 'https://www.ncsc.govt.nz/alerts/multiple-vulnerabilities-affecting-citrix-netscaler-adc-and-netscaler-gateway-products-2/';
const INTERNAL = /login\.microsoftonline\.com|ingest\.monitor\.azure\.com|service-now\.com|powerplatform\.com|graph\.microsoft\.com\/v1\.0\/users/;

function setup(over = {}, envExtra = {}) {
  const net = fakeNet(over);
  const env = { DB: d1(), AUTH_MODE: 'none', FIXED_NOW: String(NOW), ...envExtra };
  globalThis.fetch = net.fetch; // auth / routes use the global fetch in the Worker
  const call = async (method, path, body, raw) => {
    const res = await worker.fetch(new Request('http://localhost' + path, { method, body: raw ?? (body === undefined ? undefined : JSON.stringify(body)), headers: { 'content-type': raw ? 'text/plain' : 'application/json' } }), env, { waitUntil() {} });
    return { status: res.status, body: await res.json().catch(() => null) };
  };
  const state = async () => { const { store, dataset } = await db.liveStore(env.DB); return E.buildState(store, dataset); };
  const nsSig = st => st.all.find(s => s.items.some(i => i.src === 'ncsc' && /NetScaler/.test(i.title)));
  return { env, net, call, state, nsSig };
}

test('A1 · Run modes: Run now and the daily 07:30 Pacific/Auckland schedule (DST-safe, once per day)', async () => {
  const { env, net, call } = setup();
  assert.equal((await tick(env, Date.parse('2026-10-19T18:15:00Z'), net.fetch)).ran, false); // 07:15 NZDT
  assert.equal((await tick(env, Date.parse('2026-10-19T18:30:00Z'), net.fetch)).ran, true); // 07:30 NZDT
  assert.equal((await tick(env, Date.parse('2026-10-19T18:45:00Z'), net.fetch)).ran, false); // already ran today
  const winter = setup();
  assert.equal((await tick(winter.env, Date.parse('2026-06-30T18:30:00Z'), winter.net.fetch)).ran, false); // 06:30 NZST
  assert.equal((await tick(winter.env, Date.parse('2026-06-30T19:30:00Z'), winter.net.fetch)).ran, true); // 07:30 NZST
  const r = await call('POST', '/api/run');
  assert.equal(r.status, 200);
  assert.equal(r.body.run.mode, 'Run now');
  // the advisory lock stops overlapping runs
  await db.acquireLock(env.DB, 'run', 'other');
  assert.equal((await call('POST', '/api/run')).status, 409);
});

test('A2 · Sources are config: a new RSS source added via the API is fetched on the next run', async () => {
  const feed = '<rss><channel><item><title>FortiGate SSL-VPN brute force spike</title><link>https://example.nz/fg-1</link><pubDate>Mon, 19 Oct 2026 06:00:00 +1300</pubDate></item><item><title>Unrelated vendor funding round</title><link>https://example.nz/x</link></item></channel></rss>';
  const { call, state } = setup({ 'https://example.nz/feed.xml': () => [200, feed, 'application/rss+xml'] });
  const add = await call('POST', '/api/sources', { name: 'Example NZ feed', url: 'https://example.nz/feed.xml', parser: 'rss@1', tier: 2, kind: 'RSS' });
  assert.equal(add.status, 200);
  const r = await call('POST', '/api/run');
  assert.equal(r.body.run.src[add.body.source.id].items, 1);
  assert.equal(r.body.run.src[add.body.source.id].noise, 1);
  const st = await state();
  assert.ok(st.all.some(s => s.srcIds.includes(add.body.source.id) && s.products.some(p => p.id === 'p04')));
  // config change only: disable it and it is skipped
  await call('PUT', '/api/sources/' + add.body.source.id, { enabled: false });
  assert.equal((await call('POST', '/api/run')).body.run.src[add.body.source.id].status, 'off');
});

test('A3 · Inventory: only matching items are kept, the rest is a count; decoys never match; scope by management model', async () => {
  const { env, call, state } = setup();
  const r = await call('POST', '/api/run');
  const inv = await db.loadInventory(env.DB), keys = new Set(inv.map(E.productKey));
  const items = (await env.DB.prepare('SELECT src, fields FROM item').all()).results.map(i => ({ src: i.src, ...JSON.parse(i.fields) }));
  assert.ok(items.length > 0 && r.body.run.noise > items.length);
  assert.ok(items.every(i => (i.keys || []).some(k => keys.has(k)) || i.peer || i.src.startsWith('ncsc')));
  const st = await state();
  const decoys = inv.filter(p => p.decoy).map(p => p.id);
  assert.equal(decoys.length, 3);
  assert.ok(!st.all.some(s => s.matches.some(m => decoys.includes(m.pid))));
  // news about a hyperscaler product (Microsoft 365) is out of scope → Hidden, listed as out of scope
  const oos = st.all.find(s => s.outOfScope.some(p => p.id === 'p25'));
  assert.ok(oos && oos.level === 'hidden');
  // CSV import through the inventory API
  const csv = E.csvImport(E.CSV_SAMPLE, inv);
  const add = csv.rows.filter(x => x.status === 'ok').map((x, i) => ({ id: 'c' + i, ...x.data }));
  assert.equal((await call('PUT', '/api/inventory', [...inv, ...add])).status, 200);
  assert.equal((await db.loadInventory(env.DB)).length, 30 + add.length);
});

test('A4 · Grouping: one signal per event across sources; a new source updates it and sets Updated', async () => {
  const { env, net, state, nsSig } = setup();
  await runPipeline(env, { now: NOW, fetch: net.fetch });
  let st = await state(), s = nsSig(st);
  assert.deepEqual(s.families.sort(), ['kev', 'ncsc']);
  // KEV 88771 and 88772 arrive first as two signals; the NCSC alert lists both CVEs and merges them (step 1)
  assert.ok(s.items.some(i => i.src === 'ncsc' && i.join.step === 1));
  assert.equal(s.merged.length, 1);
  assert.equal(s.updated, false);
  // decide it, then a SecurityBrief story about the same product arrives → step 3, Updated, re-opened
  await env.DB.prepare("INSERT INTO decision (id, sig, at, by, act, refs) VALUES ('D-t1', ?, ?, 'x', 'ack', '[]')").bind(s.id, NOW + 6e4).run();
  const rss = '<rss><channel><item><title>NetScaler attacks continue after patch</title><link>https://securitybrief.co.nz/story/netscaler-attacks</link><pubDate>Mon, 19 Oct 2026 09:00:00 +1300</pubDate></item></channel></rss>';
  const net2 = fakeNet({ 'https://securitybrief.co.nz/feed': () => [200, rss, 'application/rss+xml'] });
  await runPipeline(env, { now: NOW + 3 * 36e5, fetch: net2.fetch });
  st = await state(); const s2 = nsSig(st);
  assert.equal(s2.id, s.id);
  const story = s2.items.find(i => i.src === 'sbnz');
  assert.equal(story.join.step, 3);
  assert.equal(s2.updated, true);
  assert.equal(s2.status, 'open');
  // the KEV entry for a different CVE stays apart (disjoint IDs block steps 2–5)
  assert.ok(st.all.some(x => x.id !== s.id && x.cves.has('CVE-2026-88779')));
});

test('A5 · Levels by readable rules; thresholds come from settings', async () => {
  const { env, net, call, state, nsSig } = setup();
  await runPipeline(env, { now: NOW, fetch: net.fetch });
  let st = await state();
  assert.equal(nsSig(st).level, 'act'); assert.equal(nsSig(st).rule, 'A1');
  const kev = st.all.find(s => s.cves.has('CVE-2026-88779'));
  assert.equal(kev.level, 'act'); assert.equal(kev.rule, 'A2');
  const veeam = st.all.find(s => s.cves.has('CVE-2026-99001'));
  assert.equal(veeam.level, 'plan'); assert.equal(veeam.rule, 'P2');
  const mmh = st.all.find(s => /Manage My Health/.test(s.title));
  assert.equal(mmh.level, 'watch'); assert.equal(mmh.rule, 'W2');
  assert.ok(st.all.some(s => s.level === 'hidden' && s.rule === 'H1'));
  await call('PUT', '/api/settings', { cvss: 9.5 });
  st = await state();
  assert.equal(st.all.find(s => s.cves.has('CVE-2026-99001')).level, 'info');
});

test('A6 · AI off: the pipeline is complete with no model calls; Fix is parser-sourced only', async () => {
  let calls = 0;
  const { env, net, state } = setup({}, { AI: { run: async () => { calls++; return { response: '{}' }; } } });
  await runPipeline(env, { now: NOW, fetch: net.fetch });
  const st = await state();
  assert.equal(st.S.ai, false);
  assert.equal(calls, 0);
  assert.ok(st.all.every(s => s.items.every(i => (i.join?.step || 0) <= 3)));
  assert.ok(st.all.some(s => s.level === 'act'));
  assert.ok(st.all.every(s => s.items.every(i => !i.fix || (i.fixSrc && i.keysBy !== 'ai'))));
});

test('A7 · Storage: headline, link, date and extracted fields only; never full articles', async () => {
  const { env, net } = setup();
  await runPipeline(env, { now: NOW, fetch: net.fetch });
  const cols = (await env.DB.prepare('PRAGMA table_info(item)').all()).results.map(c => c.name);
  assert.deepEqual(cols, ['id', 'run_id', 'src', 'dkey', 'at', 'title', 'url', 'fields']);
  const allowed = new Set(['cves', 'advs', 'keys', 'keysBy', 'aiKeys', 'type', 'cvss', 'kev', 'actBy', 'fix', 'affected', 'peer', 'sample']);
  const rows = (await env.DB.prepare('SELECT title, fields FROM item').all()).results;
  assert.ok(rows.every(r => Object.keys(JSON.parse(r.fields)).every(k => allowed.has(k)) && r.title.length <= 300));
  const dump = JSON.stringify(env.DB.raw.prepare('SELECT * FROM item').all());
  assert.ok(!dump.includes('underscores Cohesity')); // SecurityBrief description text
  assert.ok(!dump.includes('What to look for')); // NCSC alert body text
  const kev = JSON.parse(fs.readFileSync(new URL('./fixtures/kev.json', import.meta.url), 'utf8'));
  assert.ok(kev.vulnerabilities.every(v => !dump.includes(v.shortDescription.slice(0, 60)))); // KEV descriptions
});

test('A8 · Inventory never leaves: outbound requests do not depend on it; model input is headlines only', async () => {
  const external = log => log.filter(x => !INTERNAL.test(x.url)).map(x => x.method + ' ' + x.url + ' ' + x.body).sort();
  const a = setup(); await runPipeline(a.env, { now: NOW, fetch: a.net.fetch });
  const b = setup();
  await b.env.DB.prepare('SELECT 1').first(); await db.ensureSeed(b.env.DB);
  await db.saveInventory(b.env.DB, [{ id: 'z1', name: 'Totally Different Product', vendor: 'Nobody', cpe: '', version: '1', owner: 'Someone Else', model: 'self' }]);
  await runPipeline(b.env, { now: NOW, fetch: b.net.fetch });
  assert.deepEqual(external(a.net.log), external(b.net.log));
  const inv = E.SEED_INVENTORY.flatMap(p => [p.cpe, p.owner, p.version].filter(x => x && x.length > 3));
  assert.ok(!a.net.log.filter(x => !INTERNAL.test(x.url)).some(x => inv.some(v => (x.url + x.body).includes(v))));
  // AI on: the model sees one or two headlines, nothing else
  const prompts = [];
  const c = setup({}, { AI: { run: async (_m, q) => { prompts.push(q.messages.map(m => m.content).join('\n')); return { response: '{"same": false, "confidence": 0.2, "vendor": "", "product": ""}' }; } } });
  await db.ensureSeed(c.env.DB); await db.saveSettings(c.env.DB, { ai: true });
  await runPipeline(c.env, { now: NOW, fetch: c.net.fetch });
  assert.ok(prompts.length > 0);
  assert.ok(prompts.every(p => !E.SEED_INVENTORY.some(x => (x.cpe && p.includes(x.cpe)) || p.includes(x.owner) || p.includes(x.version + ' ') )));
});

test('A9 · Sentinel: Logs Ingestion into SignalWatch_CL, idempotent on SignalId, Revision on change', async () => {
  const posts = [];
  const over = {
    'https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token': () => [200, JSON.stringify({ access_token: 'tok', expires_in: 3600 }), 'application/json'],
    'https://dce-1.australiaeast-1.ingest.monitor.azure.com/*': ({ url, body }) => { posts.push({ url, rows: JSON.parse(body) }); return [204, null]; },
  };
  const { env, net, call } = setup(over, { SENTINEL_CLIENT_SECRET: 's3cret' });
  await db.ensureSeed(env.DB);
  await call('PUT', '/api/settings', { dce: 'https://dce-1.australiaeast-1.ingest.monitor.azure.com', dcr: 'dcr-abc', tenant: 'tenant-1', clientId: 'app-1' });
  await runPipeline(env, { now: NOW, fetch: net.fetch });
  assert.equal(posts.length, 1);
  assert.equal(posts[0].url, 'https://dce-1.australiaeast-1.ingest.monitor.azure.com/dataCollectionRules/dcr-abc/streams/Custom-SignalWatch_CL?api-version=2023-01-01');
  const first = posts[0].rows;
  assert.ok(first.length >= 2 && first.every(r => r.Level === 'Act' && r.Revision === 1 && /^SW-\d+$/.test(r.SignalId)));
  assert.deepEqual(Object.keys(first[0]).sort(), E.DCR_COLUMNS.map(c => c[0]).sort());
  await runPipeline(env, { now: NOW + 36e5, fetch: net.fetch });
  assert.equal(posts.length, 1, 'no change → nothing sent');
  // NCSC email adds CVE-2026-112000 to the NetScaler alert → same SignalId, Revision 2
  const ns = first.find(r => /NetScaler/.test(r.Title) && r.Cves.includes('CVE-2026-88771'));
  const mail = ['From: alerts@ncsc.govt.nz', 'Subject: UPDATED: Multiple vulnerabilities affecting Citrix NetScaler ADC and NetScaler Gateway products', 'Date: Mon, 19 Oct 2026 12:00:00 +1300', 'Content-Type: text/plain', '', 'New: CVE-2026-112000. ' + NS_URL + '?utm_source=ncsc&utm_medium=email', ''].join('\r\n');
  assert.equal((await call('POST', '/api/ingest/email', undefined, mail)).status, 200);
  assert.equal(posts.length, 2);
  const upd = posts[1].rows.find(r => r.SignalId === ns.SignalId);
  assert.equal(upd.Revision, 2);
  assert.ok(upd.Cves.includes('CVE-2026-112000'));
  assert.ok(fs.readFileSync(new URL('../integrations/sentinel/analytics-rule.json', import.meta.url), 'utf8').includes('arg_max(Revision'));
});

test('A10 · Tickets: one ticket per signal per product, templates for ServiceNow, Jira SM, Freshservice, TOPdesk', async () => {
  const made = [];
  const over = { 'https://agency.service-now.com/api/now/table/incident': ({ body }) => { made.push(JSON.parse(body)); return [201, JSON.stringify({ result: { number: 'INC00990' + made.length } }), 'application/json']; } };
  const { env, net, call, state, nsSig } = setup(over, { TICKET_TOKEN: 'tkn' });
  await db.ensureSeed(env.DB);
  await call('PUT', '/api/settings', { ticketUrl: 'https://agency.service-now.com', ticketSys: 'servicenow' });
  await runPipeline(env, { now: NOW, fetch: net.fetch });
  const s = nsSig(await state());
  const t1 = await call('POST', '/api/decisions', { sig: s.id, act: 'ticket' });
  assert.equal(t1.status, 200);
  assert.deepEqual(t1.body.decision.refs.map(r => r.pid).sort(), ['p01', 'p02']);
  assert.equal(made.length, 2);
  assert.deepEqual(made.map(m => m.correlation_id).sort(), [s.id + ':p01', s.id + ':p02']);
  const t2 = await call('POST', '/api/decisions', { sig: s.id, act: 'ticket' });
  assert.equal(t2.body.exists, true);
  assert.equal(made.length, 2, 'second T creates nothing');
  for (const sys of ['servicenow', 'jira', 'freshservice', 'topdesk']) {
    const p = E.ticketPayload(sys, s, s.products[0]);
    assert.equal(p.idempotencyKey, s.id + ':p01');
    assert.ok(JSON.stringify(p.body).includes(s.id + ':p01'));
  }
});

test('A11 · Daily digest to Teams Workflows and email at 07:45; counts, titles and links only', async () => {
  const cards = [], mails = [];
  const over = {
    'https://prod.aa.environment.api.powerplatform.com/workflows/x': ({ body }) => { cards.push(JSON.parse(body)); return [202, '']; },
    'https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token': () => [200, JSON.stringify({ access_token: 'tok', expires_in: 3600 }), 'application/json'],
    'https://graph.microsoft.com/v1.0/users/signalwatch%40agency.govt.nz/sendMail': ({ body }) => { mails.push(JSON.parse(body)); return [202, '']; },
  };
  const { env, net } = setup(over, { TEAMS_WORKFLOW_URL: 'https://prod.aa.environment.api.powerplatform.com/workflows/x', GRAPH_CLIENT_SECRET: 'g' });
  await db.ensureSeed(env.DB);
  await db.saveSettings(env.DB, { tenant: 'tenant-1', clientId: 'app-1', mailFrom: 'signalwatch@agency.govt.nz', digestTo: 'security@agency.govt.nz' });
  await tick(env, Date.parse('2026-10-19T18:30:00Z'), net.fetch); // 07:30 run
  assert.equal(cards.length, 0);
  const t = await tick(env, Date.parse('2026-10-19T18:45:00Z'), net.fetch); // 07:45 digest
  assert.deepEqual(t.digest, { teams: '202', email: '202' });
  assert.equal(cards.length, 1); assert.equal(mails.length, 1);
  const card = cards[0].attachments[0].content;
  assert.equal(card.type, 'AdaptiveCard');
  assert.ok(card.body[1].facts.some(f => f.title === 'Act' && +f.value >= 2));
  await tick(env, Date.parse('2026-10-19T19:00:00Z'), net.fetch);
  assert.equal(cards.length, 1, 'once per day');
  // UI vocabulary: labels of at most two words
  for (const v of [...Object.values(E.LV), ...Object.values(E.TYPES), ...Object.values(E.MODELS)].map(x => x.label).concat(Object.values(E.DECISIONS).map(d => d.short))) assert.ok(v.split(/\s+/).length <= 2, v);
  assert.ok(teamsCard({ date: 'x', counts: { act: 0, plan: 0, watch: 0 }, hidden: 0, act: [], plan: [], watch: [] }).attachments[0].content.body.length === 2);
});

test('A12 · NCSC page down: the email fallback still lands the alert, groups it and routes Act on receipt', async () => {
  const { env, call, state } = setup({ 'https://www.ncsc.govt.nz/alerts/': () => [503, 'down', 'text/html'] });
  const r = await call('POST', '/api/run');
  assert.equal(r.body.run.src.ncsc.status, 'error');
  assert.equal(r.body.run.warn, 1);
  let st = await state();
  const kevSig = st.all.find(s => s.cves.has('CVE-2026-88771'));
  assert.equal(kevSig.rule, 'A2');
  const mail = ['From: NCSC <alerts@ncsc.govt.nz>', 'Subject: UPDATED: Multiple vulnerabilities affecting Citrix NetScaler ADC and NetScaler Gateway products', 'Date: Wed, 14 Oct 2026 12:04:00 +1300', 'Content-Type: text/plain; charset=utf-8', '', 'CVE-2026-88771 CVE-2026-88772 CVE-2026-107406', NS_URL + '?utm_source=ncsc&utm_medium=email', ''].join('\r\n');
  const m = await call('POST', '/api/ingest/email', undefined, mail);
  assert.equal(m.status, 200);
  assert.equal(m.body.run.mode, 'Email');
  st = await state();
  const s = st.all.find(x => x.cves.has('CVE-2026-88771'));
  // the email names 88771 and 88772, so the two KEV signals merge into the older one
  assert.ok(s.id === kevSig.id || s.merged.includes(kevSig.id));
  assert.ok(s.cves.has('CVE-2026-88772'));
  assert.ok(s.srcIds.includes('ncsc_mail'));
  assert.equal(s.rule, 'A1');
  assert.ok(st.routes.some(x => x.sig === s.id));
  // the page comes back: the same alert by canonical URL joins the same signal quietly
  const back = setup();
  back.env.DB = env.DB;
  await runPipeline(env, { now: NOW + 2 * 36e5, fetch: back.net.fetch });
  st = await state();
  assert.equal(st.all.find(x => x.items.some(i => i.src === 'ncsc' && i.curl === E.canonUrl(NS_URL))).id, s.id);
});
