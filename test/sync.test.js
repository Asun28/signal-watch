// Two-way sync (src/sync.js): Sentinel incidents and tickets, in the sandbox and against faked ServiceNow / ARM APIs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.js';
import { runPipeline } from '../src/pipeline.js';
import { buildState } from '../public/engine.js';
import * as db from '../src/db.js';
import { d1 } from './d1.js';
import { fakeNet } from './fake-net.js';

const NOW = Date.parse('2026-10-19T07:30:00+13:00'), MIN = 6e4;

async function setup({ settings = {}, env: extra = {}, routes = {} } = {}) {
  const net = fakeNet(routes);
  const env = { DB: d1(), AUTH_MODE: 'none', FIXED_NOW: String(NOW), ...extra };
  globalThis.fetch = net.fetch;
  await db.ensureSeed(env.DB);
  if (Object.keys(settings).length) await db.saveSettings(env.DB, settings);
  await runPipeline(env, { now: NOW, fetch: net.fetch });
  const call = async (method, path, body, at) => {
    if (at) env.FIXED_NOW = String(at);
    const pending = [];
    const res = await worker.fetch(new Request('http://localhost' + path, { method, body: body === undefined ? undefined : JSON.stringify(body), headers: { 'content-type': 'application/json' } }), env, { waitUntil: p => pending.push(p) });
    await Promise.all(pending);
    return { status: res.status, body: await res.json().catch(() => null) };
  };
  const live = async () => (await call('GET', '/api/live')).body;
  const sig = async id => { const j = await live(); return buildState(j.store, j.dataset).byId[id]; };
  const sim = ref => env.DB.prepare('SELECT * FROM sim WHERE ref = ?').bind(ref).first();
  const acts = (await env.DB.prepare("SELECT DISTINCT sig FROM send WHERE to_sys = 'sentinel' ORDER BY sig").all()).results.map(r => r.sig);
  return { env, net, call, live, sig, sim, acts };
}
const notes = x => JSON.parse(x.notes);

test('Sync sandbox: each routed Act signal gets an incident; a change there becomes a decision, once', async () => {
  const { call, live, sig, sim, acts } = await setup();
  assert.ok(acts.length >= 2);
  const j = await live();
  assert.equal(j.meta.sync.sentinel, 'sandbox');
  assert.equal(j.meta.sync.tickets, 'sandbox');
  for (const id of acts) assert.equal(j.dataset.sync.incidents[id].status, 'New');
  assert.ok(j.dataset.sends.filter(x => acts.includes(x.sig)).every(x => x.incident >= 1001));

  // closed as benign in "Sentinel" → Not affected in Signal Watch, by the incident owner, via sentinel
  const r = await call('POST', '/api/sim', { ref: 'SIM-' + acts[0], status: 'Closed', cls: 'BenignPositive' }, NOW + 60 * MIN);
  assert.equal(r.body.sync.in, 1);
  const s = await sig(acts[0]);
  assert.equal(s.status, 'na');
  assert.deepEqual([s.lastDecision.reason, s.lastDecision.by, s.lastDecision.via], ['Benign', 'Sandbox', 'sentinel']);
  // no echo: nothing is written back, and a second pass changes nothing
  assert.equal(r.body.sync.out, 0);
  const again = await call('POST', '/api/sync', undefined, NOW + 70 * MIN);
  assert.deepEqual([again.body.in, again.body.out, again.body.notes], [0, 0, 0]);
  assert.equal((await sim('SIM-' + acts[0])).status, 'Closed');
  // picked up in Sentinel (Active) → Acknowledged
  await call('POST', '/api/sim', { ref: 'SIM-' + acts[1], status: 'Active' }, NOW + 80 * MIN);
  assert.equal((await sig(acts[1])).status, 'ack');
});

test('Sync sandbox: a decision is written to the incident once; undo reopens what Signal Watch closed', async () => {
  const { call, sim, acts } = await setup();
  const id = acts[0], ref = 'SIM-' + id;
  const d = await call('POST', '/api/decisions', { sig: id, act: 'na', reason: 'Version' }, NOW + 30 * MIN);
  let x = await sim(ref);
  assert.deepEqual([x.status, x.cls], ['Closed', 'BenignPositive']);
  assert.equal(notes(x).at(-1), 'Signal Watch · Not affected · Version · Security owner');
  const again = await call('POST', '/api/sync', undefined, NOW + 40 * MIN);
  assert.deepEqual([again.body.in, again.body.out], [0, 0]);
  assert.equal(notes(await sim(ref)).length, 1);

  await call('DELETE', '/api/decisions/' + d.body.decision.id, undefined, NOW + 50 * MIN);
  x = await sim(ref);
  assert.deepEqual([x.status, notes(x).at(-1)], ['Active', 'Signal Watch · Undo']);

  // closed again, then an analyst sets it back to New: no decision maps from New, and it is not closed again
  await call('POST', '/api/decisions', { sig: id, act: 'na', reason: 'Config' }, NOW + 60 * MIN);
  assert.equal((await sim(ref)).status, 'Closed');
  const back = await call('POST', '/api/sim', { ref, status: 'New' }, NOW + 70 * MIN);
  assert.deepEqual([back.body.sync.in, back.body.sync.out], [0, 0]);
  await call('POST', '/api/sync', undefined, NOW + 80 * MIN);
  assert.equal((await sim(ref)).status, 'New');
});

test('Sync: last writer wins between Signal Watch and Sentinel', async () => {
  const { env, call, sig, sim, acts } = await setup();
  // Sentinel newer: Acknowledged here, then closed as benign there → Not affected
  await call('POST', '/api/decisions', { sig: acts[0], act: 'ack' }, NOW + 10 * MIN);
  assert.equal((await sim('SIM-' + acts[0])).status, 'Active');
  await call('POST', '/api/sim', { ref: 'SIM-' + acts[0], status: 'Closed', cls: 'FalsePositive' }, NOW + 20 * MIN);
  const a = await sig(acts[0]);
  assert.deepEqual([a.status, a.lastDecision.reason], ['na', 'False positive']);
  // Signal Watch newer: an analyst set Active at +10 (not yet read), Not affected here at +20 → incident closed
  await env.DB.prepare("UPDATE sim SET status = 'Active', owner = 'Analyst', at = ? WHERE ref = ?").bind(NOW + 10 * MIN, 'SIM-' + acts[1]).run();
  await call('POST', '/api/decisions', { sig: acts[1], act: 'na', reason: 'Config' }, NOW + 20 * MIN);
  const b = await sig(acts[1]);
  assert.deepEqual([b.status, b.lastDecision.via], ['na', undefined]);
  assert.deepEqual([(await sim('SIM-' + acts[1])).status, (await sim('SIM-' + acts[1])).cls], ['Closed', 'BenignPositive']);
});

test('Sync sandbox: tickets read back; all resolved closes the incident as a true positive', async () => {
  const { call, live, sim, acts } = await setup();
  const id = acts.find(Boolean);
  const t = await call('POST', '/api/decisions', { sig: id, act: 'ticket' }, NOW + 10 * MIN);
  const refs = t.body.decision.refs.map(r => r.ref);
  assert.ok(refs.length >= 1 && refs.every(r => r.startsWith('DRY-')));
  let x = await sim('SIM-' + id);
  assert.equal(x.status, 'Active');
  assert.equal(notes(x).at(-1), 'Signal Watch · Ticketed · ' + refs.join(' ') + ' · Security owner');
  for (const [k, ref] of refs.entries()) {
    await call('POST', '/api/sim', { ref, status: k === refs.length - 1 ? 'cancelled' : 'resolved' }, NOW + (20 + k) * MIN);
  }
  const j = await live();
  assert.ok(refs.every(r => ['resolved', 'cancelled'].includes(j.dataset.sync.tickets[r].state)));
  x = await sim('SIM-' + id);
  assert.deepEqual([x.status, x.cls, notes(x).at(-1)], ['Closed', 'TruePositive', 'Signal Watch · Tickets resolved']);
  // our own close is not read back as a decision
  const again = await call('POST', '/api/sync', undefined, NOW + 40 * MIN);
  assert.equal(again.body.in, 0);
});

test('Sync sandbox: Not affected closes open tickets; a new revision adds a note and reopens the incident', async () => {
  const { env, call, sim, acts } = await setup();
  const [a, b] = acts;
  const ta = (await call('POST', '/api/decisions', { sig: a, act: 'ticket' }, NOW + 10 * MIN)).body.decision.refs;
  await call('POST', '/api/decisions', { sig: a, act: 'na', reason: 'Mitigated' }, NOW + 20 * MIN);
  for (const r of ta) {
    const x = await sim(r.ref);
    assert.deepEqual([x.status, notes(x).at(-1)], ['resolved', 'Signal Watch · Not affected · Mitigated · Security owner']);
  }

  const tb = (await call('POST', '/api/decisions', { sig: b, act: 'ticket' }, NOW + 10 * MIN)).body.decision.refs;
  // the signals change: new route revisions (as rebuildAndRoute writes them)
  for (const id of [a, b]) await env.DB.prepare("INSERT INTO send (sig, rev, run_id, at, hash, to_sys, status) SELECT sig, rev + 1, run_id, ?, 'h2', to_sys, status FROM send WHERE sig = ? ORDER BY rev DESC LIMIT 1").bind(NOW + 30 * MIN, id).run();
  const r = await call('POST', '/api/sync', undefined, NOW + 31 * MIN);
  assert.equal(r.body.notes, tb.length);
  for (const t of tb) assert.match(notes(await sim(t.ref)).at(-1), new RegExp('^Signal Watch · Updated · r\\d+ · ' + b + '$'));
  // a's incident (closed as Not affected) reopens on the new revision, and the stale decision is not written again
  assert.equal((await sim('SIM-' + a)).status, 'New');
  await call('POST', '/api/sync', undefined, NOW + 45 * MIN);
  assert.equal((await sim('SIM-' + a)).status, 'New');
});

test('Sync ServiceNow: states read in one batch, Not affected resolves the ticket, notes carry labels only', async () => {
  const sn = new Map();
  let n = 0;
  const routes = {
    'https://agency.service-now.example/api/now/table/incident': ({ init }) => {
      if (init.method !== 'POST') return [405, '{}'];
      const id = 'sys' + ++n, number = 'INC00100' + n;
      sn.set(id, { sys_id: id, number, state: '1', sys_updated_on: '2026-10-18 18:40:00' });
      return [201, JSON.stringify({ result: { sys_id: id, number } })];
    },
    'https://agency.service-now.example/api/now/table/incident?*': ({ url }) => {
      const q = new URL(url).searchParams.get('sysparm_query'), nums = q.replace(/^numberIN/, '').split(',');
      return [200, JSON.stringify({ result: [...sn.values()].filter(x => nums.includes(x.number)) })];
    },
    'https://agency.service-now.example/api/now/table/incident/*': ({ url, body }) => {
      const x = sn.get(url.split('/').pop()), b = JSON.parse(body);
      if (b.state) Object.assign(x, { state: b.state, sys_updated_on: '2026-10-18 19:10:00' });
      return [200, JSON.stringify({ result: x })];
    },
  };
  const { env, net, call, live, acts } = await setup({ routes, env: { TICKET_TOKEN: 'tok' }, settings: { ticketSys: 'servicenow', ticketUrl: 'https://agency.service-now.example', ticketAuth: 'env:TICKET_TOKEN' } });
  assert.equal((await live()).meta.sync.tickets, 'live');
  const [a, b] = acts;
  const ra = (await call('POST', '/api/decisions', { sig: a, act: 'ticket' }, NOW + 10 * MIN)).body.decision.refs;
  const rb = (await call('POST', '/api/decisions', { sig: b, act: 'ticket' }, NOW + 10 * MIN)).body.decision.refs;
  assert.ok(ra[0].ref.startsWith('INC00100'));
  // resolved in ServiceNow → read back
  sn.get('sys1').state = '6';
  const mark = net.log.length;
  await call('POST', '/api/sync', undefined, NOW + 20 * MIN);
  const reads = net.log.slice(mark).filter(x => x.url.includes('sysparm_query'));
  assert.equal(reads.length, 1);
  assert.equal(reads[0].headers.authorization, 'Bearer tok');
  assert.equal((await live()).dataset.sync.tickets[ra[0].ref].state, 'resolved');
  // Not affected here → open tickets resolved there, with a label-only close note
  const mark2 = net.log.length;
  await call('POST', '/api/decisions', { sig: b, act: 'na', reason: 'Version' }, NOW + 30 * MIN);
  const patches = net.log.slice(mark2).filter(x => x.method === 'PATCH');
  assert.equal(patches.length, rb.length);
  const body = JSON.parse(patches[0].body);
  assert.deepEqual(body, { state: '6', close_code: 'No resolution provided', close_notes: 'Signal Watch · Not affected · Version · Security owner' });
  // nothing from the inventory beyond what the ticket already holds
  const inv = await db.loadInventory(env.DB);
  for (const p of patches) for (const prod of inv) assert.ok(!p.body.includes(prod.name) && !(prod.owner && p.body.includes(prod.owner)));
  const after = (await live()).dataset.sync.tickets;
  assert.ok(rb.every(r => after[r.ref].state === 'resolved'));
});

test('Sync Sentinel: incidents found by title, read back, and updated with etag + comment', async () => {
  const WS = '/subscriptions/0000/resourceGroups/rg-sec/providers/Microsoft.OperationalInsights/workspaces/law-sw';
  const base = 'https://management.azure.com' + WS + '/providers/Microsoft.SecurityInsights/incidents';
  const incs = new Map();
  const view = x => ({ name: x.name, etag: '"' + x.v + '"', properties: { title: x.title, severity: 'High', status: x.status, classification: x.cls, incidentNumber: x.number, owner: { assignedTo: x.owner }, lastModifiedTimeUtc: new Date(x.at).toISOString(), labels: [] } });
  const puts = [], comments = [];
  const routes = {
    'https://login.microsoftonline.com/*': ({ body }) => [200, JSON.stringify({ access_token: 'arm:' + new URLSearchParams(body).get('scope'), expires_in: 3600 })],
    'https://dce.example/*': () => [204, null],
    [base + '?*']: () => [200, JSON.stringify({ value: [...incs.values()].sort((a, b) => b.at - a.at).map(view) })],
    [base + '/*']: ({ url, init, body }) => {
      const parts = new URL(url).pathname.split('/'), i = parts.indexOf('incidents'), x = incs.get(parts[i + 1]);
      if (parts[i + 2] === 'comments') { comments.push(JSON.parse(body).properties.message); return [200, '{}']; }
      if (init.method === 'PUT') {
        const b = JSON.parse(body); puts.push({ ...b, auth: init.headers.authorization });
        Object.assign(x, { status: b.properties.status, cls: b.properties.classification || null, v: x.v + 1, at: x.at + 1000 });
      }
      return [200, JSON.stringify(view(x))];
    },
  };
  const settings = { dce: 'https://dce.example', dcr: 'dcr-1', stream: 'Custom-SignalWatch_CL', tenant: 't1', clientId: 'c1', secretRef: 'env:SENTINEL_CLIENT_SECRET', wsResource: WS };
  const { call, live, sig, acts } = await setup({ routes, settings, env: { SENTINEL_CLIENT_SECRET: 's' } });
  assert.equal((await live()).meta.sync.sentinel, 'live');
  // the analytics rule created incidents; one was picked up by an analyst
  acts.forEach((id, k) => incs.set('g' + k, { name: 'g' + k, title: `Signal Watch · ${id} · headline`, status: k ? 'New' : 'Active', cls: null, number: 2001 + k, owner: k ? null : 'Aroha T.', v: 1, at: NOW + (5 + k) * MIN }));
  incs.set('other', { name: 'other', title: 'Suspicious sign-in', status: 'Active', cls: null, number: 1999, owner: null, v: 1, at: NOW + 6 * MIN });
  const r = await call('POST', '/api/sync', undefined, NOW + 15 * MIN);
  assert.equal(r.body.linked, acts.length);
  assert.equal(r.body.in, 1);
  const s0 = await sig(acts[0]);
  assert.deepEqual([s0.status, s0.lastDecision.by, s0.lastDecision.via], ['ack', 'Aroha T.', 'sentinel']);
  const j = await live();
  assert.equal(j.dataset.sync.incidents[acts[1]].number, 2002);
  // Not affected here → PUT with the fetched etag, then a comment
  await call('POST', '/api/decisions', { sig: acts[1], act: 'na', reason: 'Not deployed' }, NOW + 20 * MIN);
  assert.equal(puts.length, 1);
  assert.equal(puts[0].etag, '"1"');
  assert.equal(puts[0].auth, 'Bearer arm:https://management.azure.com/.default');
  assert.deepEqual([puts[0].properties.status, puts[0].properties.classification, puts[0].properties.classificationReason, puts[0].properties.title], ['Closed', 'BenignPositive', 'SuspiciousButExpected', `Signal Watch · ${acts[1]} · headline`]);
  assert.deepEqual(comments, ['Signal Watch · Not affected · Not deployed · Security owner']);
  // our write is not read back as a change
  const again = await call('POST', '/api/sync', undefined, NOW + 30 * MIN);
  assert.deepEqual([again.body.in, again.body.out], [0, 0]);
  assert.equal(puts.length, 1);
});
