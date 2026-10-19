// Workers Free path: a run as Workflow steps (JSON in, JSON out), the RUN_FLOW API, and demo mode.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../src/worker.js';
import { orchestrate, runPipeline } from '../src/pipeline.js';
import * as db from '../src/db.js';
import { d1 } from './d1.js';
import { fakeNet } from './fake-net.js';

const NOW = Date.parse('2026-10-19T07:30:00+13:00');

// Workflow stand-in: each step's output goes through JSON like step.do, names must be unique.
function flowStep(names) {
  return async (name, fn) => {
    assert.ok(!names.includes(name), 'duplicate step ' + name);
    names.push(name);
    return JSON.parse(JSON.stringify((await fn()) ?? null));
  };
}

// RUN_FLOW stand-in: create() runs the workflow to completion through flowStep.
function fakeFlow(env, net) {
  const runs = new Map();
  return {
    runs,
    async create({ params }) {
      const id = 'cf_' + (runs.size + 1).toString(16).padStart(64, '0'); // Cloudflare ids are 67 characters
      const out = await orchestrate(env, { ...params, fetch: net.fetch, wait: 0 }, flowStep([]), { parallel: 1 });
      runs.set(id, out);
      return { id };
    },
    async get(id) { if (!runs.has(id)) throw new Error('not found'); return { status: async () => ({ status: 'complete', output: runs.get(id) }) }; },
  };
}

test('Steps: a run as Workflow steps gives the same result as the inline run', async () => {
  const net = fakeNet();
  const a = { DB: d1() }, b = { DB: d1() };
  const inline = await runPipeline(a, { now: NOW, fetch: net.fetch });
  const names = [];
  const stepped = await orchestrate(b, { mode: 'Run now', now: NOW, fetch: net.fetch, owner: 'wf-1' }, flowStep(names), { parallel: 1 });
  for (const k of ['items', 'fetched', 'noise', 'created', 'updated', 'hidden', 'routed']) assert.equal(stepped.run[k], inline.run[k], k);
  assert.deepEqual(stepped.open, inline.open);
  assert.deepEqual(names.slice(0, 1), ['begin']);
  assert.deepEqual(names.slice(-4), ['store', 'route', 'sync', 'release']);
  assert.ok(names.includes('pull circl 1') && names.includes('epss 1') && names.includes('ncsc 1'));
  // the lock is released and re-entrant for the same owner (a retried step keeps it)
  assert.equal(await db.lockHeld(b.DB, 'run'), false);
  assert.equal(await db.acquireLock(b.DB, 'run', 'o1'), true);
  assert.equal(await db.acquireLock(b.DB, 'run', 'o1'), true);
  assert.equal(await db.acquireLock(b.DB, 'run', 'o2'), false);
});

test('Steps: EPSS comes from threshold pages that name no CVE', async () => {
  const net = fakeNet();
  const r = await runPipeline({ DB: d1() }, { now: NOW, fetch: net.fetch });
  assert.equal(r.run.src.epss.status, 'ok');
  assert.ok(r.run.src.epss.rows > 0);
  const epss = net.log.filter(x => /first\.org/.test(x.url));
  assert.ok(epss.length >= 1 && epss.every(x => !/CVE-/i.test(x.url)));
});

function setup(envExtra = {}, host = 'https://signal-watch.example.workers.dev') {
  const net = fakeNet();
  const env = { DB: d1(), AUTH_MODE: 'demo', FIXED_NOW: String(NOW), ...envExtra };
  globalThis.fetch = net.fetch;
  const call = async (method, path, body) => {
    const res = await worker.fetch(new Request(host + path, { method, body: body === undefined ? undefined : JSON.stringify(body), headers: { 'content-type': 'application/json' } }), env, { waitUntil() {} });
    return { status: res.status, body: await res.json().catch(() => null) };
  };
  return { env, net, call };
}

test('Steps: Run now queues a Workflow (202) and its status returns the run summary', async () => {
  const { env, net, call } = setup({ AUTH_MODE: 'none' }, 'http://localhost');
  env.RUN_FLOW = fakeFlow(env, net);
  const q = await call('POST', '/api/run');
  assert.equal(q.status, 202);
  assert.equal(q.body.queued, true);
  const s = await call('GET', '/api/run/' + q.body.id);
  assert.equal(s.body.status, 'complete');
  assert.equal(s.body.output.run.mode, 'Run now');
  assert.ok(s.body.output.run.items > 0);
  // a held lock answers 409 without starting anything
  await db.acquireLock(env.DB, 'run', 'other');
  assert.equal((await call('POST', '/api/run')).status, 409);
  assert.equal(env.RUN_FLOW.runs.size, 1);
});

test('Demo mode: open on a public host; integrations and sources locked; Run now rate-limited', async () => {
  const { env, call } = setup();
  const live = await call('GET', '/api/live');
  assert.equal(live.status, 200);
  assert.equal(live.body.meta.demo, true);
  // thresholds change, integration targets do not
  const put = await call('PUT', '/api/settings', { epss: 0.2, ticketUrl: 'https://attacker.example/hook', teamsUrl: 'https://attacker.example/t', dce: 'https://x.example' });
  assert.equal(put.body.settings.epss, 0.2);
  assert.equal(put.body.settings.ticketUrl, undefined);
  assert.equal(put.body.settings.teamsUrl, undefined);
  assert.equal(put.body.settings.dce, undefined);
  // no new sources, no re-pointing; enable/disable still works
  assert.equal((await call('POST', '/api/sources', { name: 'X', url: 'https://attacker.example/feed', parser: 'rss@1' })).status, 403);
  assert.equal((await call('PUT', '/api/sources/sbnz', { url: 'https://attacker.example/feed' })).status, 403);
  assert.equal((await call('PUT', '/api/sources/sbnz', { enabled: false })).status, 200);
  assert.equal((await call('POST', '/api/ingest/email', undefined)).status, 403);
  // one Run now per 10 minutes
  assert.equal((await call('POST', '/api/run')).status, 200);
  const again = await call('POST', '/api/run');
  assert.equal(again.status, 429);
  assert.equal(again.body.wait, 10);
});

test('Auth: "none" stays refused on a public host', async () => {
  const { call } = setup({ AUTH_MODE: 'none' });
  assert.equal((await call('GET', '/api/live')).status, 503);
});
