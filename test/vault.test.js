// Write-only secrets (src/vault.js): set in Settings, never returned, encrypted in D1, bound to their host.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import worker from '../src/worker.js';
import { runPipeline } from '../src/pipeline.js';
import * as db from '../src/db.js';
import { d1 } from './d1.js';
import { fakeNet } from './fake-net.js';

const NOW = Date.parse('2026-10-19T07:30:00+13:00');
const TOKEN = 'snow-tok-7f3a9c41d2e8b6';
const SN = 'https://agency.service-now.example';

async function setup({ env: extra = {}, settings = {}, mode = 'none' } = {}) {
  let n = 0;
  const net = fakeNet({ [SN + '/api/now/table/incident']: () => [201, JSON.stringify({ result: { sys_id: 'sys' + ++n, number: 'INC00200' + n } })] });
  const env = { DB: d1(), AUTH_MODE: mode, FIXED_NOW: String(NOW), SECRETS_KEY: randomBytes(32).toString('base64'), ...extra };
  globalThis.fetch = net.fetch;
  await db.ensureSeed(env.DB);
  await db.saveSettings(env.DB, { ticketSys: 'servicenow', ticketUrl: SN, ...settings });
  await runPipeline(env, { now: NOW, fetch: net.fetch });
  const host = mode === 'demo' ? 'https://signal-watch.example.workers.dev' : 'http://localhost';
  const call = async (method, path, body) => {
    const res = await worker.fetch(new Request(host + path, { method, body: body === undefined ? undefined : JSON.stringify(body), headers: { 'content-type': 'application/json' } }), env, { waitUntil() {} });
    const text = await res.text();
    return { status: res.status, text, body: JSON.parse(text || 'null') };
  };
  const acts = (await env.DB.prepare('SELECT DISTINCT sig FROM send ORDER BY sig').all()).results.map(r => r.sig);
  return { env, net, call, acts };
}

test('Vault: a saved token is never returned, is ciphertext in D1, and authenticates ticket calls', async () => {
  const { env, net, call, acts } = await setup();
  const put = await call('PUT', '/api/secrets/ticket', { value: TOKEN });
  assert.equal(put.status, 200);
  assert.deepEqual([put.body.state, put.body.name], ['saved', 'TICKET_TOKEN']);
  assert.ok(!put.text.includes(TOKEN));
  const live = await call('GET', '/api/live');
  assert.ok(!live.text.includes(TOKEN));
  assert.equal(live.body.meta.secrets.ticket.state, 'saved');
  assert.equal(live.body.meta.configured.ticket, true);
  const row = await env.DB.prepare("SELECT * FROM vault WHERE name = 'TICKET_TOKEN'").first();
  const b64 = Buffer.from(TOKEN).toString('base64');
  assert.ok(row.ct && !row.ct.includes(TOKEN) && !row.ct.includes(b64.slice(0, 12)) && row.bind === SN);
  const t = await call('POST', '/api/decisions', { sig: acts[0], act: 'ticket' });
  assert.ok(t.body.decision.refs[0].ref.startsWith('INC00200'));
  const sent = net.log.filter(x => x.url.startsWith(SN));
  assert.ok(sent.length >= 1 && sent.every(x => x.headers.authorization === 'Bearer ' + TOKEN));
  // removed: no longer configured
  assert.equal((await call('DELETE', '/api/secrets/ticket')).body.state, 'none');
  assert.equal((await call('GET', '/api/live')).body.meta.configured.ticket, false);
});

test('Vault: changing the ticket URL stops the token being sent until it is entered again', async () => {
  const { env, net, call, acts } = await setup();
  await call('PUT', '/api/secrets/ticket', { value: TOKEN });
  await call('PUT', '/api/settings', { ticketSys: 'servicenow', ticketUrl: 'https://collector.example' });
  const live = await call('GET', '/api/live');
  assert.equal(live.body.meta.secrets.ticket.state, 'stale');
  assert.equal(live.body.meta.configured.ticket, false);
  const t = await call('POST', '/api/decisions', { sig: acts[0], act: 'ticket' });
  assert.ok(t.body.decision.refs[0].ref.startsWith('DRY-'));
  assert.equal(net.log.filter(x => x.url.startsWith('https://collector.example')).length, 0);
  assert.ok(!net.log.some(x => JSON.stringify(x.headers).includes(TOKEN)));
  // editing the row to point at the new host does not help: name and host are authenticated with the value
  await env.DB.prepare("UPDATE vault SET bind = 'https://collector.example' WHERE name = 'TICKET_TOKEN'").run();
  const after = await call('GET', '/api/live');
  assert.deepEqual([after.body.meta.secrets.ticket.state, after.body.meta.configured.ticket], ['bad', false]);
  // entered again for the new URL: used again
  await call('PUT', '/api/secrets/ticket', { value: TOKEN });
  assert.equal((await call('GET', '/api/live')).body.meta.configured.ticket, true);
});

test('Vault: refs cannot name platform secrets or bindings; Teams URL is a ref only', async () => {
  const { call } = await setup({ env: { BASIC_AUTH: 'admin:pw' } });
  for (const ref of ['env:SECRETS_KEY', 'env:BASIC_AUTH', 'env:DB']) {
    await call('PUT', '/api/settings', { ticketSys: 'servicenow', ticketUrl: SN, ticketAuth: ref });
    assert.equal((await call('GET', '/api/live')).body.meta.configured.ticket, false, ref);
  }
  const s = await call('PUT', '/api/settings', { teamsUrl: 'https://prod.example/workflows/abc?sig=x' });
  assert.equal(s.body.settings.teamsUrl, undefined);
  assert.equal((await call('PUT', '/api/secrets/teams', { value: 'http://plain.example/x' })).status, 400);
  assert.equal((await call('PUT', '/api/secrets/teams', { value: 'https://prod.example/workflows/abc?sig=x' })).status, 200);
  const live = await call('GET', '/api/live');
  assert.ok(!live.text.includes('sig=x'));
  assert.equal(live.body.meta.configured.teams, true);
  // bound secrets need their URL first
  assert.equal((await call('PUT', '/api/secrets/ai', { value: 'k' })).body.error, 'URL first');
  assert.equal((await call('PUT', '/api/secrets/BASIC_AUTH', { value: 'x' })).status, 404);
});

test('Vault: Worker secret wins (409), no key (503), demo mode (403)', async () => {
  const a = await setup({ env: { TICKET_TOKEN: 'from-wrangler' } });
  assert.equal((await a.call('PUT', '/api/secrets/ticket', { value: TOKEN })).status, 409);
  assert.equal((await a.call('GET', '/api/live')).body.meta.secrets.ticket.state, 'worker');
  const b = await setup({ env: { SECRETS_KEY: '' } });
  assert.equal((await b.call('PUT', '/api/secrets/ticket', { value: TOKEN })).status, 503);
  const c = await setup({ mode: 'demo' });
  assert.equal((await c.call('PUT', '/api/secrets/ticket', { value: TOKEN })).status, 403);
  assert.equal((await c.call('DELETE', '/api/secrets/ticket')).status, 403);
});
