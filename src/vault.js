// Write-only secrets: entered once in Settings, kept in D1 as AES-GCM ciphertext under SECRETS_KEY (a Worker
// secret), and never returned by any API. A Worker secret of the same name (wrangler secret put) takes precedence.
// A token sent to a host taken from settings (ticket base URL, AI endpoint) is bound to that origin when saved:
// change the URL and the token is not used until it is entered again, so it cannot be redirected.
import { setVault } from './util.js';

const refName = r => (String(r || '').match(/^env:([A-Z0-9_]+)$/) || [])[1] || null;
const origin = u => { try { return /^https:\/\//.test(u) ? new URL(u).origin : null; } catch { return null; } };
const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = u8 => btoa(String.fromCharCode(...u8));
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const aad = (name, bind) => enc.encode(name + '|' + (bind || ''));
const worker = (env, name) => typeof env[name] === 'string' && env[name] !== '';

// The secrets Settings can hold. The name follows the field's env: ref; `bind` is the origin the value may go to.
export function vaultFields(S) {
  return [
    { field: 'sentinel', name: refName(S.secretRef) || 'SENTINEL_CLIENT_SECRET', bind: null },
    { field: 'ticket', name: refName(S.ticketAuth) || 'TICKET_TOKEN', bind: origin(S.ticketUrl), bound: true },
    { field: 'teams', name: refName(S.teamsUrl) || 'TEAMS_WORKFLOW_URL', bind: null, url: true },
    { field: 'graph', name: 'GRAPH_CLIENT_SECRET', bind: null },
    { field: 'ai', name: 'AZURE_OPENAI_KEY', bind: origin(S.aiEndpoint), bound: true },
  ];
}

const keys = new Map();
function masterKey(env) {
  const raw = env.SECRETS_KEY;
  if (typeof raw !== 'string' || !raw) return Promise.resolve(null);
  if (!keys.has(raw)) {
    keys.set(raw, (async () => {
      const b = unb64(raw.trim());
      return b.length === 32 ? crypto.subtle.importKey('raw', b, 'AES-GCM', false, ['encrypt', 'decrypt']) : null;
    })().catch(() => null));
  }
  return keys.get(raw);
}

// Decrypt the values usable now and hand them to secret() for this invocation. Returns status by name, no values.
export async function loadVault(env, S) {
  const key = await masterKey(env), byName = new Map(vaultFields(S).map(f => [f.name, f]));
  const rows = (await env.DB.prepare('SELECT name, iv, ct, bind, at FROM vault').all()).results || [];
  const values = {}, status = {};
  for (const r of rows) {
    const f = byName.get(r.name);
    if (!f) continue;
    const stale = (r.bind || null) !== (f.bind || null);
    status[r.name] = { at: r.at, stale, bad: false };
    if (!key || stale) continue;
    try {
      values[r.name] = dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(r.iv), additionalData: aad(r.name, r.bind) }, key, unb64(r.ct)));
    } catch { status[r.name].bad = true; }
  }
  setVault(env, values);
  return status;
}

// Per field for Settings: worker | saved | stale (URL changed) | bad (key changed or row edited) | none.
export async function vaultStatus(env, S) {
  const st = await loadVault(env, S), key = !!(await masterKey(env));
  return Object.fromEntries(vaultFields(S).map(f => {
    const v = st[f.name];
    const state = worker(env, f.name) ? 'worker' : !v ? 'none' : v.stale ? 'stale' : !key || v.bad ? 'bad' : 'saved';
    return [f.field, { name: f.name, state, at: v?.at ?? null, key, ready: !f.bound || !!f.bind }];
  }));
}

export async function saveSecret(env, S, field, value, by) {
  const f = vaultFields(S).find(x => x.field === field);
  if (!f) return { error: 'Not found', status: 404 };
  if (worker(env, f.name)) return { error: 'Worker secret', status: 409 };
  const key = await masterKey(env);
  if (!key) return { error: 'Needs SECRETS_KEY', status: 503 };
  const v = String(value ?? '').trim();
  if (!v || v.length > 4096 || /[\r\n]/.test(v)) return { error: 'Value', status: 400 };
  if (f.bound && !f.bind) return { error: 'URL first', status: 400 };
  if (f.url && !origin(v)) return { error: 'https URL', status: 400 };
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(f.name, f.bind) }, key, enc.encode(v)));
  const at = Date.now();
  await env.DB.prepare('INSERT INTO vault (name, iv, ct, bind, at, by) VALUES (?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET iv = excluded.iv, ct = excluded.ct, bind = excluded.bind, at = excluded.at, by = excluded.by')
    .bind(f.name, b64(iv), b64(ct), f.bind, at, by || null).run();
  return { ok: true, field, name: f.name, state: 'saved', at };
}

export async function removeSecret(env, S, field) {
  const f = vaultFields(S).find(x => x.field === field);
  if (!f) return { error: 'Not found', status: 404 };
  await env.DB.prepare('DELETE FROM vault WHERE name = ?').bind(f.name).run();
  return { ok: true, field, name: f.name, state: worker(env, f.name) ? 'worker' : 'none' };
}
