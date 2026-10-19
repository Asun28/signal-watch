// Small shared helpers for the Worker side.
export const UA = 'SignalWatch/1.0 (security signal monitor; contact: security owner)';

export async function http(url, opts = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), opts.timeout || 25000);
  const t0 = Date.now();
  try {
    const res = await (opts.fetch || fetch)(url, { method: opts.method || 'GET', headers: { 'user-agent': UA, accept: opts.accept || '*/*', ...(opts.headers || {}) }, body: opts.body, signal: ctl.signal, redirect: 'follow' });
    return { res, ms: Date.now() - t0 };
  } finally { clearTimeout(timer); }
}

export async function sha1hex(s, n = 20) {
  const b = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('').slice(0, n);
}

// FIXED_NOW (ms) pins the clock for tests and replays; unset in production.
export const clock = env => (env && env.FIXED_NOW ? +env.FIXED_NOW : Date.now());

export const json = (data, status = 200, headers = {}) => new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers } });
export const uniq = a => [...new Set(a)];
export const chunk = (a, n) => Array.from({ length: Math.ceil(a.length / n) }, (_, i) => a.slice(i * n, i * n + n));

const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', '#039': "'", rsquo: '’', lsquo: '‘', ldquo: '“', rdquo: '”', ndash: '–', mdash: '—', hellip: '…' };
export function decodeEntities(s) {
  return String(s || '').replace(/&(#x[0-9a-f]+|#\d+|[a-z0-9]+);/gi, (m, e) => {
    if (e[0] === '#') { const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return Number.isFinite(n) ? String.fromCodePoint(n) : m; }
    return ENT[e.toLowerCase()] ?? ENT[e] ?? m;
  });
}
export const stripTags = s => decodeEntities(String(s || '').replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ')).replace(/\s+/g, ' ').trim();
export const clip = (s, n = 200) => (s.length > n ? s.slice(0, n - 1).replace(/\s+\S*$/, '') + '…' : s);

// Secrets are referenced as env:NAME in settings and resolved here: a Worker secret first, then a value saved in
// Settings (src/vault.js, decrypted per invocation). Values never reach the browser. Bindings and platform
// settings are not secrets, so no ref can name them (a ticket token ref pointing at SECRETS_KEY resolves to '').
const NOT_SECRETS = /^(DB|ASSETS|RUN_FLOW|AI|SECRETS_KEY|BASIC_AUTH|AUTH_MODE|ACCESS_[A-Z0-9_]*|APP_URL|FIXED_NOW)$/;
const VAULT = new WeakMap();
export const setVault = (env, values) => VAULT.set(env.DB || env, values);
export function secret(env, ref) {
  if (!ref) return '';
  const m = String(ref).match(/^env:([A-Z0-9_]+)$/);
  if (!m || NOT_SECRETS.test(m[1])) return '';
  const v = env[m[1]];
  return typeof v === 'string' && v ? v : VAULT.get(env.DB || env)?.[m[1]] || '';
}

const BREACH = /\b(breach(?:ed)?|cyber[\s-]?(?:security\s)?incident|cyber[\s-]?attack|ransomware attack|hack(?:ed)?|data leak|leaked data|compromised)\b/i;
export const looksBreach = t => BREACH.test(t);
