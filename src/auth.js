// Access control for UI + API. AUTH_MODE:
//   access → Cloudflare Access (Entra ID SSO) JWT in Cf-Access-Jwt-Assertion, checked against ACCESS_TEAM / ACCESS_AUD
//   basic  → BASIC_AUTH secret "user:password" (POV fallback)
//   demo   → open to anyone, for a public demo with the sample inventory only. Integration settings and source
//            URLs are read-only and Run now is rate-limited (src/api.js). Never use it with a real inventory.
//   none   → only for localhost (wrangler dev); refused on any other host so the inventory is never public by accident
let jwks = null, jwksAt = 0;

const b64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), c => c.charCodeAt(0));

async function verifyAccess(token, env) {
  const [h, p, sig] = String(token).split('.');
  if (!sig) return null;
  const head = JSON.parse(new TextDecoder().decode(b64u(h))), body = JSON.parse(new TextDecoder().decode(b64u(p)));
  if (Date.now() - jwksAt > 3600e3 || !jwks) {
    const r = await fetch(`https://${env.ACCESS_TEAM}.cloudflareaccess.com/cdn-cgi/access/certs`);
    jwks = (await r.json()).keys || []; jwksAt = Date.now();
  }
  const jwk = jwks.find(k => k.kid === head.kid);
  if (!jwk || head.alg !== 'RS256') return null;
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64u(sig), new TextEncoder().encode(h + '.' + p));
  const aud = Array.isArray(body.aud) ? body.aud : [body.aud];
  if (!ok || !aud.includes(env.ACCESS_AUD) || body.exp * 1000 < Date.now() || body.iss !== `https://${env.ACCESS_TEAM}.cloudflareaccess.com`) return null;
  return body.email || body.sub || 'Access user';
}

function same(a, b) {
  const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b);
  let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] || 0) ^ (y[i] || 0);
  return d === 0;
}

// → { user } or a Response to return.
export async function authenticate(request, env) {
  const mode = env.AUTH_MODE || 'none', host = new URL(request.url).hostname;
  if (mode === 'access') {
    const user = await verifyAccess(request.headers.get('cf-access-jwt-assertion'), env).catch(() => null);
    return user ? { user } : new Response('Unauthorized', { status: 401 });
  }
  if (mode === 'basic') {
    const want = env.BASIC_AUTH || '', got = (request.headers.get('authorization') || '').replace(/^Basic\s+/i, '');
    let dec = '';
    try { dec = atob(got); } catch { /* bad header */ }
    if (want && dec && same(dec, want)) return { user: dec.split(':')[0] };
    return new Response('Unauthorized', { status: 401, headers: { 'www-authenticate': 'Basic realm="Signal Watch", charset="UTF-8"' } });
  }
  if (mode === 'demo') return { user: null, demo: true };
  if (host === 'localhost' || host === '127.0.0.1' || host === '[::1]') return { user: null };
  return new Response('Auth not configured: set AUTH_MODE to access or basic', { status: 503 });
}
