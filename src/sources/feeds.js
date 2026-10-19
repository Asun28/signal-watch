// Feed parsers. Each parser turns one source response into raw items:
// { src, guid, at, title, url, cves, advs, keys, type, cvss, kev, actBy, fix, affected, peer, sample }
// Only the headline, link, date and these extracted fields are kept; article bodies are discarded here.
import { extractKeys, normText } from '../../public/engine.js';
import { http, stripTags, decodeEntities, clip, looksBreach, uniq } from '../util.js';
import { nzToUtc, nzParts, parseNzDate } from '../time.js';

const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;
const ADV_RE = /\b(CTX\d{6}|MC\d{6,7}|EX\d{6,7}|MO\d{6,7})\b/g;
const cvesIn = t => uniq((String(t).match(CVE_RE) || []).map(x => x.toUpperCase()));
const advsIn = t => uniq(String(t).match(ADV_RE) || []);
const keysFor = (text, ctx) => extractKeys(text, ctx.aliases);
const htmlText = s => stripTags(/&lt;/.test(s) ? decodeEntities(s) : s); // feeds that entity-encode their HTML

// ───────── NCSC NZ alerts page (no feed; cards on /alerts/) ─────────
export function parseNcscList(html, src) {
  const out = [];
  const base = new URL(src.url);
  for (const m of html.matchAll(/<a\b[^>]*href="(\/alerts\/[a-z0-9][a-z0-9-]*\/)"[^>]*>([\s\S]*?)<\/a>/gi)) {
    const body = m[2];
    const title = stripTags((body.match(/class="card__title"[^>]*>([\s\S]*?)<\/h3>/i) || [])[1] || '');
    const date = stripTags((body.match(/class="card__date"[^>]*>([\s\S]*?)<\/p>/i) || [])[1] || '');
    if (!title) continue;
    const url = new URL(m[1], base).href;
    out.push({ src: src.id, guid: url, at: parseNzDate(date) || Date.now(), title, url, type: 'alert' });
  }
  return out;
}

// Alert page: extract IDs, CVSS and affected version ranges. The page text itself is not stored.
export function parseNcscDetail(html, item, ctx) {
  const start = html.search(/advisory-page-title|content-intro__title/i);
  let body = start >= 0 ? html.slice(start) : html;
  const end = body.search(/class="card__link"|<footer\b/i);
  if (end > 0) body = body.slice(0, end);
  const text = stripTags(body);
  const keys = uniq([...keysFor(item.title, ctx), ...keysFor(text.slice(0, 1500), ctx)]);
  const cvss = Math.max(0, ...[...text.matchAll(/CVSS(?:v\d(?:\.\d)?)?[:\s]+(\d{1,2}(?:\.\d)?)/gi)].map(x => parseFloat(x[1])).filter(x => x <= 10));
  const affected = [];
  for (const seg of text.split(/For the following versions/i)) {
    const cm = seg.match(/applicable only when configured as (?:an? )?([A-Za-z ]{3,40}?)\s*:/i);
    const cond = cm ? cm[1].replace(/\bSAML SP or SAML IdP\b/i, 'SAML SP/IdP').trim() : '';
    for (const r of seg.matchAll(/between\s+(\d[\w.\-]*\d)(?:\s+FIPS)?\s+and\s+(\d[\w.\-]*\d)(?:\s+FIPS)?,?\s+inclusive/gi)) affected.push({ keys, gte: r[1], lte: r[2], ...(cond ? { cond } : {}) });
    for (const r of seg.matchAll(/\bbefore\s+(\d[\w.\-]*\d)/gi)) affected.push({ keys, lt: r[1], ...(cond ? { cond } : {}) });
  }
  const advs = advsIn(body); // vendor advisory ids often appear only in link targets
  return {
    ...item,
    cves: uniq([...(item.cves || []), ...cvesIn(text)]),
    advs: uniq([...(item.advs || []), ...advs.filter(a => a.startsWith('CTX'))]),
    keys,
    cvss: cvss || null,
    affected: affected.length ? affected : null,
    fix: advs.filter(a => a.startsWith('CTX')).length ? 'Per ' + advs.filter(a => a.startsWith('CTX')).join(' · ') : '',
  };
}

// ───────── CISA KEV (full catalogue JSON; keep the lookback window) ─────────
export function parseKev(data, src, ctx) {
  const since = ctx.now - (ctx.settings.lookbackDays || 30) * 864e5, day = new Date(since - 864e5).toISOString().slice(0, 10);
  const out = [];
  for (const v of data.vulnerabilities || []) {
    if (!(v.dateAdded >= day)) continue; // cheap string check first: the catalogue has ~1,750 entries
    const added = Date.parse(v.dateAdded + 'T12:00:00Z');
    if (!(added >= since)) continue;
    out.push({
      src: src.id, guid: v.cveID, at: added, title: v.vulnerabilityName || `${v.vendorProject} ${v.product}`,
      url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search=' + v.cveID,
      cves: [v.cveID], keys: keysFor(`${v.vendorProject} ${v.product} ${v.vulnerabilityName || ''}`, ctx), type: 'exploit',
      kev: { added: v.dateAdded, due: v.dueDate, dueAt: v.dueDate ? nzToUtc(v.dueDate, '23:59') : null, ransomware: v.knownRansomwareCampaignUse === 'Known' },
      fix: clip(String(v.requiredAction || ''), 160),
    });
  }
  return out;
}

// ───────── CIRCL Vulnerability-Lookup, CVE 5 records ─────────
const isVer = v => v && v !== '*' && v !== '0' && !/^n\/?a$/i.test(v) && !/^[0-9a-f]{20,}$/i.test(v) && /\d/.test(v);
export function parseCirclRecord(r, src, ctx) {
  const meta = r.cveMetadata || {};
  const cna = r.containers?.cna || {};
  if (!meta.cveId || meta.state === 'REJECTED') return null;
  const desc = ((cna.descriptions || []).find(d => /^en/i.test(d.lang)) || cna.descriptions?.[0] || {}).value || '';
  const aff = cna.affected || [];
  const keys = [], affected = [], fixed = [];
  for (const a of aff) {
    // CPEs are exact. Without them, match the vendor/product text, except for add-ons ("LearnPress – WordPress
    // LMS Plugin" is not WordPress core).
    const cpeKeys = (a.cpes || []).map(c => c.replace(/\\/g, '').split(':')).filter(x => x.length > 4).map(x => (x[3] + ':' + x[4]).toLowerCase());
    const addOn = /\b(plugins?|themes?|extensions?|add-?ons?|modules?|integrations?|connectors?|for (?:wordpress|moodle|jira|confluence|drupal|joomla))\b/i.test(a.product || '');
    const ks = uniq(cpeKeys.length ? cpeKeys : addOn ? [] : keysFor(`${a.vendor || ''} ${a.product || ''}`, ctx));
    keys.push(...ks);
    for (const v of a.versions || []) {
      if (v.status === 'unaffected' && isVer(v.version)) { fixed.push(v.version); continue; }
      if (v.status !== 'affected') continue;
      if (v.lessThan && isVer(v.lessThan)) { affected.push({ keys: ks, ...(isVer(v.version) ? { gte: v.version } : {}), lt: v.lessThan }); fixed.push(v.lessThan); }
      else if (v.lessThanOrEqual && isVer(v.lessThanOrEqual)) affected.push({ keys: ks, ...(isVer(v.version) ? { gte: v.version } : {}), lte: v.lessThanOrEqual });
      else if (isVer(v.version)) affected.push({ keys: ks, gte: v.version, lte: v.version });
    }
  }
  const scores = [cna, ...(r.containers?.adp || [])].flatMap(c => c.metrics || []).flatMap(m => ['cvssV4_0', 'cvssV3_1', 'cvssV3_0'].map(k => m[k]?.baseScore)).filter(x => typeof x === 'number');
  const head = cna.title || (aff[0] ? `${aff[0].vendor || ''} ${aff[0].product || ''}: ` : '') + desc.split(/(?<=\.)\s/)[0];
  return {
    src: src.id, guid: meta.cveId, at: Date.parse(meta.datePublished || meta.dateUpdated) || ctx.now,
    title: clip(`${meta.cveId} · ${head.trim()}`, 180), url: 'https://vulnerability.circl.lu/vuln/' + meta.cveId.toLowerCase(),
    cves: [meta.cveId], keys: uniq(keys), type: 'vuln', cvss: scores.length ? Math.max(...scores) : null,
    affected: affected.length ? affected : null, fix: uniq(fixed).slice(0, 3).join(' · '),
  };
}
export const parseCircl = (data, src, ctx) => (Array.isArray(data) ? data : data.data || []).map(r => parseCirclRecord(r, src, ctx)).filter(Boolean);

// ───────── RSS 2.0 / Atom (SecurityBrief NZ, Mastodon, custom feeds) ─────────
export function parseRss(xml, src, ctx) {
  const out = [];
  const tag = (b, n) => { const m = b.match(new RegExp('<' + n + '\\b[^>]*>([\\s\\S]*?)</' + n + '>', 'i')); return m ? m[1] : ''; };
  for (const m of xml.matchAll(/<(item|entry)\b[^>]*>([\s\S]*?)<\/\1>/gi)) {
    const b = m[2];
    let title = htmlText(tag(b, 'title'));
    const desc = htmlText(tag(b, 'description') || tag(b, 'summary') || tag(b, 'content'));
    if (!title) title = clip(desc, 200); // Mastodon items have no title; the post text is the headline
    const link = decodeEntities(stripTags(tag(b, 'link')) || (b.match(/<link\b[^>]*href="([^"]+)"/i) || [])[1] || '');
    const when = stripTags(tag(b, 'pubDate') || tag(b, 'published') || tag(b, 'updated') || tag(b, 'dc:date'));
    if (!title || !link) continue;
    const breach = looksBreach(title);
    out.push({
      src: src.id, guid: stripTags(tag(b, 'guid') || tag(b, 'id')) || link, at: Date.parse(when) || ctx.now, title, url: link,
      keys: keysFor(title, ctx), type: breach ? 'breach' : 'news', peer: breach && !!src.nz,
    });
  }
  return out;
}

// ───────── Privacy Commissioner statements (HTML list) ─────────
export function parseOpc(html, src, ctx) {
  const base = new URL(src.url), out = [];
  for (const m of html.matchAll(/<article\b[^>]*>([\s\S]*?)<\/article>/gi)) {
    const a = m[1].match(/<h4>\s*<a\s+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/i);
    if (!a) continue;
    const dt = (m[1].match(/<time\s+datetime="(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})/i) || []);
    const title = stripTags(a[2]), breach = looksBreach(title);
    out.push({
      src: src.id, guid: new URL(a[1], base).href, at: dt[1] ? nzToUtc(dt[1], dt[2]) : ctx.now, title, url: new URL(a[1], base).href,
      keys: keysFor(title, ctx), type: breach ? 'breach' : 'news', peer: breach,
    });
  }
  return out;
}

// ───────── Bluesky curated authors (public AppView, no auth) ─────────
export function parseBsky(data, src, ctx) {
  return (data.feed || []).filter(f => !String(f.reason?.$type || '').includes('Repost')).map(f => {
    const p = f.post, text = String(p.record?.text || '').replace(/\s+/g, ' ').trim();
    const url = `https://bsky.app/profile/${p.author.handle}/post/${p.uri.split('/').pop()}`;
    const breach = looksBreach(text);
    return { src: src.id, guid: p.uri, at: Date.parse(p.record?.createdAt || p.indexedAt) || ctx.now, title: clip(text, 220), url, keys: keysFor(text, ctx), type: breach ? 'breach' : 'news', peer: breach && /\b(NZ|New Zealand|Aotearoa)\b/i.test(text) };
  }).filter(i => i.title);
}

// ───────── Microsoft Graph service announcements (messages + issues) ─────────
export function parseGraph({ messages = [], issues = [] }, src, ctx) {
  const out = [];
  for (const m of messages) {
    const svc = (m.services || []).join(' ');
    const keys = keysFor(`microsoft ${svc} ${m.title}`, ctx);
    out.push({
      src: src.id, guid: m.id + '@' + (m.lastModifiedDateTime || ''), at: Date.parse(m.lastModifiedDateTime || m.startDateTime) || ctx.now,
      title: `${m.id} · ${m.title}`, url: 'https://admin.microsoft.com/#/MessageCenter/:/messages/' + m.id,
      advs: [m.id], keys: keys.length ? keys : ['microsoft:365'], type: 'service', actBy: m.actionRequiredByDateTime ? Date.parse(m.actionRequiredByDateTime) : null,
    });
  }
  for (const i of issues) {
    if (i.isResolved) continue;
    const keys = keysFor(`microsoft ${i.service || ''} ${i.title}`, ctx);
    out.push({
      src: src.id, guid: i.id, at: Date.parse(i.startDateTime || i.lastModifiedDateTime) || ctx.now,
      title: `${i.id} · ${i.service || 'Microsoft 365'}: ${i.title}`, url: 'https://admin.microsoft.com/#/servicehealth/:/alerts/' + i.id,
      advs: [i.id], keys: keys.length ? keys : ['microsoft:365'], type: 'service',
    });
  }
  return out;
}

// ───────── Sample mocks (tagged Sample): ransomware.live claims, AWS Health ─────────
const ORGS = ['Harbourside Freight NZ', 'Kererū District Council', 'Tōtara Valley Health', 'Southern Lakes Polytechnic', 'Matai Street Legal', 'Pōhutukawa Housing Trust'];
const h = s => { let x = 0x811c9dc5; for (let i = 0; i < s.length; i++) { x ^= s.charCodeAt(i); x = Math.imul(x, 0x01000193); } return x >>> 0; };
export function mockRwl(src, ctx) {
  const day = nzParts(ctx.now).date, v = h(day + ':rwl');
  if (v % 5) return { items: [], noise: 0 };
  const org = ORGS[v % ORGS.length];
  return { items: [{ src: src.id, guid: day, at: ctx.now - 6 * 36e5, title: 'Claim · ' + org, url: 'https://www.ransomware.live/sample/' + normText(org).trim().replace(/\s+/g, '-'), keys: [], type: 'breach', peer: true, sample: true }], noise: 0 };
}
export function mockAws(src, ctx) {
  const day = nzParts(ctx.now).date, v = h(day + ':aws');
  if (v % 7) return { items: [], noise: 0 };
  return { items: [{ src: src.id, guid: day, at: ctx.now - 3 * 36e5, title: 'Increased error rates · Amazon S3 · ap-southeast-2', url: 'https://health.aws.amazon.com/health/status#s3-ap-southeast-2-' + day, keys: ['amazon:s3'], type: 'service', sample: true }], noise: 0 };
}

// ───────── fetchers ─────────
async function getText(url, ctx, opts) {
  const { res, ms } = await http(url, { fetch: ctx.fetch, ...opts });
  if (!res.ok) return { code: res.status, ms };
  return { code: res.status, ms, text: await res.text() };
}

export async function fetchNcscDetails(items, ctx, limit = 12) {
  const out = [];
  for (const it of items) {
    if (out.length >= limit) { out.push(it); continue; }
    try {
      const r = await getText(it.url, ctx, { timeout: 15000 });
      out.push(r.text ? parseNcscDetail(r.text, it, ctx) : { ...it, keys: keysFor(it.title, ctx) });
    } catch { out.push({ ...it, keys: keysFor(it.title, ctx) }); }
  }
  return out;
}

async function graphToken(ctx) {
  const S = ctx.settings, sec = ctx.secret('env:GRAPH_CLIENT_SECRET') || ctx.secret(S.secretRef);
  if (!S.tenant || !S.clientId || !sec) return null;
  const body = new URLSearchParams({ grant_type: 'client_credentials', client_id: S.clientId, client_secret: sec, scope: 'https://graph.microsoft.com/.default' });
  const { res } = await http(`https://login.microsoftonline.com/${S.tenant}/oauth2/v2.0/token`, { fetch: ctx.fetch, method: 'POST', body, headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  return res.ok ? (await res.json()).access_token : null;
}

// name → (src, ctx) => { code, ms, items, noise? }
// Vulnerability-Lookup returns at most 100 records per page, newest update first. Page back until the updates are
// older than params.hours (default 26 h), a page is short, or params.pages (default 8) is reached; keep CVEs
// published inside the lookback window. One page per call, so a Workflow step parses at most 100 records.
async function circlPage(src, ctx, p) {
  const hours = src.params?.hours ?? 26, pages = src.params?.pages ?? 8, since = ctx.now - (ctx.settings.lookbackDays || 30) * 864e5;
  const r = await getText(src.url + (src.url.includes('?') ? '&' : '?') + 'page=' + p, ctx, { accept: 'application/json', timeout: 45000 });
  if (!r.text) return r;
  const page = JSON.parse(r.text);
  if (!Array.isArray(page) || !page.length) return { code: r.code, ms: r.ms, items: [], more: false };
  const oldest = Math.min(...page.map(x => Date.parse(x.cveMetadata?.dateUpdated || '') || ctx.now));
  const more = p < pages && page.length >= 100 && oldest >= ctx.now - hours * 36e5;
  return { code: r.code, ms: r.ms, items: parseCircl(page, src, ctx).filter(i => i.at >= since), more };
}
// Parsers that fetch in pages: (src, ctx, page) → { code, ms, items, more }.
export const PAGED = { 'circl_recent@1': circlPage };

export const PARSERS = {
  'ncsc_alerts@2': async (src, ctx) => { const r = await getText(src.url, ctx); return r.text ? { ...r, items: parseNcscList(r.text, src) } : r; },
  'ncsc_email@1': async () => ({ push: true }),
  'kev_json@1': async (src, ctx) => { const r = await getText(src.url, ctx, { accept: 'application/json' }); return r.text ? { ...r, items: parseKev(JSON.parse(r.text), src, ctx) } : r; },
  'circl_recent@1': async (src, ctx) => {
    let items = [], ms = 0, code = 200;
    for (let p = 1; ; p++) {
      const r = await circlPage(src, ctx, p);
      ms += r.ms || 0;
      if (!r.items) { if (p === 1) return r; code = r.code; break; }
      items = items.concat(r.items);
      if (!r.more) break;
    }
    return { code, ms, items };
  },
  'rss@1': async (src, ctx) => { const r = await getText(src.url, ctx, { accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml, */*;q=0.5' }); return r.text ? { ...r, items: parseRss(r.text, src, ctx) } : r; },
  'opc_html@1': async (src, ctx) => { const r = await getText(src.url, ctx); return r.text ? { ...r, items: parseOpc(r.text, src, ctx) } : r; },
  'bsky_author@1': async (src, ctx) => {
    const actors = src.params?.actors || [];
    if (!actors.length) return { code: 204, ms: 0, items: [] };
    let items = [], ms = 0, code = 200;
    for (const a of actors.slice(0, 20)) {
      const r = await getText(`${src.url}?actor=${encodeURIComponent(a)}&limit=30&filter=posts_no_replies`, ctx, { accept: 'application/json' });
      ms += r.ms; if (!r.text) { code = r.code; continue; }
      items = items.concat(parseBsky(JSON.parse(r.text), src, ctx));
    }
    return { code, ms, items };
  },
  'graph_sa@1': async (src, ctx) => {
    const tok = await graphToken(ctx);
    if (!tok) return { code: 401, ms: 0, error: 'No Graph credentials' };
    const since = new Date(ctx.now - (ctx.settings.lookbackDays || 30) * 864e5).toISOString();
    const hd = { authorization: 'Bearer ' + tok, accept: 'application/json' };
    const m = await getText(`${src.url}/messages?$filter=lastModifiedDateTime ge ${since}&$top=100`, ctx, { headers: hd });
    const i = await getText(`${src.url}/issues?$filter=lastModifiedDateTime ge ${since}&$top=100`, ctx, { headers: hd });
    if (!m.text) return m;
    return { code: m.code, ms: m.ms + (i.ms || 0), items: parseGraph({ messages: JSON.parse(m.text).value || [], issues: i.text ? JSON.parse(i.text).value || [] : [] }, src, ctx) };
  },
  'rwl_mock@1': async (src, ctx) => ({ code: 200, ms: 0, ...mockRwl(src, ctx) }),
  'aws_health_mock@1': async (src, ctx) => ({ code: 200, ms: 0, ...mockAws(src, ctx) }),
};
export const PARSER_NAMES = [...Object.keys(PARSERS), 'epss_bulk@1', 'epss_api@1'];
