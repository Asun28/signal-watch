// EPSS enrichment without naming a CVE, CPE, vendor or product, so nothing about the inventory leaves the app.
// Matching to our CVEs happens locally, and the data is fetched on every run even when nothing needs enriching,
// so request timing reveals nothing either. Bulk file (full coverage, Workers Paid) or API pages (Workers Free).
import { http } from '../util.js';

// epss_bulk@1: the daily scores file (csv.gz, ~390k rows), streamed and filtered to `wanted`.
export async function epssBulk(src, ctx, wanted) {
  const { res, ms } = await http(src.url, { fetch: ctx.fetch, timeout: 60000 });
  if (!res.ok) return { code: res.status, ms };
  const gz = !/gzip|x-gzip/i.test(res.headers.get('content-encoding') || '') && /\.gz(\?|$)/.test(src.url);
  const stream = (gz ? res.body.pipeThrough(new DecompressionStream('gzip')) : res.body).pipeThrough(new TextDecoderStream());
  return { code: res.status, ms, ...(await scanCsv(stream, wanted)) };
}

export async function scanCsv(stream, wanted) {
  const reader = stream.getReader(), epss = {};
  let buf = '', rows = 0;
  const line = l => { const c = l.indexOf(','); if (c > 0) { rows++; const id = l.slice(0, c); if (wanted.has(id)) epss[id] = parseFloat(l.slice(c + 1)); } };
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += value;
    let s = 0, i;
    while ((i = buf.indexOf('\n', s)) >= 0) { line(buf.slice(s, i)); s = i + 1; }
    buf = buf.slice(s);
  }
  if (buf) line(buf);
  return { epss, rows };
}

// epss_api@1: FIRST API in threshold mode (?epss-gt=floor), one page of params.limit rows (default 5,000) per call.
// The URL never names a CVE and the page count depends only on the floor, so requests reveal nothing either.
// Values below the floor stay unknown; the floor is half the Plan threshold (capped at 0.05).
export async function epssApiPage(src, ctx, wanted, page = 1) {
  const floor = Math.max(0, Math.min(ctx.settings.epss ?? 0.1, 0.1) / 2), per = src.params?.limit ?? 5000, off = (page - 1) * per;
  const { res, ms } = await http(`${src.url}?epss-gt=${floor}&limit=${per}&offset=${off}`, { fetch: ctx.fetch, accept: 'application/json', timeout: 30000 });
  if (!res.ok) return { code: res.status, ms };
  const j = await res.json(), epss = {};
  let rows = 0;
  for (const x of j.data || []) { rows++; if (wanted.has(x.cve)) epss[x.cve] = parseFloat(x.epss); }
  return { code: 200, ms, epss, rows, more: rows > 0 && off + per < (j.total || 0) && off + per < 60000 };
}

export async function epssApi(src, ctx, wanted) {
  const out = { code: 200, ms: 0, epss: {}, rows: 0 };
  for (let p = 1; ; p++) {
    const r = await epssApiPage(src, ctx, wanted, p);
    out.ms += r.ms || 0;
    if (!r.epss) return { code: r.code, ms: out.ms };
    Object.assign(out.epss, r.epss); out.rows += r.rows;
    if (!r.more) return out;
  }
}

export const ENRICHERS = { 'epss_bulk@1': epssBulk, 'epss_api@1': epssApi };
// Enrichers that fetch in pages: (src, ctx, wanted, page) → { code, ms, epss, rows, more }.
export const PAGED_ENRICHERS = { 'epss_api@1': epssApiPage };
