// Recorded responses (test/fixtures, captured 19 Oct 2026) behind a fetch() stand-in that logs every request.
import fs from 'node:fs';
import zlib from 'node:zlib';

const F = name => fs.readFileSync(new URL('./fixtures/' + name, import.meta.url));
const NS = 'https://www.ncsc.govt.nz/alerts/multiple-vulnerabilities-affecting-citrix-netscaler-adc-and-netscaler-gateway-products-2/';

// A synthetic CVE 5 record (clearly marked) so the CIRCL path has one inventory match.
export const SYNTH_CVE = {
  dataType: 'CVE_RECORD', dataVersion: '5.1',
  cveMetadata: { cveId: 'CVE-2026-99001', state: 'PUBLISHED', datePublished: '2026-10-18T09:00:00Z', dateUpdated: '2026-10-18T09:00:00Z' },
  containers: { cna: {
    title: 'Veeam Backup & Replication: deserialization to RCE (test fixture)',
    descriptions: [{ lang: 'en', value: 'Test fixture record.' }],
    affected: [{ vendor: 'Veeam', product: 'Backup & Replication', cpes: ['cpe:2.3:a:veeam:veeam_backup_\\&_replication:*:*:*:*:*:*:*:*'], versions: [{ version: '12.0', lessThan: '12.3.2', status: 'affected', versionType: 'custom' }] }],
    metrics: [{ cvssV3_1: { baseScore: 9.1, version: '3.1' } }],
  } },
};

function epssPage(q) {
  const rows = zlib.gunzipSync(F('epss.csv.gz')).toString().split('\n').filter(l => /^CVE-/.test(l)).map(l => l.split(','))
    .map(([cve, epss, percentile]) => ({ cve, epss, percentile, date: '2026-10-18' })).filter(x => +x.epss > +(q.get('epss-gt') || 0));
  const limit = +(q.get('limit') || 100), offset = +(q.get('offset') || 0);
  return { status: 'OK', total: rows.length, offset, limit, data: rows.slice(offset, offset + limit) };
}

export function fakeNet(over = {}) {
  const log = [];
  const routes = {
    'https://www.ncsc.govt.nz/alerts/': () => [200, F('ncsc_alerts.html'), 'text/html'],
    [NS]: () => [200, F('ncsc_detail_netscaler.html'), 'text/html'],
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json': () => [200, F('kev.json'), 'application/json'],
    'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz': () => [200, F('epss.csv.gz'), 'binary/octet-stream'],
    // FIRST API threshold pages, served from the same recorded scores
    'https://api.first.org/data/v1/epss?*': ({ url }) => [200, JSON.stringify(epssPage(new URL(url).searchParams)), 'application/json'],
    'https://vulnerability.circl.lu/api/vulnerability/last/cvelistv5/100?page=1': () => [200, JSON.stringify([...JSON.parse(F('circl_cve5.json')), SYNTH_CVE]), 'application/json'],
    'https://vulnerability.circl.lu/api/vulnerability/last/cvelistv5/100?page=*': () => [200, '[]', 'application/json'],
    'https://securitybrief.co.nz/feed': () => [200, F('sbnz.xml'), 'application/rss+xml'],
    'https://www.privacy.org.nz/tuhono-connect/statements-media-releases/': () => [200, F('opc.html'), 'text/html'],
    ...over,
  };
  async function fetch(input, init = {}) {
    const url = typeof input === 'string' ? input : input.url;
    const body = init.body == null ? '' : typeof init.body === 'string' ? init.body : String(init.body);
    log.push({ url, method: init.method || 'GET', body, headers: init.headers || {} });
    let hit = routes[url] || Object.entries(routes).find(([k]) => k.endsWith('*') && url.startsWith(k.slice(0, -1)))?.[1];
    if (!hit && url.startsWith('https://www.ncsc.govt.nz/alerts/')) hit = () => [200, '<html><main><h2 class="advisory-page-title">Alert</h2><p>No details.</p></main></html>', 'text/html'];
    if (!hit) return new Response('not found', { status: 404 });
    const [status, data, type] = await hit({ url, init, body });
    return new Response(status === 204 ? null : data, { status, headers: { 'content-type': type || 'application/json' } });
  }
  return { fetch, log };
}
