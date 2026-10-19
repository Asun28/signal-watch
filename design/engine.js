// Signal Watch POV — fixtures + pure pipeline (ingest → match → group → level → route).
// No network calls. Inventory never leaves this module except into internal routes (Sentinel / tickets).
export const DAY = 864e5;
export const TZ = 'Pacific/Auckland';
const T = s => Date.parse(/[+Z]/.test(s.slice(10)) ? s : s + ':00+13:00');
const uniq = a => [...new Set(a)];
const iso = ms => new Date(ms).toISOString();

const F = o => new Intl.DateTimeFormat('en-NZ', { timeZone: TZ, ...o });
const F_DAY = F({ weekday: 'short', day: 'numeric', month: 'short' });
const F_TIME = F({ hour: '2-digit', minute: '2-digit', hour12: false });
const F_DATE = F({ day: 'numeric', month: 'short' });
const F_FULL = F({ day: 'numeric', month: 'short', year: 'numeric' });
export const fmtDay = ms => F_DAY.format(ms).replace(',', '');
export const fmtTime = ms => F_TIME.format(ms);
export const fmtDate = ms => F_DATE.format(ms);
export const fmtFull = ms => F_FULL.format(ms);
export function fmtAgo(ms, now) {
  const d = now - ms;
  if (d < 36e5) return Math.max(1, Math.round(d / 6e4)) + ' min';
  if (d < DAY) return Math.round(d / 36e5) + ' h';
  return Math.round(d / DAY) + ' d';
}

// ───────── vocab ─────────
export const LV = {
  act: { key: 'act', label: 'Act', icon: 'warning-octagon', rank: 4 },
  plan: { key: 'plan', label: 'Plan', icon: 'calendar', rank: 3 },
  watch: { key: 'watch', label: 'Watch', icon: 'eye', rank: 2 },
  info: { key: 'info', label: 'Info', icon: 'info', rank: 1 },
  hidden: { key: 'hidden', label: 'Hidden', icon: 'eye-slash', rank: 0 },
};
const RANK = { act: 4, plan: 3, watch: 2, info: 1, hidden: 0 };
export const MODELS = {
  self: { key: 'self', label: 'Self-managed', icon: 'hard-drives' },
  shared: { key: 'shared', label: 'Shared', icon: 'handshake' },
  vendor: { key: 'vendor', label: 'Vendor-managed', icon: 'storefront' },
  hyper: { key: 'hyper', label: 'Hyperscaler', icon: 'cloud' },
};
export const TYPES = {
  alert: { key: 'alert', label: 'Alert', icon: 'megaphone' },
  exploit: { key: 'exploit', label: 'Exploit', icon: 'fire' },
  vuln: { key: 'vuln', label: 'Vuln', icon: 'bug' },
  breach: { key: 'breach', label: 'Breach', icon: 'lock-simple-open' },
  service: { key: 'service', label: 'Service', icon: 'cloud-warning' },
  news: { key: 'news', label: 'News', icon: 'newspaper' },
};
const TYPE_RANK = { alert: 6, exploit: 5, breach: 4, vuln: 3, service: 2, news: 1 };
export const DECISIONS = {
  ack: { key: 'ack', label: 'Acknowledged', short: 'Ack', icon: 'check-circle' },
  na: { key: 'na', label: 'Not affected', short: 'Not affected', icon: 'prohibit' },
  ticket: { key: 'ticket', label: 'Ticketed', short: 'Ticket', icon: 'ticket' },
  auto: { key: 'auto', label: 'Auto route', short: 'Auto', icon: 'paper-plane-tilt' },
};
export const NA_REASONS = ['Version', 'Not deployed', 'Config', 'Mitigated'];
export const TEAM = ['Aroha T.', 'Sam L.', 'Priya N.', 'Ben K.', 'Mere W.'];
export const ME = 'Aroha T.';

export const DEFAULT_SCOPE = {
  self: { alert: 1, exploit: 1, vuln: 1, breach: 1, service: 0, news: 1 },
  shared: { alert: 1, exploit: 1, vuln: 1, breach: 1, service: 1, news: 1 },
  vendor: { alert: 1, exploit: 0, vuln: 0, breach: 1, service: 1, news: 1 },
  hyper: { alert: 1, exploit: 0, vuln: 0, breach: 1, service: 1, news: 0 },
};
export const DEFAULT_SETTINGS = {
  epss: 0.1, cvss: 9, actByDays: 30, archiveDays: 14,
  jaccard: 0.85, windowDays: 7, lookbackDays: 30, perms: 128,
  ai: false, aiGroup: true, aiExtract: true, embedMin: 0.9, greyMin: 0.78,
  aiEndpoint: 'https://aoai-signalwatch.openai.azure.com', aiModel: 'gpt-4.1-mini',
  actRoute: 'sentinel', ticketSys: 'servicenow',
  schedule: '07:30', days: [1, 1, 1, 1, 1, 1, 1],
  digestTime: '07:45', digestTeams: true, digestEmail: true, digestTo: 'security@agency.govt.nz',
  teamsUrl: 'https://prod-27.australiaeast.logic.azure.com/workflows/…/triggers/manual/paths/invoke',
  dce: 'https://signalwatch-dce-k3x9.australiaeast-1.ingest.monitor.azure.com',
  dcr: 'dcr-6f1c2b8e4d0a4f7a9c3e5b1d2a7f8e90', stream: 'Custom-SignalWatch_CL', table: 'SignalWatch_CL',
  tenant: '3f0c…e21a', clientId: 'b7d4…90c1', secretRef: 'kv://kv-signalwatch/sentinel-client-secret',
  ticketUrl: 'https://agency.service-now.com', ticketAuth: 'kv://kv-signalwatch/snow-token',
  rawDays: 90,
};

// ───────── sources (config, not code) ─────────
export const SOURCES = [
  { id: 'ncsc', fam: 'ncsc', name: 'NCSC NZ', icon: 'shield-warning', kind: 'HTML', role: 'Feed', tier: 1, schedule: 'Daily 07:30', parser: 'ncsc_alerts@2', url: 'https://www.ncsc.govt.nz/alerts/', nz: true },
  { id: 'ncsc_mail', fam: 'ncsc', name: 'NCSC email', icon: 'envelope-simple', kind: 'Email', role: 'Fallback', tier: 1, schedule: 'On receipt', parser: 'ncsc_email@1', url: 'mailto:signalwatch-ingest@agency.govt.nz', nz: true },
  { id: 'kev', fam: 'kev', name: 'CISA KEV', icon: 'fire', kind: 'JSON', role: 'Feed', tier: 1, schedule: 'Daily 07:30', parser: 'kev_json@1', url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' },
  { id: 'epss', fam: 'epss', name: 'FIRST EPSS', icon: 'chart-line-up', kind: 'API', role: 'Enrich', tier: 2, schedule: 'Daily 07:30', parser: 'epss_bulk@1', url: 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz' },
  { id: 'circl', fam: 'circl', name: 'CIRCL Vuln-Lookup', icon: 'database', kind: 'API', role: 'Feed', tier: 2, schedule: 'Daily 07:30', parser: 'circl_recent@1', url: 'https://vulnerability.circl.lu/api/vulnerability/recent' },
  { id: 'sbnz', fam: 'sbnz', name: 'SecurityBrief NZ', icon: 'newspaper', kind: 'RSS', role: 'Feed', tier: 2, schedule: 'Daily 07:30', parser: 'rss@1', url: 'https://securitybrief.co.nz/feed', nz: true },
  { id: 'graph', fam: 'graph', name: 'MS Graph', icon: 'windows-logo', kind: 'API', role: 'Feed', tier: 1, schedule: 'Daily 07:30', parser: 'graph_sa@1', url: 'https://graph.microsoft.com/v1.0/admin/serviceAnnouncement/messages', optional: true },
  { id: 'opc', fam: 'opc', name: 'Privacy Commissioner', icon: 'scales', kind: 'HTML', role: 'Feed', tier: 2, schedule: 'Daily 07:30', parser: 'opc_html@1', url: 'https://www.privacy.org.nz/tuhono-connect/statements-media-releases/', optional: true, nz: true },
  { id: 'bsky', fam: 'bsky', name: 'Bluesky authors', icon: 'butterfly', kind: 'API', role: 'Feed', tier: 3, schedule: 'Daily 07:30', parser: 'bsky_author@1', url: 'https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed', optional: true, social: true },
  { id: 'masto', fam: 'masto', name: 'Mastodon RSS', icon: 'mastodon-logo', kind: 'RSS', role: 'Feed', tier: 3, schedule: 'Daily 07:30', parser: 'rss@1', url: 'https://infosec.exchange/@analyst.rss', optional: true, social: true },
  { id: 'rwl', fam: 'rwl', name: 'ransomware.live', icon: 'skull', kind: 'Mock', role: 'Feed', tier: 3, schedule: 'Daily 07:30', parser: 'rwl_mock@1', url: 'https://api.ransomware.live/v2/recentvictims', sample: true },
  { id: 'aws', fam: 'aws', name: 'AWS Health', icon: 'heartbeat', kind: 'Mock', role: 'Feed', tier: 1, schedule: 'Daily 07:30', parser: 'aws_health_mock@1', url: 'aws-health://ap-southeast-2', sample: true },
];
export const SRC = Object.fromEntries(SOURCES.map(s => [s.id, s]));
export const PARSERS = ['ncsc_alerts@2', 'ncsc_email@1', 'kev_json@1', 'epss_bulk@1', 'circl_recent@1', 'rss@1', 'graph_sa@1', 'opc_html@1', 'bsky_author@1', 'rwl_mock@1', 'aws_health_mock@1'];

// ───────── local catalogue: canonical vendor:product keys + aliases (also the CPE autocomplete dictionary) ─────────
// [key, vendor, title, aliases, hasCpe(0/1), part]
export const CATALOG = [
  ['citrix:netscaler_application_delivery_controller', 'Citrix', 'NetScaler ADC', ['netscaler adc', 'citrix adc', 'netscaler application delivery controller', 'netscaler'], 1, 'a'],
  ['citrix:netscaler_gateway', 'Citrix', 'NetScaler Gateway', ['netscaler gateway', 'citrix gateway', 'netscaler'], 1, 'a'],
  ['citrix:workspace', 'Citrix', 'Workspace app', ['citrix workspace', 'workspace app'], 1, 'a'],
  ['fortinet:fortios', 'Fortinet', 'FortiOS', ['fortios', 'fortigate'], 1, 'o'],
  ['fortinet:forticlient_ems', 'Fortinet', 'FortiClient EMS', ['forticlient ems'], 1, 'a'],
  ['microsoft:windows_server_2022', 'Microsoft', 'Windows Server 2022', ['windows server 2022'], 1, 'o'],
  ['microsoft:windows_11', 'Microsoft', 'Windows 11', ['windows 11'], 1, 'o'],
  ['microsoft:exchange_server', 'Microsoft', 'Exchange Server', ['exchange server'], 1, 'a'],
  ['microsoft:sql_server_2019', 'Microsoft', 'SQL Server 2019', ['sql server 2019'], 1, 'a'],
  ['microsoft:sharepoint_server', 'Microsoft', 'SharePoint Server', ['sharepoint server'], 1, 'a'],
  ['vmware:esxi', 'VMware', 'ESXi', ['esxi'], 1, 'o'],
  ['vmware:vcenter_server', 'VMware', 'vCenter Server', ['vcenter'], 1, 'a'],
  ['veeam:veeam_backup_&_replication', 'Veeam', 'Backup & Replication', ['veeam backup', 'backup & replication', 'veeam b&r'], 1, 'a'],
  ['papercut:papercut_mf', 'PaperCut', 'PaperCut MF', ['papercut mf', 'papercut'], 1, 'a'],
  ['wordpress:wordpress', 'WordPress', 'WordPress', ['wordpress'], 1, 'a'],
  ['apache:tomcat', 'Apache', 'Tomcat', ['apache tomcat', 'tomcat'], 1, 'a'],
  ['canonical:ubuntu_linux', 'Canonical', 'Ubuntu Linux', ['ubuntu'], 1, 'o'],
  ['zohocorp:manageengine_servicedesk_plus', 'Zoho', 'ManageEngine ServiceDesk Plus', ['manageengine servicedesk', 'servicedesk plus'], 1, 'a'],
  ['cisco:ios_xe', 'Cisco', 'IOS XE', ['ios xe', 'catalyst 9300'], 1, 'o'],
  ['cisco:catalyst_sd-wan_manager', 'Cisco', 'Catalyst SD-WAN Manager', ['catalyst sd-wan manager', 'sd-wan manager'], 1, 'a'],
  ['checkpoint:management_server', 'Check Point', 'Management Server', ['check point management server'], 1, 'a'],
  ['ivanti:connect_secure', 'Ivanti', 'Connect Secure', ['ivanti connect secure'], 1, 'a'],
  ['paloaltonetworks:pan-os', 'Palo Alto Networks', 'PAN-OS', ['pan-os', 'globalprotect'], 1, 'o'],
  ['atlassian:confluence_data_center', 'Atlassian', 'Confluence Data Center', ['confluence'], 1, 'a'],
  ['atlassian:jira', 'Atlassian', 'Jira', ['jira cloud', 'jira'], 1, 'a'],
  ['sonicwall:sonicos', 'SonicWall', 'SonicOS', ['sonicwall', 'sonicos'], 1, 'o'],
  ['f5:big-ip', 'F5', 'BIG-IP', ['big-ip'], 1, 'a'],
  ['moodle:moodle', 'Moodle', 'Moodle', ['moodle'], 1, 'a'],
  ['openssl:openssl', 'OpenSSL', 'OpenSSL', ['openssl'], 1, 'a'],
  ['zoom:workplace', 'Zoom', 'Zoom Workplace', ['zoom workplace'], 1, 'a'],
  ['microsoft:365', 'Microsoft', 'Microsoft 365', ['microsoft 365', 'exchange online', 'message center'], 0],
  ['microsoft:entra_id', 'Microsoft', 'Entra ID', ['entra id', 'microsoft entra'], 0],
  ['microsoft:intune', 'Microsoft', 'Intune', ['intune'], 0],
  ['microsoft:azure_app_service', 'Microsoft', 'Azure App Service', ['app service'], 0],
  ['microsoft:azure_application_gateway', 'Microsoft', 'Azure App Gateway', ['application gateway', 'app gateway'], 0],
  ['amazon:s3', 'AWS', 'Amazon S3', ['amazon s3'], 0],
  ['mimecast:email_security', 'Mimecast', 'Email Security', ['mimecast'], 0],
  ['managemyhealth:managemyhealth', 'Manage My Health', 'Manage My Health', ['manage my health', 'managemyhealth'], 0],
  ['objective:ecm', 'Objective', 'Objective ECM', ['objective ecm'], 0],
  ['technologyone:ci_anywhere', 'TechnologyOne', 'Ci Anywhere', ['technologyone', 'ci anywhere'], 0],
  ['salesforce:service_cloud', 'Salesforce', 'Service Cloud', ['salesforce'], 0],
  ['datacom:payroll', 'Datacom', 'Datacom Payroll', ['datacom payroll'], 0],
  ['dia:realme', 'DIA', 'RealMe login', ['realme'], 0],
];
const ALIAS = (() => {
  const m = new Map();
  for (const [k, , , al] of CATALOG) for (const a of al) m.set(a, [...(m.get(a) || []), k]);
  return [...m.entries()].sort((a, b) => b[0].length - a[0].length);
})();
export function cpeSuggest(q, limit = 8) {
  const t = normText(q).trim();
  if (!t) return [];
  return CATALOG.filter(c => c[4]).map(([k, v, title, , , part]) => ({ cpe: `cpe:2.3:${part}:${k}`, vendor: v, title, key: k }))
    .filter(c => normText(c.title + ' ' + c.vendor + ' ' + c.cpe).includes(t)).slice(0, limit);
}

// ───────── text utils ─────────
export function normText(t) {
  return ' ' + String(t || '').toLowerCase().replace(/https?:\/\/\S+/g, ' ').replace(/[#@]/g, ' ')
    .replace(/[^a-z0-9&.\- ]+/g, ' ').replace(/\.(\s|$)/g, ' ').replace(/\s+/g, ' ').trim() + ' ';
}
function normShingle(t) {
  return String(t || '').toLowerCase().replace(/https?:\/\/\S+/g, ' ').replace(/[#@][\w.\-]+/g, ' ')
    .replace(/[^a-z0-9 ]+/g, ' ').replace(/\s+/g, ' ').trim();
}
export function extractKeys(text) {
  let t = normText(text);
  const keys = [];
  for (const [a, ks] of ALIAS) {
    const needle = ' ' + a + ' ';
    if (t.includes(needle)) { keys.push(...ks); t = t.split(needle).join(' ~ '); }
  }
  return uniq(keys);
}
const CVE_RE = /CVE-\d{4}-\d{4,7}/gi;
const ADV_RE = /\b(CTX\d{6}|MC\d{6,7}|EX\d{6,7})\b/gi;
export function canonUrl(u) {
  if (!u) return '';
  try {
    const x = new URL(u);
    for (const k of [...x.searchParams.keys()]) if (/^(utm_|mc_|fbclid|gclid)/i.test(k)) x.searchParams.delete(k);
    const s = (x.host.replace(/^www\./, '') + x.pathname).toLowerCase().replace(/\/+$/, '');
    const q = x.searchParams.toString();
    return (q ? s + '?' + q : s) + (x.hash.length > 1 ? x.hash.toLowerCase() : '');
  } catch { return String(u).toLowerCase(); }
}

// ───────── MinHash ─────────
function h32(str) { let h = 0x811c9dc5; for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193); } return h >>> 0; }
function fmix(x) { x ^= x >>> 16; x = Math.imul(x, 0x85ebca6b); x ^= x >>> 13; x = Math.imul(x, 0xc2b2ae35); x ^= x >>> 16; return x >>> 0; }
const SEEDS = Array.from({ length: 512 }, (_, i) => fmix(Math.imul(i + 1, 0x9e3779b1) >>> 0));
export function shingles(text, k = 5) {
  const t = normShingle(text), s = new Set();
  for (let i = 0; i + k <= t.length; i++) s.add(t.slice(i, i + k));
  if (!s.size && t) s.add(t);
  return s;
}
export function minhash(text, n = 128) {
  const sig = new Uint32Array(n).fill(0xffffffff);
  for (const sh of shingles(text)) { const b = h32(sh); for (let i = 0; i < n; i++) { const v = fmix(b ^ SEEDS[i]); if (v < sig[i]) sig[i] = v; } }
  return sig;
}
export function jaccardEst(a, b) { let e = 0; for (let i = 0; i < a.length; i++) if (a[i] === b[i]) e++; return e / a.length; }
export function jaccardExact(x, y) { const a = shingles(x), b = shingles(y); let i = 0; for (const s of a) if (b.has(s)) i++; return i / (a.size + b.size - i || 1); }
const MH = new Map();
function mh(item, n) { const k = item.id + ':' + n; if (!MH.has(k)) MH.set(k, minhash(item.title, n)); return MH.get(k); }

// ───────── embedding stub (AI flag only) — hashed bag of words + entity keys ─────────
const STOP = new Set('the and for with from into this that your our new via has have was were will can not are its over after more than about what who how why been last week'.split(' '));
const SYN = { flaw: 'vuln', flaws: 'vuln', bug: 'vuln', vulnerability: 'vuln', vulnerabilities: 'vuln', breach: 'incident', breached: 'incident', hack: 'incident', hacked: 'incident', attack: 'incident', attacks: 'incident', incident: 'incident', cyber: '', security: '', inquiry: 'inquiry', investigation: 'inquiry', investigating: 'inquiry', exploited: 'exploit', exploitation: 'exploit', patched: 'patch', patches: 'patch', upgrade: 'patch', update: 'patch', updated: 'patch', updates: 'patch' };
function toks(t) { return normShingle(t).split(' ').map(w => (w in SYN ? SYN[w] : w.replace(/(ing|ed|es|s)$/, ''))).filter(w => w.length > 2 && !STOP.has(w)); }
export function embed(item) {
  const v = new Array(64).fill(0);
  const add = (s, w) => { const h = fmix(h32(s)); v[h & 63] += (h & 64 ? 1 : -1) * w; };
  for (const t of toks(item.title)) add('w:' + t, 1);
  for (const k of item.keys) add('k:' + k, 3);
  add('t:' + item.type, 1.5);
  if (item.peer) add('nzpeer', 1);
  const n = Math.hypot(...v) || 1;
  return v.map(x => x / n);
}
export function cosine(a, b) { let s = 0; for (let i = 0; i < a.length; i++) s += a[i] * b[i]; return s; }
function centroid(sig) { const v = new Array(64).fill(0); for (const it of sig.items) { const e = it._emb || (it._emb = embed(it)); for (let i = 0; i < 64; i++) v[i] += e[i]; } const n = Math.hypot(...v) || 1; return v.map(x => x / n); }
// Small-model stub for grey-zone pairs. Input is two headlines only — never inventory.
export function greyModel(item, sig) {
  const input = { a: item.title, b: sig.items[0].title };
  const shared = item.keys.some(k => sig.keys.includes(k));
  const sameType = sig.items.some(i => i.type === item.type);
  return { same: shared && sameType, conf: shared && sameType ? 0.74 : 0.21, input };
}

// ───────── versions ─────────
function vparts(v) { return String(v).split(/[.\-\s]+/).map(x => (/^\d+$/.test(x) ? +x : x)); }
export function vcmp(a, b) { const x = vparts(a), y = vparts(b); for (let i = 0; i < Math.max(x.length, y.length); i++) { const p = x[i] ?? 0, q = y[i] ?? 0; if (p === q) continue; if (typeof p === 'number' && typeof q === 'number') return p - q; return String(p) < String(q) ? -1 : 1; } return 0; }
export function versionHit(version, affected, key) {
  if (!affected || !version || !/\d/.test(version)) return { hit: null, cond: '' };
  for (const r of affected) {
    if (r.keys && !r.keys.includes(key)) continue;
    const ok = (r.lt == null || vcmp(version, r.lt) < 0) && (r.gte == null || vcmp(version, r.gte) >= 0) && (r.lte == null || vcmp(version, r.lte) <= 0);
    if (ok) return { hit: true, cond: r.cond || '' };
  }
  return { hit: false, cond: '' };
}

// ───────── inventory ─────────
const P = (id, name, vendor, cpe, version, owner, model, decoy) => ({ id, name, vendor, cpe, version, owner, model, ...(decoy ? { decoy: true } : {}) });
export const SEED_INVENTORY = [
  P('p01', 'NetScaler ADC', 'Citrix', 'cpe:2.3:a:citrix:netscaler_application_delivery_controller', '14.1-73.41', 'Sam L.', 'self'),
  P('p02', 'NetScaler Gateway', 'Citrix', 'cpe:2.3:a:citrix:netscaler_gateway', '14.1-73.41', 'Sam L.', 'self'),
  P('p03', 'Citrix Workspace app', 'Citrix', 'cpe:2.3:a:citrix:workspace', '2409', 'Ben K.', 'self', 1),
  P('p04', 'FortiGate', 'Fortinet', 'cpe:2.3:o:fortinet:fortios', '7.4.9', 'Sam L.', 'self'),
  P('p05', 'Windows Server 2022', 'Microsoft', 'cpe:2.3:o:microsoft:windows_server_2022', '10.0.20348', 'Priya N.', 'self'),
  P('p06', 'Exchange Server', 'Microsoft', 'cpe:2.3:a:microsoft:exchange_server', '2019 CU15', 'Priya N.', 'self'),
  P('p07', 'VMware ESXi', 'VMware', 'cpe:2.3:o:vmware:esxi', '8.0 U3', 'Priya N.', 'self'),
  P('p08', 'vCenter Server', 'VMware', 'cpe:2.3:a:vmware:vcenter_server', '8.0 U3', 'Priya N.', 'self'),
  P('p09', 'Veeam B&R', 'Veeam', 'cpe:2.3:a:veeam:veeam_backup_&_replication', '12.3', 'Priya N.', 'self'),
  P('p10', 'PaperCut MF', 'PaperCut', 'cpe:2.3:a:papercut:papercut_mf', '24.1', 'Ben K.', 'self'),
  P('p11', 'WordPress', 'WordPress', 'cpe:2.3:a:wordpress:wordpress', '6.8.3', 'Mere W.', 'self'),
  P('p12', 'Apache Tomcat', 'Apache', 'cpe:2.3:a:apache:tomcat', '10.1.44', 'Mere W.', 'self'),
  P('p13', 'Ubuntu Server', 'Canonical', 'cpe:2.3:o:canonical:ubuntu_linux', '24.04', 'Priya N.', 'self'),
  P('p14', 'ServiceDesk Plus', 'ManageEngine', 'cpe:2.3:a:zohocorp:manageengine_servicedesk_plus', '14.9', 'Ben K.', 'self', 1),
  P('p15', 'Catalyst 9300', 'Cisco', 'cpe:2.3:o:cisco:ios_xe', '17.9.5', 'Sam L.', 'shared', 1),
  P('p16', 'SQL Server 2019', 'Microsoft', 'cpe:2.3:a:microsoft:sql_server_2019', '15.0', 'Priya N.', 'shared'),
  P('p17', 'Objective ECM', 'Objective', '', '11.2', 'Mere W.', 'shared'),
  P('p18', 'Ci Anywhere', 'TechnologyOne', '', '2025B', 'Mere W.', 'shared'),
  P('p19', 'Mimecast', 'Mimecast', '', 'SaaS', 'Priya N.', 'vendor'),
  P('p20', 'Zoom Workplace', 'Zoom', 'cpe:2.3:a:zoom:workplace', 'SaaS', 'Ben K.', 'vendor'),
  P('p21', 'Jira Cloud', 'Atlassian', 'cpe:2.3:a:atlassian:jira', 'Cloud', 'Ben K.', 'vendor'),
  P('p22', 'Salesforce', 'Salesforce', '', 'Cloud', 'Mere W.', 'vendor'),
  P('p23', 'Datacom Payroll', 'Datacom', '', 'SaaS', 'Aroha T.', 'vendor'),
  P('p24', 'RealMe login', 'DIA', '', 'SaaS', 'Mere W.', 'vendor'),
  P('p25', 'Microsoft 365', 'Microsoft', '', 'Cloud', 'Priya N.', 'hyper'),
  P('p26', 'Entra ID', 'Microsoft', '', 'Cloud', 'Priya N.', 'hyper'),
  P('p27', 'Intune', 'Microsoft', '', 'Cloud', 'Ben K.', 'hyper'),
  P('p28', 'Azure App Service', 'Microsoft', '', 'Australia East', 'Mere W.', 'hyper'),
  P('p29', 'Azure App Gateway', 'Microsoft', '', 'Australia East', 'Sam L.', 'hyper'),
  P('p30', 'Amazon S3', 'AWS', '', 'ap-southeast-2', 'Mere W.', 'hyper'),
];
export function productKey(p) {
  if (p.cpe) { const x = p.cpe.replace(/\\/g, '').split(':'); if (x.length >= 5) return (x[3] + ':' + x[4]).toLowerCase(); }
  return extractKeys(p.vendor + ' ' + p.name)[0] || 'name:' + normText(p.name).trim();
}

// ───────── fixtures ─────────
const N = (circl = 170, sbnz = 9, bsky = 30, masto = 20, kev = 1, graph = 3, aws = 1, rwl = 5, opc = 1) => ({ circl, sbnz, bsky, masto, kev, graph, aws, rwl, opc });
const run = (at, mode, items, x = {}) => ({ at: T(at), mode, items, noise: x.noise || N(), epss: x.epss || {}, cvss: x.cvss || {}, status: x.status || {} });
const it = (n, src, at, title, url, f = {}) => ({ n, src, at, title, url, ...f });
const NS = ['citrix:netscaler_application_delivery_controller', 'citrix:netscaler_gateway'];
const NCSC_NS = 'https://www.ncsc.govt.nz/alerts/multiple-vulnerabilities-affecting-citrix-netscaler-adc-and-netscaler-gateway-products-2/';
const C88 = [1, 2, 3, 4, 5, 6, 7, 8].map(i => 'CVE-2026-8877' + i);
const AFF_SEP = [{ keys: NS, lt: '14.1-73.37', cond: 'SAML SP/IdP' }];
const AFF_OCT = [{ keys: NS, gte: '14.1-73.37', lte: '14.1-73.41', cond: 'SAML IdP' }, { keys: NS, lt: '14.1-73.37', cond: 'SAML SP/IdP' }];
const cU = c => 'https://vulnerability.circl.lu/vuln/' + c.toLowerCase();
const kU = c => 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search=' + c;
const circlNS = (n, c, what, cvss) => it(n, 'circl', '2026-09-27T09:00', `${c} · NetScaler ADC and Gateway: ${what}`, cU(c), { cves: [c], advs: ['CTX697096'], keys: NS, type: 'vuln', cvss, affected: AFF_SEP, fix: '14.1-73.37 · 13.1-64.23' });
const S = true;

const NETSCALER_RUNS = [
  run('2026-07-02T07:30+12:00', 'Schedule', [
    it(100, 'ncsc', '2026-07-01T10:00+12:00', 'Multiple vulnerabilities affecting Citrix NetScaler ADC and NetScaler Gateway products', 'https://www.ncsc.govt.nz/alerts/multiple-vulnerabilities-affecting-citrix-netscaler-adc-and-netscaler-gateway-products/', { cves: ['CVE-2026-8655', 'CVE-2026-10816', 'CVE-2026-10817', 'CVE-2026-13474'], type: 'alert', cvss: 8.8, affected: [{ keys: NS, lt: '14.1-72.61' }], fix: '14.1-72.61 · 13.1-63.18' }),
  ]),
  run('2026-09-25T07:30', 'Schedule', [
    it(102, 'ncsc', '2026-09-23T14:00', 'CVE-2026-93616 affecting Check Point Management Server', 'https://www.ncsc.govt.nz/alerts/cve-2026-93616-affecting-check-point-management-server/', { type: 'alert' }),
    it(101, 'ncsc', '2026-09-24T15:00', 'CVE-2026-87902 Affecting WordPress', 'https://www.ncsc.govt.nz/alerts/cve-2026-87902-affecting-wordpress/', { type: 'alert', fix: 'Update to latest' }),
  ]),
  run('2026-09-27T07:30', 'Schedule', [
    it(103, 'bsky', '2026-09-26T21:40', 'Active exploitation of a NetScaler zero-day seen across several orgs. No patch yet. Consider taking appliances offline.', 'https://bsky.app/profile/analyst.example/post/3m2a', { sample: S }),
    it(104, 'masto', '2026-09-26T22:05', 'Active exploitation of a NetScaler zero-day seen across several orgs. No patch yet. Consider taking appliances offline. #infosec', 'https://infosec.exchange/@analyst/1153', { sample: S }),
  ]),
  run('2026-09-28T07:30', 'Schedule', [
    it(105, 'kev', '2026-09-27T08:00', 'Citrix NetScaler ADC and NetScaler Gateway Improper Input Validation Vulnerability', kU('CVE-2026-88771'), { cves: ['CVE-2026-88771'], advs: ['CTX697096'], keys: NS, type: 'exploit', kev: { added: '2026-09-27', due: '2026-09-30' } }),
    it(106, 'kev', '2026-09-27T08:00', 'Citrix NetScaler ADC and NetScaler Gateway Memory Overflow Vulnerability', kU('CVE-2026-88772'), { cves: ['CVE-2026-88772'], advs: ['CTX697096'], keys: NS, type: 'exploit', kev: { added: '2026-09-27', due: '2026-09-30' } }),
    circlNS(107, C88[0], 'unauthenticated RCE via input validation', 9.5),
    circlNS(108, C88[1], 'memory overflow, RCE or DoS', 9.5),
    circlNS(109, C88[2], 'HTTP request smuggling', 9.3),
    circlNS(110, C88[3], 'feature policy bypass', 7.0),
    circlNS(111, C88[4], 'memory overflow, denial of service', 8.8),
    circlNS(112, C88[5], 'memory overflow, denial of service', 8.8),
    circlNS(113, C88[6], 'memory overflow, denial of service', 8.8),
    circlNS(114, C88[7], 'TCP sequence number prediction', 8.8),
  ], { epss: { 'CVE-2026-88771': 0.71, 'CVE-2026-88772': 0.64 } }),
  run('2026-09-29T13:05', 'Run now', [
    it(115, 'ncsc', '2026-09-29T12:00', 'Multiple vulnerabilities affecting Citrix NetScaler ADC and NetScaler Gateway products', NCSC_NS, { cves: C88, advs: ['CTX697096'], keys: NS, type: 'alert', cvss: 9.5, affected: AFF_SEP, fix: 'Upgrade per CTX697096' }),
  ], { noise: N(40, 2, 8, 5, 0, 1, 0, 1, 0) }),
  run('2026-10-01T07:30', 'Schedule', [
    it(116, 'sbnz', '2026-10-01T06:00', 'Arctic Wolf details post-exploit NetScaler attacks', 'https://securitybrief.co.nz/story/arctic-wolf-details-post-exploit-netscaler-attacks', { type: 'news' }),
  ]),
  run('2026-10-02T07:30', 'Schedule', [
    it(117, 'ncsc', '2026-10-01T11:00', 'CVE-2026-76504 affecting Cisco Catalyst SD-WAN Manager', 'https://www.ncsc.govt.nz/alerts/cve-2026-76504-affecting-cisco-catalyst-sd-wan-manager/', { type: 'alert' }),
    it(118, 'ncsc', '2026-10-01T15:00', "Cyber risks of Democratic People's Republic of Korea IT workers to New Zealand organisations", 'https://www.ncsc.govt.nz/alerts/cyber-risks-of-democratic-peoples-republic-of-korea-it-workers-to-new-zealand-organisations/', { type: 'alert' }),
    it(124, 'circl', '2026-10-01T20:00', 'CVE-2026-89310 · FortiOS: heap overflow in SSL-VPN web portal', cU('CVE-2026-89310'), { cves: ['CVE-2026-89310'], keys: ['fortinet:fortios'], type: 'vuln', cvss: 9.0, sample: S, affected: [{ lt: '7.4.10' }], fix: '7.4.10' }),
  ], { epss: { 'CVE-2026-89310': 0.04 } }),
  run('2026-10-04T07:30', 'Schedule', [
    it(119, 'circl', '2026-10-03T10:00', 'CVE-2026-88779 · NetScaler ADC and Gateway: memory overflow, denial of service (SAML)', cU('CVE-2026-88779'), { cves: ['CVE-2026-88779'], advs: ['CTX697174'], keys: NS, type: 'vuln', cvss: 8.7, affected: [{ keys: NS, lt: '14.1-73.41', cond: 'SAML SP/IdP' }], fix: 'See CTX697174' }),
  ]),
  run('2026-10-05T07:30', 'Schedule', [
    it(120, 'kev', '2026-10-04T09:00', 'Citrix NetScaler ADC and NetScaler Gateway Memory Overflow Vulnerability', kU('CVE-2026-88779'), { cves: ['CVE-2026-88779'], advs: ['CTX697174'], keys: NS, type: 'exploit', kev: { added: '2026-10-04', due: '2026-10-07' } }),
    it(121, 'bsky', '2026-10-04T19:00', 'CVE-2026-88779 is a DoS that crashes SAML-enabled NetScalers. Patch again.', 'https://bsky.app/profile/analyst.example/post/3m4k', { sample: S }),
  ]),
  run('2026-10-09T07:30', 'Schedule', [
    it(122, 'circl', '2026-10-08T11:00', 'CVE-2026-107406 · NetScaler ADC and Gateway: memory overflow, RCE or DoS', cU('CVE-2026-107406'), { cves: ['CVE-2026-107406'], advs: ['CTX697191'], keys: NS, type: 'vuln', cvss: 9.5, affected: AFF_OCT, fix: 'See CTX697191' }),
  ], { epss: { 'CVE-2026-107406': 0.02 } }),
  run('2026-10-10T07:30', 'Schedule', [
    it(123, 'ncsc', '2026-10-09T14:00', 'Chinese Government-linked cyber threat actors combine automated and hands-on hacking tools to steal sensitive data', 'https://www.ncsc.govt.nz/alerts/chinese-government-linked-cyber-threat-actors-combine-automated-and-hands-on-hacking-tools-to-steal-sensitive-data/', { type: 'alert' }),
  ]),
  run('2026-10-12T07:30', 'Schedule', [
    it(125, 'rwl', '2026-10-11T09:00', 'Claim · Harbourside Freight NZ', 'https://www.ransomware.live/sample/harbourside-freight', { type: 'breach', peer: true }),
    it(126, 'graph', '2026-10-11T16:00', 'MC1187650 · Microsoft Entra: legacy MFA policy settings retire', 'https://admin.microsoft.com/#/MessageCenter/:/messages/MC1187650', { keys: ['microsoft:entra_id'], type: 'service', actBy: '2026-11-30T09:00', sample: S }),
  ]),
  run('2026-10-13T07:30', 'Schedule', []),
  // ── replay runs ──
  run('2026-10-14T07:30', 'Schedule', [
    it(130, 'circl', '2026-10-13T18:00', 'CVE-2026-91204 · Veeam Backup & Replication: deserialization to RCE', cU('CVE-2026-91204'), { cves: ['CVE-2026-91204'], keys: ['veeam:veeam_backup_&_replication'], type: 'vuln', cvss: 8.8, sample: S, affected: [{ lt: '12.3.2' }], fix: '12.3.2' }),
    it(131, 'graph', '2026-10-13T20:00', 'MC1190331 · Exchange Online: legacy PowerShell auth retires', 'https://admin.microsoft.com/#/MessageCenter/:/messages/MC1190331', { keys: ['microsoft:365'], type: 'service', actBy: '2026-11-09T09:00', sample: S }),
    it(132, 'aws', '2026-10-14T03:10', 'Increased error rates · Amazon S3 · ap-southeast-2', 'https://health.aws.amazon.com/health/status#s3-ap-southeast-2', { keys: ['amazon:s3'], type: 'service' }),
    it(133, 'circl', '2026-10-13T22:00', 'CVE-2026-90877 · PaperCut MF: stored XSS in print release', cU('CVE-2026-90877'), { cves: ['CVE-2026-90877'], keys: ['papercut:papercut_mf'], type: 'vuln', cvss: 5.4, sample: S, affected: [{ lt: '24.1.4' }], fix: '24.1.4' }),
    it(134, 'rwl', '2026-10-13T23:30', 'Claim · Kererū District Council', 'https://www.ransomware.live/sample/kereru-dc', { type: 'breach', peer: true }),
    it(135, 'bsky', '2026-10-14T06:20', 'Big spike in FortiGate SSL-VPN brute force from a new botnet this morning', 'https://bsky.app/profile/nzsec.example/post/3m6p', { sample: S }),
  ], { epss: { 'CVE-2026-91204': 0.23, 'CVE-2026-88771': 0.94, 'CVE-2026-88772': 0.92, 'CVE-2026-107406': 0.08, 'CVE-2026-90877': 0.01, 'CVE-2026-89310': 0.05 } }),
  run('2026-10-14T12:15', 'Run now', [
    it(136, 'ncsc_mail', '2026-10-14T12:04', 'UPDATED: Multiple vulnerabilities affecting Citrix NetScaler ADC and NetScaler Gateway products', NCSC_NS + '?utm_source=ncsc&utm_medium=email', { cves: [...C88, 'CVE-2026-107406'], advs: ['CTX697096', 'CTX697191'], keys: NS, type: 'alert', cvss: 9.5, affected: AFF_OCT, fix: 'Upgrade per CTX697191' }),
  ], { noise: N(21, 2, 6, 3, 0, 0, 0, 0, 0), status: { ncsc: 503 } }),
  run('2026-10-15T07:30', 'Schedule', [
    it(137, 'ncsc', '2026-10-14T12:00', 'UPDATED: Multiple vulnerabilities affecting Citrix NetScaler ADC and NetScaler Gateway products', NCSC_NS, { cves: [...C88, 'CVE-2026-107406'], advs: ['CTX697096', 'CTX697191'], keys: NS, type: 'alert', cvss: 9.5, affected: AFF_OCT, fix: 'Upgrade per CTX697191' }),
    it(138, 'bsky', '2026-10-14T14:10', 'NCSC NZ updated its NetScaler alert: CVE-2026-107406 hits builds patched last week', 'https://bsky.app/profile/nzsec.example/post/3m6t', { sample: S }),
    it(139, 'bsky', '2026-10-14T16:40', "If your NetScaler is a SAML IdP, last week's patch is not enough. Upgrade again.", 'https://bsky.app/profile/analyst.example/post/3m6x', { sample: S }),
    it(140, 'masto', '2026-10-14T16:45', "If your NetScaler is a SAML IdP, last week's patch is not enough. Upgrade again! #NetScaler", 'https://infosec.exchange/@analyst/1162', { sample: S }),
    it(141, 'kev', '2026-10-14T08:00', 'VMware ESXi Out-of-Bounds Write Vulnerability', kU('CVE-2026-90561'), { cves: ['CVE-2026-90561'], keys: ['vmware:esxi'], type: 'exploit', kev: { added: '2026-10-14', due: '2026-11-04' }, sample: S }),
    it(142, 'circl', '2026-10-14T09:00', 'CVE-2026-90561 · VMware ESXi: out-of-bounds write in VMX', cU('CVE-2026-90561'), { cves: ['CVE-2026-90561'], keys: ['vmware:esxi'], type: 'vuln', cvss: 9.3, sample: S, affected: [{ lt: '8.0.3.0.60' }], fix: 'ESXi 8.0 U3g' }),
    it(143, 'circl', '2026-10-14T10:30', 'CVE-2026-91877 · Exchange Server: elevation of privilege via EWS', cU('CVE-2026-91877'), { cves: ['CVE-2026-91877'], keys: ['microsoft:exchange_server'], type: 'vuln', cvss: 9.1, sample: S, fix: 'Oct 2026 SU' }),
    it(144, 'circl', '2026-10-14T12:30', 'CVE-2026-90110 · Apache Tomcat: request smuggling via chunked trailers', cU('CVE-2026-90110'), { cves: ['CVE-2026-90110'], keys: ['apache:tomcat'], type: 'vuln', cvss: 7.5, sample: S, affected: [{ lt: '10.1.47' }], fix: '10.1.47' }),
  ], { epss: { 'CVE-2026-107406': 0.41, 'CVE-2026-90561': 0.36, 'CVE-2026-91877': 0.05, 'CVE-2026-90110': 0.03 } }),
  run('2026-10-16T07:30', 'Schedule', [
    it(145, 'sbnz', '2026-10-15T15:00', 'NCSC updates NetScaler alert as new flaw hits patched appliances', 'https://securitybrief.co.nz/story/sample-ncsc-updates-netscaler-alert', { type: 'news', sample: S }),
    it(146, 'circl', '2026-10-15T09:00', 'CVE-2026-92410 · Zoom Workplace: improper access control in meeting SDK', cU('CVE-2026-92410'), { cves: ['CVE-2026-92410'], keys: ['zoom:workplace'], type: 'vuln', cvss: 8.1, sample: S }),
    it(147, 'graph', '2026-10-15T18:30', 'EX1188420 · Exchange Online: delayed message delivery', 'https://admin.microsoft.com/#/servicehealth/:/alerts/EX1188420', { keys: ['microsoft:365'], type: 'service', sample: S }),
    it(148, 'bsky', '2026-10-15T20:00', 'PoC for a WordPress plugin RCE (CVE-2026-90777) is circulating', 'https://bsky.app/profile/analyst.example/post/3m7c', { sample: S }),
    it(149, 'masto', '2026-10-15T21:10', 'Patched last week? SAML IdP builds up to 73.41 are still exposed. Check the new advisory.', 'https://infosec.exchange/@nzsec/1170', { sample: S, aiKeys: NS }),
  ], { epss: { 'CVE-2026-90777': 0.12 }, cvss: { 'CVE-2026-90777': 9.8 } }),
];
const D = (id, sig, at, act, refs = [], reason) => ({ id, sig, at: T(at), by: ME, act, refs, ...(reason ? { reason } : {}), fixture: true });
const NETSCALER_DECISIONS = [
  D('D-0101', 'SW-1100', '2026-07-02T08:20+12:00', 'ticket', [{ pid: 'p01', ref: 'INC0011820' }, { pid: 'p02', ref: 'INC0011821' }]),
  D('D-0102', 'SW-1101', '2026-09-25T08:05', 'ticket', [{ pid: 'p11', ref: 'INC0012190' }]),
  D('D-0103', 'SW-1103', '2026-09-28T08:12', 'ticket', [{ pid: 'p01', ref: 'INC0012231' }, { pid: 'p02', ref: 'INC0012232' }]),
  D('D-0104', 'SW-1103', '2026-09-29T13:20', 'ack'),
  D('D-0105', 'SW-1103', '2026-10-01T08:40', 'ack'),
  D('D-0106', 'SW-1119', '2026-10-05T08:25', 'ticket', [{ pid: 'p01', ref: 'INC0012310' }, { pid: 'p02', ref: 'INC0012311' }]),
  D('D-0107', 'SW-1122', '2026-10-09T08:05', 'ack'),
];

const MMH_RUNS = [
  run('2025-12-29T07:30', 'Schedule', []),
  run('2025-12-30T07:30', 'Schedule', [
    it(206, 'graph', '2025-12-29T15:00', 'MC1180002 · Microsoft 365 Apps: holiday change freeze', 'https://admin.microsoft.com/#/MessageCenter/:/messages/MC1180002', { keys: ['microsoft:365'], type: 'service', sample: S }),
  ]),
  run('2026-01-01T07:30', 'Schedule', [
    it(202, 'sbnz', '2025-12-31T16:00', 'Manage My Health investigating cyber security incident', 'https://securitybrief.co.nz/story/sample-manage-my-health-incident', { type: 'breach', peer: true, sample: S }),
    it(201, 'bsky', '2025-12-31T19:40', "Hearing NZ patient portal Manage My Health has had a breach. Patients' documents involved.", 'https://bsky.app/profile/nzsec.example/post/3lzz', { type: 'breach', peer: true, sample: S }),
    it(207, 'aws', '2025-12-31T22:00', 'Increased latency · Amazon S3 · ap-southeast-2', 'https://health.aws.amazon.com/health/status#s3-ap-southeast-2-1231', { keys: ['amazon:s3'], type: 'service' }),
  ], { noise: N(96, 4, 22, 14, 0, 1, 1, 3, 0) }),
  run('2026-01-02T07:30', 'Schedule', [
    it(203, 'opc', '2026-01-01T15:00', 'Statement on Manage My Health cyber incident', 'https://www.privacy.org.nz/tuhono-connect/statements-media-releases/statement-on-manage-my-health-cyber-incident/', { type: 'breach', peer: true }),
  ], { noise: N(88, 3, 18, 11, 0, 1, 0, 2, 1) }),
  run('2026-01-06T07:30', 'Schedule', [
    it(204, 'ncsc_mail', '2026-01-05T16:30', 'ManageMyHealth (MMH) cyber security breach involving patient information', 'https://www.ncsc.govt.nz/news/managemyhealth-mmh-cyber-security-breach-involving-patient-information/?utm_source=ncsc&utm_medium=email', { type: 'breach', peer: true }),
  ]),
  run('2026-01-22T07:30', 'Schedule', [
    it(205, 'opc', '2026-01-21T11:00', 'Privacy Commissioner announces inquiry into Manage My Health breach', 'https://www.privacy.org.nz/tuhono-connect/statements-media-releases/sample-inquiry-manage-my-health/', { type: 'breach', peer: true }),
  ]),
];

export const REPLAYS = {
  netscaler: { id: 'netscaler', name: 'Citrix NetScaler', short: 'NetScaler', when: '14 Oct 2026', base: 13, def: 2, runs: NETSCALER_RUNS, decisions: NETSCALER_DECISIONS, incident0: 1038, ticket0: 12400 },
  mmh: { id: 'mmh', name: 'Manage My Health', short: 'MMH', when: 'Jan 2026', base: 2, def: 2, runs: MMH_RUNS, decisions: [], incident0: 980, ticket0: 11200 },
};
export function freshStore(replay = 'netscaler') {
  const R = REPLAYS[replay];
  return { v: 1, replay, runIdx: R.def, settings: {}, inventory: SEED_INVENTORY.map(p => ({ ...p })), sources: {}, extraSources: [], decisions: R.decisions.map(d => ({ ...d })), seq: { ticket: R.ticket0, decision: 1 } };
}

// ───────── pipeline ─────────
function ingest(raw, runAt, S) {
  const s = SRC[raw.src];
  const cves = uniq([...(raw.cves || []), ...(raw.title.match(CVE_RE) || [])].map(x => x.toUpperCase()));
  const advs = uniq([...(raw.advs || []), ...(raw.title.match(ADV_RE) || [])].map(x => x.toUpperCase()));
  let keys = raw.keys ? raw.keys.slice() : extractKeys(raw.title), keysBy = raw.keys ? 'feed' : 'rules';
  if (!keys.length && S.ai && S.aiExtract && raw.aiKeys) { keys = raw.aiKeys.slice(); keysBy = 'ai'; }
  return {
    id: 'i' + raw.n, n: raw.n, src: raw.src, fam: s.fam, tier: s.tier, social: !!s.social, sample: !!(raw.sample ?? s.sample),
    at: T(raw.at), seen: runAt, title: raw.title, url: raw.url, curl: canonUrl(raw.url), cves, advs, keys, keysBy,
    type: raw.type || 'news', cvss: raw.cvss ?? null, kev: raw.kev || null,
    actBy: raw.kev ? T(raw.kev.due + 'T23:59') : raw.actBy ? T(raw.actBy) : null,
    fix: raw.fix || '', fixSrc: raw.fix ? s.name : '', affected: raw.affected || null, peer: !!raw.peer,
  };
}
const idsOf = i => [...i.cves.map(c => 'cve:' + c), ...i.advs.map(a => 'adv:' + a), ...(i.curl ? ['url:' + i.curl] : [])];
function conflict(item, s) {
  if (item.cves.length && s.cves.size && !item.cves.some(c => s.cves.has(c))) return true;
  if (item.advs.length && s.advs.size && !item.advs.some(a => s.advs.has(a))) return true;
  return false;
}
function absorb(s, item) {
  s.items.push(item);
  for (const x of idsOf(item)) s.ids.add(x);
  item.cves.forEach(c => s.cves.add(c)); item.advs.forEach(a => s.advs.add(a));
  s.keys = uniq([...s.keys, ...item.keys]);
  s.firstAt = Math.min(s.firstAt, item.at); s.lastAt = Math.max(s.lastAt, item.at);
}
function create(st, item) {
  const s = { id: 'SW-' + (1000 + item.n), n: item.n, items: [], ids: new Set(), cves: new Set(), advs: new Set(), keys: [], createdAt: item.seen, firstAt: item.at, lastAt: item.at, changedAt: null, changes: [], merged: [], levels: [] };
  item.join = { step: 0 };
  absorb(s, item);
  st.signals.push(s); st.byId[s.id] = s;
  return s;
}
function join(s, item, how) {
  const newFam = !s.items.some(i => i.fam === item.fam);
  const newIds = item.cves.filter(c => !s.cves.has(c));
  item.join = how;
  absorb(s, item);
  if (newFam || newIds.length) { s.changedAt = item.seen; s.changes.push({ at: item.seen, kind: newFam ? 'source' : 'ids', item: item.id }); }
  return s;
}
function mergeInto(st, target, other, at) {
  for (const i of other.items) { i.mergedFrom = other.id; absorb(target, i); }
  target.merged.push(other.id, ...other.merged);
  other.dead = true; other.into = target.id;
  target.changedAt = at; target.changes.push({ at, kind: 'merge', from: other.id });
}
function attach(st, item, S) {
  const live = st.signals.filter(s => !s.dead);
  const ids = idsOf(item);
  const hits = live.filter(s => ids.some(x => s.ids.has(x)));
  if (hits.length) {
    hits.sort((a, b) => a.firstAt - b.firstAt || a.n - b.n);
    const t = hits[0];
    for (const o of hits.slice(1)) mergeInto(st, t, o, item.seen);
    const k = ids.find(x => t.ids.has(x));
    return join(t, item, { step: 1, key: k.slice(k.indexOf(':') + 1), merged: hits.length > 1 ? hits.slice(1).map(h => h.id) : null });
  }
  const elig = live.filter(s => !conflict(item, s) && Math.abs(item.at - s.lastAt) <= S.lookbackDays * DAY);
  const m = mh(item, S.perms);
  let best = null, bj = 0;
  for (const s of elig) for (const i of s.items) { const j = jaccardEst(m, mh(i, S.perms)); if (j > bj) { bj = j; best = s; } }
  if (best && bj > S.jaccard) return join(best, item, { step: 2, score: +bj.toFixed(2) });
  if (item.keys.length) {
    const c = elig.filter(s => s.keys.some(k => item.keys.includes(k)) && Math.abs(item.at - s.lastAt) <= S.windowDays * DAY).sort((a, b) => b.lastAt - a.lastAt)[0];
    if (c) return join(c, item, { step: 3, key: c.keys.find(k => item.keys.includes(k)) });
  }
  if (S.ai && S.aiGroup && elig.length) {
    const v = item._emb || (item._emb = embed(item));
    let bs = null, bc = -1;
    for (const s of elig) { const c = cosine(v, centroid(s)); if (c > bc) { bc = c; bs = s; } }
    if (bs && bc >= S.embedMin) return join(bs, item, { step: 4, score: +bc.toFixed(2) });
    if (bs && bc >= S.greyMin) {
      const r = greyModel(item, bs);
      st.modelCalls.push(r.input);
      if (r.same) return join(bs, item, { step: 5, score: +bc.toFixed(2), conf: r.conf, flagged: true });
    }
  }
  return create(st, item);
}

export function evaluate(sig, ctx) {
  const { S, now } = ctx;
  const items = sig.items;
  const m = (sig.matches || []).filter(x => x.inScope);
  const matched = m.length > 0;
  const srcs = items.map(i => SRC[i.src] || { tier: i.tier, social: i.social, fam: i.fam });
  const socialOnly = srcs.every(s => s.social);
  const tier3Only = srcs.every(s => s.tier === 3);
  const ncscAlert = items.some(i => (SRC[i.src]?.fam || i.fam) === 'ncsc' && i.type === 'alert');
  const kev = items.some(i => i.src === 'kev');
  const self = m.some(x => x.model === 'self'), vendor = m.some(x => x.model === 'vendor');
  const breach = items.some(i => i.type === 'breach');
  const cves = sig.cves ? [...sig.cves] : uniq(items.flatMap(i => i.cves || []));
  const ep = cves.map(c => ctx.epss?.[c]).filter(x => x != null);
  const epss = ep.length ? Math.max(...ep) : null;
  const cv = [...items.map(i => i.cvss), ...cves.map(c => ctx.cvss?.[c])].filter(x => x != null);
  const cvss = cv.length ? Math.max(...cv) : null;
  const ab = items.map(i => i.actBy).filter(Boolean);
  const actBy = ab.length ? Math.min(...ab) : null;
  const days = actBy != null ? Math.ceil((actBy - now) / DAY) : null;
  const peer = !matched && items.some(i => i.peer);
  const checks = [
    { id: 'A1', label: 'NCSC alert', ok: ncscAlert && matched, level: 'act' },
    { id: 'A2', label: 'KEV self-managed', ok: kev && self, level: 'act' },
    { id: 'P1', label: 'EPSS ≥ ' + S.epss, ok: matched && epss != null && epss >= S.epss, level: 'plan', val: epss != null ? epss.toFixed(2) : '—' },
    { id: 'P2', label: 'CVSS ≥ ' + S.cvss, ok: matched && cvss != null && cvss >= S.cvss, level: 'plan', val: cvss != null ? cvss.toFixed(1) : '—' },
    { id: 'P3', label: 'Vendor breach', ok: breach && vendor, level: 'plan' },
    { id: 'P4', label: 'Act-by ≤ ' + S.actByDays + ' d', ok: matched && days != null && days <= S.actByDays, level: 'plan', val: days != null ? days + ' d' : '—' },
    { id: 'W1', label: 'Tier-3 only', ok: matched && tier3Only, level: 'watch' },
    { id: 'W2', label: 'NZ peer', ok: peer, level: 'watch' },
    { id: 'I1', label: 'Other match', ok: matched, level: 'info' },
  ];
  let level = 'hidden', rule = 'H1';
  for (const c of checks) if (c.ok && RANK[c.level] > RANK[level]) { level = c.level; rule = c.id; }
  const raw = level;
  const caps = [];
  if (socialOnly && RANK[level] > RANK.watch) { level = 'watch'; caps.push({ id: 'C1', label: 'Social cap' }); }
  if (tier3Only && RANK[level] > RANK.watch) { level = 'watch'; caps.push({ id: 'C2', label: 'Tier-3 cap' }); }
  const archived = level === 'info' && (now - sig.lastAt) / DAY > S.archiveDays;
  return { level, raw, rule, checks, caps, archived, epss, cvss, actBy, days, socialOnly, tier3Only, matched, peer };
}

function matchesFor(sig, inv, scope) {
  const out = new Map();
  for (const i of sig.items) for (const p of inv) if (i.keys.includes(p.key)) {
    const inScope = !!scope[p.model]?.[i.type];
    const prev = out.get(p.id);
    out.set(p.id, { pid: p.id, model: p.model, inScope: inScope || !!prev?.inScope });
  }
  return [...out.values()];
}
const routeHash = (s, lvl) => [lvl, [...s.cves].sort().join(','), [...s.advs].sort().join(','), uniq(s.items.map(i => i.fam)).sort().join(',')].join('|');

export function buildState(store) {
  const R = REPLAYS[store.replay] || REPLAYS.netscaler;
  const S = { ...DEFAULT_SETTINGS, ...(store.settings || {}) };
  S.scope = store.settings?.scope || DEFAULT_SCOPE;
  const inv = (store.inventory || SEED_INVENTORY).map(p => ({ ...p, key: productKey(p) }));
  const invById = Object.fromEntries(inv.map(p => [p.id, p]));
  const enabled = id => store.sources?.[id]?.enabled ?? true;
  const st = { signals: [], byId: {}, epss: {}, cvss: {}, routes: [], sent: {}, runs: [], modelCalls: [], noise: 0, incident: R.incident0 };
  const runIdx = Math.max(0, Math.min(store.runIdx ?? R.def, R.runs.length - R.base));
  const runs = R.runs.slice(0, R.base + runIdx);
  for (const [ri, rn] of runs.entries()) {
    const before = new Set(st.signals.filter(s => !s.dead).map(s => s.id));
    const srcStat = {};
    let fetched = 0, noise = 0;
    for (const s of SOURCES) {
      if (!enabled(s.id)) { srcStat[s.id] = { status: 'off', items: 0, noise: 0 }; continue; }
      if (rn.status[s.id]) { srcStat[s.id] = { status: 'error', code: rn.status[s.id], items: 0, noise: 0 }; continue; }
      const its = rn.items.filter(i => i.src === s.id).length, nz = rn.noise[s.id] || 0;
      srcStat[s.id] = { status: 'ok', code: 200, items: its, noise: nz };
      fetched += its + nz; noise += nz;
    }
    Object.assign(st.epss, rn.epss); Object.assign(st.cvss, rn.cvss);
    const batch = rn.items.filter(i => srcStat[i.src]?.status === 'ok').map(r => ingest(r, rn.at, S)).sort((a, b) => a.at - b.at || a.n - b.n);
    for (const item of batch) attach(st, item, S);
    st.noise += noise;
    const ctx = { S, now: rn.at, epss: st.epss, cvss: st.cvss };
    let routed = 0;
    for (const s of st.signals) {
      if (s.dead) continue;
      s.matches = matchesFor(s, inv, S.scope);
      const ev = evaluate(s, ctx);
      const prev = s.levels.length ? s.levels[s.levels.length - 1].level : null;
      if (prev !== ev.level) {
        s.levels.push({ at: rn.at, level: ev.level });
        if (prev && RANK[ev.level] > RANK[prev] && s.changedAt !== rn.at) { s.changedAt = rn.at; s.changes.push({ at: rn.at, kind: 'level', from: prev, to: ev.level }); }
      }
      s.ev = ev;
      if (ev.level === 'act') {
        const h = routeHash(s, ev.level), was = st.sent[s.id];
        if (!was || was.hash !== h) {
          const rev = (was?.rev || 0) + 1, incident = was?.incident || ++st.incident;
          st.sent[s.id] = { hash: h, rev, incident, at: rn.at };
          st.routes.push({ sig: s.id, rev, incident, at: rn.at, to: S.actRoute });
          routed++;
        }
      }
    }
    const live = st.signals.filter(s => !s.dead);
    st.runs.push({
      i: ri, at: rn.at, mode: rn.mode, replay: ri >= R.base, fetched, items: batch.length, noise, src: srcStat, routed,
      created: live.filter(s => !before.has(s.id) && s.ev.level !== 'hidden').length,
      updated: live.filter(s => before.has(s.id) && s.changedAt === rn.at && s.ev.level !== 'hidden').length,
      hidden: live.filter(s => !before.has(s.id) && s.ev.level === 'hidden').length + noise,
      warn: Object.values(srcStat).filter(x => x.status === 'error').length,
      ms: 2100 + ((rn.at / 6e4) % 900) | 0,
    });
  }
  const now = runs.length ? runs[runs.length - 1].at : Date.now();
  const nextRun = R.runs[R.base + runIdx] || null;
  const decisions = (store.decisions || []).slice().sort((a, b) => a.at - b.at);
  const live = st.signals.filter(s => !s.dead);
  for (const s of live) {
    const famIds = new Set([s.id, ...s.merged]);
    const ds = decisions.filter(d => famIds.has(d.sig));
    const human = ds.filter(d => d.act !== 'auto');
    const last = human[human.length - 1] || null;
    const ev = s.ev;
    const sent = st.sent[s.id] || null;
    s.level = ev.level; s.rule = ev.rule;
    s.decisions = ds;
    s.lastDecision = last;
    s.updated = !!s.changedAt && s.changes.length > 0 && (!last || s.changedAt > last.at) && (s.createdAt < s.changedAt);
    s.status = last && !(s.changedAt && s.changedAt > last.at) ? last.act : 'open';
    s.isNew = s.createdAt === now && !last;
    s.tickets = ds.flatMap(d => d.refs || []);
    s.route = sent;
    const rep = s.items.slice().sort((a, b) => (TYPE_RANK[b.type] - TYPE_RANK[a.type]) || (a.tier - b.tier) || (b.at - a.at))[0];
    s.title = rep.title; s.link = rep.url; s.type = rep.type; s.repSrc = rep.src;
    s.families = uniq(s.items.map(i => i.fam));
    s.srcIds = uniq(s.items.map(i => i.src));
    const ranges = s.items.filter(i => i.affected).map(i => i.affected);
    s.products = s.matches.filter(x => x.inScope).map(x => {
      const p = invById[x.pid]; let hit = null, cond = '';
      for (const a of ranges) { const r = versionHit(p.version, a, p.key); if (r.hit) { hit = true; cond = r.cond; break; } if (r.hit === false) hit = false; }
      return { ...p, hit, cond };
    });
    s.outOfScope = s.matches.filter(x => !x.inScope).map(x => invById[x.pid]);
    s.fixes = uniq(s.items.filter(i => i.fix).sort((a, b) => a.tier - b.tier || b.at - a.at).map(i => i.fix + '|' + i.fixSrc)).map(x => ({ text: x.split('|')[0], src: x.split('|')[1] }));
    s.sample = s.items.every(i => i.sample);
    s.ai = s.items.some(i => (i.join?.step || 0) >= 4 || i.keysBy === 'ai');
    s.flagged = s.items.some(i => i.join?.flagged);
    s.items.sort((a, b) => b.at - a.at || b.n - a.n);
  }
  const visible = live.filter(s => s.level !== 'hidden');
  const hiddenCount = live.filter(s => s.level === 'hidden').length + st.noise;
  const dayKey = ms => fmtFull(ms);
  const hiddenToday = st.runs.filter(r => dayKey(r.at) === dayKey(now)).reduce((a, r) => a + r.hidden, 0);
  const counts = { act: 0, plan: 0, watch: 0, info: 0 }, open = { act: 0, plan: 0, watch: 0, info: 0 };
  for (const s of visible) { if (s.ev.archived) continue; counts[s.level]++; if (s.status === 'open') open[s.level]++; }
  return { S, R, inv, invById, now, runIdx, maxRun: R.runs.length - R.base, nextRun, signals: visible, all: live, byId: st.byId, hiddenCount, hiddenToday, counts, open, routes: st.routes, sent: st.sent, runs: st.runs, modelCalls: st.modelCalls, decisions, epss: st.epss, cvss: st.cvss, sigOf: n => { let s = live.find(x => x.items.some(i => i.n === n)); return s || null; } };
}
export function sortSignals(list) {
  return list.slice().sort((a, b) => (RANK[b.level] - RANK[a.level]) || ((b.updated ? 1 : 0) - (a.updated ? 1 : 0)) || ((a.ev.actBy ?? 9e15) - (b.ev.actBy ?? 9e15)) || (b.lastAt - a.lastAt));
}

// ───────── routes & payloads (internal systems only) ─────────
export function sentinelRecord(s, now) {
  return { TimeGenerated: iso(now), SignalId: s.id, Revision: s.route?.rev || 1, Level: LV[s.level].label, Rule: s.rule, Title: s.title, Cves: [...s.cves].sort(), Products: s.products.map(p => p.name), Sources: s.families, ActBy: s.ev.actBy ? iso(s.ev.actBy) : null, Link: s.link, Updated: s.updated };
}
export const DCR_COLUMNS = [['TimeGenerated', 'datetime'], ['SignalId', 'string'], ['Revision', 'int'], ['Level', 'string'], ['Rule', 'string'], ['Title', 'string'], ['Cves', 'dynamic'], ['Products', 'dynamic'], ['Sources', 'dynamic'], ['ActBy', 'datetime'], ['Link', 'string'], ['Updated', 'boolean']];
export const KQL = `SignalWatch_CL
| where TimeGenerated > ago(2d)
| summarize arg_max(Revision, *) by SignalId
| where Level == "Act"
| project TimeGenerated, SignalId, Revision, Title, Cves, Products, ActBy, Rule, Link
// Incident grouping: group by SignalId (custom details), reopen closed: on`;
export const TICKET_SYSTEMS = {
  servicenow: { label: 'ServiceNow', method: 'POST', path: '/api/now/table/incident', body: { short_description: '{{signal.title}}', correlation_id: '{{signal.id}}:{{product.id}}', cmdb_ci: '{{product.name}}', assigned_to: '{{product.owner}}', urgency: '{{level.urgency}}', u_cves: '{{signal.cves}}', u_act_by: '{{signal.actBy}}', u_link: '{{signal.link}}' } },
  jira: { label: 'Jira SM', method: 'POST', path: '/rest/servicedeskapi/request', body: { serviceDeskId: '4', requestTypeId: '17', requestFieldValues: { summary: '{{signal.title}}', labels: ['signalwatch', '{{signal.id}}'], customfield_10050: '{{signal.id}}:{{product.id}}', customfield_10051: '{{signal.cves}}' } } },
  freshservice: { label: 'Freshservice', method: 'POST', path: '/api/v2/tickets', body: { subject: '{{signal.title}}', priority: '{{level.priority}}', tags: ['signalwatch', '{{signal.id}}'], custom_fields: { sw_key: '{{signal.id}}:{{product.id}}', sw_product: '{{product.name}}', sw_cves: '{{signal.cves}}' } } },
  topdesk: { label: 'TOPdesk', method: 'POST', path: '/tas/api/incidents', body: { briefDescription: '{{signal.title}}', externalNumber: '{{signal.id}}:{{product.id}}', object: { name: '{{product.name}}' }, priority: { name: '{{level.priority}}' }, optionalFields1: { text1: '{{signal.cves}}' } } },
};
export function ticketPayload(sys, s, p) {
  const t = TICKET_SYSTEMS[sys] || TICKET_SYSTEMS.servicenow;
  const vals = { 'signal.title': s.title.slice(0, 160), 'signal.id': s.id, 'product.id': p.id, 'product.name': p.name, 'product.owner': p.owner, 'level.urgency': s.level === 'act' ? '1' : '2', 'level.priority': s.level === 'act' ? 'P1' : 'P2', 'signal.cves': [...s.cves].join(' '), 'signal.actBy': s.ev.actBy ? iso(s.ev.actBy).slice(0, 10) : '', 'signal.link': s.link };
  const fill = v => (typeof v === 'string' ? v.replace(/\{\{([\w.]+)\}\}/g, (_, k) => vals[k] ?? '') : Array.isArray(v) ? v.map(fill) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x)])) : v);
  return { method: t.method, path: t.path, idempotencyKey: s.id + ':' + p.id, body: fill(t.body) };
}
export function planTickets(s, decisions) {
  const fam = new Set([s.id, ...s.merged]);
  const have = new Set(decisions.filter(d => fam.has(d.sig)).flatMap(d => (d.refs || []).map(r => r.pid)));
  return s.products.filter(p => !have.has(p.id));
}
// Enrichment never sends inventory-derived parameters: bulk files only.
export function enrichmentRequests() { return [{ src: 'epss', method: 'GET', url: SRC.epss.url }, { src: 'circl', method: 'GET', url: SRC.circl.url }]; }
export function digest(state) {
  const pick = l => sortSignals(state.signals.filter(s => s.level === l && s.status === 'open')).slice(0, 3).map(s => ({ id: s.id, title: s.title, link: s.link }));
  return { date: fmtDay(state.now), counts: { ...state.open }, act: pick('act'), plan: pick('plan'), watch: pick('watch'), hidden: state.hiddenCount };
}

// ───────── CSV ─────────
export const CSV_HEADERS = ['name', 'vendor', 'cpe', 'version', 'owner', 'model'];
export function parseCSV(text) {
  const rows = []; let row = [], f = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"' && text[i + 1] === '"') { f += '"'; i++; } else if (c === '"') q = false; else f += c; continue; }
    if (c === '"') q = true; else if (c === ',') { row.push(f); f = ''; } else if (c === '\n' || c === '\r') { if (c === '\r' && text[i + 1] === '\n') i++; row.push(f); rows.push(row); row = []; f = ''; } else f += c;
  }
  if (f || row.length) { row.push(f); rows.push(row); }
  return rows.filter(r => r.some(x => x.trim()));
}
export function normModel(v) {
  const t = String(v || '').toLowerCase().replace(/[^a-z]/g, '');
  if (/^(self|selfmanaged|onprem|onpremises)$/.test(t)) return 'self';
  if (/^(shared|comanaged|sharedresponsibility)$/.test(t)) return 'shared';
  if (/^(vendor|vendormanaged|saas)$/.test(t)) return 'vendor';
  if (/^(hyper|hyperscaler|cloud|iaas|paas)$/.test(t)) return 'hyper';
  return null;
}
export function csvImport(text, existing) {
  const rows = parseCSV(text);
  if (!rows.length) return { rows: [], map: {}, ok: 0, err: 0, dup: 0 };
  const head = rows[0].map(h => h.trim().toLowerCase());
  const syn = { name: ['name', 'product', 'product name'], vendor: ['vendor', 'publisher', 'manufacturer'], cpe: ['cpe', 'cpe23', 'cpe 2.3'], version: ['version', 'ver', 'build'], owner: ['owner', 'contact', 'responsible'], model: ['model', 'management', 'management model', 'managed by'] };
  const map = {};
  for (const [k, al] of Object.entries(syn)) { const i = head.findIndex(h => al.includes(h)); if (i >= 0) map[k] = i; }
  const seen = new Set(existing.map(p => normText(p.vendor + ' ' + p.name)));
  const out = rows.slice(1).map((r, n) => {
    const g = k => (map[k] != null ? (r[map[k]] || '').trim() : '');
    const d = { name: g('name'), vendor: g('vendor'), cpe: g('cpe'), version: g('version'), owner: g('owner'), model: normModel(g('model')) };
    const errors = [];
    if (!d.name) errors.push('Name');
    if (!d.model) errors.push('Model');
    if (d.cpe && !/^cpe:2\.3:[aho]:[^:]+:[^:]+/i.test(d.cpe)) errors.push('CPE');
    const key = normText(d.vendor + ' ' + d.name);
    const dup = !errors.length && seen.has(key);
    if (!errors.length) seen.add(key);
    return { line: n + 2, data: d, errors, status: errors.length ? 'error' : dup ? 'dup' : 'ok' };
  });
  return { rows: out, map, ok: out.filter(r => r.status === 'ok').length, err: out.filter(r => r.status === 'error').length, dup: out.filter(r => r.status === 'dup').length };
}
export const CSV_SAMPLE = `name,vendor,cpe,version,owner,model
Manage My Health,Manage My Health,,SaaS,Aroha T.,vendor-managed
FortiClient EMS,Fortinet,cpe:2.3:a:fortinet:forticlient_ems,7.2.4,Sam L.,self-managed
Confluence Data Center,Atlassian,cpe:2.3:a:atlassian:confluence_data_center,8.5.9,Ben K.,self-managed
Moodle,Moodle,cpe:2.3:a:moodle:moodle,4.4,Mere W.,shared
WordPress,WordPress,cpe:2.3:a:wordpress:wordpress,6.8.3,Mere W.,self-managed
Payroll kiosk,,,1.0,Aroha T.,managed?`;
export function toCSV(inv) {
  const esc = v => (/[",\n]/.test(v) ? '"' + String(v).replace(/"/g, '""') + '"' : v);
  return [CSV_HEADERS.join(','), ...inv.map(p => [p.name, p.vendor, p.cpe, p.version, p.owner, MODELS[p.model]?.label || p.model].map(x => esc(x || '')).join(','))].join('\n');
}
