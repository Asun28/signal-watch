// Microsoft Sentinel via the Azure Monitor Logs Ingestion API (DCR + Entra app) into SignalWatch_CL.
// Idempotency: a row is sent only when hash(level, CVEs, advisories, source families) changes; SignalId is
// stable and Revision increments, and the analytics rule takes arg_max(Revision) per SignalId.
import { http, secret } from '../util.js';
import { sentinelRecord } from '../../public/engine.js';

const tokens = new Map();
export async function entraToken(env, S, scope, fetchImpl, secretRef = S.secretRef) {
  const sec = secret(env, secretRef);
  if (!S.tenant || !S.clientId || !sec) return null;
  const k = S.tenant + '|' + S.clientId + '|' + scope, hit = tokens.get(k);
  if (hit && hit.exp > Date.now() + 60e3) return hit.token;
  const body = new URLSearchParams({ grant_type: 'client_credentials', client_id: S.clientId, client_secret: sec, scope });
  const { res } = await http(`https://login.microsoftonline.com/${encodeURIComponent(S.tenant)}/oauth2/v2.0/token`, { fetch: fetchImpl, method: 'POST', body, headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  if (!res.ok) throw new Error('Entra token ' + res.status);
  const j = await res.json();
  tokens.set(k, { token: j.access_token, exp: Date.now() + (j.expires_in || 3000) * 1000 });
  return j.access_token;
}

export const sentinelConfigured = (env, S) => !!(S.dce && S.dcr && S.stream && S.tenant && S.clientId && secret(env, S.secretRef));

// records: SignalWatch_CL rows. Returns { status } — '204' on success, 'dry-run' when not configured.
export async function sendSentinel(env, S, records, fetchImpl) {
  if (!records.length) return { status: 'skip' };
  if (!sentinelConfigured(env, S)) return { status: 'dry-run' };
  try {
    const tok = await entraToken(env, S, 'https://monitor.azure.com//.default', fetchImpl);
    const url = `${S.dce.replace(/\/+$/, '')}/dataCollectionRules/${encodeURIComponent(S.dcr)}/streams/${encodeURIComponent(S.stream)}?api-version=2023-01-01`;
    const { res } = await http(url, { fetch: fetchImpl, method: 'POST', body: JSON.stringify(records), headers: { authorization: 'Bearer ' + tok, 'content-type': 'application/json' } });
    return { status: String(res.status) };
  } catch (e) {
    return { status: 'error', error: String(e.message || e) };
  }
}

export function recordFor(s, now, rev) {
  return { ...sentinelRecord(s, now), Revision: rev };
}

// ───────── incidents (two-way sync, src/sync.js) ─────────
// The analytics rule names each incident "Signal Watch · SW-… · headline". Reading and updating incidents needs the
// Entra app to hold "Microsoft Sentinel Responder" on the workspace (Settings → Sentinel → workspace resource ID).
export const WS_RE = /^\/subscriptions\/[\w-]+\/resourceGroups\/[\w.()-]+\/providers\/Microsoft\.OperationalInsights\/workspaces\/[\w-]+$/i;
export const INCIDENT_API = '2024-09-01';
const ARM = 'https://management.azure.com';
const SIG_RE = /^Signal Watch · (SW-\d+)\b/;

async function arm(env, S, path, fetchImpl, opts = {}) {
  const tok = await entraToken(env, S, ARM + '/.default', fetchImpl);
  if (!tok) throw new Error('No token');
  const url = path.startsWith('https://') ? path : `${ARM}${S.wsResource}/providers/Microsoft.SecurityInsights/incidents${path}${path.includes('?') ? '&' : '?'}api-version=${INCIDENT_API}`;
  const { res } = await http(url, { fetch: fetchImpl, method: opts.method || 'GET', body: opts.body && JSON.stringify(opts.body), headers: { authorization: 'Bearer ' + tok, 'content-type': 'application/json', accept: 'application/json' } });
  if (!res.ok) throw new Error('Sentinel ' + res.status);
  return res.status === 204 ? null : res.json();
}

const asIncident = x => {
  const p = x.properties || {}, m = String(p.title || '').match(SIG_RE);
  return m && { sig: m[1], name: x.name, number: p.incidentNumber ?? null, status: p.status, cls: p.status === 'Closed' ? p.classification || null : null, owner: p.owner?.assignedTo || null, at: Date.parse(p.lastModifiedTimeUtc) || 0 };
};

// Signal Watch incidents changed since `since` (newest first, at most 3 pages of 50).
export async function incidentsChanged(env, S, since, fetchImpl) {
  const out = [];
  let next = '?$orderby=' + encodeURIComponent('properties/lastModifiedTimeUtc desc') + '&$top=50';
  for (let page = 0; next && page < 3; page++) {
    const j = await arm(env, S, next, fetchImpl);
    const list = j?.value || [];
    for (const x of list) { const i = asIncident(x); if (i) out.push(i); }
    const oldest = Date.parse(list[list.length - 1]?.properties?.lastModifiedTimeUtc) || 0;
    next = list.length && oldest >= since ? j.nextLink || null : null;
  }
  return out.filter(i => i.at >= since);
}

// Set status (and classification when closing), then add the comment. Returns the incident as it now stands.
export async function updateIncident(env, S, name, want, comment, fetchImpl) {
  const cur = await arm(env, S, '/' + encodeURIComponent(name), fetchImpl);
  const p = cur.properties || {};
  if (p.status !== want.status || (want.status === 'Closed' && p.classification !== want.cls)) {
    const props = { title: p.title, description: p.description, severity: p.severity, owner: p.owner, labels: p.labels, status: want.status };
    if (want.status === 'Closed') Object.assign(props, { classification: want.cls, classificationReason: CLS_REASON[want.cls], classificationComment: comment });
    Object.assign(cur, await arm(env, S, '/' + encodeURIComponent(name), fetchImpl, { method: 'PUT', body: { etag: cur.etag, properties: props } }));
  }
  await arm(env, S, `/${encodeURIComponent(name)}/comments/${crypto.randomUUID()}`, fetchImpl, { method: 'PUT', body: { properties: { message: comment } } });
  return asIncident(cur);
}
const CLS_REASON = { TruePositive: 'SuspiciousActivity', BenignPositive: 'SuspiciousButExpected', FalsePositive: 'InaccurateData', Undetermined: undefined };
