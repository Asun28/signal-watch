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
