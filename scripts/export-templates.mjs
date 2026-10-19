// Regenerate integration templates and samples from the engine, so docs never drift from code:
//   node scripts/export-templates.mjs
import fs from 'node:fs';
import * as E from '../public/engine.js';
import { teamsCard, emailHtml } from '../src/routes/digest.js';
import { TICKET_SYNC } from '../src/routes/tickets.js';
import { INCIDENT_API } from '../src/routes/sentinel.js';

const out = (p, data) => { const u = new URL('../' + p, import.meta.url); fs.mkdirSync(new URL('.', u), { recursive: true }); fs.writeFileSync(u, typeof data === 'string' ? data : JSON.stringify(data, null, 2) + '\n'); };
const R = E.REPLAYS.netscaler, st = E.buildState({ ...E.freshStore('netscaler'), runIdx: R.runs.length - R.base });
const hero = E.sortSignals(st.signals.filter(s => s.level === 'act'))[0];

const AUTH = {
  servicenow: 'Bearer token, or Basic when Settings → Tickets → user is set (user + env:TICKET_TOKEN).',
  jira: 'Basic: Atlassian account email (ticketUser) + API token (env:TICKET_TOKEN). Set serviceDeskId / requestTypeId / custom field ids for your site.',
  freshservice: 'Basic: API key (env:TICKET_TOKEN) + "X". Create custom fields sw_key, sw_product, sw_cves.',
  topdesk: 'Basic: operator login (ticketUser) + application password (env:TICKET_TOKEN).',
};
// Two-way sync (src/sync.js): what the account behind env:TICKET_TOKEN must be allowed to do, and example requests.
const SYNC_NEEDS = {
  servicenow: 'Read incident (number, sys_id, state, sys_updated_on); write work_notes, state, close_code, close_notes (role itil). Close value: close code.',
  jira: 'Service desk agent: browse, internal comment, transition. Close value: workflow transition id (GET /rest/api/3/issue/{key}/transitions); without it only a comment is added.',
  freshservice: 'Agent: view and edit tickets, add private notes. Close value: status (4 Resolved, 5 Closed).',
  topdesk: 'Operator: read and edit incidents (actions, completed).',
};
const SAMPLE = { servicenow: { ref: 'INC0012231', ext_id: '9d385017c611228701d22104cc95c371' }, jira: { ref: 'SEC-142', ext_id: 'SEC-142' }, freshservice: { ref: '#4211', ext_id: '4211' }, topdesk: { ref: 'I 2610 042', ext_id: '1f4a6b5c-0d3e-4c2b-9a7f-6e5d4c3b2a10' } };
const CLOSE = { jira: '31' };
for (const [k, t] of Object.entries(E.TICKET_SYSTEMS)) {
  const y = TICKET_SYNC[k], tk = SAMPLE[k];
  const sync = { needs: SYNC_NEEDS[k], read: y.read([tk.ref]), note: y.note(tk, `Signal Watch · Updated · r2 · ${hero.id}`), close: y.close(tk, `Signal Watch · Not affected · Version · ${E.ME}`, { ticketClose: CLOSE[k] || '' }) };
  out(`integrations/tickets/${k}.json`, { system: t.label, method: t.method, path: t.path, auth: AUTH[k], idempotencyKey: '{{signal.id}}:{{product.id}}', body: t.body, example: E.ticketPayload(k, hero, hero.products[0]), sync });
}
out('integrations/sentinel/incident-sync.json', {
  needs: 'Microsoft Sentinel Responder on the workspace for the Entra app (same tenant, client id and secret as ingestion). Settings → Sentinel → Two-way → Workspace resource ID.',
  apiVersion: INCIDENT_API,
  read: `GET https://management.azure.com{workspace}/providers/Microsoft.SecurityInsights/incidents?$orderby=properties/lastModifiedTimeUtc desc&$top=50&api-version=${INCIDENT_API}`,
  link: 'Incident title "Signal Watch · SW-… · headline" (analytics rule alertDisplayNameFormat)',
  write: [`GET …/incidents/{name}`, `PUT …/incidents/{name} { etag, properties: { title, severity, owner, labels, status, classification, classificationReason, classificationComment } }`, `PUT …/incidents/{name}/comments/{guid} { properties: { message } }`],
  out: { 'Not affected': 'Closed · BenignPositive · SuspiciousButExpected', Acknowledged: 'Active', Ticketed: 'Active', 'All tickets resolved': 'Closed · TruePositive · SuspiciousActivity', 'Undo of a close': 'Active' },
  in: { Active: 'Acknowledged', 'Closed · TruePositive': 'Acknowledged', 'Closed · Undetermined': 'Acknowledged', 'Closed · BenignPositive': 'Not affected', 'Closed · FalsePositive': 'Not affected' },
  comment: `Signal Watch · Not affected · Version · ${E.ME}`,
});
out('integrations/sentinel/sample-record.json', [E.sentinelRecord(hero, st.now)]);
out('integrations/sentinel/columns.json', E.DCR_COLUMNS.map(([name, type]) => ({ name, type })));
const dg = E.digest(st);
out('integrations/teams/digest-card.sample.json', teamsCard(dg, 'https://signalwatch.example.govt.nz/'));
out('integrations/teams/digest-email.sample.html', emailHtml(dg, 'https://signalwatch.example.govt.nz/'));
out('config/inventory-sample.csv', E.toCSV(E.SEED_INVENTORY) + '\n');
console.log('templates written');
