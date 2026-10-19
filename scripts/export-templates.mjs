// Regenerate integration templates and samples from the engine, so docs never drift from code:
//   node scripts/export-templates.mjs
import fs from 'node:fs';
import * as E from '../public/engine.js';
import { teamsCard, emailHtml } from '../src/routes/digest.js';

const out = (p, data) => { const u = new URL('../' + p, import.meta.url); fs.mkdirSync(new URL('.', u), { recursive: true }); fs.writeFileSync(u, typeof data === 'string' ? data : JSON.stringify(data, null, 2) + '\n'); };
const R = E.REPLAYS.netscaler, st = E.buildState({ ...E.freshStore('netscaler'), runIdx: R.runs.length - R.base });
const hero = E.sortSignals(st.signals.filter(s => s.level === 'act'))[0];

const AUTH = {
  servicenow: 'Bearer token, or Basic when Settings → Tickets → user is set (user + env:TICKET_TOKEN).',
  jira: 'Basic: Atlassian account email (ticketUser) + API token (env:TICKET_TOKEN). Set serviceDeskId / requestTypeId / custom field ids for your site.',
  freshservice: 'Basic: API key (env:TICKET_TOKEN) + "X". Create custom fields sw_key, sw_product, sw_cves.',
  topdesk: 'Basic: operator login (ticketUser) + application password (env:TICKET_TOKEN).',
};
for (const [k, t] of Object.entries(E.TICKET_SYSTEMS)) {
  out(`integrations/tickets/${k}.json`, { system: t.label, method: t.method, path: t.path, auth: AUTH[k], idempotencyKey: '{{signal.id}}:{{product.id}}', body: t.body, example: E.ticketPayload(k, hero, hero.products[0]) });
}
out('integrations/sentinel/sample-record.json', [E.sentinelRecord(hero, st.now)]);
out('integrations/sentinel/columns.json', E.DCR_COLUMNS.map(([name, type]) => ({ name, type })));
const dg = E.digest(st);
out('integrations/teams/digest-card.sample.json', teamsCard(dg, 'https://signalwatch.example.govt.nz/'));
out('integrations/teams/digest-email.sample.html', emailHtml(dg, 'https://signalwatch.example.govt.nz/'));
out('config/inventory-sample.csv', E.toCSV(E.SEED_INVENTORY) + '\n');
console.log('templates written');
