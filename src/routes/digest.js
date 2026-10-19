// Daily digest: Teams Workflows (Adaptive Card to a "When a Teams webhook request is received" flow) and email
// (Graph sendMail from one mailbox, or a Cloudflare send_email binding). Counts, titles and links only.
import { digest, LV } from '../../public/engine.js';
import { http, secret } from '../util.js';
import { entraToken } from './sentinel.js';

export function teamsCard(dg, appUrl) {
  const items = ['act', 'plan', 'watch'].flatMap(l => dg[l].map(i => ({ type: 'TextBlock', wrap: true, spacing: 'Small', text: `**${LV[l].label}** · [${i.title.replace(/[[\]]/g, '')}](${i.link}) · ${i.id}` })));
  return {
    type: 'message',
    attachments: [{
      contentType: 'application/vnd.microsoft.card.adaptive',
      content: {
        $schema: 'http://adaptivecards.io/schemas/adaptive-card.json', type: 'AdaptiveCard', version: '1.4',
        body: [
          { type: 'TextBlock', text: 'Signal Watch · ' + dg.date, weight: 'Bolder', size: 'Medium' },
          { type: 'FactSet', facts: [['Act', dg.counts.act], ['Plan', dg.counts.plan], ['Watch', dg.counts.watch], ['Hidden', dg.hidden]].map(([title, v]) => ({ title, value: String(v) })) },
          ...items,
        ],
        actions: appUrl ? [{ type: 'Action.OpenUrl', title: 'Open Today', url: appUrl }] : [],
      },
    }],
  };
}

const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
export function emailHtml(dg, appUrl) {
  const row = (l, i) => `<tr><td style="padding:4px 10px 4px 0;font-weight:600">${LV[l].label}</td><td style="padding:4px 10px 4px 0"><a href="${esc(i.link)}">${esc(i.title)}</a></td><td style="padding:4px 0;color:#555d6b">${esc(i.id)}</td></tr>`;
  return `<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#111418">
<h2 style="font-size:18px;font-weight:600;margin:0 0 8px">Signal Watch · ${esc(dg.date)}</h2>
<p style="margin:0 0 12px">Act ${dg.counts.act} · Plan ${dg.counts.plan} · Watch ${dg.counts.watch} · Hidden ${dg.hidden}</p>
<table style="border-collapse:collapse">${['act', 'plan', 'watch'].flatMap(l => dg[l].map(i => row(l, i))).join('')}</table>
${appUrl ? `<p style="margin:12px 0 0"><a href="${esc(appUrl)}">Open Today</a></p>` : ''}</div>`;
}

export async function sendDigest(env, S, state, fetchImpl) {
  const dg = digest(state), appUrl = env.APP_URL || '';
  const out = { teams: 'off', email: 'off', digest: dg };
  if (S.digestTeams) {
    const url = S.teamsUrl && S.teamsUrl.startsWith('env:') ? secret(env, S.teamsUrl) : S.teamsUrl;
    if (!url) out.teams = 'dry-run';
    else {
      try { const { res } = await http(url, { fetch: fetchImpl, method: 'POST', body: JSON.stringify(teamsCard(dg, appUrl)), headers: { 'content-type': 'application/json' } }); out.teams = String(res.status); }
      catch (e) { out.teams = 'error'; }
    }
  }
  if (S.digestEmail) {
    const subject = `Signal Watch · ${dg.date} · Act ${dg.counts.act} · Plan ${dg.counts.plan}`;
    if (!S.digestTo) out.email = 'dry-run';
    else if (env.EMAIL && S.mailFrom) {
      try {
        const { EmailMessage } = await import('cloudflare:email');
        const raw = [`From: ${S.mailFrom}`, `To: ${S.digestTo}`, `Subject: ${subject}`, 'MIME-Version: 1.0', 'Content-Type: text/html; charset=utf-8', '', emailHtml(dg, appUrl)].join('\r\n');
        await env.EMAIL.send(new EmailMessage(S.mailFrom, S.digestTo, raw));
        out.email = 'sent';
      } catch (e) { out.email = 'error'; }
    } else if (S.mailFrom && S.tenant && S.clientId) {
      try {
        const tok = await entraToken(env, S, 'https://graph.microsoft.com/.default', fetchImpl, 'env:GRAPH_CLIENT_SECRET');
        const msg = { message: { subject, body: { contentType: 'HTML', content: emailHtml(dg, appUrl) }, toRecipients: S.digestTo.split(/[;,\s]+/).filter(Boolean).map(a => ({ emailAddress: { address: a } })) }, saveToSentItems: false };
        const { res } = await http(`https://graph.microsoft.com/v1.0/users/${encodeURIComponent(S.mailFrom)}/sendMail`, { fetch: fetchImpl, method: 'POST', body: JSON.stringify(msg), headers: { authorization: 'Bearer ' + tok, 'content-type': 'application/json' } });
        out.email = String(res.status);
      } catch (e) { out.email = 'error'; }
    } else out.email = 'dry-run';
  }
  return out;
}
