// Ticket webhooks (ServiceNow, Jira SM, Freshservice, TOPdesk). One ticket per signal per product:
// the ticket table's primary key (sig, pid) is claimed before the POST, so retries never duplicate.
import { http, secret } from '../util.js';
import { ticketPayload, TICKET_SYSTEMS } from '../../public/engine.js';

const REF = {
  servicenow: j => j?.result?.number || j?.result?.sys_id,
  jira: j => j?.issueKey || j?.key,
  freshservice: j => j?.ticket?.id && '#' + j.ticket.id,
  topdesk: j => j?.number || j?.id,
};

export const ticketConfigured = (env, S) => !!(S.ticketUrl && secret(env, S.ticketAuth));

function authHeader(env, S) {
  const tok = secret(env, S.ticketAuth);
  if (S.ticketSys === 'freshservice') return 'Basic ' + btoa(tok + ':X');
  return S.ticketUser ? 'Basic ' + btoa(S.ticketUser + ':' + tok) : 'Bearer ' + tok;
}

export async function postTicket(env, S, s, p, fetchImpl) {
  const sys = TICKET_SYSTEMS[S.ticketSys] ? S.ticketSys : 'servicenow';
  const payload = ticketPayload(sys, s, p);
  if (!ticketConfigured(env, S)) return { status: 'dry-run', payload };
  const { res } = await http(S.ticketUrl.replace(/\/+$/, '') + payload.path, { fetch: fetchImpl, method: payload.method, body: JSON.stringify(payload.body), headers: { authorization: authHeader(env, S), 'content-type': 'application/json', accept: 'application/json', 'idempotency-key': payload.idempotencyKey } });
  let j = null;
  try { j = await res.json(); } catch { /* non-JSON */ }
  return { status: String(res.status), ref: res.ok ? String(REF[sys](j) || payload.idempotencyKey) : null, payload };
}

// Create tickets for products that do not have one yet. Returns refs [{ pid, ref }].
export async function createTickets(env, S, s, products, fetchImpl) {
  const db = env.DB, refs = [], now = Date.now();
  const sys = TICKET_SYSTEMS[S.ticketSys] ? S.ticketSys : 'servicenow';
  for (const p of products) {
    const claim = await db.prepare('INSERT OR IGNORE INTO ticket (sig, pid, ref, sys, status, at) VALUES (?, ?, NULL, ?, ?, ?)').bind(s.id, p.id, sys, 'pending', now).run();
    if (!(claim.meta?.changes > 0)) {
      const ex = await db.prepare('SELECT ref FROM ticket WHERE sig = ? AND pid = ?').bind(s.id, p.id).first();
      if (ex?.ref) refs.push({ pid: p.id, ref: ex.ref });
      continue;
    }
    let r;
    try { r = await postTicket(env, S, s, p, fetchImpl); } catch (e) { r = { status: 'error' }; }
    if (r.status === 'dry-run') r.ref = 'DRY-' + s.id.replace('SW-', '') + '-' + p.id;
    if (!r.ref) { await db.prepare('DELETE FROM ticket WHERE sig = ? AND pid = ?').bind(s.id, p.id).run(); continue; }
    await db.prepare('UPDATE ticket SET ref = ?, status = ? WHERE sig = ? AND pid = ?').bind(r.ref, r.status, s.id, p.id).run();
    refs.push({ pid: p.id, ref: r.ref });
  }
  return refs;
}
