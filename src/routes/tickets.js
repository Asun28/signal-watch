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
// System id used by later updates when it differs from the ref.
const EXT = {
  servicenow: j => j?.result?.sys_id,
  jira: j => j?.issueKey || j?.key,
  freshservice: j => j?.ticket?.id && String(j.ticket.id),
  topdesk: j => j?.id,
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
  return { status: String(res.status), ref: res.ok ? String(REF[sys](j) || payload.idempotencyKey) : null, ext: res.ok ? EXT[sys](j) || null : null, payload };
}

// Create tickets for products that do not have one yet. Returns refs [{ pid, ref }]. In dry run each ticket is also a
// sandbox row (src/sync.js), so its state can be changed and read back like a real one.
export async function createTickets(env, S, s, products, fetchImpl, now = Date.now()) {
  const db = env.DB, refs = [];
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
    await db.prepare('UPDATE ticket SET ref = ?, status = ?, ext_id = ?, ext_at = ?, rev = ? WHERE sig = ? AND pid = ?').bind(r.ref, r.status, r.ext || null, now, s.route?.rev || 0, s.id, p.id).run();
    if (r.status === 'dry-run') await db.prepare("INSERT OR IGNORE INTO sim (ref, kind, sig, status, at) VALUES (?, 'ticket', ?, 'open', ?)").bind(r.ref, s.id, now).run();
    refs.push({ pid: p.id, ref: r.ref });
  }
  return refs;
}

// ───────── two-way sync (src/sync.js) ─────────
// Ticket state is one of open | progress | resolved | cancelled. Requests carry ticket refs and label-only notes.
const SN_STATE = { 1: 'open', 2: 'progress', 3: 'progress', 6: 'resolved', 7: 'resolved', 8: 'cancelled' };
const FS_STATE = { 2: 'open', 3: 'progress', 4: 'resolved', 5: 'resolved' };
const when = s => Date.parse(String(s || '').replace(/([+-]\d\d)(\d\d)$/, '$1:$2')) || 0;
const fsId = t => String(t.ref).replace(/^#/, '');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-/i;

// read: one request for up to `batch` refs. note / close: the requests to send (null = not possible for this ticket).
// ticketClose (Settings → Tickets → close value): ServiceNow close code, Jira transition id, Freshservice status.
export const TICKET_SYNC = {
  servicenow: {
    batch: 40,
    read: refs => ({ path: '/api/now/table/incident?sysparm_query=' + encodeURIComponent('numberIN' + refs.join(',')) + '&sysparm_fields=sys_id,number,state,sys_updated_on&sysparm_limit=' + refs.length }),
    parse: j => (j?.result || []).map(r => ({ ref: r.number, id: r.sys_id, state: SN_STATE[r.state] || 'open', at: Date.parse(String(r.sys_updated_on).replace(' ', 'T') + 'Z') || 0 })),
    note: (t, text) => t.ext_id ? [{ method: 'PATCH', path: '/api/now/table/incident/' + t.ext_id, body: { work_notes: text } }] : null,
    close: (t, text, S) => t.ext_id ? [{ method: 'PATCH', path: '/api/now/table/incident/' + t.ext_id, body: { state: '6', close_code: S.ticketClose || 'No resolution provided', close_notes: text } }] : null,
  },
  jira: {
    batch: 40,
    read: refs => ({ path: '/rest/api/3/search/jql?jql=' + encodeURIComponent('key in (' + refs.join(',') + ')') + '&fields=status,resolution,updated&maxResults=' + refs.length }),
    parse: j => (j?.issues || []).map(x => {
      const f = x.fields || {}, cat = f.status?.statusCategory?.key;
      const state = cat === 'done' ? (/won.?t|declin|cancel|duplicate|reject/i.test(f.resolution?.name || '') ? 'cancelled' : 'resolved') : cat === 'indeterminate' ? 'progress' : 'open';
      return { ref: x.key, id: x.key, state, at: when(f.updated) };
    }),
    note: (t, text) => [{ method: 'POST', path: `/rest/servicedeskapi/request/${t.ref}/comment`, body: { body: text, public: false } }],
    // the workflow's transition id is site-specific; without it only the comment is added
    close: (t, text, S) => S.ticketClose ? [{ method: 'POST', path: `/rest/servicedeskapi/request/${t.ref}/comment`, body: { body: text, public: false } }, { method: 'POST', path: `/rest/api/3/issue/${t.ref}/transitions`, body: { transition: { id: String(S.ticketClose) } } }] : null,
  },
  freshservice: {
    batch: 1,
    read: refs => ({ path: '/api/v2/tickets/' + fsId({ ref: refs[0] }) }),
    parse: j => j?.ticket ? [{ ref: '#' + j.ticket.id, id: String(j.ticket.id), state: FS_STATE[j.ticket.status] || 'open', at: when(j.ticket.updated_at) }] : [],
    note: (t, text) => [{ method: 'POST', path: `/api/v2/tickets/${fsId(t)}/notes`, body: { body: text, private: true } }],
    close: (t, text, S) => [{ method: 'POST', path: `/api/v2/tickets/${fsId(t)}/notes`, body: { body: text, private: true } }, { method: 'PUT', path: `/api/v2/tickets/${fsId(t)}`, body: { status: +S.ticketClose || 4 } }],
  },
  topdesk: {
    batch: 1,
    read: refs => ({ path: '/tas/api/incidents/' + (UUID.test(refs[0]) ? 'id/' : 'number/') + encodeURIComponent(refs[0]) }),
    parse: j => j?.id ? [{ ref: j.number || j.id, id: j.id, state: j.closed || j.completed ? 'resolved' : /progress|behandeling/i.test(j.processingStatus?.name || '') ? 'progress' : 'open', at: when(j.modificationDate) }] : [],
    note: (t, text) => t.ext_id ? [{ method: 'PATCH', path: '/tas/api/incidents/id/' + t.ext_id, body: { action: text, actionInvisibleForCaller: true } }] : null,
    close: (t, text) => t.ext_id ? [{ method: 'PATCH', path: '/tas/api/incidents/id/' + t.ext_id, body: { completed: true, action: text, actionInvisibleForCaller: true } }] : null,
  },
};
const syncSpec = S => TICKET_SYNC[S.ticketSys] || TICKET_SYNC.servicenow;

async function call(env, S, req, fetchImpl) {
  const { res } = await http(S.ticketUrl.replace(/\/+$/, '') + req.path, { fetch: fetchImpl, method: req.method || 'GET', body: req.body && JSON.stringify(req.body), headers: { authorization: authHeader(env, S), 'content-type': 'application/json', accept: 'application/json' } });
  if (!res.ok) throw new Error('Ticket ' + res.status);
  try { return await res.json(); } catch { return null; }
}

// Current state of these refs in the ticket system: [{ ref, id, state, at }].
export async function ticketStates(env, S, refs, fetchImpl) {
  const spec = syncSpec(S), out = [];
  for (let i = 0; i < refs.length; i += spec.batch) out.push(...spec.parse(await call(env, S, spec.read(refs.slice(i, i + spec.batch)), fetchImpl)));
  return out;
}
// op 'note' or 'close'. Returns false when the system cannot do it for this ticket.
export async function ticketWrite(env, S, op, t, text, fetchImpl) {
  const reqs = syncSpec(S)[op](t, text, S);
  if (!reqs) return false;
  for (const r of reqs) await call(env, S, r, fetchImpl);
  return true;
}
