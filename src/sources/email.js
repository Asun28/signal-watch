// NCSC email fallback: parse an alert email (RFC 822) into one raw item. Only subject, link, date and IDs are kept.
import { stripTags, uniq } from '../util.js';

function headers(block) {
  const out = {};
  for (const l of block.replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/)) {
    const i = l.indexOf(':');
    if (i > 0) out[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim();
  }
  return out;
}
function decodeWord(s) {
  return String(s || '').replace(/=\?([^?]+)\?([bq])\?([^?]*)\?=/gi, (_, cs, enc, txt) => {
    try {
      const bytes = enc.toLowerCase() === 'b' ? Uint8Array.from(atob(txt), c => c.charCodeAt(0)) : qpBytes(txt.replace(/_/g, ' '));
      return new TextDecoder(cs.toLowerCase()).decode(bytes);
    } catch { return txt; }
  });
}
function qpBytes(s) {
  const out = [];
  s = s.replace(/=\r?\n/g, '');
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '=' && /^[0-9A-F]{2}$/i.test(s.slice(i + 1, i + 3))) { out.push(parseInt(s.slice(i + 1, i + 3), 16)); i += 2; }
    else out.push(s.charCodeAt(i) & 0xff);
  }
  return Uint8Array.from(out);
}
function decodeBody(body, h) {
  const enc = (h['content-transfer-encoding'] || '').toLowerCase();
  const cs = ((h['content-type'] || '').match(/charset="?([\w-]+)/i) || [])[1] || 'utf-8';
  try {
    if (enc === 'base64') return new TextDecoder(cs).decode(Uint8Array.from(atob(body.replace(/\s+/g, '')), c => c.charCodeAt(0)));
    if (enc === 'quoted-printable') return new TextDecoder(cs).decode(qpBytes(body));
  } catch { /* fall through */ }
  return body;
}
// Flatten a MIME tree into text parts.
function parts(raw, depth = 0) {
  const sep = raw.search(/\r?\n\r?\n/);
  const h = headers(sep >= 0 ? raw.slice(0, sep) : raw), body = sep >= 0 ? raw.slice(sep).replace(/^\r?\n\r?\n/, '') : '';
  const ct = h['content-type'] || 'text/plain';
  const b = (ct.match(/boundary="?([^";]+)"?/i) || [])[1];
  if (/^multipart\//i.test(ct) && b && depth < 5) return body.split('--' + b).slice(1).filter(p => !p.startsWith('--')).flatMap(p => parts(p.replace(/^\r?\n/, ''), depth + 1));
  return [{ type: ct.split(';')[0].trim().toLowerCase(), text: decodeBody(body, h) }];
}

export function parseNcscEmail(raw, src = { id: 'ncsc_mail' }) {
  const sep = raw.search(/\r?\n\r?\n/);
  const h = headers(sep >= 0 ? raw.slice(0, sep) : raw);
  const text = parts(raw).filter(p => p.type.startsWith('text/')).map(p => (p.type === 'text/html' ? stripTags(p.text) + ' ' + (p.text.match(/href="([^"]+)"/gi) || []).join(' ') : p.text)).join(' ');
  const links = uniq((text.match(/https?:\/\/(?:www\.)?ncsc\.govt\.nz\/(?:alerts|news)\/[^\s"'<>)]+/gi) || []).map(u => u.replace(/^href="/i, '').replace(/[.,;]+$/, '')));
  const subject = decodeWord(h.subject || '').replace(/^\s*(?:\[[^\]]*\]\s*|(?:fw|fwd|re):\s*)*/i, '').replace(/^NCSC(?: NZ)?\s*[:|-]\s*/i, '').trim();
  if (!subject || !links.length) return null;
  const at = Date.parse(h.date || '') || Date.now();
  return {
    src: src.id, guid: links[0] + '#' + subject, at, title: subject, url: links[0],
    cves: uniq((text.match(/CVE-\d{4}-\d{4,7}/gi) || []).map(x => x.toUpperCase())),
    advs: uniq(text.match(/\bCTX\d{6}\b/g) || []),
    type: /breach|incident/i.test(subject) && !/vulnerab/i.test(subject) ? 'breach' : 'alert', peer: /breach|incident/i.test(subject) && !/vulnerab/i.test(subject),
    from: h.from || '',
  };
}
