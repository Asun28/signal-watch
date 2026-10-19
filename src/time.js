// Pacific/Auckland helpers. Cron runs in UTC; everything user-facing is NZ local time (NZST/NZDT).
export const TZ = 'Pacific/Auckland';
const DOW = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const FMT = new Intl.DateTimeFormat('en-GB', { timeZone: TZ, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23', weekday: 'short' });

// { date: 'YYYY-MM-DD', hm: 'HH:MM', dow: 0 (Mon) … 6 (Sun) } in NZ local time.
export function nzParts(ms) {
  const p = Object.fromEntries(FMT.formatToParts(ms).map(x => [x.type, x.value]));
  return { date: `${p.year}-${p.month}-${p.day}`, hm: `${p.hour}:${p.minute}`, dow: DOW.indexOf(p.weekday) };
}

// Minutes east of UTC at instant ms (720 = NZST, 780 = NZDT).
export function nzOffsetMin(ms) {
  const { date, hm } = nzParts(ms);
  const [y, m, d] = date.split('-').map(Number), [h, mi] = hm.split(':').map(Number);
  return Math.round((Date.UTC(y, m - 1, d, h, mi) - Math.floor(ms / 6e4) * 6e4) / 6e4);
}

// NZ wall-clock date + time → UTC ms (DST-aware).
export function nzToUtc(date, hm = '00:00') {
  const [y, m, d] = date.split('-').map(Number), [h, mi] = hm.split(':').map(Number);
  const wall = Date.UTC(y, m - 1, d, h, mi);
  let t = wall - 780 * 6e4;
  t = wall - nzOffsetMin(t) * 6e4;
  return wall - nzOffsetMin(t) * 6e4;
}

export const addDays = (date, n) => new Date(Date.parse(date + 'T00:00:00Z') + n * 864e5).toISOString().slice(0, 10);

// The daily run is due once per NZ day, on enabled weekdays, at or after Settings → Schedule.
export function runDue(now, S, lastScheduledDate) {
  const p = nzParts(now);
  return !!(S.days || [1, 1, 1, 1, 1, 1, 1])[p.dow] && p.hm >= (S.schedule || '07:30') && lastScheduledDate !== p.date;
}

export function digestDue(now, S, lastDigestDate, ranToday) {
  const p = nzParts(now);
  return !!(S.digestTeams || S.digestEmail) && !!(S.days || [1, 1, 1, 1, 1, 1, 1])[p.dow] && ranToday && p.hm >= (S.digestTime || '07:45') && lastDigestDate !== p.date;
}

// Next scheduled run instant after `now`.
export function nextRunAt(now, S, lastScheduledDate) {
  const days = S.days || [1, 1, 1, 1, 1, 1, 1];
  let date = nzParts(now).date;
  for (let i = 0; i < 8; i++, date = addDays(date, 1)) {
    const at = nzToUtc(date, S.schedule || '07:30');
    if (!days[nzParts(at).dow] || date === lastScheduledDate) continue;
    return Math.max(at, now); // today's slot already passed but not run yet → due now
  }
  return null;
}

// Feed dates such as "14 October 2026" → NZ noon (date-only sources).
const MONTHS = ['january', 'february', 'march', 'april', 'may', 'june', 'july', 'august', 'september', 'october', 'november', 'december'];
export function parseNzDate(text) {
  const m = String(text || '').trim().match(/^(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})$/);
  if (!m) return null;
  const mo = MONTHS.indexOf(m[2].toLowerCase());
  if (mo < 0) return null;
  return nzToUtc(`${m[3]}-${String(mo + 1).padStart(2, '0')}-${m[1].padStart(2, '0')}`, '12:00');
}
