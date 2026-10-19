// Schedule maths: Pacific/Auckland, DST-safe.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nzParts, nzToUtc, nzOffsetMin, runDue, nextRunAt, parseNzDate } from '../src/time.js';

const S = { schedule: '07:30', days: [1, 1, 1, 1, 1, 1, 1] };

test('Offsets: NZST +12 in July, NZDT +13 in October', () => {
  assert.equal(nzOffsetMin(Date.parse('2026-07-01T00:00:00Z')), 720);
  assert.equal(nzOffsetMin(Date.parse('2026-10-19T00:00:00Z')), 780);
});

test('07:30 NZ maps to 18:30Z in NZDT and 19:30Z in NZST', () => {
  assert.equal(new Date(nzToUtc('2026-10-20', '07:30')).toISOString(), '2026-10-19T18:30:00.000Z');
  assert.equal(new Date(nzToUtc('2026-07-01', '07:30')).toISOString(), '2026-06-30T19:30:00.000Z');
});

test('DST change days (27 Sep 2026 start, 5 Apr 2026 end)', () => {
  assert.equal(new Date(nzToUtc('2026-09-27', '07:30')).toISOString(), '2026-09-26T18:30:00.000Z');
  assert.equal(new Date(nzToUtc('2026-04-05', '07:30')).toISOString(), '2026-04-04T19:30:00.000Z');
});

test('Run is due once per NZ day at or after the schedule', () => {
  const at = h => Date.parse(h);
  assert.equal(runDue(at('2026-10-19T18:15:00Z'), S, null), false); // 07:15 NZDT
  assert.equal(runDue(at('2026-10-19T18:30:00Z'), S, null), true);
  assert.equal(runDue(at('2026-10-19T18:45:00Z'), S, '2026-10-20'), false);
  assert.equal(runDue(at('2026-06-30T18:30:00Z'), S, null), false); // 06:30 NZST
  assert.equal(runDue(at('2026-06-30T19:30:00Z'), S, null), true);
});

test('Weekday switches and next run', () => {
  const weekdays = { schedule: '07:30', days: [1, 1, 1, 1, 1, 0, 0] };
  const sat = Date.parse('2026-10-16T18:30:00Z'); // Sat 17 Oct 07:30 NZDT
  assert.equal(nzParts(sat).dow, 5);
  assert.equal(runDue(sat, weekdays, null), false);
  assert.equal(new Date(nextRunAt(sat, weekdays, null)).toISOString(), '2026-10-18T18:30:00.000Z'); // Mon 19 Oct
});

test('Feed date "14 October 2026" → NZ noon', () => {
  assert.equal(new Date(parseNzDate('14 October 2026')).toISOString(), '2026-10-13T23:00:00.000Z');
});
