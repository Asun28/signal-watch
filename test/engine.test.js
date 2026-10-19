// Grouping ladder (G1–G12), level rules (L1–L14), matching/privacy (M1–M4), routing (R1–R5) on the replay fixtures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as E from '../public/engine.js';
import { runTests } from '../public/tests.js';

for (const r of runTests(E)) {
  test(`${r.id} ${r.group} · ${r.name}`, () => assert.ok(r.pass, r.detail));
}

test('Replay sets load: NetScaler (14 Oct 2026) and Manage My Health (Jan 2026)', () => {
  assert.equal(E.REPLAYS.netscaler.when, '14 Oct 2026');
  assert.equal(E.REPLAYS.mmh.when, 'Jan 2026');
  for (const id of ['netscaler', 'mmh']) {
    const R = E.REPLAYS[id], st = E.buildState({ ...E.freshStore(id), runIdx: R.runs.length - R.base });
    assert.ok(st.signals.length > 0);
  }
});

test('Seed inventory: 30 products, 3 decoys, all four management models', () => {
  assert.equal(E.SEED_INVENTORY.length, 30);
  assert.equal(E.SEED_INVENTORY.filter(p => p.decoy).length, 3);
  assert.deepEqual([...new Set(E.SEED_INVENTORY.map(p => p.model))].sort(), ['hyper', 'self', 'shared', 'vendor']);
});

test('CSV import: header synonyms, model words, errors and duplicates', () => {
  const r = E.csvImport(E.CSV_SAMPLE, E.SEED_INVENTORY);
  assert.equal(r.ok, 4);
  assert.equal(r.dup, 1);
  assert.equal(r.err, 1);
  assert.equal(r.rows.find(x => x.data.name === 'Manage My Health').data.model, 'vendor');
});

test('Inventory aliases match products outside the catalogue, but not generic words', () => {
  const inv = [{ id: 'q1', name: 'Chamilo LMS', vendor: 'Chamilo', cpe: 'cpe:2.3:a:chamilo:chamilo_lms', version: '1.11', owner: 'x', model: 'self' }, { id: 'q2', name: 'Gateway', vendor: '', cpe: '', version: '', owner: 'x', model: 'self' }];
  const al = E.aliasesFor(inv);
  assert.deepEqual(E.extractKeys('Chamilo LMS: stored XSS in course page', al), ['chamilo:chamilo_lms']);
  assert.equal(E.extractKeys('Payment gateway outage', al).length, 0);
});
