// Signal Watch — automated tests for the grouping ladder, level rules, matching, privacy and routing.
// Usage (browser): const E = await import('./engine.js'); (await import('./tests.js')).runTests(E)
// Usage (Node 18+): npm test  (test/engine.test.js wraps runTests and the acceptance suite)
export function runTests(E) {
  const out = [];
  const t = (id, group, name, fn) => {
    try {
      const r = fn();
      const pass = r === true || (r && r.pass === true);
      out.push({ id, group, name, pass, detail: (r && r.detail) || (pass ? '' : 'assertion failed') });
    } catch (e) { out.push({ id, group, name, pass: false, detail: String(e && e.message || e) }); }
  };
  const R = (replay, patch = {}) => E.buildState({ ...E.freshStore(replay), runIdx: E.REPLAYS[replay].runs.length - E.REPLAYS[replay].base, ...patch });
  const ns = R('netscaler'), nsAI = R('netscaler', { settings: { ai: true } });
  const mmh = R('mmh'), mmhAI = R('mmh', { settings: { ai: true } });
  const nsDef = E.buildState(E.freshStore('netscaler'));
  const item = (st, n) => st.sigOf(n)?.items.find(i => i.n === n);
  const title = n => { for (const r of [...E.REPLAYS.netscaler.runs, ...E.REPLAYS.mmh.runs]) for (const i of r.items) if (i.n === n) return i.title; return ''; };
  const lv = (st, n) => st.sigOf(n)?.level;
  const d = x => ({ pass: !!x.pass, detail: x.detail });

  // ── Grouping ladder ──
  t('G1', 'Grouping', 'Step 1 · same CVE merges', () => d({ pass: ns.sigOf(141) === ns.sigOf(142) && item(ns, 142).join.step === 1, detail: 'KEV + CIRCL CVE-2026-90561' }));
  t('G2', 'Grouping', 'Step 1 · same URL merges', () => d({ pass: E.canonUrl('https://www.ncsc.govt.nz/alerts/x/?utm_source=ncsc&utm_medium=email') === E.canonUrl('https://www.ncsc.govt.nz/alerts/x/') && ns.sigOf(136) === ns.sigOf(137), detail: 'NCSC email vs page' }));
  t('G3', 'Grouping', 'Step 2 · MinHash > 0.85 merges', () => { const j = E.jaccardEst(E.minhash(title(103)), E.minhash(title(104))); return d({ pass: j > 0.85 && item(ns, 104).join.step === 2, detail: 'J=' + j.toFixed(2) }); });
  t('G4', 'Grouping', 'Step 2 · low Jaccard stays apart', () => { const j = E.jaccardEst(E.minhash(title(125)), E.minhash(title(134))); return d({ pass: j <= 0.85 && ns.sigOf(125) !== ns.sigOf(134), detail: 'J=' + j.toFixed(2) }); });
  t('G5', 'Grouping', 'Same title, different CVEs', () => { const j = E.jaccardExact(title(100), title(115)); return d({ pass: j > 0.95 && ns.sigOf(100) !== ns.sigOf(115), detail: 'NCSC Jul vs Sep · J=' + j.toFixed(2) }); });
  t('G6', 'Grouping', 'Step 3 · vendor+product ≤ 7 d', () => d({ pass: ns.sigOf(116) === ns.sigOf(105) && item(ns, 116).join.step === 3, detail: 'SecurityBrief → NetScaler' }));
  t('G7', 'Grouping', 'Step 3 · outside window splits', () => d({ pass: mmh.sigOf(205) !== mmh.sigOf(203), detail: 'MMH inquiry +16 d' }));
  t('G8', 'Grouping', 'Conflicting CVEs block 2–5', () => d({ pass: ns.sigOf(119) !== ns.sigOf(105) && ns.sigOf(120) !== ns.sigOf(106), detail: 'CVE-2026-88779 apart' }));
  t('G9', 'Grouping', 'Multi-hit exact IDs merge', () => { const s = ns.sigOf(122); return d({ pass: s === ns.sigOf(105) && s.merged.includes('SW-1122'), detail: s ? s.id + ' ← ' + s.merged.join(',') : '' }); });
  t('G10', 'Grouping', 'AI off · steps 4–5 never run', () => d({ pass: ns.modelCalls.length === 0 && mmh.modelCalls.length === 0 && ![...ns.all, ...mmh.all].some(s => s.items.some(i => (i.join?.step || 0) >= 4)), detail: 'model calls 0' }));
  t('G11', 'Grouping', 'AI on · grey zone flagged', () => { const j = item(mmhAI, 205)?.join; return d({ pass: mmhAI.sigOf(205) === mmhAI.sigOf(203) && j.step === 5 && j.flagged, detail: 'score ' + j?.score }); });
  t('G12', 'Grouping', 'New source sets Updated', () => { const s = nsDef.byId['SW-1103']; const dup = ns.byId['SW-1103'].changes.some(c => c.item === 'i137'); return d({ pass: s.updated && s.status === 'open' && !dup, detail: 'email update ✓ · page dup quiet' }); });

  // ── Level rules ──
  const one = (items, products, settings = {}, now = Date.parse('2026-10-14T07:30:00+13:00')) => E.evaluate({ items, matches: products.map(m => ({ pid: 'x', model: m, inScope: true })), lastAt: now }, { S: { ...E.DEFAULT_SETTINGS, ...settings }, now, epss: {}, cvss: {} });
  t('L1', 'Levels', 'Act · NCSC alert + match', () => { const s = ns.byId['SW-1103']; return d({ pass: s.level === 'act' && s.rule === 'A1', detail: s.rule }); });
  t('L2', 'Levels', 'Act · KEV + self-managed', () => { const s = ns.sigOf(120); return d({ pass: s.level === 'act' && s.rule === 'A2', detail: s.id }); });
  t('L3', 'Levels', 'KEV + shared ≠ Act', () => { const r = one([{ src: 'kev', type: 'exploit', tier: 1, cves: ['CVE-X'], actBy: Date.parse('2026-11-01') }], ['shared']); return d({ pass: r.level === 'plan' && r.rule === 'P4', detail: r.rule }); });
  t('L4', 'Levels', 'Plan · EPSS ≥ 0.1', () => d({ pass: lv(ns, 130) === 'plan' && ns.sigOf(130).rule === 'P1', detail: 'Veeam 0.23' }));
  t('L5', 'Levels', 'Plan · CVSS ≥ 9', () => d({ pass: lv(ns, 143) === 'plan' && ns.sigOf(143).rule === 'P2', detail: 'Exchange 9.1' }));
  t('L6', 'Levels', 'Plan · vendor breach', () => { const inv = [...E.SEED_INVENTORY, { id: 'p31', name: 'Manage My Health', vendor: 'Manage My Health', cpe: '', version: 'SaaS', owner: 'Aroha T.', model: 'vendor' }]; const st = R('mmh', { inventory: inv }); return d({ pass: lv(st, 203) === 'plan' && st.sigOf(203).rule === 'P3', detail: 'MMH vendor-managed' }); });
  t('L7', 'Levels', 'Plan · act-by ≤ 30 d', () => d({ pass: lv(ns, 131) === 'plan' && ns.sigOf(131).rule === 'P4', detail: 'MC1190331' }));
  t('L8', 'Levels', 'Watch · tier-3 only', () => d({ pass: lv(ns, 135) === 'watch' && ns.sigOf(135).rule === 'W1', detail: 'FortiGate post' }));
  t('L9', 'Levels', 'Watch · NZ peer, no match', () => d({ pass: lv(ns, 134) === 'watch' && lv(mmh, 203) === 'watch' && mmh.sigOf(203).rule === 'W2', detail: 'Kererū · MMH' }));
  t('L10', 'Levels', 'Info · other match', () => d({ pass: lv(ns, 132) === 'info' && lv(ns, 133) === 'info', detail: 'S3 · PaperCut' }));
  t('L11', 'Levels', 'Hidden · no match', () => d({ pass: lv(ns, 117) === 'hidden' && lv(ns, 102) === 'hidden' && lv(ns, 123) === 'hidden', detail: 'SD-WAN · Check Point · joint' }));
  t('L12', 'Levels', 'Social-only caps at Watch', () => { const s = ns.sigOf(148); return d({ pass: s.level === 'watch' && s.ev.raw === 'plan' && s.ev.caps.some(c => c.id === 'C1'), detail: 'raw ' + s.ev.raw }); });
  t('L13', 'Levels', 'Thresholds from settings', () => { const a = R('netscaler', { settings: { epss: 0.3 } }), b = R('netscaler', { settings: { epss: 0.3, cvss: 8.5 } }); return d({ pass: lv(a, 130) === 'info' && lv(b, 130) === 'plan' && b.sigOf(130).rule === 'P2', detail: 'EPSS 0.3 · CVSS 8.5' }); });
  t('L14', 'Levels', 'Info archives after 14 d', () => { const a = R('netscaler', { settings: { archiveDays: 1 } }); return d({ pass: !ns.sigOf(132).ev.archived && a.sigOf(132).ev.archived, detail: 'S3 health' }); });

  // ── Matching, scope, privacy ──
  const decoys = E.SEED_INVENTORY.filter(p => p.decoy).map(p => p.id);
  t('M1', 'Matching', '3 decoys never match', () => { const hit = [ns, nsAI, mmh, mmhAI].flatMap(st => st.all.flatMap(s => s.matches.map(m => m.pid))).filter(p => decoys.includes(p)); return d({ pass: decoys.length === 3 && hit.length === 0, detail: decoys.join(' ') }); });
  t('M2', 'Matching', 'Scope · vendor-managed vuln', () => { const s = ns.sigOf(146); return d({ pass: s.level === 'hidden' && s.outOfScope.some(p => p.id === 'p20'), detail: 'Zoom out of scope' }); });
  t('M3', 'Privacy', 'Inventory never leaves', () => {
    const inv = JSON.stringify(E.SEED_INVENTORY.flatMap(p => [p.cpe, p.version, p.owner]).filter(x => x && x.length > 3));
    const calls = mmhAI.modelCalls.concat(nsAI.modelCalls);
    const okCalls = calls.every(c => Object.keys(c).join() === 'a,b' && typeof c.a === 'string' && typeof c.b === 'string' && !E.SEED_INVENTORY.some(p => (p.cpe && JSON.stringify(c).includes(p.cpe)) || JSON.stringify(c).includes(p.owner)));
    const okEnrich = E.enrichmentRequests().every(r => r.method === 'GET' && !/[?&](cve|cpe|product|vendor)=/i.test(r.url));
    return d({ pass: okCalls && okEnrich && inv.length > 0, detail: calls.length + ' model calls · bulk enrich' });
  });
  t('M4', 'Matching', 'Version range check', () => { const p = ns.byId['SW-1103'].products.find(x => x.id === 'p01'); return d({ pass: p.hit === true && /IdP/.test(p.cond), detail: '14.1-73.41 · ' + p.cond }); });

  // ── Routing ──
  t('R1', 'Routing', 'Sentinel idempotent', () => { const r = ns.routes.filter(x => x.sig === 'SW-1103'); const inc = new Set(r.map(x => x.incident)); const lastRun = ns.runs[ns.runs.length - 1].at; return d({ pass: inc.size === 1 && r.every((x, i) => x.rev === i + 1) && !r.some(x => x.at === lastRun), detail: r.length + ' revs · 1 incident' }); });
  t('R2', 'Routing', 'One ticket per signal/product', () => { const s = ns.byId['SW-1141']; const first = E.planTickets(s, []); const dec = [{ sig: s.id, act: 'ticket', refs: first.map(p => ({ pid: p.id, ref: 'X' })) }]; return d({ pass: first.length === 1 && E.planTickets(s, dec).length === 0, detail: 'ESXi' }); });
  t('R3', 'Routing', 'Fix field is source-only', () => { const ok = [nsAI, mmhAI].every(st => st.all.every(s => s.items.every(i => !i.fix || (i.fixSrc && i.keysBy !== 'ai')))); return d({ pass: ok, detail: 'no model-written fix' }); });
  t('R4', 'Routing', 'Pipeline with AI off', () => { const c = nsDef.open; return d({ pass: c.act === 1 && c.plan === 3 && c.watch === 3, detail: JSON.stringify(c) }); });
  t('R5', 'Routing', 'Ticket payload keyed', () => { const s = ns.byId['SW-1103']; const p = E.ticketPayload('servicenow', s, s.products[0]); return d({ pass: p.idempotencyKey === 'SW-1103:p01' && p.body.correlation_id === 'SW-1103:p01', detail: p.path }); });
  return out;
}
export function cli(E) {
  const r = runTests(E);
  for (const x of r) console.log((x.pass ? 'PASS ' : 'FAIL ') + x.id.padEnd(4) + ' ' + x.name + (x.detail ? '  — ' + x.detail : ''));
  const f = r.filter(x => !x.pass).length;
  console.log(`\n${r.length - f}/${r.length} passed`);
  if (typeof process !== 'undefined' && f) process.exitCode = 1;
  return r;
}
