// Parsers against recorded real responses (test/fixtures, 19 Oct 2026).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { SEED_INVENTORY, aliasesFor, versionHit } from '../public/engine.js';
import { parseNcscList, parseNcscDetail, parseKev, parseCircl, parseRss, parseOpc, parseBsky, parseGraph } from '../src/sources/feeds.js';
import { scanCsv } from '../src/sources/epss.js';
import { parseNcscEmail } from '../src/sources/email.js';
import { SYNTH_CVE } from './fake-net.js';

const F = n => fs.readFileSync(new URL('./fixtures/' + n, import.meta.url), 'utf8');
const ctx = { now: Date.parse('2026-10-19T07:30:00+13:00'), settings: { lookbackDays: 30 }, aliases: aliasesFor(SEED_INVENTORY) };
const NS = ['citrix:netscaler_application_delivery_controller', 'citrix:netscaler_gateway'];

test('NCSC alerts page → 12 cards with title, link and NZ date', () => {
  const items = parseNcscList(F('ncsc_alerts.html'), { id: 'ncsc', url: 'https://www.ncsc.govt.nz/alerts/' });
  assert.equal(items.length, 12);
  const ns = items.find(i => /NetScaler/.test(i.title));
  assert.match(ns.title, /^UPDATED: Multiple vulnerabilities affecting Citrix NetScaler/);
  assert.equal(ns.url, 'https://www.ncsc.govt.nz/alerts/multiple-vulnerabilities-affecting-citrix-netscaler-adc-and-netscaler-gateway-products-2/');
  assert.equal(new Date(ns.at).toISOString(), '2026-10-13T23:00:00.000Z'); // 14 Oct 2026 12:00 NZDT
});

test('NCSC alert page → CVEs, advisories, CVSS, version ranges with condition', () => {
  const base = { src: 'ncsc', title: 'UPDATED: Multiple vulnerabilities affecting Citrix NetScaler ADC and NetScaler Gateway products', url: 'x' };
  const d = parseNcscDetail(F('ncsc_detail_netscaler.html'), base, ctx);
  assert.equal(d.cves.length, 9);
  assert.ok(d.cves.includes('CVE-2026-107406'));
  assert.deepEqual(d.advs.sort(), ['CTX697096', 'CTX697191']);
  assert.equal(d.cvss, 9.5);
  assert.deepEqual(d.keys.sort(), NS);
  assert.deepEqual(versionHit('14.1-73.41', d.affected, NS[0]), { hit: true, cond: 'SAML IdP' });
  assert.equal(versionHit('14.1-73.36', d.affected, NS[0]).cond, 'SAML SP/IdP');
  assert.equal(versionHit('14.1-73.50', d.affected, NS[0]).hit, false);
  assert.equal(d.fix, 'Per CTX697096 · CTX697191');
});

test('CISA KEV → window only, keys from vendor/product, due date as act-by', () => {
  const items = parseKev(JSON.parse(F('kev.json')), { id: 'kev' }, ctx);
  assert.ok(items.length >= 30 && items.length <= 40);
  const ns = items.find(i => i.cves[0] === 'CVE-2026-88771');
  assert.deepEqual(ns.keys.sort(), NS);
  assert.equal(ns.type, 'exploit');
  assert.equal(ns.kev.due, '2026-09-30');
  assert.ok(ns.fix.length > 0 && ns.fix.length <= 160);
  assert.ok(!items.some(i => i.cves[0] === 'CVE-2020-29583')); // old entry outside lookback
});

test('CIRCL CVE 5 → CPE keys, ranges, CVSS, fixed version', () => {
  const [r] = parseCircl([SYNTH_CVE], { id: 'circl' }, ctx);
  assert.deepEqual(r.keys, ['veeam:veeam_backup_&_replication']);
  assert.equal(r.cvss, 9.1);
  assert.equal(r.fix, '12.3.2');
  assert.equal(versionHit('12.3', r.affected, r.keys[0]).hit, true);
  const real = parseCircl(JSON.parse(F('circl_cve5.json')), { id: 'circl' }, ctx);
  assert.ok(real.length >= 15);
  assert.ok(real.every(i => /^CVE-\d{4}-\d+ · /.test(i.title) && i.url.startsWith('https://vulnerability.circl.lu/vuln/')));
});

test('RSS (SecurityBrief NZ) → headline, link, date; description not kept', () => {
  const items = parseRss(F('sbnz.xml'), { id: 'sbnz', nz: true }, ctx);
  assert.equal(items.length, 10);
  assert.ok(items.every(i => i.title && i.url.startsWith('https://securitybrief.co.nz/') && Number.isFinite(i.at)));
  assert.ok(items.every(i => !('description' in i)));
});

test('Mastodon-style RSS without titles uses post text as headline', () => {
  const xml = '<rss><channel><item><link>https://infosec.exchange/@a/1</link><description>&lt;p&gt;NetScaler SAML IdP builds still exposed&lt;/p&gt;</description><pubDate>Thu, 15 Oct 2026 21:10:00 +0000</pubDate></item></channel></rss>';
  const [i] = parseRss(xml, { id: 'masto' }, ctx);
  assert.equal(i.title, 'NetScaler SAML IdP builds still exposed');
  assert.deepEqual(i.keys.sort(), NS);
});

test('Privacy Commissioner HTML → statements; breach wording marks NZ peer', () => {
  const items = parseOpc(F('opc.html'), { id: 'opc', url: 'https://www.privacy.org.nz/tuhono-connect/statements-media-releases/' }, ctx);
  assert.ok(items.length >= 10);
  const mmh = items.find(i => /Manage My Health breach/i.test(i.title));
  assert.ok(mmh && mmh.peer && mmh.type === 'breach');
  assert.deepEqual(mmh.keys, ['managemyhealth:managemyhealth']);
});

test('Bluesky author feed → post text, bsky.app link', () => {
  const items = parseBsky(JSON.parse(F('bsky.json')), { id: 'bsky' }, ctx);
  assert.ok(items.length >= 1);
  assert.ok(items.every(i => i.url.startsWith('https://bsky.app/profile/')));
});

test('Graph service announcements → MC/EX ids, act-by, Microsoft keys', () => {
  const items = parseGraph({ messages: [{ id: 'MC1190331', title: 'Exchange Online: legacy PowerShell auth retires', services: ['Exchange Online'], actionRequiredByDateTime: '2026-11-09T09:00:00Z', lastModifiedDateTime: '2026-10-13T20:00:00Z' }], issues: [{ id: 'EX1188420', title: 'Delayed message delivery', service: 'Exchange Online', isResolved: false, startDateTime: '2026-10-15T18:30:00Z' }, { id: 'EX1', title: 'x', isResolved: true }] }, { id: 'graph' }, ctx);
  assert.equal(items.length, 2);
  assert.deepEqual(items[0].keys, ['microsoft:365']);
  assert.equal(new Date(items[0].actBy).toISOString(), '2026-11-09T09:00:00.000Z');
});

test('EPSS bulk CSV is filtered locally to wanted CVEs', async () => {
  const gz = fs.readFileSync(new URL('./fixtures/epss.csv.gz', import.meta.url));
  const stream = new Response(gz).body.pipeThrough(new DecompressionStream('gzip')).pipeThrough(new TextDecoderStream());
  const r = await scanCsv(stream, new Set(['CVE-2026-87902', 'CVE-2026-88771']));
  assert.deepEqual(Object.keys(r.epss).sort(), ['CVE-2026-87902', 'CVE-2026-88771']);
  assert.equal(r.epss['CVE-2026-87902'], 0.39979);
  assert.ok(r.rows > 2000);
});

test('NCSC email (quoted-printable HTML) → subject, canonical alert link, CVEs', () => {
  const raw = ['From: NCSC <alerts@ncsc.govt.nz>', 'Subject: =?utf-8?Q?UPDATED:_Multiple_vulnerabilities_affecting_Citrix_NetScaler?=', 'Date: Wed, 14 Oct 2026 12:04:00 +1300', 'MIME-Version: 1.0', 'Content-Type: multipart/alternative; boundary="b1"', '', '--b1', 'Content-Type: text/html; charset=utf-8', 'Content-Transfer-Encoding: quoted-printable', '', '<p>CVE-2026-107406 <a href=3D"https://www.ncsc.govt.nz/alerts/multiple-vulnerabilities-affecting-citrix-netscaler-adc-and-netscaler-gateway-products-2/?utm_source=3Dncsc&amp;utm_medium=3Demail">Read</a></p>', '--b1--', ''].join('\r\n');
  const i = parseNcscEmail(raw);
  assert.equal(i.title, 'UPDATED: Multiple vulnerabilities affecting Citrix NetScaler');
  assert.match(i.url, /^https:\/\/www\.ncsc\.govt\.nz\/alerts\/multiple-vulnerabilities-affecting-citrix-netscaler/);
  assert.deepEqual(i.cves, ['CVE-2026-107406']);
  assert.equal(i.type, 'alert');
});

test('CIRCL: add-on products (plugins, themes) do not match the platform they extend', () => {
  const rec = (product, cpes) => ({ cveMetadata: { cveId: 'CVE-2026-1', state: 'PUBLISHED', datePublished: '2026-10-18T00:00:00Z' }, containers: { cna: { title: 't', affected: [{ vendor: 'thimpress', product, ...(cpes ? { cpes } : {}), versions: [{ version: '0', lessThanOrEqual: '4.4.10', status: 'affected' }] }] } } });
  assert.deepEqual(parseCircl([rec('LearnPress – WordPress LMS Plugin for Create and Sell Online Courses')], { id: 'circl' }, ctx)[0].keys, []);
  assert.deepEqual(parseCircl([rec('WordPress')], { id: 'circl' }, ctx)[0].keys, ['wordpress:wordpress']);
  assert.deepEqual(parseCircl([rec('Anything', ['cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*'])], { id: 'circl' }, ctx)[0].keys, ['wordpress:wordpress']);
});
