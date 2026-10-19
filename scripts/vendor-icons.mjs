// Vendor the Phosphor icons the UI uses into public/icons/ (run after adding icons): npm run icons
// Source: the pinned @phosphor-icons/core npm package (MIT). Candidate names are collected from the UI,
// engine and source config; only names that exist in the package are copied.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execSync } from 'node:child_process';

const VERSION = '2.1.1';
const root = new URL('../', import.meta.url);
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'phosphor-'));
execSync(`npm pack @phosphor-icons/core@${VERSION} --silent`, { cwd: tmp, stdio: 'ignore' });
execSync(`tar -xzf phosphor-icons-core-${VERSION}.tgz`, { cwd: tmp });
const assets = path.join(tmp, 'package', 'assets');

const files = ['public/index.html', 'public/engine.js', 'public/rules.html', 'config/sources.json'];
const text = files.map(f => fs.readFileSync(new URL(f, root), 'utf8')).join('\n');
const names = new Set();
for (const m of text.matchAll(/["'`]([a-z][a-z0-9]*(?:-[a-z0-9]+)*)["'`]/g)) names.add(m[1]);

const out = new URL('public/icons/', root);
fs.mkdirSync(out, { recursive: true });
let n = 0;
const copy = (file, name) => {
  if (!fs.existsSync(file)) return;
  // width/height let icons.js size the glyph; fill stays currentColor
  fs.writeFileSync(new URL(name + '.svg', out), fs.readFileSync(file, 'utf8').replace('<svg ', '<svg width="256" height="256" '));
  n++;
};
for (const name of names) {
  copy(path.join(assets, 'regular', name + '.svg'), name);
  copy(path.join(assets, 'fill', name + '-fill.svg'), name + '-fill');
}
fs.rmSync(tmp, { recursive: true, force: true });
console.log(`icons: ${n} files from @phosphor-icons/core@${VERSION}`);
