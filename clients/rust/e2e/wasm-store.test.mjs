// Stage-2c test: browser-persistent engine storage. Writes state through the
// WASM Session, snapshots it to IndexedDB, RELOADS the page, and verifies the
// state came back — proving engine state survives restarts in the browser (the
// wasm counterpart to the native FileStore on disk).
//
// Run:  node clients/rust/e2e/wasm-store.test.mjs   (build first: clients/web/build.sh)

import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer-core';

const WEB = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../web');
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm' };

function freePort() { return new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); }); }

let failed = false;
const check = (cond, m) => { console.error((cond ? '  ✓ ' : '  ✗ ') + m); if (!cond) failed = true; };

async function main() {
  if (!fs.existsSync(path.join(WEB, 'pkg', 'mycellium_wasm.js'))) throw new Error('run clients/web/build.sh first');
  const port = await freePort();
  const server = http.createServer((req, res) => {
    const rel = decodeURIComponent(req.url.split('?')[0]);
    const file = path.join(WEB, rel === '/' ? 'index.html' : rel);
    if (!file.startsWith(WEB) || !fs.existsSync(file)) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
  });
  await new Promise((r) => server.listen(port, '127.0.0.1', r));
  const url = `http://127.0.0.1:${port}/index.html`;

  const browser = await puppeteer.launch({
    executablePath: '/usr/bin/google-chrome', headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });
  try {
    const page = await browser.newPage();
    page.on('pageerror', (e) => console.error('  [pageerror]', e.message));
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.mycellium?.session !== undefined, { timeout: 15000 });

    console.error('• write engine state and snapshot it to IndexedDB');
    const before = await page.evaluate(async () => {
      const s = window.mycellium.session;
      s.put('name', 'Mary');
      s.put('greeting', 'hello from wasm');
      await window.mycellium.persist();
      return { name: s.get('name'), greeting: s.get('greeting'), missing: s.get('nope') ?? null };
    });
    check(before.name === 'Mary' && before.greeting === 'hello from wasm', 'values readable in the same session');
    check(before.missing === null, 'absent key returns undefined/null');

    console.error('• reload the page — a fresh WASM instance restores from IndexedDB');
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.mycellium?.session !== undefined, { timeout: 15000 });
    const after = await page.evaluate(() => ({
      name: window.mycellium.session.get('name'),
      greeting: window.mycellium.session.get('greeting'),
    }));
    check(after.name === 'Mary', 'value survived the reload (loaded from IndexedDB)');
    check(after.greeting === 'hello from wasm', 'second value survived too');

    console.error('• delete persists as well');
    const afterDel = await page.evaluate(async () => {
      window.mycellium.session.del('greeting');
      await window.mycellium.persist();
      return window.mycellium.session.get('greeting') ?? null;
    });
    check(afterDel === null, 'deleted key is gone');
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.mycellium?.session !== undefined, { timeout: 15000 });
    const gone = await page.evaluate(() => window.mycellium.session.get('greeting') ?? null);
    check(gone === null, 'deletion survived the reload');
  } finally {
    await browser.close();
    server.close();
  }
}

main()
  .then(() => { console.error(failed ? '\nFAILED' : '\nALL PASSED'); process.exit(failed ? 1 : 0); })
  .catch((e) => { console.error('\nERROR:', e.message); process.exit(1); });
