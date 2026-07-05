// Stage-1 WASM test: serve clients/web statically, load it in a real (headless)
// Chrome, and verify the in-browser WebAssembly engine produces correct crypto —
// the account-id hash matches an independent SHA-256, normalization holds, and
// device-key generation yields distinct 33-byte keys from browser entropy.
//
// Run:  node clients/rust/e2e/wasm.test.mjs   (build the pkg first: clients/web/build.sh)

import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer-core';

const WEB = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../web');
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm', '.ts': 'text/plain' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function freePort() { return new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); }); }

let failed = false;
const check = (cond, m) => { console.error((cond ? '  ✓ ' : '  ✗ ') + m); if (!cond) failed = true; };

// Independent ground truth for user_id: SHA-256("mycellium-user:" + normalized),
// first 16 bytes as hex (32 chars).
function expectedUserId(s) {
  const norm = s.trim().toLowerCase();
  return crypto.createHash('sha256').update('mycellium-user:' + norm).digest('hex').slice(0, 32);
}

async function main() {
  if (!fs.existsSync(path.join(WEB, 'pkg', 'mycellium_wasm.js'))) {
    throw new Error('clients/web/pkg missing — run clients/web/build.sh first');
  }
  const port = await freePort();
  const server = http.createServer((req, res) => {
    const rel = decodeURIComponent(req.url.split('?')[0]);
    const file = path.join(WEB, rel === '/' ? 'index.html' : rel);
    if (!file.startsWith(WEB) || !fs.existsSync(file)) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
  });
  await new Promise((r) => server.listen(port, '127.0.0.1', r));

  const browser = await puppeteer.launch({
    executablePath: process.env.CHROME_BIN || '/usr/bin/google-chrome', headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });
  try {
    const page = await browser.newPage();
    page.on('pageerror', (e) => console.error('  [pageerror]', e.message));
    await page.goto(`http://127.0.0.1:${port}/index.html`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.mycellium !== undefined, { timeout: 15000, polling: 100 });
    const r = await page.evaluate(() => {
      const m = window.mycellium;
      return {
        version: m.version(),
        uid: m.user_id('mary@example.com'),
        uidUpper: m.user_id('  MARY@Example.com  '),
        w1: m.generate_wallet(),
        w2: m.generate_wallet(),
      };
    });

    console.error('• WebAssembly engine loaded and ran in the browser');
    check(typeof r.version === 'string' && r.version.includes('mycellium-wasm'), `version export works: ${r.version}`);
    check(r.uid === expectedUserId('mary@example.com'), `user_id matches independent SHA-256: ${r.uid}`);
    check(r.uid === r.uidUpper, 'user_id normalizes case + whitespace (MARY/pad → same id)');
    check(/^[0-9a-f]{66}$/.test(r.w1), `generated a 33-byte wallet key: ${r.w1.slice(0, 16)}…`);
    check(r.w1 !== r.w2, 'two generations differ (real browser entropy)');
  } finally {
    await browser.close();
    server.close();
  }
}

main()
  .then(() => { console.error(failed ? '\nFAILED' : '\nALL PASSED'); process.exit(failed ? 1 : 0); })
  .catch((e) => { console.error('\nERROR:', e.message); process.exit(1); });
