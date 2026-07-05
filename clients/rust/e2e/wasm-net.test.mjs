// Stage-2b test: prove the *whole* client stack runs in the browser against a
// real server. Starts a real mycellium-directory, serves clients/web from a
// different origin, and has the in-browser WASM engine perform a full directory
// login (generate identity → challenge → sign → verify) over synchronous XHR —
// exercising the shared client logic, the injected browser transport, CORS, and
// the crypto, end to end.
//
// Run:  node clients/rust/e2e/wasm-net.test.mjs   (build first: clients/web/build.sh + cargo build)

import { spawn } from 'node:child_process';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer-core';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const WEB = path.join(ROOT, 'clients/web');
const BIN = (n) => path.join(ROOT, 'target/debug', n);
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const procs = [];
function freePort() { return new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); }); }
async function waitHttp(u, ms = 10000) { const e = Date.now() + ms; while (Date.now() < e) { try { const r = await fetch(u); if (r.status < 500) return; } catch {} await sleep(150); } throw new Error('timeout ' + u); }

let failed = false;
const check = (cond, m) => { console.error((cond ? '  ✓ ' : '  ✗ ') + m); if (!cond) failed = true; };

async function main() {
  if (!fs.existsSync(path.join(WEB, 'pkg', 'mycellium_wasm.js'))) throw new Error('run clients/web/build.sh first');
  if (!fs.existsSync(BIN('mycellium-server'))) throw new Error('run: cargo build');

  const [dirPort, webPort] = await Promise.all([freePort(), freePort()]);
  const dirUrl = `http://127.0.0.1:${dirPort}`;
  procs.push(spawn(BIN('mycellium-server'), ['--addr', `127.0.0.1:${dirPort}`], { stdio: 'ignore' }));
  await waitHttp(dirUrl + '/health');

  // Static server for the PWA — a DIFFERENT origin than the directory, so this
  // genuinely exercises cross-origin CORS.
  const web = http.createServer((req, res) => {
    const rel = decodeURIComponent(req.url.split('?')[0]);
    const file = path.join(WEB, rel === '/' ? 'index.html' : rel);
    if (!file.startsWith(WEB) || !fs.existsSync(file)) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
  });
  await new Promise((r) => web.listen(webPort, '127.0.0.1', r));

  const browser = await puppeteer.launch({
    executablePath: process.env.CHROME_BIN || '/usr/bin/google-chrome', headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });
  try {
    const page = await browser.newPage();
    page.on('pageerror', (e) => console.error('  [pageerror]', e.message));
    await page.goto(`http://127.0.0.1:${webPort}/index.html`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.mycellium !== undefined, { timeout: 15000, polling: 100 });

    console.error('• in-browser WASM engine logs into a real directory (cross-origin)');
    const result = await page.evaluate((url) => {
      try { return { token: window.mycellium.directory_login(url) }; }
      catch (e) { return { error: String(e) }; }
    }, dirUrl);

    check(!result.error, `login succeeded (${result.error || 'ok'})`);
    check(typeof result.token === 'string' && result.token.length >= 16, `got a session token: ${result.token?.slice(0, 12)}…`);

    // Two logins yield distinct tokens (fresh challenge each time).
    const second = await page.evaluate((url) => window.mycellium.directory_login(url), dirUrl);
    check(second !== result.token, 'a second login returns a distinct token');
  } finally {
    await browser.close();
    web.close();
    for (const p of procs) { try { p.kill('SIGKILL'); } catch {} }
  }
}

main()
  .then(() => { console.error(failed ? '\nFAILED' : '\nALL PASSED'); process.exit(failed ? 1 : 0); })
  .catch((e) => { for (const p of procs) { try { p.kill('SIGKILL'); } catch {} } console.error('\nERROR:', e.message); process.exit(1); });
