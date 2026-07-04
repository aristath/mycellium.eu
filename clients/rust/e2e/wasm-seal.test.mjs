// Stage-3b test: real end-to-end message encryption in the browser. Two WASM
// Sessions (Alice + Bob) each generate a device identity; Bob seals a text
// message to Alice's signed record (X3DH + Double Ratchet, via the engine's
// shared `wireops`), Alice opens it, and a third party cannot. This exercises
// the actual engine crypto running entirely in the browser — no server.
//
// Run:  node clients/rust/e2e/wasm-seal.test.mjs   (build first: clients/web/build.sh)

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

  const browser = await puppeteer.launch({
    executablePath: process.env.CHROME_BIN || '/usr/bin/google-chrome', headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });
  try {
    const page = await browser.newPage();
    page.on('pageerror', (e) => console.error('  [pageerror]', e.message));
    await page.goto(`http://127.0.0.1:${port}/index.html`, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.mycellium?.Session !== undefined, { timeout: 15000 });

    console.error('• two in-browser identities, one encrypts to the other');
    const r = await page.evaluate(() => {
      const S = window.mycellium.Session;
      const alice = new S();
      const bob = new S();
      const q = 'http://queue.example';
      const aliceRecord = alice.record('alice', 'Alice', q);
      const sealed = bob.seal('bob', 'Bob', q, aliceRecord, 'meet me at the mycelium 🍄');
      const opened = JSON.parse(alice.open(sealed));
      // A third party who is not the recipient must not be able to decrypt.
      let intruderBlocked = false;
      try { new S().open(sealed); } catch { intruderBlocked = true; }
      return { opened, wallets: [alice.wallet(), bob.wallet()], sealedLen: sealed.length, intruderBlocked };
    });

    check(r.opened.text === 'meet me at the mycelium 🍄', `decrypted plaintext matches (incl. emoji): "${r.opened.text}"`);
    check(r.opened.from === 'bob', `sender identity recovered from the signed record: ${r.opened.from}`);
    check(r.wallets[0] !== r.wallets[1], 'the two identities are distinct');
    check(r.sealedLen > 100, `ciphertext is a real sealed envelope (${r.sealedLen} bytes)`);
    check(r.intruderBlocked, 'a non-recipient session cannot decrypt the envelope');
  } finally {
    await browser.close();
    server.close();
  }
}

main()
  .then(() => { console.error(failed ? '\nFAILED' : '\nALL PASSED'); process.exit(failed ? 1 : 0); })
  .catch((e) => { console.error('\nERROR:', e.message); process.exit(1); });
