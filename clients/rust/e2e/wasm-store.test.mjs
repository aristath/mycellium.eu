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
    executablePath: process.env.CHROME_BIN || '/usr/bin/google-chrome', headless: true,
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
  });
  try {
    const page = await browser.newPage();
    page.on('pageerror', (e) => console.error('  [pageerror]', e.message));
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.mycellium?.rpc !== undefined, { timeout: 15000 });

    console.error('• write engine state and snapshot it to IndexedDB');
    const before = await page.evaluate(async () => {
      const rpc = window.mycellium.rpc;
      await rpc('put', ['name', 'Mary']);
      await rpc('put', ['greeting', 'hello from wasm']);
      return { name: await rpc('get', ['name']), greeting: await rpc('get', ['greeting']), missing: (await rpc('get', ['nope'])) ?? null, wallet: await rpc('wallet') };
    });
    check(before.name === 'Mary' && before.greeting === 'hello from wasm', 'values readable in the same session');
    check(before.missing === null, 'absent key returns undefined/null');

    console.error('• the persisted snapshot is encrypted at rest (not raw identity)');
    const snap = await page.evaluate(async () => {
      const db = await new Promise((res, rej) => { const r = indexedDB.open('mycellium', 1); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
      const get = (k) => new Promise((res) => { const g = db.transaction('state', 'readonly').objectStore('state').get(k); g.onsuccess = () => res(g.result ?? null); g.onerror = () => res(null); });
      const s = await get('snapshot');
      const key = await get('wrapkey');
      return { hasIv: !!(s && s.iv), hasCt: !!(s && s.ct), isRawBuffer: s instanceof ArrayBuffer || s instanceof Uint8Array, keyExtractable: key ? key.extractable : null };
    });
    check(snap.hasIv && snap.hasCt && !snap.isRawBuffer, 'snapshot is AES-GCM ciphertext (iv+ct), not plaintext identity bytes');
    check(snap.keyExtractable === false, 'the wrapping key is stored non-extractable');

    console.error('• the worker RPC only honors allowlisted ops');
    const guard = await page.evaluate(async () => {
      const tryOp = async (op) => { try { await window.mycellium.rpc(op, []); return 'ok'; } catch { return 'rejected'; } };
      return { exp: await tryOp('export'), proto: await tryOp('__proto__'), bogus: await tryOp('nope'), wallet: await tryOp('wallet') };
    });
    check(guard.exp === 'rejected', "'export' is not reachable over RPC");
    check(guard.proto === 'rejected' && guard.bogus === 'rejected', 'unknown / prototype ops are rejected');
    check(guard.wallet === 'ok', 'an allowlisted op still works');

    console.error('• reload the page — a fresh WASM instance restores from IndexedDB');
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.mycellium?.rpc !== undefined, { timeout: 15000 });
    const after = await page.evaluate(async () => ({
      name: await window.mycellium.rpc('get', ['name']),
      greeting: await window.mycellium.rpc('get', ['greeting']),
      wallet: await window.mycellium.rpc('wallet'),
    }));
    check(after.name === 'Mary', 'value survived the reload (loaded from IndexedDB)');
    check(after.greeting === 'hello from wasm', 'second value survived too');
    check(!!before.wallet && before.wallet === after.wallet, `the device identity is the SAME after reload (${after.wallet.slice(0, 12)}…)`);

    console.error("• the engine's own history module runs against the browser store");
    const thread = await page.evaluate(async () => {
      const rpc = window.mycellium.rpc;
      await rpc('add_message', ['bob', 'hi bob', true]);
      await rpc('add_message', ['bob', 'hey!', false]);
      return JSON.parse(await rpc('thread', ['bob']));
    });
    check(thread.length === 2, 'two messages stored via engine::history');
    check(thread[0].text === 'hi bob' && thread[0].from_me === true, 'sent message fields correct');
    check(thread[1].from_me === false, 'received message flagged');
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.mycellium?.rpc !== undefined, { timeout: 15000 });
    const threadAfter = await page.evaluate(async () => JSON.parse(await window.mycellium.rpc('thread', ['bob'])));
    check(threadAfter.length === 2, 'conversation survived reload (engine history + IndexedDB)');

    console.error('• expired (disappearing) messages drop out of the thread + list views');
    const exp = await page.evaluate(async () => {
      const rpc = window.mycellium.rpc;
      await rpc('add_message', ['dave', 'still here', true]);      // no expiry
      await rpc('add_message', ['dave', 'poof', true, 1n]);        // expires_at = 1 (long past); u64 → BigInt
      const thread = JSON.parse(await rpc('thread', ['dave'])).map((m) => m.text);
      const list = JSON.parse(await rpc('peers')).find((p) => p.peer === 'dave');
      return { thread, listLast: list ? list.last : null };
    });
    check(exp.thread.includes('still here') && !exp.thread.includes('poof'), 'an expired message is pruned from the thread view');
    check(exp.listLast === 'still here', 'the conversation list shows the last non-expired message');

    console.error('• delete persists as well');
    const afterDel = await page.evaluate(async () => {
      await window.mycellium.rpc('del', ['greeting']);
      return (await window.mycellium.rpc('get', ['greeting'])) ?? null;
    });
    check(afterDel === null, 'deleted key is gone');
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.waitForFunction(() => window.mycellium?.rpc !== undefined, { timeout: 15000 });
    const gone = await page.evaluate(async () => (await window.mycellium.rpc('get', ['greeting'])) ?? null);
    check(gone === null, 'deletion survived the reload');
  } finally {
    await browser.close();
    server.close();
  }
}

main()
  .then(() => { console.error(failed ? '\nFAILED' : '\nALL PASSED'); process.exit(failed ? 1 : 0); })
  .catch((e) => { console.error('\nERROR:', e.message); process.exit(1); });
