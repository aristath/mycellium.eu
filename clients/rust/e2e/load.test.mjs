// T2.4 load check: hammer the directory with many concurrent requests and
// confirm the worker pool serves them without dropping any, reporting throughput
// and latency percentiles. This validates the Tier-0.2 concurrency work under
// real load. (Loopback + Node fetch, so absolute numbers are conservative — the
// assertions are about *no drops*, not a specific req/s.)
//
// Run:  node clients/rust/e2e/load.test.mjs   (needs: cargo build)

import { spawn } from 'node:child_process';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const BIN = (n) => path.join(ROOT, 'target/debug', n);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const TOTAL = 4000;
const CONCURRENCY = 64;

const procs = [];
function freePort() { return new Promise((res) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => res(p)); }); }); }
async function waitHttp(u, ms = 10000) { const e = Date.now() + ms; while (Date.now() < e) { try { const r = await fetch(u); if (r.status < 500) return; } catch {} await sleep(150); } throw new Error('timeout ' + u); }

let failed = false;
const check = (cond, m) => { console.error((cond ? '  ✓ ' : '  ✗ ') + m); if (!cond) failed = true; };
const pct = (arr, p) => arr[Math.min(arr.length - 1, Math.floor((p / 100) * arr.length))];

async function runPool(total, concurrency, task) {
  let next = 0, errors = 0;
  const lat = [];
  const worker = async () => {
    while (true) {
      const i = next++;
      if (i >= total) return;
      const t0 = performance.now();
      try { await task(i); lat.push(performance.now() - t0); }
      catch { errors++; }
    }
  };
  await Promise.all(Array.from({ length: concurrency }, worker));
  return { lat, errors };
}

async function main() {
  if (!fs.existsSync(BIN('mycellium-server'))) throw new Error('run: cargo build');
  const dp = await freePort();
  const dir = `http://127.0.0.1:${dp}`;
  procs.push(spawn(BIN('mycellium-server'), ['--addr', `127.0.0.1:${dp}`], { stdio: 'ignore' }));
  await waitHttp(dir + '/health');

  // Warm up.
  await runPool(200, 16, () => fetch(dir + '/health'));

  console.error(`• ${TOTAL} lookups at concurrency ${CONCURRENCY}`);
  const started = performance.now();
  const { lat, errors } = await runPool(TOTAL, CONCURRENCY, async (i) => {
    // Random non-existent handle → 404 (exercises routing + the worker pool).
    const r = await fetch(`${dir}/records/${(i * 2654435761 >>> 0).toString(16).padStart(8, '0')}`);
    if (r.status >= 500) throw new Error('5xx');
    await r.text();
  });
  const secs = (performance.now() - started) / 1000;
  lat.sort((a, b) => a - b);
  const rps = Math.round((TOTAL - errors) / secs);

  console.error(`  throughput: ${rps} req/s over ${secs.toFixed(2)}s`);
  console.error(`  latency ms: p50 ${pct(lat, 50).toFixed(1)} · p95 ${pct(lat, 95).toFixed(1)} · p99 ${pct(lat, 99).toFixed(1)} · max ${lat[lat.length - 1].toFixed(1)}`);

  check(errors === 0, `no dropped/failed requests (${errors} errors)`);
  check(lat.length === TOTAL, `all ${TOTAL} requests got a response`);
  check(rps > 500, `throughput above floor (${rps} req/s > 500)`);

  // The server counted them all.
  const metrics = await (await fetch(dir + '/metrics')).text();
  const counted = Number((metrics.match(/mycellium_requests_total\S* (\d+)/) || [])[1] || 0);
  check(counted >= TOTAL, `/metrics counted the load (${counted} total requests)`);
}

main()
  .then(() => { for (const p of procs) { try { p.kill('SIGKILL'); } catch {} } console.error(failed ? '\nFAILED' : '\nALL PASSED'); process.exit(failed ? 1 : 0); })
  .catch((e) => { for (const p of procs) { try { p.kill('SIGKILL'); } catch {} } console.error('\nERROR:', e.message); process.exit(1); });
