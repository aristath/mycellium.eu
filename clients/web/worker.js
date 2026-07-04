// The Mycellium engine runs here, off the UI thread, so its synchronous network
// (XHR) and crypto never freeze the page. The UI talks to it by RPC: it posts
// {id, op, args}; we run session[op](...args) and post back {id, ok, result}.
// This worker also owns durability (IndexedDB), persisting after any mutation.
import init, * as W from './pkg/mycellium_wasm.js';

const DB = 'mycellium';
const idb = () => new Promise((res, rej) => {
  const r = indexedDB.open(DB, 1);
  r.onupgradeneeded = () => r.result.createObjectStore('state');
  r.onsuccess = () => res(r.result);
  r.onerror = () => rej(r.error);
});
const load = async () => {
  const db = await idb();
  return new Promise((res) => { const tx = db.transaction('state', 'readonly'); const g = tx.objectStore('state').get('snapshot'); g.onsuccess = () => res(g.result || null); g.onerror = () => res(null); });
};
const save = async (bytes) => {
  const db = await idb();
  return new Promise((res) => { const tx = db.transaction('state', 'readwrite'); tx.objectStore('state').put(bytes, 'snapshot'); tx.oncomplete = res; tx.onerror = res; });
};

// Ops that only read never need a persist afterwards.
const READS = new Set(['peers', 'groups', 'thread', 'group_thread', 'wallet', 'file', 'name_of', 'get', 'push_key', 'export', 'version']);

let session = null;
const ready = (async () => {
  await init();
  const snap = await load();
  session = snap ? W.Session.restore(new Uint8Array(snap)) : new W.Session();
  if (!snap) await save(session.export());
})();

self.onmessage = async (e) => {
  const { id, op, args } = e.data;
  try {
    await ready;
    const result = session[op](...(args || []));
    if (!READS.has(op)) await save(session.export());
    self.postMessage({ id, ok: true, result });
  } catch (err) {
    self.postMessage({ id, ok: false, err: String((err && err.message) || err) });
  }
};
