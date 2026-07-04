// Minimal app-shell cache so Mycellium opens offline. Network-first for the
// WASM/JS bundle (so updates land), cache fallback when offline.
const CACHE = 'mycellium-shell-v1';
const SHELL = ['./', './index.html', './manifest.json', './icon.svg',
  './pkg/mycellium_wasm.js', './pkg/mycellium_wasm_bg.wasm'];

self.addEventListener('install', (e) => { e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).catch(() => {})); self.skipWaiting(); });
self.addEventListener('activate', (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))); self.clients.claim(); });
// Contentless wake from the queue → show a generic notification (the message
// itself is fetched + decrypted in-app; the server never sees it).
self.addEventListener('push', (e) => {
  e.waitUntil(self.registration.showNotification('Mycellium', { body: 'New message', tag: 'mycellium-push', icon: './icon.svg' }));
});
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window' }).then((cs) => (cs[0] ? cs[0].focus() : self.clients.openWindow('./'))));
});

self.addEventListener('fetch', (e) => {
  if (e.request.method !== 'GET') return;
  e.respondWith(
    fetch(e.request).then((r) => { const cp = r.clone(); caches.open(CACHE).then((c) => c.put(e.request, cp)).catch(() => {}); return r; })
      .catch(() => caches.match(e.request).then((m) => m || caches.match('./index.html')))
  );
});
