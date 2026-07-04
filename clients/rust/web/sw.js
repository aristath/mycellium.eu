// Minimal service worker: cache the app shell for offline load. The API is
// never cached — it always hits the local server.
const CACHE = 'mycellium-v1';
const SHELL = ['/', '/index.html', '/styles.css', '/app.js', '/icon.svg', '/manifest.webmanifest'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
  );
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (url.pathname.startsWith('/api/')) return; // API is always live
  e.respondWith(caches.match(e.request).then((r) => r || fetch(e.request)));
});

// Web Push: a contentless wake. Show a generic notification (no sender/content
// travels through the push service) and let the app sync when reopened.
self.addEventListener('push', (e) => {
  e.waitUntil(self.registration.showNotification('Mycellium', {
    body: 'You have a new message',
    icon: '/icon.svg',
    tag: 'mycellium-msg',
  }));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((cs) => {
    for (const c of cs) { if ('focus' in c) return c.focus(); }
    return self.clients.openWindow ? self.clients.openWindow('/') : undefined;
  }));
});
