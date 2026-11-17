/* Service worker (English edition): makes the app files available offline. CVE APIs are not cached. */
const CACHE = 'otrisk-en-v2';
const ASSETS = ['./', 'index.html', 'guide.html', 'legal.html', '../css/styles.css', 'js/risk.js', 'js/mitigations.js', 'js/api.js', 'js/local.js', 'js/cyclonedx.js', 'js/demo.js', 'js/app.js', 'manifest.webmanifest', '../icons/icon.svg', '../icons/icon-180.png', '../icons/icon-192.png', '../icons/icon-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  // Only remove older caches of this edition – the German edition keeps its own cache
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k.startsWith('otrisk-en-') && k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.origin !== location.origin || e.request.method !== 'GET') return;
  if (url.pathname.includes('/api/')) return; // local helper: never cache
  // Network first so updates arrive at once; offline from the cache
  e.respondWith(
    fetch(e.request, { cache: 'no-cache' }).then(r => { const copy = r.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); return r; })
      .catch(() => caches.match(e.request).then(r => r || caches.match('index.html')))
  );
});
