const CACHE_NAME = 'multi-ai-cache-v1';
const CACHE_URLS = [
  './index.html',
  './manifest.json'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(CACHE_URLS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  // শুধু same-origin GET request cache হবে (app shell)।
  // Render backend-এর কোনো API call কখনো cache হবে না —
  // ওগুলো (chat, auth, memory, search) সবসময় fresh network call হতে হবে।
  const url = new URL(event.request.url);
  const isApiCall = url.origin.includes('onrender.com');

  if (event.request.method !== 'GET' || isApiCall) {
    return; // সরাসরি network-এ যাবে, cache হবে না
  }

  event.respondWith(
    caches.match(event.request).then((cached) => {
      return cached || fetch(event.request);
    })
  );
});