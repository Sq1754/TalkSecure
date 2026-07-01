/**
 * Talk-Secure — Service Worker
 * Handles caching for offline shell and push notifications
 */

const CACHE_NAME = 'talk-secure-v2';
const STATIC_ASSETS = [
    '/',
    '/index.html',
    '/css/styles.css',
    '/js/crypto.js',
    '/js/keystore.js',
    '/js/websocket.js',
    '/js/webrtc.js',
    '/js/app.js',
    '/icons/icon-512.png',
    '/manifest.json'
];

// ═══════════════════════════════════════
// Install — cache static assets
// ═══════════════════════════════════════
self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => cache.addAll(STATIC_ASSETS))
            .then(() => self.skipWaiting())
    );
    console.log('📦 Service Worker installed');
});

// ═══════════════════════════════════════
// Activate — clean old caches
// ═══════════════════════════════════════
self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) => {
            return Promise.all(
                keys.filter((key) => key !== CACHE_NAME)
                    .map((key) => caches.delete(key))
            );
        }).then(() => self.clients.claim())
    );
    console.log('✅ Service Worker activated');
});

// ═══════════════════════════════════════
// Fetch — network-first for API, cache-first for assets
// ═══════════════════════════════════════
self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    // Skip non-GET requests and API calls (always go to network)
    if (event.request.method !== 'GET' || url.pathname.startsWith('/api/')) {
        return;
    }

    // For WebSocket upgrades, don't intercept
    if (event.request.headers.get('upgrade') === 'websocket') {
        return;
    }

    event.respondWith(
        // Try network first, fall back to cache
        fetch(event.request)
            .then((response) => {
                // Cache successful responses
                if (response.ok) {
                    const responseClone = response.clone();
                    caches.open(CACHE_NAME).then((cache) => {
                        cache.put(event.request, responseClone);
                    });
                }
                return response;
            })
            .catch(() => {
                // Network failed — serve from cache
                return caches.match(event.request).then((cached) => {
                    return cached || new Response('Offline — please reconnect', {
                        status: 503,
                        headers: { 'Content-Type': 'text/plain' }
                    });
                });
            })
    );
});

// ═══════════════════════════════════════
// Push Notifications (for future use)
// ═══════════════════════════════════════
self.addEventListener('push', (event) => {
    if (!event.data) return;

    const data = event.data.json();
    event.waitUntil(
        self.registration.showNotification(data.title || 'Talk-Secure', {
            body: data.body || 'New encrypted message',
            icon: '/icons/icon-512.png',
            badge: '/icons/icon-512.png',
            tag: 'talk-secure-message',
            vibrate: [200, 100, 200],
            data: { url: '/' }
        })
    );
});

// Open app when notification is clicked
self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true })
            .then((clientList) => {
                // Focus existing window if open
                for (const client of clientList) {
                    if (client.url.includes(self.location.origin)) {
                        return client.focus();
                    }
                }
                // Otherwise open a new window
                return clients.openWindow(event.notification.data?.url || '/');
            })
    );
});
