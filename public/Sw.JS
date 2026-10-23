// Service worker: shows push notifications even when the staff page is closed
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

self.addEventListener('push', (event) => {
  let d = {};
  try {
    d = event.data ? event.data.json() : {};
  } catch (_) {
    d = { title: 'إشعار جديد', body: event.data ? event.data.text() : '' };
  }
  event.waitUntil(
    self.registration.showNotification(d.title || 'ريلاكس سبا', {
      body: d.body || '',
      tag: d.tag || 'booking',
      renotify: true,
      requireInteraction: true,
      dir: 'rtl',
      lang: 'ar',
      vibrate: [300, 150, 300, 150, 300],
      data: { url: d.url || '/staff' }
    })
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/staff';
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
      for (const c of list) {
        if (c.url.includes('/staff') && 'focus' in c) return c.focus();
      }
      return self.clients.openWindow(url);
    })
  );
});