/* Minimal service worker: registers successfully without caching or
   intercepting requests. The template registers /sw.js on load; without this
   file the browser logs a 404 page error. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', () => self.clients.claim());
