// js/api.js — backend origin + wake-up ping.
//
// The frontend is a static site; the Node backend (OCSP proxy) sleeps on the
// free tier, so the page pings /healthz on boot to wake it before it is
// needed. Override with window.LOCALSIGN_API (e.g. in tests or mirrors).
export const DEFAULT_API = 'https://localsign-api.onrender.com';

export function apiBase() {
  if (typeof window !== 'undefined' && window.LOCALSIGN_API) return window.LOCALSIGN_API;
  return DEFAULT_API;
}

export function apiUrl(path) {
  return apiBase() + path;
}

export function wakeBackend() {
  // no-cors: the response is unreadable, but the request still wakes a
  // sleeping free-tier instance. Never rejects — failure is silent.
  try {
    fetch(apiUrl('/healthz'), { mode: 'no-cors', cache: 'no-store' }).catch(() => {});
  } catch {
    /* non-browser/test env */
  }
}
