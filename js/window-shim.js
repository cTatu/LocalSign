// js/window-shim.js
// Node/test-env compat: lib/forge.min.js UMD invokes its IIFE with `window`.
// In browsers globalThis.window already exists (no-op). In Node/vitest it does
// not, so alias it to globalThis BEFORE forge evaluates (import order matters:
// this module must be imported before '../lib/forge.min.js').
if (typeof globalThis.window === 'undefined') globalThis.window = globalThis;
