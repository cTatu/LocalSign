// js/forge-shim.js
import './window-shim.js';
import forgeCjs from '../lib/forge.min.js';
import '../lib/forge.min.js';
// Browser (classic <script> or ESM side-effect): forge lands on window/globalThis.
// Vitest/Vite (CJS interop): the UMD takes the module.exports branch, so the
// forge object arrives as the default import instead of a global.
export const forge = forgeCjs ?? globalThis.forge;
if (!forge || !forge.pkcs7) throw new Error('FORGE_UMD_NOT_LOADED');
// Test-env repair (vitest/vite): the UMD's node-crypto branch can resolve to a
// browser shim without randomBytes, breaking forge.random seedFileSync and all
// sync keygen. Probe once; if broken, rewire the shared instance to WebCrypto.
try {
  forge.random.getBytesSync(1);
} catch {
  const randStr = (n) => {
    const arr = new Uint8Array(n);
    if (globalThis.crypto?.getRandomValues) globalThis.crypto.getRandomValues(arr);
    else for (let i = 0; i < n; i++) arr[i] = Math.floor(256 * Math.random());
    let s = '';
    for (let i = 0; i < n; i++) s += String.fromCharCode(arr[i]);
    return s;
  };
  forge.random.seedFileSync = (n) => randStr(n);
  forge.random.seedFile = (n, cb) => {
    try { cb(null, randStr(n)); } catch (e) { cb(e); }
  };
}
