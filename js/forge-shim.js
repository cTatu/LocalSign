// js/forge-shim.js
import './window-shim.js';
// NOTE: lib/forge.min.js is pure UMD with no ESM exports. A static default
// import (`import forgeCjs from ...`) works under Vite CJS interop but throws
// SyntaxError in real browsers, killing the whole module graph. A dynamic
// import instead: browsers execute the UMD (it assigns window.forge via the
// classic `<script>`-equivalent path) and resolve an empty namespace, while
// Vite interops the CJS default export. Top-level await is fine (min
// Chrome/Edge 120+, Firefox 120+, Safari 17+).
const mod = await import('../lib/forge.min.js');
// Browser (classic <script> or UMD side-effect): forge lands on window/globalThis.
// Vitest/Vite (CJS interop): the forge object arrives as the default export.
export const forge = mod.default ?? globalThis.forge;
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
