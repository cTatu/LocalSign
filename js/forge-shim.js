// js/forge-shim.js
import './window-shim.js';
import forgeCjs from '../lib/forge.min.js';
import '../lib/forge.min.js';
// Browser (classic <script> or ESM side-effect): forge lands on window/globalThis.
// Vitest/Vite (CJS interop): the UMD takes the module.exports branch, so the
// forge object arrives as the default import instead of a global.
export const forge = forgeCjs ?? globalThis.forge;
if (!forge || !forge.pkcs7) throw new Error('FORGE_UMD_NOT_LOADED');
