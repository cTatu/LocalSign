// js/forge-shim.js
import '../lib/forge.min.js';
export const forge = globalThis.forge;
if (!forge || !forge.pkcs7) throw new Error('FORGE_UMD_NOT_LOADED');
