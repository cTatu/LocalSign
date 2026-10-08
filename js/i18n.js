// js/i18n.js — ES/EN/CA strings, language state, DOM application.
//
// Every user-visible string lives here (static UI, stages, error codes,
// verification labels). Error *codes* double as dict keys, so app.js renders
// t(code) with the current language.
export const LANGS = ['es', 'en', 'ca'];
const FALLBACK = 'en';

const ES = {
  title: 'LocalSign — Firma PDF en local',
  tagline: 'Firma PDF en tu navegador. Nada sale de esta pestaña.',
  privacy: 'Tus claves y documentos nunca salen de esta pestaña. Las únicas llamadas de red son consultas de revocación/sello de tiempo al mismo origen (solo seriales y hashes — nunca claves ni documentos). La comprobación interna es orientativa: la válida es Adobe Reader.',
  badge_free: 'Gratis siempre',
  badge_nolimit: 'Sin límites',
  badge_local: '100% local',
  s1: '1. Documento',
  s1_file: 'Archivo PDF',
  s2: '2. Certificado',
  s2_cert: 'Archivo .p12 / .pfx',
  s2_pass: 'Contraseña',
  s2_pass_ph: 'Contraseña del P12',
  s3: '3. Vista previa y firma',
  page_label: 'Página',
  hint: 'Arrastra un rectángulo en la vista previa para la zona de firma. Un clic coloca un recuadro estándar. Si no eliges nada, se usa la esquina inferior derecha.',
  sign: 'Firmar',
  status_h: 'Estado',
  boot: 'Listo — elige un PDF y tu .p12 para empezar.',
  st_reading: 'Leyendo PDF',
  st_preview: 'Mostrando vista previa',
  st_cert: 'Leyendo certificado',
  st_appear: 'Preparando apariencia',
  st_build: 'Construyendo firma',
  st_hash: 'Calculando hash',
  st_sign: 'Firmando',
  st_verify: 'Verificando y descargando',
  FILE_TOO_LARGE: 'El archivo supera el límite de 25 MB.',
  DOCX_DEFERRED: 'La firma .docx llegará en fase 2 — MVP solo PDF.',
  ENCRYPTED_NOT_SUPPORTED: 'PDF cifrados no soportados en el MVP.',
  ALREADY_SIGNED: 'Ya firmado — multifirma fuera de alcance.',
  CERTIFIED_NOT_SUPPORTED: 'PDF certificados no soportados en el MVP.',
  ROTATED_NOT_SUPPORTED: 'Páginas rotadas no soportadas — aplana a 0° y reintenta.',
  BAD_PASSWORD_OR_CORRUPT_P12: 'Contraseña incorrecta o .p12 corrupto — inténtalo de nuevo.',
  EC_NOT_SUPPORTED_MVP: 'Certificados EC no soportados en el MVP (solo RSA).',
  SIGNATURE_TOO_LARGE: 'La firma supera el hueco de 16 KB — abortando.',
  NO_FILE: 'Elige primero un PDF.',
  INSECURE_CONTEXT: 'Ábrelo vía http://localhost:8000 o https (file:// no soportado).',
  warn_expired: 'Aviso: certificado fuera de validez — continuando.\n',
  fail_template: 'Fallo en el paso "{stage}": {n}: {m}',
  signed_by: 'Firmado por {n} (reloj local, sin verificar)',
  chk_br: 'ByteRange presente + 4.º == Z-Y',
  chk_br_d: 'el 4.º valor debe ser Z-Y',
  chk_sub: 'SubFilter adbe.pkcs7.detached',
  chk_sub_d: 'requerido para PAdES',
  chk_filter: 'Filter Adobe.PPKLite',
  chk_filter_d: 'requerido',
  chk_noocsp: 'Revocación (OCSP)',
  chk_noocsp_d: 'la comprueba Adobe Reader, no esta página',
  precheck_label: 'Pre-comprobación — la decisión de confianza es Adobe Reader',
};

const EN = {
  title: 'LocalSign — Sign PDFs locally',
  tagline: 'Sign PDFs in your browser. Nothing leaves this tab.',
  privacy: 'Keys and documents never leave this tab. The only network calls are same-origin revocation/timestamp lookups (certificate serials and hashes only — never keys or documents). The in-page check is a pre-check only — trust Adobe Reader.',
  badge_free: 'Free forever',
  badge_nolimit: 'No limits',
  badge_local: '100% local',
  s1: '1. Document',
  s1_file: 'PDF file',
  s2: '2. Certificate',
  s2_cert: '.p12 / .pfx file',
  s2_pass: 'Password',
  s2_pass_ph: 'P12 password',
  s3: '3. Preview & sign',
  page_label: 'Page',
  hint: 'Drag a rectangle on the preview for the signature zone. A simple click places a default-size box. Leave it to use the bottom-right corner.',
  sign: 'Sign',
  status_h: 'Status',
  boot: 'Ready — select a PDF and your .p12 to begin.',
  st_reading: 'Reading PDF',
  st_preview: 'Rendering preview',
  st_cert: 'Reading certificate',
  st_appear: 'Preparing appearance',
  st_build: 'Building signature',
  st_hash: 'Hashing document',
  st_sign: 'Signing',
  st_verify: 'Verifying and downloading',
  FILE_TOO_LARGE: 'File exceeds 25MB limit.',
  DOCX_DEFERRED: '.docx signing lands in Phase 2 — MVP is PDF-only.',
  ENCRYPTED_NOT_SUPPORTED: 'Encrypted PDFs not supported in MVP.',
  ALREADY_SIGNED: 'Already signed — multi-signer out of scope.',
  CERTIFIED_NOT_SUPPORTED: 'Certified PDFs not supported in MVP.',
  ROTATED_NOT_SUPPORTED: 'Rotated pages not supported — flatten to 0° and retry.',
  BAD_PASSWORD_OR_CORRUPT_P12: 'Wrong password or corrupt .p12 — try again.',
  EC_NOT_SUPPORTED_MVP: 'EC certificates not supported in MVP (RSA only).',
  SIGNATURE_TOO_LARGE: 'Signature exceeds 16KB placeholder — aborting.',
  NO_FILE: 'Select a PDF first.',
  INSECURE_CONTEXT: 'Open via http://localhost:8000 or https (file:// unsupported).',
  warn_expired: 'Warning: cert outside validity — proceeding.\n',
  fail_template: 'Failed at step "{stage}": {n}: {m}',
  signed_by: 'Signed by {n} (client clock, unverified)',
  chk_br: 'ByteRange present + 4th==Z-Y',
  chk_br_d: '4th value must equal Z-Y',
  chk_sub: 'SubFilter adbe.pkcs7.detached',
  chk_sub_d: 'required for PAdES',
  chk_filter: 'Filter Adobe.PPKLite',
  chk_filter_d: 'required',
  chk_noocsp: 'Revocation (OCSP)',
  chk_noocsp_d: 'checked by Adobe Reader, not in-page',
  precheck_label: 'Pre-check only — trust decision is Adobe Reader',
};

const CA = {
  title: 'LocalSign — Signa PDF en local',
  tagline: 'Signa PDF al navegador. Res no surt d\u2019aquesta pestanya.',
  privacy: 'Les claus i els documents no surten mai d\u2019aquesta pestanya. Les úniques crides de xarxa són consultes de revocació/segellat al mateix origen (només serials i hashes — mai claus ni documents). La comprovació interna és orientativa: la vàlida és l\u2019Adobe Reader.',
  badge_free: 'Gratis sempre',
  badge_nolimit: 'Sense límits',
  badge_local: '100% local',
  s1: '1. Document',
  s1_file: 'Fitxer PDF',
  s2: '2. Certificat',
  s2_cert: 'Fitxer .p12 / .pfx',
  s2_pass: 'Contrasenya',
  s2_pass_ph: 'Contrasenya del P12',
  s3: '3. Previsualització i signatura',
  page_label: 'Pàgina',
  hint: 'Arrossega un rectangle a la previsualització per a la zona de signatura. Un clic col·loca un requadre estàndard. Si no tries res, s\u2019usa la cantonada inferior dreta.',
  sign: 'Signa',
  status_h: 'Estat',
  boot: 'A punt — tria un PDF i el teu .p12 per començar.',
  st_reading: 'Llegint el PDF',
  st_preview: 'Mostrant la previsualització',
  st_cert: 'Llegint el certificat',
  st_appear: 'Preparant l\u2019aparença',
  st_build: 'Construint la signatura',
  st_hash: 'Calculant el hash',
  st_sign: 'Signant',
  st_verify: 'Verificant i descarregant',
  FILE_TOO_LARGE: 'El fitxer supera el límit de 25 MB.',
  DOCX_DEFERRED: 'La signatura .docx arribarà a la fase 2 — MVP només PDF.',
  ENCRYPTED_NOT_SUPPORTED: 'PDF xifrats no suportats a l\u2019MVP.',
  ALREADY_SIGNED: 'Ja signat — multifirma fora d\u2019abast.',
  CERTIFIED_NOT_SUPPORTED: 'PDF certificats no suportats a l\u2019MVP.',
  ROTATED_NOT_SUPPORTED: 'Pàgines rotades no suportades — aplaneu a 0° i reintenteu.',
  BAD_PASSWORD_OR_CORRUPT_P12: 'Contrasenya incorrecta o .p12 corrupte — torneu-ho a provar.',
  EC_NOT_SUPPORTED_MVP: 'Certificats EC no suportats a l\u2019MVP (només RSA).',
  SIGNATURE_TOO_LARGE: 'La signatura supera el forat de 16 KB — avortant.',
  NO_FILE: 'Trieu primer un PDF.',
  INSECURE_CONTEXT: 'Obriu via http://localhost:8000 o https (file:// no suportat).',
  warn_expired: 'Avís: certificat fora de validesa — continuant.\n',
  fail_template: 'Error al pas "{stage}": {n}: {m}',
  signed_by: 'Signat per {n} (rellotge local, sense verificar)',
  chk_br: 'ByteRange present + 4t == Z-Y',
  chk_br_d: 'el 4t valor ha de ser Z-Y',
  chk_sub: 'SubFilter adbe.pkcs7.detached',
  chk_sub_d: 'requerit per a PAdES',
  chk_filter: 'Filter Adobe.PPKLite',
  chk_filter_d: 'requerit',
  chk_noocsp: 'Revocació (OCSP)',
  chk_noocsp_d: 'la comprova l\u2019Adobe Reader, no aquesta pàgina',
  precheck_label: 'Pre-comprovació — la decisió de confiança és l\u2019Adobe Reader',
};

export const STRINGS = { es: ES, en: EN, ca: CA };

let current = 'en';

export function detectLang() {
  try {
    const stored = typeof localStorage !== 'undefined' && localStorage.getItem('localsign-lang');
    if (stored && LANGS.includes(stored)) return stored;
  } catch { /* private mode */ }
  const nav = typeof navigator !== 'undefined' ? (navigator.language || '') : '';
  const base = nav.split('-')[0].toLowerCase();
  if (base === 'ca') return 'ca';
  if (base === 'es') return 'es';
  return 'en';
}

export function getLang() {
  return current;
}

export function t(key) {
  return (STRINGS[current] && STRINGS[current][key]) ?? STRINGS[FALLBACK][key] ?? key;
}

export function tx(key, vars) {
  let s = t(key);
  for (const [k, v] of Object.entries(vars || {})) s = s.replace(`{${k}}`, String(v));
  return s;
}

export function setLang(lang) {
  if (!LANGS.includes(lang)) return;
  current = lang;
  try {
    if (typeof localStorage !== 'undefined') localStorage.setItem('localsign-lang', lang);
  } catch { /* private mode */ }
  applyI18n();
}

export function applyI18n() {
  if (typeof document === 'undefined') return;
  document.documentElement.lang = current;
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    el.textContent = t(el.getAttribute('data-i18n'));
  });
  document.querySelectorAll('[data-i18n-ph]').forEach((el) => {
    el.setAttribute('placeholder', t(el.getAttribute('data-i18n-ph')));
  });
  document.querySelectorAll('[data-lang-btn]').forEach((b) => {
    const active = b.getAttribute('data-lang-btn') === current;
    b.classList.toggle('active', active);
    b.setAttribute('aria-pressed', active ? 'true' : 'false');
  });
}

export function initLang() {
  current = detectLang();
  applyI18n();
}
