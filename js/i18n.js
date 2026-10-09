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
  privacy: 'Tus claves y documentos nunca salen de esta pestaña. Lo único que se consulta por internet es si tu certificado sigue vigente, sin enviar nada privado.',
  badge_free: 'Gratis siempre',
  badge_nolimit: 'Sin límites',
  badge_local: '100% local',
  s1: '1. Documento',
  s1_file: 'Archivo PDF',
  s2: '2. Certificado',
  s2_cert: 'Archivo .p12 / .pfx',
  s2_pass: 'Contraseña',
  s2_pass_ph: 'Contraseña del P12',
  choose: 'Elige archivo',
  choose_cert: 'Elige certificado',
  file_none: 'Ningún archivo elegido',
  drop_hint: '…o arrastra tu PDF a esta tarjeta.',
  s3: '3. Vista previa y firma',
  page_label: 'Página',
  hint: 'Mueve el recuadro para colocarlo, tira de su esquina para cambiar su tamaño. Un toque lo centra donde pulses.',
  sign: 'Firmar',
  status_h: 'Estado',
  boot: 'Listo — elige un PDF y tu .p12 para empezar.',
  s4: '4. Verificar',
  v_file: 'PDF firmado a comprobar',
  verify_btn: 'Verificar',
  st_done: 'Hecho.',
  pass_word: 'OK',
  fail_word: 'FALLO',
  na_word: '—',
  verdict_valid: 'Firma válida',
  verdict_invalid: 'Firma inválida',
  verdict_incomplete: 'Sin confirmación completa',
  v_structure: 'Documento firmado legible',
  v_digest: 'Documento intacto',
  v_signer: 'Firmante identificado',
  v_rsa: 'Firma criptográfica válida',
  v_certbind: 'Firma vinculada al certificado',
  v_validity: 'Certificado en vigor',
  v_chain: 'Cadena hasta raíz confiable',
  v_ocsp: 'No revocado (OCSP)',
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
  chk_br: 'Documento intacto',
  chk_br_d: 'el contenido firmado no ha cambiado',
  chk_sub: 'Formato de firma válido',
  chk_sub_d: 'estándar PAdES',
  chk_filter: 'Compatible con tu lector',
  chk_filter_d: 'tu lector de PDF puede abrirlo y verificarlo',
  chk_noocsp: 'Vigencia del certificado',
  chk_noocsp_d: 'la confirma tu lector de PDF al abrirlo',
  precheck_label: 'Auto-revisión rápida (no es el veredicto oficial)',
  faq_title: 'Preguntas frecuentes',
  faq_q1: '¿Es gratis de verdad?',
  faq_a1: 'Sí: gratis siempre, sin límites, sin registro ni tarjeta.',
  faq_q2: '¿AutoFirma no funciona, es una alternativa?',
  faq_a2: 'Sí: sin Java ni instalaciones, todo ocurre en el navegador.',
  faq_q3: '¿Vale para la administración con mi certificado?',
  faq_a3: 'Genera firmas PAdES verificables en Adobe Reader, la misma clase que Autofirma.',
  faq_q4: '¿El PDF y el certificado salen de mi equipo?',
  faq_a4: 'No: solo seriales y hashes viajan para revocación; la clave privada no sale nunca.',
  faq_q5: '¿Qué límites tiene?',
  faq_a5: 'PDF de hasta 25 MB, certificados RSA, una firma por documento. Sin límite de documentos.',
};

const EN = {
  title: 'LocalSign — Sign PDFs locally',
  tagline: 'Sign PDFs in your browser. Nothing leaves this tab.',
  privacy: 'Your keys and documents never leave this tab. The only internet check is whether your certificate is still valid — nothing private is sent.',
  badge_free: 'Free forever',
  badge_nolimit: 'No limits',
  badge_local: '100% local',
  s1: '1. Document',
  s1_file: 'PDF file',
  s2: '2. Certificate',
  s2_cert: '.p12 / .pfx file',
  s2_pass: 'Password',
  s2_pass_ph: 'P12 password',
  choose: 'Choose file',
  choose_cert: 'Choose certificate',
  file_none: 'No file chosen',
  drop_hint: '…or drag & drop your PDF anywhere on this card.',
  s3: '3. Preview & sign',
  page_label: 'Page',
  hint: 'Move the box to place it, pull its corner to resize. Tap to center it where you touch.',
  sign: 'Sign',
  status_h: 'Status',
  boot: 'Ready — select a PDF and your .p12 to begin.',
  s4: '4. Verify',
  v_file: 'Signed PDF to check',
  verify_btn: 'Verify',
  st_done: 'Done.',
  pass_word: 'PASS',
  fail_word: 'FAIL',
  na_word: '—',
  verdict_valid: 'Valid signature',
  verdict_invalid: 'Invalid signature',
  verdict_incomplete: 'Cannot fully confirm',
  v_structure: 'Signed document readable',
  v_digest: 'Document intact',
  v_signer: 'Signer identified',
  v_rsa: 'Cryptographic signature valid',
  v_certbind: 'Signature bound to certificate',
  v_validity: 'Certificate in validity period',
  v_chain: 'Chain to trusted root',
  v_ocsp: 'Not revoked (OCSP)',
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
  chk_br: 'Document intact',
  chk_br_d: 'signed content unchanged',
  chk_sub: 'Valid signature format',
  chk_sub_d: 'PAdES standard',
  chk_filter: 'Reader compatible',
  chk_filter_d: 'your PDF reader can open and verify it',
  chk_noocsp: 'Certificate status',
  chk_noocsp_d: 'confirmed by your PDF reader when opened',
  precheck_label: 'Quick self-check (not the official verdict)',
  faq_title: 'Frequently asked questions',
  faq_q1: 'Is it really free?',
  faq_a1: 'Yes: free forever, no limits, no signup, no card.',
  faq_q2: 'AutoFirma fails — is this an alternative?',
  faq_a2: 'Yes: no Java, no installers, everything runs in the browser.',
  faq_q3: 'Does it work with my certificate for official procedures?',
  faq_a3: 'It produces PAdES signatures verifiable in Adobe Reader, the same class AutoFirma makes.',
  faq_q4: 'Do my PDF and certificate leave my device?',
  faq_a4: 'No: only serials and hashes travel for revocation; the private key never leaves.',
  faq_q5: 'What are the limits?',
  faq_a5: 'PDFs up to 25 MB, RSA certificates, one signature per document. No document limit.',
};

const CA = {
  title: 'LocalSign — Signa PDF en local',
  tagline: 'Signa PDF al navegador. Res no surt d\u2019aquesta pestanya.',
  privacy: 'Les claus i els documents no surten mai d\u2019aquesta pestanya. L\u2019única comprovació per internet és si el teu certificat continua vigent, sense enviar res privat.',
  badge_free: 'Gratis sempre',
  badge_nolimit: 'Sense límits',
  badge_local: '100% local',
  s1: '1. Document',
  s1_file: 'Fitxer PDF',
  s2: '2. Certificat',
  s2_cert: 'Fitxer .p12 / .pfx',
  s2_pass: 'Contrasenya',
  s2_pass_ph: 'Contrasenya del P12',
  choose: 'Tria el fitxer',
  choose_cert: 'Tria el certificat',
  file_none: 'Cap fitxer triat',
  drop_hint: '…o arrossega el PDF a aquesta targeta.',
  s3: '3. Previsualització i signatura',
  page_label: 'Pàgina',
  hint: 'Mou el requadre per col·locar-lo, estira la cantonada per canviar la mida. Toca per centrar-lo on premis.',
  sign: 'Signa',
  status_h: 'Estat',
  boot: 'A punt — tria un PDF i el teu .p12 per començar.',
  s4: '4. Verifica',
  v_file: 'PDF signat a comprovar',
  verify_btn: 'Verifica',
  st_done: 'Fet.',
  pass_word: 'OK',
  fail_word: 'FALLA',
  na_word: '—',
  verdict_valid: 'Signatura vàlida',
  verdict_invalid: 'Signatura invàlida',
  verdict_incomplete: 'Sense confirmació completa',
  v_structure: 'Document signat llegible',
  v_digest: 'Document intacte',
  v_signer: 'Signant identificat',
  v_rsa: 'Signatura criptogràfica vàlida',
  v_certbind: 'Signatura vinculada al certificat',
  v_validity: 'Certificat en vigor',
  v_chain: 'Cadena fins a arrel confiable',
  v_ocsp: 'No revocat (OCSP)',
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
  chk_br: 'Document intacte',
  chk_br_d: 'el contingut signat no ha canviat',
  chk_sub: 'Format de signatura vàlid',
  chk_sub_d: 'estàndard PAdES',
  chk_filter: 'Compatible amb el lector',
  chk_filter_d: 'el teu lector de PDF el pot obrir i verificar',
  chk_noocsp: 'Estat del certificat',
  chk_noocsp_d: 'el confirma el teu lector de PDF en obrir-lo',
  precheck_label: 'Auto-revisió ràpida (no és el veredicte oficial)',
  faq_title: 'Preguntes freqüents',
  faq_q1: 'És gratis de veritat?',
  faq_a1: 'Sí: gratis sempre, sense límits, sense registre ni targeta.',
  faq_q2: 'L\u2019Autofirma no funciona, és una alternativa?',
  faq_a2: 'Sí: sense Java ni instal·lacions, tot passa al navegador.',
  faq_q3: 'Val per a l\u2019administració amb el meu certificat?',
  faq_a3: 'Genera signatures PAdES verificables a l\u2019Adobe Reader, la mateixa classe que l\u2019Autofirma.',
  faq_q4: 'El PDF i el certificat surten del meu equip?',
  faq_a4: 'No: només serials i hashes viatgen per a revocació; la clau privada no surt mai.',
  faq_q5: 'Quins límits té?',
  faq_a5: 'PDF de fins a 25 MB, certificats RSA, una signatura per document. Sense límit de documents.',
};

export const STRINGS = { es: ES, en: EN, ca: CA };

let current = 'en';

export function pickLang(stored, navLang, urlLang) {
  if (urlLang && LANGS.includes(urlLang)) return urlLang;
  if (stored && LANGS.includes(stored)) return stored;
  const base = (navLang || '').split('-')[0].toLowerCase();
  if (base === 'ca') return 'ca';
  if (base === 'es') return 'es';
  return 'en';
}

export function detectLang() {
  let stored = null;
  let nav = '';
  let url = null;
  try {
    if (typeof localStorage !== 'undefined') stored = localStorage.getItem('localsign-lang');
  } catch { /* private mode */ }
  if (typeof navigator !== 'undefined') nav = navigator.language || '';
  try {
    if (typeof window !== 'undefined' && window.location && window.location.search) {
      url = new URLSearchParams(window.location.search).get('lang');
    }
  } catch { /* non-browser */ }
  return pickLang(stored, nav, url);
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
  const faq = document.getElementById('faq-ld');
  if (faq) {
    const qa = [1, 2, 3, 4, 5].map((n) => ({
      '@type': 'Question',
      name: t(`faq_q${n}`),
      acceptedAnswer: { '@type': 'Answer', text: t(`faq_a${n}`) },
    }));
    faq.textContent = JSON.stringify({
      '@context': 'https://schema.org',
      '@type': 'FAQPage',
      mainEntity: qa,
    });
  }
}

export function initLang() {
  current = detectLang();
  applyI18n();
}
