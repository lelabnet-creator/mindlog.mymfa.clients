/*
 * Coffre chiffré de myMFA (cryptographie uniquement, sans DOM ni WebAuthn).
 *
 *  - Une clé de coffre (DEK) AES-256-GCM aléatoire chiffre les données sensibles.
 *  - La DEK est « enveloppée » (chiffrée) une fois par moyen de déverrouillage :
 *      · mot de passe maître → PBKDF2-SHA256 → clé d'enveloppe
 *      · chaque passkey      → sortie PRF WebAuthn → HKDF-SHA256 → clé d'enveloppe
 *    Changer de mot de passe ou ajouter un passkey ne rechiffre donc que la DEK.
 *  - Chaque chiffré est lié à son rôle par des données additionnelles (AAD) :
 *    un bloc ne peut pas être substitué à un autre sans que le déchiffrement échoue.
 *
 * Enregistrement stocké (JSON) :
 *   { v: 1,
 *     password: { kdf: 'PBKDF2-SHA256', iterations, salt, iv, wrapped },
 *     passkeys: [{ id, name, prfSalt, iv, wrapped, createdAt }],
 *     data: { iv, ct } }   // ct = JSON { clé localStorage → valeur }
 */
(function (root, factory) {
  const api = factory(root.crypto || (typeof require === 'function' ? require('node:crypto').webcrypto : null));
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Vault = api;
})(typeof self !== 'undefined' ? self : globalThis, function (webcrypto) {
  'use strict';

  const VAULT_KEY = 'mymfa.vault.v1';
  // Marqueur de synchro v2 dans les données (constante de js/sync2.js, reprise
  // ici sans dépendance : sa présence dans les données fait passer l'enveloppe
  // à v: 2 — un client d'avant exigeait v: 1 et refuse d'ouvrir, donc d'écrire).
  const SYNC_V2_KEY = 'mymfa.sync.v2';
  // Au-delà de la recommandation OWASP (600 000) : le coffre — et sa sauvegarde Drive — est
  // brute-forçable hors ligne, et ce coût n'est payé qu'au déverrouillage (une fois par session).
  const PBKDF2_ITERATIONS = 1000000;
  // Le mot de passe maître est la seule barrière du coffre et de sa sauvegarde : 8 caractères
  // tombent trop vite face à une attaque hors ligne, même avec un million d'itérations.
  const PASSWORD_MIN_LENGTH = 10;
  const AAD_DATA = 'mymfa:vault:data:v1';
  const AAD_PASSWORD = 'mymfa:vault:wrap:password:v1';
  const AAD_PASSKEY = 'mymfa:vault:wrap:passkey:v1:';
  const HKDF_INFO = 'mymfa:vault:passkey-kek:v1';

  const subtle = webcrypto && webcrypto.subtle;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  class VaultError extends Error {
    constructor(code, params) {
      super(code);
      this.name = 'VaultError';
      this.code = code;
      this.params = params || {};
    }
  }

  function requireCrypto() {
    if (!subtle) throw new VaultError('noWebCrypto');
  }

  /* ───── Encodages ───── */

  function toB64(bytes) {
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let binary = '';
    for (const b of view) binary += String.fromCharCode(b);
    return btoa(binary);
  }

  function fromB64(text) {
    const binary = atob(text);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }

  /** base64url sans remplissage : format des identifiants de credential WebAuthn. */
  function toB64Url(bytes) {
    return toB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fromB64Url(text) {
    const b64 = text.replace(/-/g, '+').replace(/_/g, '/');
    return fromB64(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  }

  function randomBytes(length) {
    return webcrypto.getRandomValues(new Uint8Array(length));
  }

  /* ───── Primitives ───── */

  async function encrypt(key, plaintext, aad) {
    const iv = randomBytes(12);
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode(aad) }, key, plaintext);
    return { iv: toB64(iv), ct: toB64(ct) };
  }

  async function decrypt(key, blob, aad, failCode) {
    try {
      return new Uint8Array(
        await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(blob.iv), additionalData: encoder.encode(aad) }, key, fromB64(blob.ct))
      );
    } catch {
      throw new VaultError(failCode);
    }
  }

  async function passwordKek(password, salt, iterations) {
    const base = await subtle.importKey('raw', encoder.encode(password.normalize('NFC')), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function prfKek(prfOutput) {
    const base = await subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: encoder.encode(HKDF_INFO) },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function wrapDek(dek, kek, aad) {
    const raw = new Uint8Array(await subtle.exportKey('raw', dek));
    const blob = await encrypt(kek, raw, aad);
    raw.fill(0);
    return { iv: blob.iv, wrapped: blob.ct };
  }

  async function unwrapDek(entry, kek, aad, failCode) {
    const raw = await decrypt(kek, { iv: entry.iv, ct: entry.wrapped }, aad, failCode);
    // Extractible : nécessaire pour ré-envelopper (nouveau mot de passe, nouveau passkey).
    const dek = await subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
    raw.fill(0);
    return dek;
  }

  /* ───── API ───── */

  function validatePassword(password) {
    if (typeof password !== 'string' || password.length < PASSWORD_MIN_LENGTH) {
      throw new VaultError('passwordTooShort', { min: PASSWORD_MIN_LENGTH });
    }
  }

  /* ───── Solidité d'un mot de passe (heuristique d'affichage, sans dépendance) ───── */

  const COMMON_PASSWORDS = [
    'password', 'motdepasse', 'azerty', 'qwerty', '123456', '12345678', 'admin', 'bonjour',
    'soleil', 'welcome', 'iloveyou', 'letmein', 'dragon', 'monkey', 'football', 'princesse',
    'chocolat', 'loulou', 'doudou', 'maman', 'secret',
  ];
  const COMMON_SEQUENCES = /012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|aze|rty|qwe|wer|sdf|dfg/i;

  /**
   * Estimation (0 à 4) : entropie de la composition, pénalisée par les répétitions,
   * les suites de touches et les mots courants. Pour guider la saisie, pas un oracle.
   */
  function passwordStrength(password) {
    const text = String(password || '');
    if (!text) return { level: 0, bits: 0 };
    let pool = 0;
    if (/[a-z]/.test(text)) pool += 26;
    if (/[A-Z]/.test(text)) pool += 26;
    if (/[0-9]/.test(text)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(text)) pool += 33;
    let bits = text.length * Math.log2(pool || 1);
    if (/(.)\1\1/.test(text)) bits *= 0.75; // « aaab… » : trois fois le même caractère
    if (/^(.)\1*$/.test(text)) bits = Math.min(bits, 8); // un seul caractère répété
    if (COMMON_SEQUENCES.test(text)) bits *= 0.7; // « 1234 », « qwer »…
    const lower = text.toLowerCase();
    if (COMMON_PASSWORDS.some((word) => lower.includes(word))) bits = Math.min(bits, 24);
    const level = bits < 36 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
    return { level, bits: Math.round(bits) };
  }

  function parse(raw) {
    if (!raw) return null;
    try {
      const record = JSON.parse(raw);
      // Enveloppes v1 (fusion d'origine) et v2 (synchro v2) se lisent ici ; un
      // client d'avant exigeait v === 1 et refusait donc un coffre v2.
      return record && (record.v === 1 || record.v === 2) && record.password && record.data ? record : null;
    } catch {
      return null;
    }
  }

  async function encryptData(dek, data) {
    return encrypt(dek, encoder.encode(JSON.stringify(data)), AAD_DATA);
  }

  async function decryptData(dek, blob) {
    return JSON.parse(decoder.decode(await decrypt(dek, blob, AAD_DATA, 'corrupted')));
  }

  /** Chiffre une valeur JSON avec la DEK sous une AAD propre (journal de synchro…) :
   *  un tel blob ne peut pas passer pour les données du coffre, ni l'inverse. */
  async function encryptJson(dek, value, aad) {
    return encrypt(dek, encoder.encode(JSON.stringify(value)), aad);
  }

  async function decryptJson(dek, blob, aad) {
    return JSON.parse(decoder.decode(await decrypt(dek, blob, aad, 'corrupted')));
  }

  async function passwordEntry(dek, password, iterations) {
    const salt = randomBytes(16);
    const kek = await passwordKek(password, salt, iterations);
    return { kdf: 'PBKDF2-SHA256', iterations, salt: toB64(salt), ...(await wrapDek(dek, kek, AAD_PASSWORD)) };
  }

  /** Crée un coffre : nouvelle DEK, données chiffrées, DEK enveloppée par le mot de passe. */
  async function create(password, data, { iterations = PBKDF2_ITERATIONS } = {}) {
    requireCrypto();
    validatePassword(password);
    const dek = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const record = {
      v: data && data[SYNC_V2_KEY] ? 2 : 1,
      password: await passwordEntry(dek, password, iterations),
      passkeys: [],
      data: await encryptData(dek, data),
    };
    return { record, dek };
  }

  async function unlockWithPassword(record, password) {
    requireCrypto();
    const entry = record.password;
    const kek = await passwordKek(password, fromB64(entry.salt), entry.iterations);
    return unwrapDek(entry, kek, AAD_PASSWORD, 'wrongPassword');
  }

  async function unlockWithPrf(record, credentialId, prfOutput) {
    requireCrypto();
    const entry = (record.passkeys || []).find((p) => p.id === credentialId);
    if (!entry) throw new VaultError('unknownPasskey');
    return unwrapDek(entry, await prfKek(prfOutput), AAD_PASSKEY + entry.id, 'passkeyRejected');
  }

  /** Nouveau mot de passe : seule l'enveloppe change, les passkeys restent valides. */
  async function changePassword(record, dek, newPassword, { iterations = PBKDF2_ITERATIONS } = {}) {
    validatePassword(newPassword);
    return { ...record, password: await passwordEntry(dek, newPassword, iterations) };
  }

  async function addPasskey(record, dek, { id, name, prfSalt, prfOutput }) {
    const entry = {
      id,
      name,
      prfSalt: toB64(prfSalt),
      createdAt: new Date().toISOString(),
      ...(await wrapDek(dek, await prfKek(prfOutput), AAD_PASSKEY + id)),
    };
    return { ...record, passkeys: [...(record.passkeys || []).filter((p) => p.id !== id), entry] };
  }

  function removePasskey(record, id) {
    return { ...record, passkeys: (record.passkeys || []).filter((p) => p.id !== id) };
  }

  return {
    VAULT_KEY,
    PBKDF2_ITERATIONS,
    PASSWORD_MIN_LENGTH,
    VaultError,
    parse,
    create,
    unlockWithPassword,
    unlockWithPrf,
    changePassword,
    addPasskey,
    removePasskey,
    encryptData,
    decryptData,
    encryptJson,
    decryptJson,
    passwordStrength,
    randomBytes,
    toB64,
    fromB64,
    toB64Url,
    fromB64Url,
  };
});
