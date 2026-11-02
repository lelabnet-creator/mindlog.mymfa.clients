/*
 * Authentificateur WebAuthn logiciel : myMFA crée et utilise les passkeys des sites.
 *  - Clés ES256 (ECDSA P-256, alg -7), clé privée PKCS#8 rangée dans le coffre chiffré ;
 *  - attestation « none », compteur de signature à 0 (passkey synchronisée : drapeaux BE et BS) ;
 *  - clientDataJSON construit ici avec l'origine fournie par le navigateur (jamais par la page).
 * Aucun accès au DOM : utilisable dans le service d'arrière-plan de l'extension et sous Node.
 */
(function (root, factory) {
  const api = factory(root.crypto || (typeof require === 'function' ? require('node:crypto').webcrypto : null));
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Authn = api;
})(typeof self !== 'undefined' ? self : globalThis, function (webcrypto) {
  'use strict';

  const ES256 = -7;
  const AAGUID = new Uint8Array(16);
  const FLAG = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40 };

  class AuthnError extends Error {
    /** name : nom de DOMException rendu à la page (NotAllowedError, InvalidStateError…). */
    constructor(name, message) {
      super(message || name);
      this.name = name;
      this.code = name;
    }
  }

  /* ───── Encodages ───── */

  function toB64Url(bytes) {
    let bin = '';
    for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fromB64Url(text) {
    const b64 = String(text).replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  }

  const utf8 = (text) => new TextEncoder().encode(text);

  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let offset = 0;
    for (const part of parts) {
      out.set(part, offset);
      offset += part.length;
    }
    return out;
  }

  async function sha256(bytes) {
    return new Uint8Array(await webcrypto.subtle.digest('SHA-256', bytes));
  }

  /* ───── CBOR (sous-ensemble utile à WebAuthn) ───── */

  function cborHead(major, value) {
    if (value < 24) return Uint8Array.of((major << 5) | value);
    if (value < 0x100) return Uint8Array.of((major << 5) | 24, value);
    if (value < 0x10000) return Uint8Array.of((major << 5) | 25, value >> 8, value & 0xff);
    return Uint8Array.of((major << 5) | 26, (value >>> 24) & 0xff, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff);
  }

  /** Map → CBOR, clés dans l'ordre d'insertion (WebAuthn donne l'ordre canonique attendu). */
  function cborEncode(value) {
    if (value instanceof Uint8Array) return concat(cborHead(2, value.length), value);
    if (typeof value === 'number') return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
    if (typeof value === 'string') {
      const bytes = utf8(value);
      return concat(cborHead(3, bytes.length), bytes);
    }
    if (Array.isArray(value)) return concat(cborHead(4, value.length), ...value.map(cborEncode));
    if (value instanceof Map) {
      const parts = [cborHead(5, value.size)];
      for (const [k, v] of value) parts.push(cborEncode(k), cborEncode(v));
      return concat(...parts);
    }
    throw new TypeError('CBOR : type non pris en charge');
  }

  /** CBOR → valeur ; renvoie aussi la longueur lue (les données suivent la clé dans authData). */
  function cborDecode(bytes, offset = 0) {
    const view = new Uint8Array(bytes);
    function readLength(info) {
      if (info < 24) return info;
      const size = { 24: 1, 25: 2, 26: 4 }[info];
      if (!size) throw new TypeError('CBOR : longueur non prise en charge');
      let value = 0;
      for (let i = 0; i < size; i++) value = value * 256 + view[offset++];
      return value;
    }
    function item() {
      const head = view[offset++];
      const major = head >> 5;
      const length = readLength(head & 0x1f);
      switch (major) {
        case 0: return length;
        case 1: return -1 - length;
        case 2: { const out = view.slice(offset, offset + length); offset += length; return out; }
        case 3: { const out = new TextDecoder().decode(view.slice(offset, offset + length)); offset += length; return out; }
        case 4: return Array.from({ length }, item);
        case 5: { const map = new Map(); for (let i = 0; i < length; i++) map.set(item(), item()); return map; }
        default: throw new TypeError('CBOR : type non pris en charge');
      }
    }
    const value = item();
    return { value, end: offset };
  }

  /* ───── Signatures ───── */

  /** Signature brute r‖s (Web Crypto) → DER (format exigé par WebAuthn pour ES256). */
  function rawToDer(raw) {
    const int = (bytes) => {
      let i = 0;
      while (i < bytes.length - 1 && bytes[i] === 0) i++;
      let out = bytes.slice(i);
      if (out[0] & 0x80) out = concat(Uint8Array.of(0), out);
      return concat(Uint8Array.of(0x02, out.length), out);
    };
    const r = int(raw.slice(0, 32));
    const s = int(raw.slice(32));
    return concat(Uint8Array.of(0x30, r.length + s.length), r, s);
  }

  function derToRaw(der) {
    const out = new Uint8Array(64);
    let offset = 2;
    for (const target of [0, 32]) {
      const length = der[offset + 1];
      let value = der.slice(offset + 2, offset + 2 + length);
      while (value.length > 32 && value[0] === 0) value = value.slice(1);
      out.set(value, target + 32 - value.length);
      offset += 2 + length;
    }
    return out;
  }

  /* ───── Contrôles ───── */

  /** rpId valable pour cette origine : https (ou localhost), domaine égal ou parent, jamais un TLD seul. */
  function checkRpId(origin, rpId) {
    let url;
    try {
      url = new URL(origin);
    } catch {
      throw new AuthnError('SecurityError', 'origine invalide');
    }
    const host = url.hostname;
    const local = host === 'localhost' || host.endsWith('.localhost');
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) throw new AuthnError('SecurityError', 'contexte non sécurisé');
    const id = rpId || host;
    if (id !== host && !host.endsWith(`.${id}`)) throw new AuthnError('SecurityError', 'rpId sans rapport avec l’origine');
    if (!local && !id.includes('.')) throw new AuthnError('SecurityError', 'rpId trop large');
    return id;
  }

  function clientData(type, challenge, origin) {
    return utf8(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  }

  async function authenticatorData(rpId, flags, attested) {
    const counter = new Uint8Array(4); // 0 : passkey synchronisée, le compteur n'a pas de sens
    return concat(await sha256(utf8(rpId)), Uint8Array.of(flags), counter, attested || new Uint8Array(0));
  }

  /* ───── Création ───── */

  /**
   * options : { origin, rpId, rpName, user: { id (b64url), name, displayName }, challenge (b64url),
   *             pubKeyCredParams: [{ alg }], excludeCredentials: [b64url] }
   * known : credentialId (b64url) des passkeys déjà enregistrées pour ce site.
   * Réponse : { passkey (à ranger dans le coffre), response (à rendre à la page) }.
   */
  async function create(options, known = []) {
    const rpId = checkRpId(options.origin, options.rpId);
    const params = options.pubKeyCredParams || [];
    if (params.length && !params.some((p) => p.alg === ES256)) throw new AuthnError('NotSupportedError', 'aucun algorithme pris en charge');
    if ((options.excludeCredentials || []).some((id) => known.includes(id))) throw new AuthnError('InvalidStateError', 'passkey déjà enregistrée');

    const keys = await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const point = new Uint8Array(await webcrypto.subtle.exportKey('raw', keys.publicKey)); // 0x04 ‖ x ‖ y
    const spki = new Uint8Array(await webcrypto.subtle.exportKey('spki', keys.publicKey));
    const pkcs8 = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey));
    const credentialId = webcrypto.getRandomValues(new Uint8Array(16));
    const cose = cborEncode(new Map([[1, 2], [3, ES256], [-1, 1], [-2, point.slice(1, 33)], [-3, point.slice(33, 65)]]));
    const attested = concat(AAGUID, Uint8Array.of(credentialId.length >> 8, credentialId.length & 0xff), credentialId, cose);
    const authData = await authenticatorData(rpId, FLAG.UP | FLAG.UV | FLAG.BE | FLAG.BS | FLAG.AT, attested);
    const attestationObject = cborEncode(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));

    return {
      passkey: {
        credentialId: toB64Url(credentialId),
        rpId,
        rpName: options.rpName || rpId,
        origin: options.origin,
        userHandle: options.user && options.user.id ? options.user.id : '',
        userName: (options.user && options.user.name) || '',
        userDisplayName: (options.user && options.user.displayName) || '',
        algorithm: ES256,
        privateKey: toB64Url(pkcs8),
      },
      response: {
        id: toB64Url(credentialId),
        clientDataJSON: toB64Url(clientData('webauthn.create', options.challenge, options.origin)),
        attestationObject: toB64Url(attestationObject),
        authenticatorData: toB64Url(authData),
        publicKey: toB64Url(spki),
        publicKeyAlgorithm: ES256,
        transports: ['hybrid', 'internal'],
      },
    };
  }

  /* ───── Authentification ───── */

  /** Passkeys utilisables pour cette demande : même rpId, et dans allowCredentials s'il est donné. */
  function usable(passkeys, rpId, allowCredentials) {
    const allowed = allowCredentials && allowCredentials.length ? new Set(allowCredentials) : null;
    return passkeys.filter((p) => p.rpId === rpId && (!allowed || allowed.has(p.credentialId)));
  }

  /** options : { origin, rpId, challenge (b64url) } ; passkey : élément du coffre. */
  async function get(options, passkey) {
    const rpId = checkRpId(options.origin, options.rpId);
    if (passkey.rpId !== rpId) throw new AuthnError('NotAllowedError', 'passkey d’un autre site');
    const authData = await authenticatorData(rpId, FLAG.UP | FLAG.UV | FLAG.BE | FLAG.BS);
    const data = clientData('webauthn.get', options.challenge, options.origin);
    const key = await webcrypto.subtle.importKey('pkcs8', fromB64Url(passkey.privateKey), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const raw = new Uint8Array(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, concat(authData, await sha256(data))));
    return {
      id: passkey.credentialId,
      clientDataJSON: toB64Url(data),
      authenticatorData: toB64Url(authData),
      signature: toB64Url(rawToDer(raw)),
      userHandle: passkey.userHandle || null,
    };
  }

  return { ES256, AuthnError, create, get, usable, checkRpId, toB64Url, fromB64Url, cborEncode, cborDecode, rawToDer, derToRaw };
});
