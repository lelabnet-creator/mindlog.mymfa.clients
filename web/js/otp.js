/*
 * Cœur OTP : base32, HOTP (RFC 4226), TOTP (RFC 6238), parsing otpauth://.
 * Script classique (pas de module ES) pour que index.html fonctionne aussi en
 * file:// ; exporté en CommonJS pour les tests Node.
 */
(function (root, factory) {
  const api = factory(root.crypto || (typeof require === 'function' ? require('node:crypto').webcrypto : null));
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.OTP = api;
})(typeof self !== 'undefined' ? self : globalThis, function (webcrypto) {
  'use strict';

  /** Erreur porteuse d'un code traduisible (clé i18n `error.<code>`). */
  class OtpError extends Error {
    constructor(code, params) {
      super(code);
      this.name = 'OtpError';
      this.code = code;
      this.params = params || {};
    }
  }
  function fail(code, params) {
    throw new OtpError(code, params);
  }

  const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const ALGORITHMS = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

  /** Normalise une clé saisie à la main : majuscules, sans espaces/tirets/padding. */
  function normalizeSecret(secret) {
    return String(secret || '').toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  }

  function base32Decode(input) {
    const clean = normalizeSecret(input);
    if (!clean) fail('secretEmpty');
    let bits = 0;
    let value = 0;
    const out = [];
    for (const ch of clean) {
      const idx = BASE32_ALPHABET.indexOf(ch);
      if (idx === -1) fail('secretInvalidChar', { char: ch });
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        out.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }
    if (out.length === 0) fail('secretTooShort');
    return new Uint8Array(out);
  }

  function isValidSecret(secret) {
    try {
      base32Decode(secret);
      return true;
    } catch {
      return false;
    }
  }

  function counterBytes(counter) {
    const buf = new Uint8Array(8);
    let c = BigInt(counter);
    for (let i = 7; i >= 0; i--) {
      buf[i] = Number(c & 0xffn);
      c >>= 8n;
    }
    return buf;
  }

  async function hotp(secret, counter, { digits = 6, algorithm = 'SHA1' } = {}) {
    if (!webcrypto || !webcrypto.subtle) {
      fail('noWebCrypto');
    }
    const hash = ALGORITHMS[String(algorithm).toUpperCase()];
    if (!hash) fail('unsupportedAlgorithm', { algorithm });
    const key = await webcrypto.subtle.importKey(
      'raw', base32Decode(secret), { name: 'HMAC', hash }, false, ['sign']
    );
    const mac = new Uint8Array(await webcrypto.subtle.sign('HMAC', key, counterBytes(counter)));
    const offset = mac[mac.length - 1] & 0x0f;
    const bin =
      ((mac[offset] & 0x7f) << 24) |
      (mac[offset + 1] << 16) |
      (mac[offset + 2] << 8) |
      mac[offset + 3];
    return String(bin % 10 ** digits).padStart(digits, '0');
  }

  async function totp(secret, { period = 30, digits = 6, algorithm = 'SHA1', timestamp = Date.now() } = {}) {
    const counter = Math.floor(timestamp / 1000 / period);
    return hotp(secret, counter, { digits, algorithm });
  }

  /** Secondes restantes avant le prochain code. */
  function remainingSeconds(period = 30, timestamp = Date.now()) {
    return period - (Math.floor(timestamp / 1000) % period);
  }

  /**
   * Parse une URI otpauth://totp/Label?secret=...&issuer=...
   * Retourne { type, issuer, account, secret, algorithm, digits, period, counter }.
   */
  function parseOtpauthUri(uri) {
    const text = String(uri || '').trim();
    if (/^otpauth-migration:/i.test(text)) {
      fail('migrationUnsupported');
    }
    let url;
    try {
      url = new URL(text);
    } catch {
      fail('invalidUri');
    }
    if (url.protocol !== 'otpauth:') fail('notOtpauth');
    // new URL('otpauth://totp/x') → host = "totp", pathname = "/x"
    const type = (url.host || url.hostname).toLowerCase();
    if (type !== 'totp' && type !== 'hotp') fail('unknownType', { type });

    const label = decodeURIComponent(url.pathname.replace(/^\//, ''));
    let labelIssuer = '';
    let account = label;
    const sep = label.indexOf(':');
    if (sep !== -1) {
      labelIssuer = label.slice(0, sep).trim();
      account = label.slice(sep + 1).trim();
    }

    const params = url.searchParams;
    const secret = normalizeSecret(params.get('secret'));
    if (!secret) fail('missingSecret');
    base32Decode(secret); // valide

    const algorithm = (params.get('algorithm') || 'SHA1').toUpperCase();
    if (!ALGORITHMS[algorithm]) fail('unsupportedAlgorithm', { algorithm });
    const digits = parseInt(params.get('digits') || '6', 10);
    if (![6, 7, 8].includes(digits)) fail('unsupportedDigits', { digits });
    const period = parseInt(params.get('period') || '30', 10);
    if (!(period > 0)) fail('invalidPeriod', { period: params.get('period') });
    const counter = parseInt(params.get('counter') || '0', 10);

    return {
      type,
      issuer: params.get('issuer') || labelIssuer,
      account,
      secret,
      algorithm,
      digits,
      period,
      counter: Number.isFinite(counter) ? counter : 0,
    };
  }

  /** Reconstruit une URI otpauth:// (pour l'export / la ré-affichage en QR). */
  function buildOtpauthUri({ type = 'totp', issuer = '', account = '', secret, algorithm = 'SHA1', digits = 6, period = 30, counter = 0 }) {
    const label = encodeURIComponent(issuer ? `${issuer}:${account}` : account);
    const params = new URLSearchParams({ secret: normalizeSecret(secret) });
    if (issuer) params.set('issuer', issuer);
    params.set('algorithm', algorithm);
    params.set('digits', String(digits));
    if (type === 'hotp') params.set('counter', String(counter));
    else params.set('period', String(period));
    return `otpauth://${type}/${label}?${params.toString()}`;
  }

  return {
    OtpError,
    normalizeSecret,
    base32Decode,
    isValidSecret,
    hotp,
    totp,
    remainingSeconds,
    parseOtpauthUri,
    buildOtpauthUri,
  };
});
