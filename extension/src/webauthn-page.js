/*
 * myMFA, fournisseur de passkeys (monde de la page, avant ses scripts).
 * Enveloppe navigator.credentials.create / get pour les demandes WebAuthn (publicKey) :
 * la demande passe au script de contenu (webauthn.js), qui propose myMFA dans un toast.
 * Tout ce que myMFA ne sait pas faire (PRF, largeBlob, clé de sécurité exigée, app myMFA elle-même,
 * refus ou « Autre appareil ») repart vers l'implémentation du navigateur, inchangée.
 * Aucun secret ici : la page ne reçoit que la réponse WebAuthn qu'elle a demandée.
 */
(() => {
  'use strict';
  const container = navigator.credentials;
  if (!container || !window.PublicKeyCredential || container.__mymfa) return;

  const CHANNEL = 'mymfa-webauthn';
  const nativeCreate = container.create.bind(container);
  const nativeGet = container.get.bind(container);
  const waiting = new Map();
  let seq = 0;

  window.addEventListener('message', (event) => {
    const data = event.data;
    if (event.source !== window || !data || data.channel !== CHANNEL || data.dir !== 'res') return;
    const resolve = waiting.get(data.id);
    if (!resolve) return;
    waiting.delete(data.id);
    resolve(data.result || { fallback: true });
  });

  /** Demande au script de contenu ; { aborted } si la page annule entre-temps. */
  function ask(kind, payload, signal) {
    const id = `${++seq}.${Math.random().toString(36).slice(2)}`;
    return new Promise((resolve) => {
      if (signal && signal.aborted) return resolve({ aborted: true });
      waiting.set(id, resolve);
      window.postMessage({ channel: CHANNEL, dir: 'req', id, kind, payload }, location.origin);
      if (signal) {
        signal.addEventListener('abort', () => {
          if (!waiting.has(id)) return;
          waiting.delete(id);
          window.postMessage({ channel: CHANNEL, dir: 'req', id, kind: 'abort' }, location.origin);
          resolve({ aborted: true });
        }, { once: true });
      }
    });
  }

  /* ───── Encodages ───── */

  function bytes(value) {
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    return new Uint8Array(0);
  }

  function b64url(value) {
    let bin = '';
    for (const b of bytes(value)) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function buffer(text) {
    const b64 = String(text || '').replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
  }

  const isApp = () => Boolean(document.querySelector('meta[name="application-name"][content="myMFA"]'));
  const UNSUPPORTED = ['prf', 'largeBlob', 'payment'];
  const unsupported = (extensions) => Object.keys(extensions || {}).some((name) => UNSUPPORTED.includes(name));

  function abortError(signal) {
    return signal && signal.reason !== undefined ? signal.reason : new DOMException('The operation was aborted.', 'AbortError');
  }

  const domError = (error) => new DOMException(error.message || error.code || 'NotAllowedError', error.code || 'NotAllowedError');

  /* ───── Objets rendus à la page : mêmes prototypes que ceux du navigateur ───── */

  function define(target, props) {
    for (const [key, value] of Object.entries(props)) Object.defineProperty(target, key, { value, enumerable: true, configurable: true });
    return target;
  }

  function credential(id, response, extensions, responseJSON) {
    return define(Object.create(PublicKeyCredential.prototype), {
      id,
      rawId: buffer(id),
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response,
      getClientExtensionResults: () => ({ ...extensions }),
      toJSON: () => ({ id, rawId: id, type: 'public-key', authenticatorAttachment: 'platform', clientExtensionResults: { ...extensions }, response: responseJSON }),
    });
  }

  function attestation(c, extensions) {
    const response = define(Object.create(AuthenticatorAttestationResponse.prototype), {
      clientDataJSON: buffer(c.clientDataJSON),
      attestationObject: buffer(c.attestationObject),
      getTransports: () => c.transports.slice(),
      getAuthenticatorData: () => buffer(c.authenticatorData),
      getPublicKey: () => buffer(c.publicKey),
      getPublicKeyAlgorithm: () => c.publicKeyAlgorithm,
    });
    const json = {
      clientDataJSON: c.clientDataJSON,
      attestationObject: c.attestationObject,
      authenticatorData: c.authenticatorData,
      publicKey: c.publicKey,
      publicKeyAlgorithm: c.publicKeyAlgorithm,
      transports: c.transports,
    };
    return credential(c.id, response, extensions, json);
  }

  function assertion(c) {
    const response = define(Object.create(AuthenticatorAssertionResponse.prototype), {
      clientDataJSON: buffer(c.clientDataJSON),
      authenticatorData: buffer(c.authenticatorData),
      signature: buffer(c.signature),
      userHandle: c.userHandle ? buffer(c.userHandle) : null,
    });
    const json = { clientDataJSON: c.clientDataJSON, authenticatorData: c.authenticatorData, signature: c.signature, userHandle: c.userHandle || undefined };
    return credential(c.id, response, {}, json);
  }

  /* ───── create ───── */

  function createPayload(pk) {
    return {
      rpId: pk.rp && pk.rp.id,
      rpName: pk.rp && pk.rp.name,
      user: pk.user ? { id: b64url(pk.user.id), name: pk.user.name, displayName: pk.user.displayName } : null,
      challenge: b64url(pk.challenge),
      pubKeyCredParams: (pk.pubKeyCredParams || []).map((p) => ({ alg: p.alg })),
      excludeCredentials: (pk.excludeCredentials || []).map((c) => b64url(c.id)),
    };
  }

  async function create(options) {
    const pk = options.publicKey;
    const res = await ask('create', createPayload(pk), options.signal);
    if (res.aborted) throw abortError(options.signal);
    if (res.fallback) return nativeCreate(options);
    if (res.error) throw domError(res.error);
    return attestation(res.credential, pk.extensions && pk.extensions.credProps ? { credProps: { rk: true } } : {});
  }

  /* ───── get ───── */

  function getPayload(pk, conditional) {
    return { rpId: pk.rpId, challenge: b64url(pk.challenge), allowCredentials: (pk.allowCredentials || []).map((c) => b64url(c.id)), conditional };
  }

  async function get(options) {
    const pk = options.publicKey;
    if (options.mediation !== 'conditional') {
      const res = await ask('get', getPayload(pk, false), options.signal);
      if (res.aborted) throw abortError(options.signal);
      if (res.fallback) return nativeGet(options);
      if (res.error) throw domError(res.error);
      return assertion(res.credential);
    }
    // Saisie automatique (mediation « conditional ») : le toast myMFA et la suggestion du navigateur
    // attendent en parallèle ; le premier choisi l'emporte, l'autre est annulé.
    const controller = new AbortController();
    const outer = options.signal;
    if (outer) outer.addEventListener('abort', () => controller.abort(outer.reason), { once: true });
    const ours = ask('get', getPayload(pk, true), controller.signal).then((result) => ({ ours: result }));
    const theirs = nativeGet({ ...options, signal: controller.signal }).then((cred) => ({ cred }), (error) => ({ error }));
    let first = await Promise.race([ours, theirs]);
    if (first.ours) {
      const res = first.ours;
      if (res.credential) {
        controller.abort();
        return assertion(res.credential);
      }
      if (res.error) {
        controller.abort();
        throw domError(res.error);
      }
      first = await theirs; // myMFA n'a rien pour ce site, ou l'utilisateur préfère le navigateur
    } else {
      controller.abort(); // le navigateur a répondu : on retire le toast
      if (first.error && !(outer && outer.aborted)) {
        const res = (await ours).ours;
        if (res && res.credential) return assertion(res.credential);
      }
    }
    if (first.cred) return first.cred;
    throw first.error;
  }

  function wrap(name, handler, native) {
    const fn = {
      [name](options) {
        const pk = options && options.publicKey;
        if (!pk || isApp() || unsupported(pk.extensions)) return native(options);
        const selection = pk.authenticatorSelection || {};
        if (selection.authenticatorAttachment === 'cross-platform') return native(options);
        return handler(options);
      },
    }[name];
    Object.defineProperty(container, name, { value: fn, configurable: true, writable: true });
  }

  wrap('create', create, nativeCreate);
  wrap('get', get, nativeGet);
  Object.defineProperty(container, '__mymfa', { value: true });
})();
