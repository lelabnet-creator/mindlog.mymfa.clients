/*
 * L'app web embarquée dans l'extension (app/index.html, copiée depuis ../web par scripts/build.mjs) :
 * ce script en fait une page de l'extension. Chargé avant lock.js et app.js, qui le trouvent dans
 * window.MYMFA_HOST ; sans lui (app hébergée), ils fonctionnent seuls.
 *  - Synchronisation : la copie de l'app (localStorage de l'extension) et celle du service
 *    d'arrière-plan sont fusionnées comme pour une app hébergée — même échange que le pont de
 *    content.js, mais par messages directs : une page de l'extension n'a pas de script de contenu.
 *  - Un seul verrou : déverrouiller ici ouvre l'extension, et inversement ; verrouiller de même.
 *    Le délai de verrouillage automatique est celui de l'extension, l'activité ici le repousse.
 *  - Google Drive : pas de script Google distant (interdit en MV3), le jeton vient de
 *    chrome.identity, par le service d'arrière-plan. L'identifiant client Google et la politique
 *    de sauvegarde automatique (toutes les N heures, tenue par l'extension) sont partagés.
 */
(function () {
  'use strict';

  const PAGE_KEYS = ['mymfa.vault.v1', 'mymfa.accounts.v1', 'mymfa.history.v1', 'mymfa.deleted.v1', 'mymfa.logins.v1', 'mymfa.passkeys.v1'];
  const AUTOLOCK_KEY = 'mymfa.autoLock';
  const TOUCH_EVERY = 30000; // activité signalée au plus une fois par période

  async function send(message) {
    const res = await chrome.runtime.sendMessage(message);
    if (res && res.error) throw Object.assign(new Error(res.error.code), res.error);
    return res;
  }

  const snapshot = () => {
    const out = {};
    for (const key of PAGE_KEYS) {
      const value = localStorage.getItem(key);
      if (value !== null) out[key] = value;
    }
    return out;
  };

  const importKey = (b64) => crypto.subtle.importKey('raw', Vault.fromB64(b64), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);

  /** Extension déverrouillée, app verrouillée sur le même coffre : on ouvre l'app avec la même clé. */
  async function adoptKey() {
    if (Lock.status() !== 'locked') return;
    const { key } = await send({ type: 'app:key' });
    if (key) await Lock.unlockFromHost(await importKey(key));
  }

  let last = '';
  async function runSync() {
    const res = await send({ type: 'app:sync', page: snapshot() });
    if (res && res.write) {
      for (const [key, value] of Object.entries(res.write)) {
        if (value === null) localStorage.removeItem(key);
        else if (localStorage.getItem(key) !== value) localStorage.setItem(key, value);
      }
      window.dispatchEvent(new CustomEvent('mymfa:external-change'));
    }
    last = JSON.stringify(snapshot());
    await adoptKey();
  }

  // Une synchronisation à la fois, dans l'ordre : `unlocked` doit attendre la sienne.
  let chain = Promise.resolve();
  function sync() {
    chain = chain.then(runSync).catch((err) => console.warn('[myMFA] synchronisation avec l’extension', err));
    return chain;
  }

  let lastTouch = 0;
  // Réglages de l'extension utiles à l'app (délai de verrouillage, Drive), demandés une fois.
  const ready = send({ type: 'app:settings' }).catch(() => null);

  window.MYMFA_HOST = {
    kind: 'extension',
    driveRedirect: chrome.identity.getRedirectURL(),
    driveTokens(clientId) {
      return {
        getToken: async () => (await send({ type: 'app:driveToken', clientId })).token,
        signOut() {},
      };
    },
    async unlocked(key) {
      // Le coffre d'abord : l'extension doit l'avoir pour vérifier la clé qu'on lui confie.
      await sync();
      const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
      try {
        await send({ type: 'app:unlocked', key: Vault.toB64(raw) });
      } catch (err) {
        console.warn('[myMFA] déverrouillage de l’extension', err);
      } finally {
        raw.fill(0);
      }
    },
    locked() {
      send({ type: 'app:locked' }).catch(() => {});
    },
    touch() {
      if (Date.now() - lastTouch < TOUCH_EVERY) return;
      lastTouch = Date.now();
      send({ type: 'app:touch' }).catch(() => {});
    },
    autoLockChanged(minutes) {
      send({ type: 'app:autoLock', minutes }).catch(() => {});
    },
    ready,
    driveClientChanged(clientId) {
      send({ type: 'app:driveClientId', clientId }).catch(() => {});
    },
    driveEvery: (hours) => send({ type: 'app:driveEvery', hours }),
    driveBackedUp: () => send({ type: 'app:driveBackedUp' }).catch(() => null),
  };

  chrome.runtime.onMessage.addListener((message) => {
    if (!message) return;
    if (message.type === 'mymfa:push') sync();
    else if (message.type === 'mymfa:lock') Lock.lockFromHost();
  });

  document.addEventListener('DOMContentLoaded', async () => {
    // Le réglage de l'extension fait foi : l'app l'affiche.
    const settings = await ready; // service indisponible : la synchronisation le dira
    if (settings) localStorage.setItem(AUTOLOCK_KEY, String(settings.autoLock));
    // Les écritures de l'app ne déclenchent pas d'événement dans son propre onglet : on compare.
    setInterval(() => {
      if (JSON.stringify(snapshot()) !== last) sync();
    }, 1500);
    sync();
  });
})();
