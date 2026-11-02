/*
 * myMFA, fournisseur de passkeys (script de contenu, cadre principal).
 * Reçoit les demandes de webauthn-page.js et les présente dans un toast :
 *  - création : « Enregistrer une passkey pour ce site dans myMFA ? » ;
 *  - connexion : choix de la passkey myMFA du site (y compris en saisie automatique).
 * Coffre fermé : bouton « Déverrouiller » (popup de l'extension), puis la demande reprend.
 * « Autre appareil » ou rien pour ce site : la demande repart, inchangée, vers le navigateur.
 */
(() => {
  'use strict';
  if (window.__mymfaWebauthn || window.top !== window) return;
  window.__mymfaWebauthn = true;

  const CHANNEL = 'mymfa-webauthn';
  const send = (message) => chrome.runtime.sendMessage(message).catch(() => null);
  const t = (...args) => I18n.t(...args);
  const requests = new Map(); // id → { kind, payload, state, offer, ask }
  let ready = null;

  /** Langue et thème chargés une fois, à la première demande. */
  function init() {
    if (!ready) {
      ready = send({ type: 'content:state' }).then((state) => {
        if (state && state.settings) {
          I18n.init(state.settings.lang, { stored: false });
          MyMfaUi.setSettings(state.settings);
        }
      });
    }
    return ready;
  }

  function reply(id, result) {
    if (!requests.has(id)) return;
    requests.delete(id);
    MyMfaUi.toast.close(`passkey:${id}`);
    window.postMessage({ channel: CHANNEL, dir: 'res', id, result }, location.origin);
  }

  window.addEventListener('message', async (event) => {
    const data = event.data;
    if (event.source !== window || !data || data.channel !== CHANNEL || data.dir !== 'req') return;
    if (data.kind === 'abort') {
      requests.delete(data.id);
      MyMfaUi.toast.close(`passkey:${data.id}`);
      return;
    }
    if (data.kind !== 'create' && data.kind !== 'get') return;
    await init();
    requests.set(data.id, { kind: data.kind, payload: data.payload, state: 'ask' });
    data.kind === 'create' ? prepareCreate(data.id) : prepareGet(data.id);
  });

  /* ───── Création ───── */

  async function prepareCreate(id) {
    const request = requests.get(id);
    if (!request) return;
    const res = await send({ type: 'webauthn:create', options: request.payload });
    if (!res || res.error || res.fallback) return reply(id, { fallback: true });
    request.ask = res.ask;
    request.state = 'ask';
    show(id);
  }

  async function confirmCreate(id) {
    const request = requests.get(id);
    if (!request) return;
    if (request.ask.status === 'locked' || request.ask.status === 'empty' || request.ask.status === 'plain') return;
    request.state = 'working';
    MyMfaUi.toast.refresh(`passkey:${id}`, { force: true });
    const res = await send({ type: 'webauthn:create', options: request.payload, confirmed: true });
    if (!res || res.fallback) return reply(id, { fallback: true });
    if (res.error) {
      const code = res.error.code;
      if (code === 'locked' || code === 'credentialsNeedVault') {
        request.ask.status = code === 'locked' ? 'locked' : 'empty';
        request.state = 'ask';
        return show(id);
      }
      return reply(id, { error: { code: /Error$/.test(code) ? code : 'NotAllowedError', message: code } });
    }
    request.state = 'created';
    show(id);
    setTimeout(() => reply(id, { credential: res.credential }), 900);
  }

  /* ───── Connexion ───── */

  async function prepareGet(id) {
    const request = requests.get(id);
    if (!request) return;
    const res = await send({ type: 'webauthn:get', options: request.payload });
    if (!res || res.error || res.fallback) return reply(id, { fallback: true });
    request.offer = res.offer;
    request.state = 'ask';
    show(id);
  }

  async function chooseGet(id, passkeyId) {
    const request = requests.get(id);
    if (!request) return;
    request.state = 'working';
    MyMfaUi.toast.refresh(`passkey:${id}`, { force: true });
    const res = await send({ type: 'webauthn:get', options: request.payload, passkeyId });
    if (!res || res.fallback) return reply(id, { fallback: true });
    if (res.error) {
      if (res.error.code === 'locked') return prepareGet(id);
      return reply(id, { error: { code: 'NotAllowedError', message: res.error.code } });
    }
    reply(id, { credential: res.credential });
  }

  /* ───── Toast ───── */

  function show(id) {
    MyMfaUi.toast.open(`passkey:${id}`, {
      priority: 40,
      render: () => view(id),
      // Fermé par l'utilisateur : la demande repart vers le navigateur (autre appareil, clé de sécurité…).
      onClose: (byUser) => byUser && reply(id, { fallback: true }),
    });
  }

  function openPopupButton(intent, note) {
    const { el, icon, ICON } = MyMfaUi;
    return el('button', {
      class: 'btn primary',
      type: 'button',
      onclick: async () => {
        const res = await send({ type: 'content:openPopup', intent });
        if ((!res || !res.opened) && note) note.textContent = t('ext.card.lockedHint');
      },
    }, [icon(ICON.lock), document.createTextNode(t(intent === 'create' ? 'ext.toast.createVault' : 'ext.card.unlock'))]);
  }

  function otherButton(id, link = false) {
    return MyMfaUi.el('button', { class: link ? 'link' : 'btn', type: 'button', text: t(link ? 'ext.toast.otherDeviceLong' : 'ext.toast.otherDevice'), onclick: () => reply(id, { fallback: true }) });
  }

  function view(id) {
    const { el, icon, ICON, trusted, tile } = MyMfaUi;
    const request = requests.get(id);
    if (!request) return null;
    const isCreate = request.kind === 'create';
    const info = isCreate ? request.ask : request.offer;
    const site = info.rpId;
    const status = info.status;
    const badge = el('span', { class: 'badge', text: t('ext.toast.passkeyBadge') });

    if (request.state === 'created') {
      return { badge, body: el('div', { class: 'body' }, [el('p', { class: 'success' }, [icon(ICON.check), document.createTextNode(t('ext.toast.passkeyCreated'))])]) };
    }
    if (status === 'locked' || status === 'empty' || status === 'plain') {
      const intent = status === 'locked' ? 'unlock' : 'create';
      const note = el('p', { class: 'note', text: t(intent === 'unlock' ? 'ext.toast.passkeyLockedText' : 'ext.toast.passkeyVaultText') });
      return {
        badge: el('span', { class: 'badge warn', text: t(intent === 'unlock' ? 'ext.card.badgeLocked' : 'ext.toast.badgeProtect') }),
        body: el('div', { class: 'body' }, [
          el('p', { class: 'title', text: t(isCreate ? 'ext.toast.passkeyCreateTitle' : 'ext.toast.passkeyGetTitle', { site }) }),
          note,
          el('div', { class: 'actions' }, [openPopupButton(intent, note), otherButton(id)]),
        ]),
      };
    }
    const working = request.state === 'working';
    if (isCreate) {
      return {
        badge,
        label: t('ext.toast.passkeyCreateTitle', { site }),
        body: el('div', { class: 'body' }, [
          el('p', { class: 'title', text: t('ext.toast.passkeyCreateTitle', { site }) }),
          el('div', { class: 'who' }, [
            tile(info.rpName || site),
            el('div', { class: 'who-text' }, [el('span', { class: 'issuer', text: info.rpName || site }), el('span', { class: 'account', text: info.userName || site })]),
          ]),
          el('div', { class: 'actions one' }, [
            el('button', { class: 'btn primary', type: 'button', disabled: working, onclick: trusted(() => confirmCreate(id)) }, [icon(ICON.key), document.createTextNode(t('ext.toast.passkeySave'))]),
          ]),
          el('p', { class: 'note', text: t('ext.toast.passkeyCreateNote') }),
          otherButton(id, true),
        ]),
      };
    }
    const rows = info.passkeys.map((p) =>
      el('button', { class: 'row', type: 'button', disabled: working, onclick: trusted(() => chooseGet(id, p.id)) }, [
        tile(p.userName || p.userDisplayName || site, true),
        el('span', { class: 'who-text' }, [
          el('span', { class: 'issuer', text: p.userDisplayName || p.userName || t('ext.toast.noUsername') }),
          el('span', { class: 'account', text: p.userName && p.userDisplayName ? p.userName : p.rpName || site }),
        ]),
        el('span', { class: 'row-go' }, icon(ICON.key)),
      ])
    );
    return {
      badge,
      label: t('ext.toast.passkeyGetTitle', { site }),
      body: el('div', { class: 'body' }, [
        el('p', { class: 'title', text: t('ext.toast.passkeyGetTitle', { site }) }),
        el('div', { class: 'rows' }, rows),
        el('div', { class: 'actions one' }, [otherButton(id)]),
      ]),
    };
  }

  /* Déverrouillage ou coffre créé dans le popup : les demandes en attente reprennent. */
  chrome.runtime.onMessage.addListener((message) => {
    if (!message || message.type !== 'mymfa:state') return false;
    for (const [id, request] of requests) {
      if (request.state === 'working') continue;
      if (request.kind === 'create') prepareCreate(id);
      else prepareGet(id);
    }
    return false;
  });
})();
