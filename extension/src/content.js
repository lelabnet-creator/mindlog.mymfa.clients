/*
 * Script de contenu myMFA (toutes les pages).
 *  1. Repère les QR codes 2FA (otpauth://) affichés par la page et affiche une carte :
 *     compte connu → code + « Remplir le champ » ; nouveau → ajout avec tag et description.
 *  2. Repère un champ « code à usage unique » : si myMFA a un compte pour ce site, toast avec le code.
 *  3. Sur l'adresse de l'app configurée uniquement : pont de synchronisation app ↔ extension.
 * Aucun secret n'arrive ici : seul le code du compte correspondant au QR de la page.
 * Les toasts (ui.js) vivent dans un shadow root fermé ; aucun mot de passe maître n'y est jamais saisi.
 */
(() => {
  'use strict';
  if (window.__mymfa) return;
  window.__mymfa = true;

  const { t } = I18n;
  const Ui = MyMfaUi;
  const { el, icon, ICON } = Ui;
  const send = (message) => chrome.runtime.sendMessage(message).catch(() => null);
  const OTPAUTH_RE = /^\s*otpauth:/i;
  let settings = null;

  /* ═════════════ Pont avec l'app ═════════════ */

  const PAGE_KEYS = ['mymfa.vault.v1', 'mymfa.accounts.v1', 'mymfa.history.v1', 'mymfa.deleted.v1', 'mymfa.logins.v1', 'mymfa.passkeys.v1'];

  function setupBridge() {
    const isApp = document.querySelector('meta[name="application-name"][content="myMFA"]');
    if (!isApp) return;
    const snapshot = () => {
      const out = {};
      for (const key of PAGE_KEYS) {
        const value = localStorage.getItem(key);
        if (value !== null) out[key] = value;
      }
      return out;
    };
    let last = '';
    let running = false;
    async function sync() {
      if (running) return;
      running = true;
      try {
        const res = await send({ type: 'content:sync', page: snapshot() });
        if (res && res.write) {
          for (const [key, value] of Object.entries(res.write)) {
            if (value === null) localStorage.removeItem(key);
            else if (localStorage.getItem(key) !== value) localStorage.setItem(key, value);
          }
          window.dispatchEvent(new CustomEvent('mymfa:external-change'));
        }
        // L'app affiche le dernier passage de l'extension (barre latérale).
        if (res && !res.error) {
          localStorage.setItem('mymfa.extensionSync', new Date().toISOString());
          window.dispatchEvent(new CustomEvent('mymfa:extension-sync'));
        }
        last = JSON.stringify(snapshot());
      } finally {
        running = false;
      }
    }
    chrome.runtime.onMessage.addListener((message) => {
      if (message && message.type === 'mymfa:push') sync();
    });
    // Les écritures de l'app ne déclenchent pas d'événement dans son propre onglet : on compare.
    setInterval(() => {
      if (JSON.stringify(snapshot()) !== last) sync();
    }, 1500);
    sync();
  }

  /* ═════════════ Détection des QR codes ═════════════ */

  let decoderReady = null;
  function ensureDecoder() {
    if (typeof jsQR === 'function') return Promise.resolve(true);
    if (!decoderReady) {
      decoderReady = send({ type: 'content:injectDecoder' }).then(() => typeof jsQR === 'function');
    }
    return decoderReady;
  }

  const processed = new WeakMap(); // élément → source déjà analysée
  const found = new Map(); // uri → élément
  const dismissed = new Set();
  const canvas = document.createElement('canvas');
  const ctx2d = canvas.getContext('2d', { willReadFrequently: true });

  function isCandidate(el) {
    const rect = el.getBoundingClientRect();
    if (rect.width < 64 || rect.height < 64 || rect.width > 1200 || rect.height > 1200) return false;
    const ratio = rect.width / rect.height;
    if (ratio < 0.75 || ratio > 1.33) return false;
    const style = getComputedStyle(el);
    return style.visibility !== 'hidden' && style.display !== 'none' && Number(style.opacity) > 0.1;
  }

  function sourceKey(el) {
    if (el instanceof HTMLImageElement) return el.currentSrc || el.src;
    if (el instanceof HTMLCanvasElement) return `canvas:${el.width}x${el.height}`;
    return `svg:${el.innerHTML.length}`;
  }

  function loadImage(src) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = reject;
      img.src = src;
    });
  }

  /** ImageData de l'élément, ou { url } si l'image est d'une autre origine (canvas « teinté »). */
  async function rasterize(el) {
    let source = el;
    let width;
    let height;
    if (el instanceof HTMLImageElement) {
      if (!el.complete || !el.naturalWidth) return null;
      width = el.naturalWidth;
      height = el.naturalHeight;
    } else if (el instanceof HTMLCanvasElement) {
      width = el.width;
      height = el.height;
    } else {
      const rect = el.getBoundingClientRect();
      const clone = el.cloneNode(true);
      clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
      clone.setAttribute('width', String(Math.round(rect.width)));
      clone.setAttribute('height', String(Math.round(rect.height)));
      const url = URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(clone)], { type: 'image/svg+xml' }));
      try {
        source = await loadImage(url);
      } catch {
        return null;
      } finally {
        URL.revokeObjectURL(url);
      }
      width = Math.round(rect.width) * 2;
      height = Math.round(rect.height) * 2;
    }
    const scale = Math.min(1, 600 / Math.max(width, height));
    canvas.width = Math.max(1, Math.round(width * scale));
    canvas.height = Math.max(1, Math.round(height * scale));
    ctx2d.fillStyle = '#fff';
    ctx2d.fillRect(0, 0, canvas.width, canvas.height);
    ctx2d.drawImage(source, 0, 0, canvas.width, canvas.height);
    try {
      return ctx2d.getImageData(0, 0, canvas.width, canvas.height);
    } catch {
      return el instanceof HTMLImageElement ? { url: el.currentSrc || el.src } : null;
    }
  }

  /** Préfiltre bon marché : un QR code est presque entièrement noir et blanc. */
  function looksLikeQr(image) {
    const { data } = image;
    const step = Math.max(4, Math.floor(data.length / 4 / 4000)) * 4;
    let dark = 0;
    let light = 0;
    let total = 0;
    for (let i = 0; i < data.length; i += step) {
      const lum = 0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2];
      if (lum < 90) dark++;
      else if (lum > 170) light++;
      total++;
    }
    return total > 0 && (dark + light) / total > 0.85 && dark / total > 0.12 && light / total > 0.12;
  }

  async function decode(el) {
    const image = await rasterize(el);
    if (!image) return null;
    if (image.url) {
      const res = await send({ type: 'content:decodeUrl', url: image.url });
      return res && res.text;
    }
    if (!looksLikeQr(image) || !(await ensureDecoder())) return null;
    const result = jsQR(image.data, image.width, image.height, { inversionAttempts: 'attemptBoth' });
    return result && result.data;
  }

  let scanning = false;
  let rescan = false;
  async function scan() {
    if (!settings || !settings.detect) return;
    if (scanning) {
      rescan = true;
      return;
    }
    scanning = true;
    try {
      const candidates = [...document.querySelectorAll('img, canvas, svg')].filter((node) => !ownNode(node)).filter(isCandidate).slice(0, 40);
      for (const el of candidates) {
        const key = sourceKey(el);
        if (processed.get(el) === key) continue;
        processed.set(el, key);
        let text = null;
        try {
          text = await decode(el);
        } catch {
          text = null;
        }
        if (text && OTPAUTH_RE.test(text) && !found.has(text.trim())) found.set(text.trim(), el);
      }
      send({ type: 'content:found', count: found.size });
      const next = [...found.keys()].find((uri) => !dismissed.has(uri));
      if (next && (!card.uri || !found.has(card.uri))) showCard(next);
    } finally {
      scanning = false;
      if (rescan) {
        rescan = false;
        scheduleScan();
      }
    }
  }

  let scanTimer = null;
  function scheduleScan(delay = 600) {
    clearTimeout(scanTimer);
    scanTimer = setTimeout(scan, delay);
  }

  /* ═════════════ Remplissage du champ de code ═════════════ */

  const ownNode = (node) => {
    const host = Ui.toast.host();
    return Boolean(host && host.contains(node));
  };

  /** Champ où taper le code : cases d'un chiffre, ou champ le plus probable (score ≥ minScore). */
  function otpTarget(digits, minScore = 3) {
    const inputs = [...document.querySelectorAll('input')].filter(
      (i) => Ui.visible(i) && !i.disabled && !i.readOnly && ['text', 'tel', 'number', 'password', ''].includes(i.type) && !ownNode(i)
    );
    const boxes = inputs.filter((i) => i.maxLength === 1);
    if (boxes.length >= digits) return { boxes: boxes.slice(0, digits) };
    let best = null;
    let bestScore = 0;
    for (const input of inputs) {
      const hints = [input.name, input.id, input.placeholder, input.getAttribute('aria-label'), input.autocomplete].join(' ');
      let score = 0;
      if (input.autocomplete === 'one-time-code') score += 10;
      if (/otp|totp|2fa|mfa|code|token|verif|pin|auth/i.test(hints)) score += 5;
      if (input.maxLength >= 6 && input.maxLength <= 8) score += 3;
      if (input.inputMode === 'numeric' || input.type === 'tel' || input.type === 'number') score += 2;
      if (score > bestScore) {
        best = input;
        bestScore = score;
      }
    }
    return bestScore >= minScore ? { input: best } : null;
  }

  function fill(code) {
    const target = otpTarget(code.length);
    if (!target) return false;
    if (target.boxes) target.boxes.forEach((box, i) => Ui.setValue(box, code[i]));
    else {
      target.input.focus();
      Ui.setValue(target.input, code);
    }
    return true;
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message && message.type === 'mymfa:fill') {
      sendResponse({ filled: fill(String(message.code || '')) });
      return false;
    }
    if (message && message.type === 'mymfa:hasField') {
      sendResponse({ field: Boolean(otpTarget(6)) });
      return false;
    }
    if (message && message.type === 'mymfa:state') {
      if (card.uri) refresh();
      checkOtp(true);
    }
    return false;
  });

  /* ═════════════ Anneau de décompte ═════════════ */

  function updateRing(ring, known) {
    const length = 2 * Math.PI * 19;
    ring.querySelector('.value').style.strokeDasharray = String(length);
    ring.querySelector('.value').style.strokeDashoffset = String(length * (1 - known.remaining / known.period));
    ring.querySelector('.secs').textContent = String(known.remaining);
    ring.classList.toggle('expiring', known.remaining <= 5);
    ring.setAttribute('aria-label', t('list.remaining', { count: known.remaining }));
  }

  function ringNode(known) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 46 46');
    svg.setAttribute('aria-hidden', 'true');
    for (const cls of ['track', 'value']) {
      const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      c.setAttribute('class', cls);
      c.setAttribute('cx', '23');
      c.setAttribute('cy', '23');
      c.setAttribute('r', '19');
      svg.append(c);
    }
    const ring = el('div', { class: 'ring', role: 'img' }, [svg, el('span', { class: 'secs' })]);
    updateRing(ring, known);
    return ring;
  }

  /** Bouton « Déverrouiller » : ouvre le popup de l'extension (le mot de passe maître ne se tape jamais dans la page). */
  function unlockButton(note, intent = 'unlock') {
    return el('button', {
      class: 'btn primary',
      type: 'button',
      onclick: async () => {
        const res = await send({ type: 'content:openPopup', intent });
        if ((!res || !res.opened) && note) note.textContent = t('ext.card.lockedHint');
      },
    }, [icon(ICON.lock), document.createTextNode(t(intent === 'create' ? 'ext.toast.createVault' : 'ext.card.unlock'))]);
  }

  /* ═════════════ Carte du QR code ═════════════ */

  // addedUri : QR ajouté depuis cette carte (l'état « ajouté » ne dépend pas de l'ordre des réponses).
  const card = { uri: null, data: null, filledStep: null, tag: '', copied: false, timer: null, highlighted: null, addedUri: null };

  function highlight(element) {
    if (card.highlighted && card.highlighted !== element) {
      card.highlighted.style.outline = card.highlighted.dataset.mymfaOutline || '';
      card.highlighted.style.outlineOffset = card.highlighted.dataset.mymfaOffset || '';
    }
    if (!element) return;
    element.dataset.mymfaOutline = element.style.outline;
    element.dataset.mymfaOffset = element.style.outlineOffset;
    element.style.outline = '3px solid #13A89A';
    element.style.outlineOffset = '4px';
    card.highlighted = element;
  }

  function closeCard() {
    if (card.uri) dismissed.add(card.uri);
    clearInterval(card.timer);
    highlight(null);
    card.highlighted = null;
    card.uri = null;
    card.data = null;
    Ui.toast.close('qr');
    const next = [...found.keys()].find((uri) => !dismissed.has(uri));
    if (next) showCard(next);
  }

  async function showCard(uri) {
    card.uri = uri;
    card.filledStep = null;
    card.copied = false;
    card.data = await send({ type: 'content:lookup', uri });
    card.tag = '';
    highlight(found.get(uri));
    render();
    clearInterval(card.timer);
    card.timer = setInterval(tick, 1000);
  }

  async function refresh() {
    if (!card.uri) return;
    card.data = await send({ type: 'content:lookup', uri: card.uri });
    render();
  }

  /** Décompte local ; nouveau code demandé au changement de période. */
  function tick() {
    const known = card.data && card.data.known;
    if (!known || known.type === 'hotp') return;
    known.remaining -= 1;
    if (known.remaining <= 0) {
      refresh();
      return;
    }
    const ring = Ui.toast.query('qr', '.ring');
    if (!ring) return;
    updateRing(ring, known);
    Ui.toast.query('qr', '.code').classList.toggle('expiring', known.remaining <= 5);
  }

  async function copy(code) {
    await Ui.copyText(code);
    card.copied = true;
    render();
    setTimeout(() => {
      card.copied = false;
      render();
    }, 1600);
  }

  function knownView(known, added) {
    const step = Math.floor(Date.now() / 1000 / (known.period || 30));
    const filled = card.filledStep === step;
    const canFill = settings.fill && Boolean(otpTarget(known.digits));
    return el('div', { class: 'body' }, [
      el('div', { class: 'who' }, [
        Ui.tile(known.issuer || known.account),
        el('div', { class: 'who-text' }, [
          el('span', { class: 'issuer', text: known.issuer || known.account || '—' }),
          known.issuer && known.account ? el('span', { class: 'account', text: known.account }) : null,
        ]),
        known.tag ? el('span', { class: 'tag', text: known.tag.charAt(0).toUpperCase() + known.tag.slice(1) }) : null,
      ]),
      el('div', { class: 'code-box' }, [
        el('span', { class: `code${known.remaining !== null && known.remaining <= 5 ? ' expiring' : ''}`, text: Ui.formatCode(known.code) }),
        known.type === 'hotp' ? null : ringNode(known),
      ]),
      el('div', { class: 'actions wide' }, [
        el('button', {
          class: 'btn primary',
          type: 'button',
          disabled: !canFill && !filled,
          title: canFill ? null : t('ext.card.noField'),
          onclick: () => {
            if (fill(known.code)) {
              card.filledStep = step;
              render();
            }
          },
        }, [icon(ICON.fill), document.createTextNode(t(filled ? 'ext.card.filled' : 'ext.card.fill'))]),
        el('button', { class: 'btn', type: 'button', onclick: () => copy(known.code) }, [icon(ICON.copy), document.createTextNode(t(card.copied ? 'ext.card.copied' : 'ext.card.copy'))]),
      ]),
      el('p', { class: 'note', text: t(added ? 'ext.card.addedNote' : 'ext.card.knownNote', { issuer: known.issuer || '' }) }),
    ]);
  }

  function newView(data) {
    const parsed = data.parsed || {};
    const issuer = el('input', { value: parsed.issuer || '', 'aria-label': t('field.issuer') });
    const account = el('input', { value: parsed.account || '', 'aria-label': t('field.account') });
    const description = el('input', { placeholder: t('field.descriptionPlaceholder') });
    const tags = (data.tags || []).map((tag) =>
      el('button', {
        type: 'button',
        class: 'chip',
        'aria-pressed': String(card.tag === tag),
        text: tag.charAt(0).toUpperCase() + tag.slice(1),
        onclick: () => {
          card.tag = card.tag === tag ? '' : tag;
          render();
        },
      })
    );
    const newTag = el('input', { placeholder: t('field.newTagPlaceholder'), 'aria-label': t('field.newTagPlaceholder') });
    const error = el('p', { class: 'error', hidden: true });
    const add = el('button', { class: 'btn primary', type: 'submit' }, [icon(ICON.plus), document.createTextNode(t('ext.card.add'))]);
    const form = el('form', { class: 'body' }, [
      el('p', { class: 'title', text: t('ext.card.newTitle') }),
      el('div', { class: 'group' }, [
        el('label', {}, [document.createTextNode(t('field.issuer')), issuer]),
        el('label', {}, [document.createTextNode(t('field.account')), account]),
      ]),
      el('div', { class: 'field' }, [el('span', { class: 'section', text: t('field.tag') }), tags.length ? el('div', { class: 'chips' }, tags) : null, newTag]),
      el('label', { class: 'field' }, [el('span', { class: 'section', text: t('field.description') }), description]),
      error,
      el('div', { class: 'actions wide' }, [add, el('button', { class: 'btn', type: 'button', text: t('ext.card.ignore'), onclick: closeCard })]),
      el('p', { class: 'note', text: t('ext.card.privacy') }),
    ]);
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      add.disabled = true;
      const res = await send({
        type: 'content:add',
        uri: card.uri,
        issuer: issuer.value.trim(),
        account: account.value.trim(),
        tag: newTag.value.trim() || card.tag,
        description: description.value.trim(),
      });
      add.disabled = false;
      if (!res || res.error) {
        error.textContent = res ? t(`error.${res.error.code}`, res.error.params) : t('ext.error.noExtension');
        error.hidden = false;
        return;
      }
      card.addedUri = card.uri;
      card.data = res;
      render(true);
    });
    return form;
  }

  function lockedView() {
    const note = el('p', { class: 'note', text: t('ext.card.lockedText') });
    return el('div', { class: 'body' }, [
      el('p', { class: 'title', text: t('ext.card.lockedTitle') }),
      note,
      el('div', { class: 'actions' }, [unlockButton(note), el('button', { class: 'btn', type: 'button', text: t('ext.card.retry'), onclick: refresh })]),
    ]);
  }

  function cardView() {
    const data = card.data;
    if (!data) return { body: el('div', { class: 'body' }, [el('p', { class: 'error', text: t('ext.error.noExtension') })]) };
    if (data.error) return { body: el('div', { class: 'body' }, [el('p', { class: 'error', text: t(`error.${data.error.code}`, data.error.params) })]) };
    if (data.status === 'locked') return { badge: el('span', { class: 'badge warn', text: t('ext.card.badgeLocked') }), body: lockedView() };
    if (data.known) {
      const added = card.addedUri === card.uri;
      return { badge: el('span', { class: 'badge', text: t(added ? 'ext.card.badgeAdded' : 'ext.card.badgeKnown') }), body: knownView(data.known, added) };
    }
    return { badge: el('span', { class: 'badge warn', text: t('ext.card.badgeNew') }), body: newView(data) };
  }

  function render(force = false) {
    if (!card.uri) return;
    if (!Ui.toast.has('qr')) Ui.toast.open('qr', { priority: 25, render: cardView, onClose: (byUser) => byUser && closeCard() });
    else Ui.toast.refresh('qr', { force });
  }

  /* ═════════════ Code demandé par la page ═════════════ */

  // Le site attend un code (champ « code à usage unique ») et myMFA a un compte pour ce site :
  // toast avec les comptes du site. Les codes restent masqués : le service d'arrière-plan ne les
  // délivre qu'au clic (content:revealCode), pour ne rien donner d'avance à une page qui
  // imiterait un champ de vérification.
  const otp = { codes: [], status: null, known: false, filled: null, dismissed: false, timer: null, copied: null, checking: false, revealed: new Map() };

  /** Champ de code franchement identifié (pas un simple champ numérique). */
  const otpRequested = () => Boolean(otpTarget(6, 5));

  async function checkOtp(force = false) {
    if (!settings || !settings.fill || otp.dismissed || otp.checking || isApp) return;
    if (!force && Ui.toast.has('otp')) return;
    if (!otpRequested()) return;
    otp.checking = true;
    try {
      const res = await send({ type: 'content:codes' });
      if (!res || res.error) return;
      otp.status = res.status;
      otp.known = Boolean(res.known);
      otp.codes = res.codes || [];
      otp.revealed.clear(); // nouvelle liste (nouvelle période) : les codes révélés sont périmés
      if (otp.codes.length || (res.status === 'locked' && res.known)) showOtp();
      else Ui.toast.close('otp');
    } finally {
      otp.checking = false;
    }
  }

  function showOtp() {
    // Le code passe avant « Enregistrer le mot de passe ? » : c'est lui que la page attend maintenant.
    Ui.toast.open('otp', {
      priority: 35,
      render: otpView,
      onClose: (byUser) => {
        clearInterval(otp.timer);
        if (byUser || otp.filled) otp.dismissed = true; // rempli : ne pas reproposer (boucle)
      },
    });
    clearInterval(otp.timer);
    otp.timer = setInterval(otpTick, 1000);
  }

  function otpTick() {
    if (!Ui.toast.has('otp')) return clearInterval(otp.timer);
    let expired = false;
    for (const code of otp.codes) {
      if (code.type === 'hotp') continue;
      code.remaining -= 1;
      if (code.remaining <= 0) expired = true;
    }
    if (expired) return checkOtp(true);
    // Décompte mis à jour sur place : redessiner le toast chaque seconde le ferait clignoter.
    for (const item of Ui.toast.queryAll('otp', '.otp-item')) {
      const code = otp.codes.find((c) => c.id === item.dataset.id);
      if (!code || code.type === 'hotp') continue;
      const ring = item.querySelector('.ring');
      if (ring) updateRing(ring, code);
      item.querySelector('.code').classList.toggle('expiring', code.remaining <= 5);
    }
  }

  const maskCode = (digits) => {
    const half = Math.floor(digits / 2);
    return `${'•'.repeat(half)} ${'•'.repeat(digits - half)}`;
  };

  /** Le code d'un compte, demandé au service d'arrière-plan (clic utilisateur requis). */
  async function reveal(item) {
    if (otp.revealed.has(item.id)) return otp.revealed.get(item.id);
    const res = await send({ type: 'content:revealCode', id: item.id });
    if (!res || !res.code) return null;
    const entry = { code: res.code };
    otp.revealed.set(item.id, entry);
    return entry;
  }

  function otpView() {
    if (otp.status === 'locked') {
      const note = el('p', { class: 'note', text: t('ext.toast.otpLockedText') });
      return {
        badge: el('span', { class: 'badge warn', text: t('ext.card.badgeLocked') }),
        body: el('div', { class: 'body' }, [el('p', { class: 'title', text: t('ext.toast.otpTitle') }), note, el('div', { class: 'actions one' }, [unlockButton(note)])]),
      };
    }
    if (otp.filled) {
      setTimeout(() => Ui.toast.close('otp'), 1800);
      return { body: el('div', { class: 'body' }, [el('p', { class: 'success' }, [icon(ICON.check), document.createTextNode(t('ext.toast.codeFilled', { name: otp.filled }))])]) };
    }
    const rows = otp.codes.map((code) => {
      const name = code.issuer || code.account || '—';
      const revealed = otp.revealed.get(code.id);
      return el('div', { class: 'otp-item', 'data-id': code.id }, [
        el('div', { class: 'who' }, [
          Ui.tile(name, true),
          el('div', { class: 'who-text' }, [
            el('span', { class: 'issuer', text: name }),
            code.issuer && code.account ? el('span', { class: 'account', text: code.account }) : null,
          ]),
          code.type === 'hotp' ? null : ringNode(code),
        ]),
        el('div', { class: 'code-box' }, [
        el('span', { class: `code${code.remaining !== null && code.remaining <= 5 ? ' expiring' : ''}`, text: revealed ? Ui.formatCode(revealed.code) : maskCode(code.digits) }),
        el('button', {
          class: 'icon',
          type: 'button',
          'aria-label': t('credentials.show'),
          title: t('credentials.show'),
          onclick: async () => {
            await reveal(code);
            Ui.toast.refresh('otp');
          },
        }, icon(ICON.key)),
        el('button', {
          class: 'btn primary',
          type: 'button',
          'aria-label': t('ext.card.fill'),
          onclick: async () => {
            const got = await reveal(code);
            if (got && fill(got.code)) {
              otp.filled = name;
              Ui.toast.refresh('otp', { force: true });
            }
          },
        }, [icon(ICON.fill), document.createTextNode(t('ext.toast.fillShort'))]),
        el('button', {
          class: 'icon',
          type: 'button',
          'aria-label': t('ext.card.copy'),
          title: t(otp.copied === code.id ? 'ext.card.copied' : 'ext.card.copy'),
          onclick: async () => {
            const got = await reveal(code);
            if (!got) return;
            await Ui.copyText(got.code);
            otp.copied = code.id;
            Ui.toast.refresh('otp');
          },
        }, icon(otp.copied === code.id ? ICON.check : ICON.copy)),
        ]),
      ]);
    });
    return {
      badge: el('span', { class: 'badge', text: t('ext.toast.otpBadge') }),
      body: el('div', { class: 'body' }, [el('p', { class: 'title', text: t('ext.toast.otpTitle') }), el('div', { class: 'rows' }, rows)]),
    };
  }

  /* ═════════════ Démarrage ═════════════ */

  const isApp = Ui.isApp();

  async function start() {
    const state = await send({ type: 'content:state' });
    if (!state) return;
    settings = state.settings;
    I18n.init(settings.lang, { stored: false });
    Ui.setSettings(settings);
    if (state.appOrigin && location.origin === state.appOrigin) setupBridge();
    let otpTimer = null;
    new MutationObserver(() => {
      if (settings.detect) scheduleScan();
      clearTimeout(otpTimer);
      otpTimer = setTimeout(checkOtp, 400);
    }).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['src', 'srcset', 'style', 'class', 'hidden'] });
    checkOtp();
    if (!settings.detect) return;
    document.addEventListener('load', (event) => {
      if (event.target instanceof HTMLImageElement) scheduleScan(300);
    }, true);
    scheduleScan(300);
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes['ext.settings']) {
      settings = { ...settings, ...changes['ext.settings'].newValue };
      Ui.setSettings(settings);
    }
    if (area === 'local' && changes['ext.snapshot'] && card.uri) refresh();
  });

  start();
})();
