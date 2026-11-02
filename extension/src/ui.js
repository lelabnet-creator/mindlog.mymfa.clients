/*
 * Interface des scripts de contenu myMFA : un toast en bas à droite de la page.
 *  - Un seul toast visible ; le plus prioritaire l'emporte (passkey > code demandé > mot de passe > QR > remplissage),
 *    les autres attendent qu'il se ferme.
 *  - Shadow root fermé ; les actions qui libèrent un secret ou créent une passkey n'acceptent
 *    que de vrais clics (event.isTrusted), jamais un clic simulé par la page.
 *  - Aucun mot de passe maître n'est jamais saisi ici : la page pourrait écouter le clavier.
 * Partagé par content.js, passwords.js et webauthn.js (même monde isolé).
 */
(() => {
  'use strict';
  if (self.MyMfaUi) return;

  const STYLE = `
    :host { all: initial; }
    .card { position: fixed; right: 20px; bottom: 20px; z-index: 2147483647; width: 352px; max-width: calc(100vw - 40px);
      box-sizing: border-box; border-radius: 22px; overflow: hidden; font: 14px/1.45 'Manrope', system-ui, -apple-system, 'Segoe UI', sans-serif;
      background: var(--surface); color: var(--text); border: 1px solid var(--border2); box-shadow: 0 24px 60px rgba(7, 11, 19, .45);
      --surface:#0E1420; --inset:#070B13; --border:#1A2231; --border2:#283244; --text:#EEF2F8; --text2:#C3CBD8; --muted:#8E9AAE;
      --accent:#5EE6CF; --accentText:#5EE6CF; --accentSoft:#0F2A2A; --accentLine:#1F5C58; --warn:#F2B65A; --danger:#FF8A8A;
      --primaryBg:#F4F7FB; --primaryFg:#0A0F1A; --ring:#1F2A3A; --chip:#111826; }
    .card.light { --surface:#FFFFFF; --inset:#F2F5F9; --border:#E1E6EE; --border2:#D2D9E3; --text:#0B1220; --text2:#2E3A4C; --muted:#566275;
      --accent:#0E9488; --accentText:#0B7A72; --accentSoft:#E1F5F2; --accentLine:#9ED9D1; --warn:#9A5800; --danger:#B42318;
      --primaryBg:#0B1220; --primaryFg:#FFFFFF; --ring:#E1E6EE; --chip:#FFFFFF; box-shadow: 0 24px 60px rgba(11, 18, 32, .22); }
    .card.enter { animation: rise .22s ease-out; }
    @keyframes rise { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: none; } }
    * { box-sizing: border-box; }
    header { display: flex; align-items: center; gap: 8px; padding: 14px 10px 0 18px; }
    .brand { font-size: 15px; font-weight: 500; } .brand b { font-weight: 800; }
    .badge { margin-left: auto; font-size: 12px; font-weight: 700; padding: 3px 10px; border-radius: 999px; background: var(--accentSoft); color: var(--accentText); }
    .badge.warn { background: transparent; border: 1px solid var(--warn); color: var(--warn); }
    .icon { width: 36px; height: 36px; border: 0; border-radius: 10px; background: transparent; color: var(--muted); display: flex; align-items: center; justify-content: center; cursor: pointer; }
    .spacer { margin-left: auto; }
    .icon:hover { background: var(--inset); }
    svg { width: 18px; height: 18px; fill: none; stroke: currentColor; stroke-width: 2; stroke-linecap: round; stroke-linejoin: round; flex: none; }
    .body { padding: 12px 18px 18px; display: flex; flex-direction: column; gap: 12px; }
    .who { display: flex; align-items: center; gap: 12px; }
    .tile { width: 44px; height: 44px; border-radius: 12px; background: #fff; border: 1px solid var(--border); display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 15px; flex: none; }
    .tile.sm { width: 36px; height: 36px; border-radius: 10px; font-size: 13px; }
    .who-text { flex: 1; min-width: 0; display: flex; flex-direction: column; }
    .issuer { font-size: 15px; font-weight: 700; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .account { font-size: 13px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .tag { font-size: 12px; font-weight: 700; padding: 1px 8px; border-radius: 999px; background: var(--accentSoft); color: var(--accentText); }
    .code-box { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 14px; border-radius: 16px; background: var(--inset); border: 1px solid var(--border); }
    .code { font-size: 32px; font-weight: 500; letter-spacing: .03em; font-variant-numeric: tabular-nums; white-space: nowrap; flex: 1; }
    .otp-item { display: flex; flex-direction: column; gap: 8px; }
    .otp-item + .otp-item { padding-top: 10px; border-top: 1px solid var(--border); }
    .code.sm { font-size: 22px; }
    .secret { margin: 0; padding: 10px 12px; border-radius: 12px; border: 1px solid var(--border); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 15px; line-height: 1.4; word-break: break-all; user-select: all; }
    .code.expiring, .ring.expiring .secs { color: var(--warn); }
    .ring { position: relative; width: 44px; height: 44px; flex: none; }
    .ring svg { width: 44px; height: 44px; transform: rotate(-90deg); stroke-width: 3; }
    .ring .track { stroke: var(--ring); } .ring .value { stroke: var(--accent); transition: stroke-dashoffset .9s linear; }
    .ring.expiring .value { stroke: var(--warn); }
    .secs { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; font-size: 13px; font-weight: 700; color: var(--accentText); }
    .actions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
    .actions.wide { grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); }
    .actions.one { grid-template-columns: 1fr; }
    button.btn { display: flex; align-items: center; justify-content: center; gap: 8px; min-height: 44px; padding: 0 12px; border-radius: 14px; font: inherit; font-weight: 700; cursor: pointer; border: 1px solid var(--border2); background: transparent; color: var(--text); }
    button.primary { border: 0; background: var(--primaryBg); color: var(--primaryFg); }
    button.link { all: unset; align-self: flex-start; font-size: 12px; font-weight: 600; color: var(--muted); cursor: pointer; text-decoration: underline; text-underline-offset: 2px; }
    button:disabled { opacity: .5; cursor: not-allowed; }
    button:focus-visible, input:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .note { margin: 0; font-size: 12px; color: var(--muted); }
    .error { margin: 0; font-size: 13px; color: var(--danger); font-weight: 600; }
    .success { margin: 0; font-size: 14px; color: var(--accentText); font-weight: 700; display: flex; align-items: center; gap: 8px; }
    .title { margin: 0; font-size: 16px; font-weight: 700; }
    .group { border-radius: 16px; background: var(--inset); border: 1px solid var(--border); }
    .group label { display: flex; flex-direction: column; padding: 8px 14px; font-size: 11px; font-weight: 600; color: var(--muted); }
    .group label + label { border-top: 1px solid var(--border); }
    input { all: unset; display: block; width: 100%; font: inherit; color: var(--text); font-size: 15px; }
    .group label:first-child input { font-weight: 700; }
    .dots { font-size: 15px; letter-spacing: .12em; color: var(--text); }
    .section { font-size: 11px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; color: var(--muted); }
    .chips { display: flex; flex-wrap: wrap; gap: 6px; }
    .chip { min-height: 34px; padding: 0 12px; border-radius: 10px; border: 1px solid var(--border); background: var(--chip); color: var(--text2); font: inherit; font-size: 13px; font-weight: 600; cursor: pointer; }
    .chip[aria-pressed="true"] { background: var(--accentSoft); border-color: var(--accentLine); color: var(--accentText); }
    .field { display: flex; flex-direction: column; gap: 6px; }
    .field input { box-sizing: border-box; min-height: 40px; padding: 0 12px; border-radius: 12px; border: 1px solid var(--border2); background: var(--inset); font-size: 14px; }
    .rows { display: flex; flex-direction: column; gap: 6px; max-height: 260px; overflow: auto; }
    button.row { all: unset; display: flex; align-items: center; gap: 12px; padding: 8px 10px; border-radius: 14px; border: 1px solid var(--border); background: var(--inset); cursor: pointer; }
    button.row:hover { border-color: var(--accentLine); }
    button.row:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .row-go { color: var(--accentText); }
    @media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }
  `;

  const ICON = {
    close: 'M6 6l12 12M18 6 6 18',
    fill: 'M4 12h12M12 6l6 6-6 6M20 5v14',
    copy: 'M9 9h12v12H9zM5 15V5a2 2 0 0 1 2-2h10',
    plus: 'M12 5v14M5 12h14',
    lock: 'M6 10h12v11H6zM8 10V7a4 4 0 0 1 8 0v3',
    key: 'M15 7a4 4 0 1 1-3.9 4.9L4 19v2h3v-2h2v-2h2l1.1-1.1A4 4 0 0 1 15 7zM16 9h.01',
    check: 'M5 12l5 5L20 7',
    person: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0',
  };

  let settings = { theme: 'auto' };

  function el(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? '' : value);
    }
    for (const child of [].concat(children)) if (child) node.append(child);
    return node;
  }

  function icon(d) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', d);
    svg.append(path);
    return svg;
  }

  function logo() {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 30 22');
    svg.setAttribute('aria-hidden', 'true');
    svg.style.cssText = 'width:24px;height:18px;stroke:#2BB3C0;stroke-width:4';
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M3 19V10.5a5.75 5.75 0 0 1 11.5 0V19M14.5 10.5a5.75 5.75 0 0 1 11.5 0V19');
    svg.append(path);
    return svg;
  }

  function initials(name) {
    const words = String(name || '?').trim().split(/[\s._@-]+/).filter(Boolean);
    if (words.length > 1) return (words[0][0] + words[1][0]).toUpperCase();
    const word = words[0] || '?';
    const inner = word.slice(1).match(/[A-Z]/);
    return (word[0] + (inner ? inner[0] : word.slice(1, 2))).toUpperCase();
  }

  function brandColor(name) {
    let hash = 0;
    for (const ch of String(name || '').toLowerCase()) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
    return `hsl(${hash % 360} 62% 36%)`;
  }

  function tile(name, small) {
    const node = el('div', { class: small ? 'tile sm' : 'tile', text: initials(name) });
    node.style.color = brandColor(name);
    return node;
  }

  const formatCode = (code) => `${code.slice(0, Math.floor(code.length / 2))} ${code.slice(Math.floor(code.length / 2))}`;

  /** Gestionnaire d'événement réservé aux vrais clics de l'utilisateur. */
  const trusted = (handler) => (event) => {
    if (event.isTrusted) handler(event);
  };

  /** Valeur d'un champ, de façon que les frameworks (React, Vue…) la voient. */
  function setValue(input, value) {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    setter.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function visible(node) {
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0 && getComputedStyle(node).visibility !== 'hidden';
  }

  function isLight() {
    if (settings.theme === 'light') return true;
    if (settings.theme === 'dark') return false;
    return !window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  /* ───────────── Toast ───────────── */

  let host = null;
  let root = null;
  let shown = null; // clé du toast affiché
  const toasts = new Map(); // clé → { priority, render, onClose, order }
  let order = 0;

  function ensureHost() {
    if (host && document.documentElement.contains(host)) return;
    host = document.createElement('mymfa-card');
    root = host.attachShadow({ mode: 'closed' });
    document.documentElement.append(host);
  }

  function current() {
    let best = null;
    for (const [key, toast] of toasts) {
      if (!best || toast.priority > best[1].priority || (toast.priority === best[1].priority && toast.order > best[1].order)) best = [key, toast];
    }
    return best;
  }

  function draw(force) {
    const top = current();
    if (!top) {
      if (host) host.remove();
      host = null;
      shown = null;
      return;
    }
    const [key, toast] = top;
    ensureHost();
    // Ne pas effacer une saisie en cours dans ce même toast.
    if (!force && shown === key && root.activeElement && root.activeElement.tagName === 'INPUT') return;
    const view = toast.render() || {};
    // L'entrée ne s'anime qu'à l'apparition d'un toast, pas à chaque redessin (décompte, clic…) :
    // sinon la carte semble resurgir sans cesse.
    const entering = shown !== key;
    shown = key;
    root.replaceChildren(
      el('style', { text: STYLE }),
      el('aside', { class: `card${entering ? ' enter' : ''}${isLight() ? ' light' : ''}`, role: 'dialog', 'aria-label': view.label || 'myMFA' }, [
        el('header', {}, [
          logo(),
          el('span', { class: 'brand' }, [document.createTextNode('my'), el('b', { text: 'MFA' })]),
          view.badge || el('span', { class: 'spacer' }),
          el('button', {
            class: 'icon',
            type: 'button',
            'aria-label': I18n.t('ext.card.close'),
            title: I18n.t('ext.card.close'),
            onclick: () => close(key, true),
          }, icon(ICON.close)),
        ]),
        view.body,
      ])
    );
  }

  /**
   * Ouvre (ou remplace) un toast. render() → { badge, body, label } ; onClose(parUtilisateur).
   * Renvoie { refresh, close }.
   */
  function open(key, { priority = 0, render, onClose }) {
    const existing = toasts.get(key);
    toasts.set(key, { priority, render, onClose, order: existing ? existing.order : ++order });
    draw(shown !== key);
    return { refresh: () => refresh(key), close: () => close(key) };
  }

  function refresh(key, { force = false } = {}) {
    if (toasts.has(key) && (shown === key || current()[0] === key)) draw(force);
  }

  function close(key, byUser = false) {
    const toast = toasts.get(key);
    if (!toast) return;
    toasts.delete(key);
    draw(true);
    if (toast.onClose) toast.onClose(byUser);
  }

  /** Élément du toast affiché, s'il s'agit bien de celui-ci. */
  function query(key, selector) {
    return shown === key && root ? root.querySelector(selector) : null;
  }

  /** Tous les éléments du toast affiché qui répondent au sélecteur, s'il s'agit bien de celui-ci. */
  function queryAll(key, selector) {
    return shown === key && root ? [...root.querySelectorAll(selector)] : [];
  }

  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      ensureHost();
      const area = el('textarea');
      area.value = text;
      root.append(area);
      area.select();
      document.execCommand('copy');
      area.remove();
    }
  }

  function setSettings(next) {
    settings = { ...settings, ...next };
    if (shown) draw(false);
  }

  const isApp = () => Boolean(document.querySelector('meta[name="application-name"][content="myMFA"]'));

  self.MyMfaUi = {
    el, icon, ICON, logo, initials, brandColor, tile, formatCode, trusted, setValue, visible, copyText, setSettings, isApp,
    toast: { open, refresh, close, query, queryAll, has: (key) => toasts.has(key), host: () => host },
  };
})();
