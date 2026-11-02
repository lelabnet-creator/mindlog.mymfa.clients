/* Popup de l'extension myMFA. Dépend de : I18n, OTP, Store, Vault, Passgen. */
(() => {
  'use strict';

  const { t } = I18n;
  const $ = (id) => document.getElementById(id);
  const send = (message) => chrome.runtime.sendMessage(message);
  const AUTOLOCK_CHOICES = [1, 5, 15, 60, 0];
  const SWITCHES = [['sw-detect', 'detect'], ['sw-fill', 'fill'], ['sw-save', 'savePasswords'], ['sw-generate', 'generate'], ['sw-passkeys', 'passkeys']];
  const CLIENT_ID_RE = /^[\w-]+\.apps\.googleusercontent\.com$/;
  const DRIVE_EVERY_CHOICES = [0, 1, 6, 12, 24, 72, 168]; // heures (mêmes choix que le service d'arrière-plan)
  const TAB_KEY = 'mymfa.popupTab'; // dernier onglet choisi (Tout, Codes…)
  const ORDER_KEY = 'mymfa.popupOrder'; // vue « Tout » : domain | recent | alpha | tag
  const ORDERS = ['domain', 'recent', 'alpha', 'tag'];
  const TABS = ['all', 'codes', 'logins', 'passkeys'];

  const state = {
    view: 'main',
    status: 'empty',
    accounts: [],
    logins: [],
    passkeys: [],
    tabName: 'codes',
    settings: null,
    lastSync: null,
    drive: null,
    tab: null,
    host: '',
    hasField: false,
    query: '',
    filter: 'all', // vue « Tout » : all | fav
    order: 'domain', // vue « Tout » : groupée par domaine, ou comptes triés (recent, alpha)
    merged: new Map(), // clé de ligne → { login, account, passkey }
    editing: null,
    codes: new Map(),
    pendingUri: null,
  };

  /* ───────────── Utilitaires ───────────── */

  function h(tag, attrs = {}, children = []) {
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

  function errorText(res) {
    const err = res && res.error;
    if (!err) return t('ext.error.noExtension');
    const key = `error.${err.code}`;
    const text = t(key, err.params || {});
    return text === key ? t('error.generic', { message: err.code }) : text;
  }

  let toastTimer = null;
  function toast(message) {
    $('toast').textContent = message;
    $('toast').hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => ($('toast').hidden = true), 1800);
  }

  function initials(name) {
    const words = String(name || '?').trim().split(/[\s._-]+/).filter(Boolean);
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

  const formatCode = (code) => `${code.slice(0, Math.floor(code.length / 2))} ${code.slice(Math.floor(code.length / 2))}`;

  /* ───────────── Thème et langue ───────────── */

  function applyTheme() {
    const theme = state.settings.theme;
    if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
    else delete document.documentElement.dataset.theme;
    document.querySelectorAll('#theme [data-value]').forEach((b) => b.setAttribute('aria-checked', String(b.dataset.value === theme)));
  }

  async function saveSettings(patch) {
    const res = await send({ type: 'popup:saveSettings', settings: patch });
    if (res && res.settings) state.settings = res.settings;
  }

  /* ───────────── Site de l'onglet ───────────── */

  const matchesSite = (account) => Boolean(state.host) && Store.accountMatchesHost(account, state.host);

  /* ───────────── Codes ───────────── */

  async function codeOf(account, now) {
    const step = account.type === 'hotp' ? `c${account.counter}` : Math.floor(now / 1000 / account.period);
    const cached = state.codes.get(account.id);
    if (cached && cached.step === step) return cached.code;
    const code = account.type === 'hotp'
      ? await OTP.hotp(account.secret, account.counter, account)
      : await OTP.totp(account.secret, { ...account, timestamp: now });
    state.codes.set(account.id, { step, code });
    return code;
  }

  function row(account, { site }) {
    const node = $('tpl-row').content.firstElementChild.cloneNode(true);
    const name = account.issuer || account.account || '—';
    node.dataset.id = account.id;
    const tile = node.querySelector('.tile');
    tile.textContent = initials(name);
    tile.style.color = brandColor(name);
    node.querySelector('.item-issuer').textContent = name;
    node.querySelector('.item-account').textContent = account.issuer ? account.account : '';
    node.querySelector('[data-action="copy"]').setAttribute('aria-label', t('list.copy', { name }));
    const fill = node.querySelector('[data-action="fill"]');
    fill.hidden = !(site && state.hasField && state.settings.fill);
    fill.setAttribute('aria-label', t('ext.popup.fillFor', { name }));
    fill.title = t('ext.card.fill');
    const edit = node.querySelector('[data-action="edit"]');
    edit.setAttribute('aria-label', t('ext.popup.editItem', { name }));
    edit.title = edit.getAttribute('aria-label');
    if (site) node.classList.add('is-site');
    return node;
  }

  function renderLists() {
    const query = state.query.trim().toLowerCase();
    const site = state.accounts.filter(matchesSite);
    const all = state.accounts.filter(
      (a) => !query || [a.issuer, a.account, a.tag, a.description].some((v) => (v || '').toLowerCase().includes(query))
    );
    $('site-section').hidden = site.length === 0;
    $('site-list').replaceChildren(...site.map((a) => row(a, { site: true })));
    $('all-list').replaceChildren(...all.map((a) => row(a, { site: false })));
    const forSite = site.length + state.logins.filter(loginForSite).length;
    $('site-count').textContent = state.host ? t('ext.popup.siteCount', { count: forSite }) : '';
    const empty = $('empty');
    empty.hidden = all.length > 0;
    empty.textContent = state.accounts.length === 0
      ? t(state.status === 'empty' ? 'ext.popup.neverSynced' : 'ext.popup.noAccounts')
      : t('list.noMatch');
    tick();
  }

  async function tick() {
    const now = Date.now();
    const byId = new Map(state.accounts.map((a) => [a.id, a]));
    for (const li of document.querySelectorAll('.list li')) {
      const account = byId.get(li.dataset.id);
      if (!account) continue;
      try {
        const code = await codeOf(account, now);
        const button = li.querySelector('.item-code');
        button.textContent = formatCode(code);
        const expiring = account.type !== 'hotp' && OTP.remainingSeconds(account.period, now) <= 5;
        button.classList.toggle('is-expiring', expiring);
      } catch {
        li.querySelector('.item-code').textContent = '—';
      }
    }
  }

  async function copyCode(account) {
    await navigator.clipboard.writeText(await codeOf(account, Date.now()));
    send({ type: 'popup:logCopy', id: account.id });
    toast(t('toast.copied', { name: account.issuer || account.account }));
  }

  async function copyPassword(login) {
    await navigator.clipboard.writeText(login.password);
    send({ type: 'popup:touchLogin', id: login.id });
    toast(t('ext.popup.copiedPassword'));
  }

  async function onListClick(event) {
    const button = event.target.closest('[data-action]');
    const li = event.target.closest('li');
    if (!button || !li) return;
    const account = state.accounts.find((a) => a.id === li.dataset.id);
    if (!account) return;
    const code = await codeOf(account, Date.now());
    if (button.dataset.action === 'copy') {
      await copyCode(account);
    } else if (button.dataset.action === 'edit') {
      openEditor({ account });
    } else if (button.dataset.action === 'fill' && state.tab) {
      const res = await chrome.tabs.sendMessage(state.tab.id, { type: 'mymfa:fill', code }).catch(() => null);
      if (res && res.filled) window.close();
      else toast(t('ext.card.noField'));
    }
  }

  /* ───────────── Mots de passe et passkeys ───────────── */

  const { siteOf } = Store;

  const loginHost = (login) => {
    try {
      return new URL(login.origin).hostname.replace(/^www\./, '');
    } catch {
      return login.origin;
    }
  };
  const loginForSite = (login) => Boolean(state.host) && siteOf(loginHost(login)) === siteOf(state.host);

  function loginRow(login, { site }) {
    const node = $('tpl-login').content.firstElementChild.cloneNode(true);
    const host = loginHost(login);
    node.dataset.id = login.id;
    const tile = node.querySelector('.tile');
    tile.textContent = initials(login.title || host);
    tile.style.color = brandColor(host);
    node.querySelector('.item-issuer').textContent = login.title || host;
    // Ligne du site ouvert : ce qui l'accompagne (2FA, passkey) et un vrai bouton « Remplir ».
    const extras = site
      ? [host, state.accounts.some((a) => Store.accountMatchesHost(a, host)) ? '2FA' : '', state.passkeys.some((p) => siteOf(p.rpId) === siteOf(host)) ? 'passkey' : '']
      : [];
    node.querySelector('.item-account').textContent = site ? `${login.username || t('ext.toast.noUsername')} · ${extras.filter(Boolean).join(' · ')}` : login.username || t('ext.toast.noUsername');
    const label = (key) => t(key, { name: login.username || host });
    for (const [action, key] of [['copy-user', 'ext.popup.copyUser'], ['copy-password', 'ext.popup.copyPassword'], ['fill-login', 'ext.popup.fillLogin']]) {
      const button = node.querySelector(`[data-action="${action}"]`);
      button.setAttribute('aria-label', label(key));
      button.title = label(key);
    }
    node.querySelector('[data-action="copy-user"]').hidden = !login.username || site;
    node.querySelector('[data-action="copy-password"]').hidden = site;
    node.querySelector('[data-action="fill-login"]').hidden = !site;
    const edit = node.querySelector('[data-action="edit"]');
    edit.setAttribute('aria-label', t('ext.popup.editItem', { name: login.title || host }));
    edit.title = edit.getAttribute('aria-label');
    if (site) node.classList.add('is-site');
    return node;
  }

  function renderLogins() {
    const query = state.query.trim().toLowerCase();
    const site = state.logins.filter(loginForSite);
    const all = state.logins.filter((l) => !query || [loginHost(l), l.username, l.title].some((v) => (v || '').toLowerCase().includes(query)));
    $('protect').hidden = !(state.status === 'empty' || state.status === 'plain');
    $('site-logins-section').hidden = site.length === 0;
    $('site-logins').replaceChildren(...site.map((l) => loginRow(l, { site: true })));
    $('all-logins').replaceChildren(...all.map((l) => loginRow(l, { site: false })));
    $('empty-logins').hidden = all.length > 0 || !$('protect').hidden;
    $('empty-logins').textContent = state.logins.length ? t('list.noMatch') : t('ext.popup.noLogins');
  }

  function renderPasskeys() {
    const list = state.passkeys.slice().sort((a, b) => (a.rpName || a.rpId).localeCompare(b.rpName || b.rpId));
    $('all-passkeys').replaceChildren(
      ...list.map((p) => {
        const name = p.rpName || p.rpId;
        const tile = h('span', { class: 'tile', text: initials(name) });
        tile.style.color = brandColor(p.rpId);
        return h('li', { class: state.host && siteOf(state.host) === siteOf(p.rpId) ? 'is-site' : null }, [
          h('div', { class: 'item' }, [
            tile,
            h('span', { class: 'item-text' }, [h('span', { class: 'item-issuer', text: name }), h('span', { class: 'item-account', text: p.userName || p.userDisplayName || p.rpId })]),
          ]),
        ]);
      })
    );
    $('empty-passkeys').hidden = list.length > 0;
    $('empty-passkeys').textContent = t(state.status === 'empty' || state.status === 'plain' ? 'ext.popup.protectText' : 'ext.popup.noPasskeys');
  }

  async function onLoginClick(event) {
    const button = event.target.closest('[data-action]');
    const li = event.target.closest('li');
    if (!button || !li) return;
    const login = state.logins.find((l) => l.id === li.dataset.id);
    if (!login) return;
    if (button.dataset.action === 'copy-user') {
      await navigator.clipboard.writeText(login.username);
      toast(t('ext.popup.copiedUser'));
    } else if (button.dataset.action === 'copy-password') {
      await copyPassword(login);
    } else if (button.dataset.action === 'edit') {
      openEditor({ login });
    } else if (button.dataset.action === 'fill-login' && state.tab) {
      const res = await send({ type: 'popup:fillLogin', tabId: state.tab.id, id: login.id });
      if (res && res.filled) window.close();
      else toast(t('ext.card.noField'));
    }
  }

  /* ───────────── Vue « Tout » : un compte par ligne, ses trois informations ───────────── */

  const SVG_NS = 'http://www.w3.org/2000/svg';
  function svg(d, cls) {
    const node = document.createElementNS(SVG_NS, 'svg');
    node.setAttribute('viewBox', '0 0 24 24');
    node.setAttribute('aria-hidden', 'true');
    if (cls) node.setAttribute('class', cls);
    for (const part of [].concat(d)) {
      const path = document.createElementNS(SVG_NS, 'path');
      path.setAttribute('d', part);
      node.append(path);
    }
    return node;
  }
  const ICONS = {
    key: 'M15 7a4 4 0 1 1-3.9 4.9L4 19v2h3v-2h2v-2h2l1.1-1.1A4 4 0 0 1 15 7z',
    passkey: ['M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8z', 'M4 21a8 8 0 0 1 11-7.4', 'M19 15v6M17 19h4'],
    edit: 'M4 20h4L19 9l-4-4L4 16zM14 6l4 4',
    star: 'M12 3.5l2.6 5.3 5.9.9-4.3 4.1 1 5.8-5.2-2.7-5.2 2.7 1-5.8L3.5 9.7l5.9-.9z',
  };

  /**
   * Entrées de la vue « Tout » : une par site (ou par service pour un code 2FA sans site), chacune avec
   * un ou plusieurs comptes. Un compte réunit un mot de passe, le code 2FA et la passkey du même
   * identifiant ; à défaut d'identifiant commun, un seul mot de passe et un seul code restés d'un même
   * site vont ensemble. Le reste forme des comptes à part (code seul, passkey seule).
   */
  // Adresse IP (v4, ou v6 entre crochets) : pas un domaine, regroupées dans une entrée « Adresses IP ».
  const IP_HOST = /^(?:\d{1,3}\.){3}\d{1,3}$|^\[[0-9a-f:.]+\]$/i;
  const IP_KEY = 'ip';
  /** Hôte et port d'un mot de passe (192.168.1.1:8443), pour nommer une ligne d'adresse IP. */
  const hostPort = (login) => {
    try {
      return new URL(login.origin).host;
    } catch {
      return login.origin;
    }
  };

  /** Même utilisateur : identifiants égaux, ou même partie avant « @ » (alice ≈ alice@exemple.fr). */
  function sameUser(a, b) {
    const norm = (v) => String(v || '').trim().toLowerCase();
    const [x, y] = [norm(a), norm(b)];
    if (!x || !y) return false;
    return x === y || x.split('@')[0] === y.split('@')[0];
  }

  function mergedEntries() {
    const entries = new Map();
    const entry = (key, name, host) => {
      if (!entries.has(key)) entries.set(key, { key, name, host, logins: [], accounts: [], passkeys: [] });
      return entries.get(key);
    };
    for (const login of state.logins) {
      const host = loginHost(login);
      if (IP_HOST.test(host)) entry(IP_KEY, t('ext.popup.ipAddresses'), '').logins.push(login);
      else entry(`s:${siteOf(host)}`, siteOf(host), host).logins.push(login);
    }
    for (const passkey of state.passkeys) entry(`s:${siteOf(passkey.rpId)}`, siteOf(passkey.rpId), passkey.rpId).passkeys.push(passkey);
    for (const account of state.accounts) {
      const site = [...entries.values()].find((e) => e.host && Store.accountMatchesHost(account, e.host));
      const name = account.issuer || account.account || '—';
      (site || entry(`i:${name.toLowerCase()}`, name, '')).accounts.push(account);
    }
    const result = [];
    for (const e of entries.values()) {
      const accounts = [...e.accounts];
      const passkeys = [...e.passkeys];
      const take = (list, match) => {
        const i = list.findIndex(match);
        return i === -1 ? null : list.splice(i, 1)[0];
      };
      const lines = e.logins.map((login) => ({
        login,
        account: take(accounts, (a) => sameUser(a.account, login.username)),
        passkey: take(passkeys, (p) => sameUser(p.userName, login.username) || sameUser(p.userDisplayName, login.username)),
      }));
      // Identifiants différents mais un seul de chaque côté : c'est le même compte.
      const lone = lines.filter((l) => !l.account);
      if (lone.length === 1 && accounts.length === 1) lone[0].account = accounts.pop();
      const noKey = lines.filter((l) => !l.passkey);
      if (noKey.length === 1 && passkeys.length === 1) noKey[0].passkey = passkeys.pop();
      for (const account of accounts) lines.push({ login: null, account, passkey: null });
      for (const passkey of passkeys) lines.push({ login: null, account: null, passkey });
      for (const line of lines) {
        const { login, account, passkey } = line;
        line.name = (login && login.title) || (login && e.key === IP_KEY ? hostPort(login) : e.name);
        line.user = (login && (login.username || t('ext.toast.noUsername'))) || (account && (account.issuer ? account.account : '')) || (passkey && (passkey.userName || passkey.userDisplayName)) || '';
        line.favorite = Boolean((login && login.favorite) || (account && account.favorite));
        line.tag = (login && login.tag) || (account && account.tag) || '';
        // Dernier usage : mot de passe rempli ou copié, code affiché ou copié, passkey utilisée.
        line.usedAt = [login, account, passkey].reduce((max, item) => (item && item.usedAt && item.usedAt > max ? item.usedAt : max), '');
      }
      // Dans un domaine : comptes par ordre alphabétique (identifiant, puis nom).
      // Adresses IP : par adresse d'abord (192.168.1.2 avant 192.168.1.10).
      const byUser = (a, b) => a.user.localeCompare(b.user, undefined, { sensitivity: 'base' });
      const plain = (name) => name.replace(/^\[/, ''); // [fd00::1] après les IPv4
      const byName = (a, b) => plain(a.name).localeCompare(plain(b.name), undefined, { numeric: true });
      lines.sort(e.key === IP_KEY ? (a, b) => byName(a, b) || byUser(a, b) : (a, b) => byUser(a, b) || byName(a, b));
      lines.forEach((line, i) => (line.key = `${e.key}#${i}`));
      e.lines = lines;
      e.favorite = lines.some((l) => l.favorite);
      e.site = Boolean(state.host) && ((e.host && siteOf(e.host) === siteOf(state.host)) || e.accounts.some(matchesSite) || e.logins.some(loginForSite));
      result.push(e);
    }
    // Le site ouvert d'abord, puis les favoris, puis l'ordre alphabétique.
    return result.sort((a, b) => b.site - a.site || b.favorite - a.favorite || a.name.localeCompare(b.name));
  }

  function tileFor(entry) {
    // Domaine : initiales du nom, sans l'extension (github.com → GI, comme l'app).
    const label = entry.key === IP_KEY ? 'IP' : initials(entry.host && entry.name === siteOf(entry.host) ? entry.name.split('.')[0] : entry.name);
    const tile = h('span', { class: 'tile', text: label });
    tile.style.color = brandColor(entry.host || entry.name);
    return tile;
  }

  /** Ce qu'un compte permet : passkey (indicateur), code (copie), mot de passe (copie), modifier. */
  function lineActions(line) {
    const label = (key) => t(key, { name: line.user || line.name });
    return [
      line.passkey ? h('span', { class: 'item-passkey', title: t('ext.popup.hasPasskey'), role: 'img', 'aria-label': t('ext.popup.hasPasskey') }, svg(ICONS.passkey)) : null,
      line.account ? h('button', { type: 'button', class: 'item-code', 'data-action': 'copy', 'aria-label': t('list.copy', { name: line.user || line.name }) }) : null,
      line.login ? h('button', { type: 'button', class: 'icon-btn small', 'data-action': 'copy-password', 'aria-label': label('ext.popup.copyPassword'), title: label('ext.popup.copyPassword') }, svg(ICONS.key)) : null,
      line.login || line.account
        ? h('button', { type: 'button', class: 'icon-btn small muted-btn', 'data-action': 'edit', 'aria-label': label('ext.popup.editItem'), title: label('ext.popup.editItem') }, svg(ICONS.edit))
        : null,
    ];
  }

  function starred(text, favorite, cls) {
    const node = h('span', { class: cls });
    if (favorite) node.append(svg(ICONS.star, 'item-star'));
    node.append(text);
    return node;
  }

  /** Une entrée : une ligne si elle n'a qu'un compte, sinon un en-tête et une ligne par compte. */
  function mergedEntry(entry, lines) {
    const data = (line) => ({ 'data-key': line.key, 'data-id': line.account ? line.account.id : null });
    if (entry.lines.length === 1) {
      const [line] = lines;
      return h('li', { class: `line${entry.site ? ' is-site' : ''}`, ...data(line) }, [
        h('div', { class: 'item' }, [
          tileFor(entry),
          h('span', { class: 'item-text' }, [starred(line.name, line.favorite, 'item-issuer'), h('span', { class: 'item-account', text: line.user })]),
          ...lineActions(line),
        ]),
      ]);
    }
    return h('li', { class: `entry${entry.site ? ' is-site' : ''}`, 'data-entry': entry.key }, [
      h('div', { class: 'item entry-head' }, [
        tileFor(entry),
        h('span', { class: 'item-text' }, [
          h('span', { class: 'item-issuer', text: entry.name }),
          h('span', { class: 'item-account', text: t('ext.popup.accountCount', { count: entry.lines.length }) }),
        ]),
      ]),
      h('ul', { class: 'sublist' }, lines.map((line) =>
        h('li', { class: 'line', ...data(line) }, [
          h('div', { class: 'item sub' }, [
            h('span', { class: 'item-text' }, [
              starred(line.user || line.name, line.favorite, 'item-user'),
              // Sous l'identifiant : l'adresse (entrée « Adresses IP ») ou le nom donné au mot de passe.
              entry.key === IP_KEY
                ? h('span', { class: 'item-account', text: line.name })
                : line.login && line.login.title && line.login.title !== entry.name ? h('span', { class: 'item-account', text: line.login.title }) : null,
            ]),
            ...lineActions(line),
          ]),
        ])
      )),
    ]);
  }

  function tagGroup(tag, items) {
    return h('li', { class: 'entry tag-group', 'data-tag': tag || null }, [
      h('div', { class: 'tag-head' }, [
        h('span', { class: tag ? 'tag-name' : 'tag-name none', text: tag ? `#${tag}` : t('ext.popup.noTag') }),
        h('span', { class: 'item-account', text: t('ext.popup.accountCount', { count: items.length }) }),
      ]),
      h('ul', { class: 'sublist' }, items.map(({ entry, line }) => mergedEntry(entry, [line]))),
    ]);
  }

  function renderMerged() {
    const query = state.query.trim().toLowerCase();
    const entries = mergedEntries();
    state.merged = new Map(entries.flatMap((e) => e.lines.map((line) => [line.key, line])));
    const matches = (v) => (v || '').toLowerCase().includes(query);
    const visible = (entry) => {
      const entryHit = !query || matches(entry.name) || matches(entry.host);
      return entry.lines.filter(
        (line) => (state.filter !== 'fav' || line.favorite) && (entryHit || [line.user, line.name, line.tag].some(matches))
      );
    };
    const nodes = [];
    if (state.order === 'domain') {
      for (const entry of entries) {
        const lines = visible(entry);
        if (lines.length) nodes.push(mergedEntry(entry, lines));
      }
    } else {
      // Un compte par ligne, avec le nom de son site : par dernier usage (jamais utilisés à la fin) ou A → Z.
      const flat = entries.flatMap((entry) => visible(entry).map((line) => ({ entry: { ...entry, lines: [line], site: false }, line })));
      const alpha = (a, b) => a.line.name.localeCompare(b.line.name) || a.line.user.localeCompare(b.line.user);
      flat.sort(state.order === 'recent' ? (a, b) => b.line.usedAt.localeCompare(a.line.usedAt) || alpha(a, b) : alpha);
      if (state.order === 'tag') {
        // Un groupe par tag (A → Z), puis les comptes sans tag.
        const groups = new Map();
        for (const item of flat) {
          if (!groups.has(item.line.tag)) groups.set(item.line.tag, []);
          groups.get(item.line.tag).push(item);
        }
        const keys = [...groups.keys()].sort((a, b) => (a === '') - (b === '') || a.localeCompare(b));
        for (const tag of keys) nodes.push(tagGroup(tag, groups.get(tag)));
      } else {
        for (const { entry, line } of flat) nodes.push(mergedEntry(entry, [line]));
      }
    }
    $('merged-list').replaceChildren(...nodes);
    document.querySelectorAll('[data-filter]').forEach((chip) => chip.setAttribute('aria-pressed', String(chip.dataset.filter === state.filter)));
    const empty = $('empty-merged');
    empty.hidden = nodes.length > 0;
    empty.textContent = !entries.length
      ? t(state.status === 'empty' ? 'ext.popup.neverSynced' : 'ext.popup.noAccounts')
      : state.filter === 'fav' && !query ? t('ext.popup.noFavorites') : t('list.noMatch');
    tick();
  }

  async function onMergedClick(event) {
    const button = event.target.closest('[data-action]');
    const li = event.target.closest('li.line');
    const row = li && state.merged.get(li.dataset.key);
    if (!button || !row) return;
    if (button.dataset.action === 'copy' && row.account) await copyCode(row.account);
    else if (button.dataset.action === 'copy-password' && row.login) await copyPassword(row.login);
    else if (button.dataset.action === 'edit') openEditor(row);
  }

  /* ───────────── Modifier ───────────── */

  /** Formulaire de modification : la partie mot de passe et / ou la partie code 2FA. */
  function openEditor({ login = null, account = null }) {
    state.editing = { login, account };
    const f = $('edit-form').elements;
    $('edit-login').hidden = !login;
    $('edit-account').hidden = !account;
    if (login) {
      f.origin.value = login.origin;
      f.username.value = login.username || '';
      f.password.value = login.password;
      f.password.type = 'password';
      f.title.value = login.title || '';
      f.note.value = login.note || '';
    }
    if (account) {
      f.issuer.value = account.issuer || '';
      f.account.value = account.account || '';
      f.description.value = account.description || '';
    }
    // Un tag pour la ligne : celui du mot de passe ou du code ; enregistré sur les deux.
    f.tag.value = (login && login.tag) || (account && account.tag) || '';
    const tags = [...new Set([...state.accounts, ...state.logins].map((x) => x.tag).filter(Boolean))].sort();
    $('tag-list').replaceChildren(...tags.map((tag) => h('option', { value: tag })));
    $('sw-favorite').setAttribute('aria-checked', String(Boolean((login && login.favorite) || (account && account.favorite))));
    $('edit-title').textContent = t('ext.popup.editItem', { name: login ? login.title || loginHost(login) : account.issuer || account.account || '—' });
    $('edit-error').hidden = true;
    showView('edit');
  }

  async function saveEdit(event) {
    event.preventDefault();
    const { login, account } = state.editing || {};
    const f = $('edit-form').elements;
    const favorite = $('sw-favorite').getAttribute('aria-checked') === 'true';
    const error = $('edit-error');
    error.hidden = true;
    let res = null;
    if (login) {
      const origin = f.origin.value.trim();
      res = await send({
        type: 'popup:updateLogin',
        id: login.id,
        patch: {
          origin: /^[a-z][a-z0-9+.-]*:/i.test(origin) ? origin : `https://${origin}`,
          username: f.username.value,
          password: f.password.value,
          title: f.title.value,
          note: f.note.value,
          tag: f.tag.value,
          favorite,
        },
      });
    }
    if (account && !(res && res.error)) {
      res = await send({
        type: 'popup:updateAccount',
        id: account.id,
        patch: { issuer: f.issuer.value, account: f.account.value, tag: f.tag.value, description: f.description.value, favorite },
      });
    }
    if (!res || res.error) {
      error.textContent = errorText(res);
      error.hidden = false;
      return;
    }
    state.editing = null;
    f.password.value = '';
    apply(res);
    showView('main');
    toast(t('ext.popup.saved'));
  }

  function showTab(tab) {
    state.tabName = tab;
    try {
      localStorage.setItem(TAB_KEY, tab);
    } catch {
      /* préférence non retenue */
    }
    document.querySelectorAll('#tabs [data-tab]').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === tab)));
    document.querySelectorAll('[data-pane]').forEach((pane) => (pane.hidden = pane.dataset.pane !== tab));
    $('btn-scan').hidden = state.view !== 'main' || tab !== 'codes';
  }

  /* ───────────── Vues ───────────── */

  function showView(view) {
    state.view = view;
    document.querySelectorAll('[data-view]').forEach((section) => (section.hidden = section.dataset.view !== view));
    $('btn-back').hidden = view === 'main' || view === 'unlock';
    $('btn-scan').hidden = view !== 'main' || (state.tabName || 'codes') !== 'codes';
    $('btn-settings').hidden = view !== 'main' && view !== 'unlock';
    $('btn-lock').hidden = !(view === 'main' && state.status === 'unlocked');
    if (view === 'unlock') setTimeout(() => $('unlock-password').focus(), 30);
    if (view === 'create') setTimeout(() => $('create-password').focus(), 30);
  }

  /** L'app embarquée, sur la vue `hash` : son onglet s'il est déjà ouvert, sinon un nouveau. */
  async function openApp(hash = '') {
    const page = chrome.runtime.getURL('app/index.html');
    // Sans la permission « tabs », chrome.tabs.query ne donne pas les adresses : les contextes de l'extension, si.
    const contexts = await chrome.runtime.getContexts({ contextTypes: ['TAB'] });
    const open = contexts.find((c) => c.documentUrl && c.documentUrl.startsWith(page));
    if (open) {
      await chrome.tabs.update(open.tabId, { active: true, ...(hash ? { url: page + hash } : {}) });
      await chrome.windows.update(open.windowId, { focused: true });
    } else {
      await chrome.tabs.create({ url: page + hash });
    }
    window.close();
  }

  function renderFooter() {
    const synced = Boolean(state.lastSync);
    $('foot-dot').classList.toggle('off', !synced);
    $('sync-dot').classList.toggle('off', !synced);
    const text = synced
      ? t('ext.popup.lastSync', { date: new Intl.DateTimeFormat(I18n.getLocale(), { dateStyle: 'short', timeStyle: 'short' }).format(new Date(state.lastSync)) })
      : t('ext.popup.notSynced');
    $('foot-text').textContent = text;
    $('sync-text').textContent = text;
  }

  function apply(data) {
    if (!data || data.error) {
      toast(errorText(data));
      return;
    }
    state.status = data.status;
    state.accounts = data.accounts || [];
    state.logins = data.logins || [];
    state.passkeys = data.passkeys || [];
    // Mots de passe en attente du coffre : rappelés là où on le crée ou le déverrouille.
    const pending = (data.pending || []).join(', ');
    for (const id of ['create-pending', 'unlock-pending']) {
      $(id).hidden = !pending;
      $(id).textContent = pending ? t('ext.popup.pendingSave', { sites: pending }) : '';
    }
    state.settings = data.settings;
    state.lastSync = data.lastSync;
    state.drive = data.drive || null;
    state.codes.clear();
    applyTheme();
    renderFooter();
    renderDrive();
    renderLists();
    renderLogins();
    renderPasskeys();
    renderMerged();
    if (state.view === 'create' && (state.status === 'locked' || state.status === 'unlocked')) showView('main');
    if (state.view === 'main' || state.view === 'unlock') showView(state.status === 'locked' ? 'unlock' : 'main');
  }

  async function reload() {
    apply(await send({ type: 'popup:list' }));
  }

  /* ───────────── Scanner l'onglet ───────────── */

  async function scanTab() {
    if (!state.tab) return;
    const status = $('scan-status');
    status.hidden = false;
    status.textContent = t('ext.popup.scanning');
    const res = await send({ type: 'popup:scanTab', windowId: state.tab.windowId });
    if (!res || res.error) {
      status.textContent = errorText(res);
      return;
    }
    if (!res.found) {
      status.textContent = t(res.notOtp ? 'error.qrNotOtp' : 'ext.popup.scanNone');
      return;
    }
    const lookup = res.lookup || {};
    if (lookup.error) {
      status.textContent = errorText(lookup);
      return;
    }
    if (lookup.status === 'locked') {
      status.textContent = t('ext.card.lockedTitle');
      return;
    }
    if (lookup.known) {
      status.textContent = t('ext.popup.scanKnown', { name: lookup.known.issuer || lookup.known.account });
      const li = document.querySelector(`#all-list li[data-id="${CSS.escape(lookup.known.id)}"]`);
      if (li) {
        li.classList.add('is-found');
        li.scrollIntoView({ block: 'center' });
      }
      return;
    }
    status.hidden = true;
    state.pendingUri = res.uri;
    const form = $('add-form');
    form.reset();
    form.elements.issuer.value = (lookup.parsed && lookup.parsed.issuer) || '';
    form.elements.account.value = (lookup.parsed && lookup.parsed.account) || '';
    $('tag-list').replaceChildren(...(lookup.tags || []).map((tag) => h('option', { value: tag })));
    $('add-error').hidden = true;
    showView('add');
  }

  /* ───────────── Google Drive ───────────── */

  function renderDrive() {
    const drive = state.drive;
    if (!drive) return;
    const ok = Boolean(drive.lastSync) && !drive.error;
    $('drive-dot').classList.toggle('off', !ok);
    $('drive-text').textContent = drive.error
      ? errorText({ error: { code: drive.error } })
      : drive.lastSync
        ? t('ext.settings.driveLastSync', { date: I18n.formatDateTime(drive.lastSync) })
        : t('ext.settings.driveNever');
    // Prochaine sauvegarde automatique (politique « toutes les N heures ») ; en retard = à la prochaine vérification.
    const next = drive.next && Date.parse(drive.next) > Date.now() ? drive.next : null;
    $('drive-next').hidden = !drive.next;
    $('drive-next').textContent = next ? t('ext.settings.driveNext', { date: I18n.formatDateTime(next) }) : t('ext.settings.driveDue');
    const every = $('drive-every');
    every.replaceChildren(...DRIVE_EVERY_CHOICES.map((hours) => h('option', { value: String(hours), text: t(`ext.settings.every.${hours}`) })));
    every.value = String(state.settings.driveEvery ?? 24);
    $('drive-client-field').hidden = drive.deployed;
    if (document.activeElement !== $('drive-client-id')) $('drive-client-id').value = drive.deployed ? '' : drive.clientId;
    $('drive-redirect').replaceChildren(`${t('ext.settings.driveRedirect')} `, h('code', { class: 'redirect', text: drive.redirectUrl }));
    $('btn-drive-off').hidden = !state.settings.drive;
  }

  function setupDrive() {
    $('drive-client-id').addEventListener('change', async () => {
      const value = $('drive-client-id').value.trim();
      if (value && !CLIENT_ID_RE.test(value)) {
        toast(t('error.invalidClientId'));
        return;
      }
      await saveSettings({ driveClientId: value });
      reload();
    });
    // La fenêtre de connexion Google ferme le popup : le résultat s'affichera à sa réouverture.
    $('btn-drive-sync').addEventListener('click', async (event) => {
      const button = event.currentTarget;
      button.disabled = true;
      const res = await send({ type: 'popup:driveSync' });
      button.disabled = false;
      await reload();
      if (!res || res.error) toast(errorText(res));
      else if (res.needsUnlock || state.status === 'locked') toast(t('ext.settings.driveUnlock'));
      else toast(t('ext.settings.backupDone'));
    });
    $('drive-every').addEventListener('change', async () => {
      await saveSettings({ driveEvery: Number($('drive-every').value) });
      await reload();
      toast(t('ext.settings.driveEverySaved'));
    });
    $('btn-drive-off').addEventListener('click', async () => {
      apply(await send({ type: 'popup:driveDisconnect' }));
      toast(t('ext.settings.driveOffDone'));
    });
  }

  /* ───────────── Réglages ───────────── */

  function renderSettings() {
    const s = state.settings;
    for (const [id, key] of SWITCHES) $(id).setAttribute('aria-checked', String(Boolean(s[key])));
    $('never-panel').hidden = !(s.neverSave || []).length;
    $('never-list').replaceChildren(
      ...(s.neverSave || []).map((site) =>
        h('li', {}, [
          h('span', { text: site }),
          h('button', {
            type: 'button',
            class: 'btn btn-ghost btn-sm',
            text: t('ext.settings.neverRemove'),
            onclick: async () => {
              const res = await send({ type: 'popup:forgetSite', site });
              if (res && res.settings) state.settings = res.settings;
              renderSettings();
            },
          }),
        ])
      )
    );
    $('app-url').value = s.appUrl;
    $('lang').value = I18n.getLocale();
    $('auto-lock').value = String(s.autoLock);
    applyTheme();
  }

  function setupSettings() {
    for (const [id, key] of SWITCHES) {
      $(id).addEventListener('click', async () => {
        await saveSettings({ [key]: !state.settings[key] });
        renderSettings();
      });
    }
    $('app-url').addEventListener('change', async () => {
      // Facultative : vide, l'extension ne se synchronise qu'avec l'app qu'elle embarque.
      const value = $('app-url').value.trim();
      let url = null;
      try {
        if (value) url = new URL(value);
      } catch {
        /* traité ci-dessous */
      }
      if (value && (!url || !/^https?:$/.test(url.protocol))) {
        toast(t('ext.error.badUrl'));
        renderSettings();
        return;
      }
      await saveSettings({ appUrl: url ? url.origin : '' });
      renderSettings();
      toast(t('ext.settings.saved'));
    });
    $('btn-sync').addEventListener('click', async () => {
      const res = await send({ type: 'popup:syncNow' });
      if (res && res.tabs > 0) {
        toast(t('ext.settings.syncStarted'));
        setTimeout(reload, 1200);
      } else {
        toast(t('ext.settings.openAppToSync'));
      }
    });
    document.querySelectorAll('#theme [data-value]').forEach((button) =>
      button.addEventListener('click', async () => {
        await saveSettings({ theme: button.dataset.value });
        applyTheme();
      })
    );
    $('lang').replaceChildren(...I18n.locales().map(({ code, name }) => h('option', { value: code, text: name })));
    $('lang').addEventListener('change', async () => {
      await saveSettings({ lang: $('lang').value });
      I18n.setLocale($('lang').value);
    });
    $('auto-lock').replaceChildren(
      ...AUTOLOCK_CHOICES.map((m) => h('option', { value: String(m), text: m === 0 ? t('security.autoLockNever') : t('security.autoLockMinutes', { count: m }) }))
    );
    $('auto-lock').addEventListener('change', () => saveSettings({ autoLock: Number($('auto-lock').value) }));
  }

  /* ───────────── Démarrage ───────────── */

  async function init() {
    const data = await send({ type: 'popup:list' });
    state.settings = (data && data.settings) || { theme: 'auto', lang: '', fill: true, detect: true, appUrl: '', autoLock: 15 };
    I18n.init(state.settings.lang, { stored: false });
    I18n.apply(document);
    applyTheme();
    setupSettings();
    setupDrive();

    [state.tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    try {
      const url = new URL(state.tab.url);
      if (/^https?:$/.test(url.protocol)) state.host = url.hostname.replace(/^www\./, '');
    } catch {
      state.host = '';
    }
    $('site-host').textContent = state.host || t('ext.popup.noSite');
    if (state.host) {
      const res = await chrome.tabs.sendMessage(state.tab.id, { type: 'mymfa:hasField' }).catch(() => null);
      state.hasField = Boolean(res && res.field);
    }

    apply(data);
    // Ouvert depuis un toast de la page : on montre ce qu'il faut (sites connus, mots de passe…).
    const { intent } = (await send({ type: 'popup:intent' })) || {};
    let remembered = null;
    try {
      remembered = localStorage.getItem(TAB_KEY);
    } catch {
      /* rien de retenu */
    }
    if (TABS.includes(remembered)) showTab(remembered);
    else if (state.logins.some(loginForSite) && !state.accounts.some(matchesSite)) showTab('logins');
    else showTab('codes');
    if (intent === 'create' && (state.status === 'empty' || state.status === 'plain')) showView('create');

    $('site-list').addEventListener('click', onListClick);
    $('all-list').addEventListener('click', onListClick);
    $('site-logins').addEventListener('click', onLoginClick);
    $('all-logins').addEventListener('click', onLoginClick);
    $('merged-list').addEventListener('click', onMergedClick);
    document.querySelectorAll('[data-filter]').forEach((chip) =>
      chip.addEventListener('click', () => {
        state.filter = chip.dataset.filter;
        renderMerged();
      })
    );
    try {
      const order = localStorage.getItem(ORDER_KEY);
      if (ORDERS.includes(order)) state.order = order;
    } catch {
      /* rien de retenu */
    }
    $('merged-order').value = state.order;
    renderMerged();
    $('merged-order').addEventListener('change', () => {
      state.order = $('merged-order').value;
      try {
        localStorage.setItem(ORDER_KEY, state.order);
      } catch {
        /* préférence non retenue */
      }
      renderMerged();
    });
    $('search-all').addEventListener('input', () => {
      state.query = $('search-all').value;
      renderMerged();
    });
    $('edit-form').addEventListener('submit', saveEdit);
    $('sw-favorite').addEventListener('click', () => {
      const sw = $('sw-favorite');
      sw.setAttribute('aria-checked', String(sw.getAttribute('aria-checked') !== 'true'));
    });
    $('edit-reveal').addEventListener('click', () => {
      const input = $('edit-password');
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      const label = t(show ? 'credentials.hide' : 'credentials.show');
      $('edit-reveal').setAttribute('aria-label', label);
      $('edit-reveal').title = label;
    });
    $('edit-generate').addEventListener('click', () => {
      const input = $('edit-password');
      input.value = Passgen.generate();
      input.type = 'text';
    });
    document.querySelectorAll('#tabs [data-tab]').forEach((button) => button.addEventListener('click', () => showTab(button.dataset.tab)));
    $('btn-protect').addEventListener('click', () => showView('create'));
    // Jauge de solidité du futur mot de passe maître (estimation partagée, lib/vault.js).
    const meter = $('create-meter');
    const meterBars = meter.querySelectorAll('.meter-bars span');
    const meterLabel = meter.querySelector('.meter-label');
    $('create-password').addEventListener('input', () => {
      const value = $('create-password').value;
      const { level } = Vault.passwordStrength(value);
      meter.hidden = !value;
      meter.dataset.level = String(level);
      meterBars.forEach((bar, i) => bar.classList.toggle('is-on', i < level));
      meterLabel.textContent = level ? t(`security.strength.${level}`) : '';
    });
    $('create-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const error = $('create-error');
      error.hidden = true;
      if ($('create-password').value !== $('create-confirm').value) {
        error.textContent = t('error.passwordMismatch');
        error.hidden = false;
        return;
      }
      const button = event.submitter;
      button.disabled = true;
      const res = await send({ type: 'popup:createVault', password: $('create-password').value });
      button.disabled = false;
      if (!res || res.error) {
        error.textContent = errorText(res);
        error.hidden = false;
        return;
      }
      $('create-password').value = '';
      $('create-confirm').value = '';
      toast(t('ext.popup.created'));
      apply(res);
      showView('main');
    });
    $('search').addEventListener('input', () => {
      state.query = $('search').value;
      renderLists();
      renderLogins();
    });
    $('btn-scan').addEventListener('click', scanTab);
    $('btn-settings').addEventListener('click', () => {
      renderSettings();
      showView('settings');
    });
    $('btn-back').addEventListener('click', () => showView(state.status === 'locked' ? 'unlock' : 'main'));
    $('btn-lock').addEventListener('click', async () => apply(await send({ type: 'popup:lock' })));
    $('open-app').addEventListener('click', (event) => {
      event.preventDefault();
      openApp();
    });
    // Le choix d'un fichier fermerait le popup : l'import se fait dans l'app embarquée, sur sa ligne.
    $('btn-import').addEventListener('click', () => openApp('#/settings/import'));

    $('unlock-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = event.submitter;
      button.disabled = true;
      $('unlock-error').hidden = true;
      const res = await send({ type: 'popup:unlock', password: $('unlock-password').value });
      button.disabled = false;
      if (!res || res.error) {
        $('unlock-error').textContent = errorText(res);
        $('unlock-error').hidden = false;
        $('unlock-password').select();
        return;
      }
      $('unlock-password').value = '';
      apply(res);
    });

    $('add-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const f = event.target.elements;
      const res = await send({
        type: 'popup:add',
        uri: state.pendingUri,
        issuer: f.issuer.value.trim(),
        account: f.account.value.trim(),
        tag: f.tag.value.trim(),
        description: f.description.value.trim(),
      });
      if (!res || res.error) {
        $('add-error').textContent = errorText(res);
        $('add-error').hidden = false;
        return;
      }
      state.pendingUri = null;
      toast(t('toast.added'));
      showView('main');
      reload();
    });

    I18n.onChange(() => {
      I18n.apply(document);
      renderFooter();
      renderDrive();
      renderLists();
      $('site-host').textContent = state.host || t('ext.popup.noSite');
      renderLogins();
      renderPasskeys();
      renderMerged();
    });

    // Données mises à jour par une synchronisation ou un ajout depuis une page : on suit en direct.
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== 'local') return;
      if (changes['ext.snapshot'] && state.view === 'main') reload();
      else if (changes['ext.driveLastSync'] || changes['ext.driveError']) reload();
    });

    setInterval(tick, 1000);
  }

  init();
})();
