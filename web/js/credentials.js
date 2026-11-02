/*
 * Vue « Mots de passe » de l'app : mots de passe et passkeys des sites, toujours dans le coffre chiffré.
 *  - Liste (récemment utilisés, puis tous les sites) et détail du site choisi : sur bureau côte à côte,
 *    sur mobile le détail a son propre écran (#/passwords/<id>).
 *  - Par site, ce qui en dépend : compte 2FA (code en direct), passkeys, mot de passe.
 *  - Éditeur avec générateur (caractères ou phrase de syllabes, Web Crypto, sans biais) et jauge de solidité.
 *  - Coffre en clair : rien n'est stocké, on propose d'activer le mot de passe maître.
 * Dépend de : I18n, Store, OTP, Lock, Audit.
 */
(function () {
  'use strict';

  const { t } = I18n;
  const $ = (id) => document.getElementById(id);
  const RECENT_MAX = 3;
  const RECENT_DAYS = 30;

  let ctx = null; // { store, toast, errorMessage, copyText }
  const view = { filter: 'all', query: '', selected: null, revealed: new Set(), timer: null, code: null };

  /* ───────────── Outils ───────────── */

  function h(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key === 'value') node.value = value;
      else if (key === 'checked') node.checked = Boolean(value);
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
    for (const part of [].concat(d)) {
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('d', part);
      svg.append(path);
    }
    return svg;
  }

  const ICONS = {
    user: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0',
    copy: ['M11.5 9h7A2.5 2.5 0 0 1 21 11.5v7a2.5 2.5 0 0 1-2.5 2.5h-7A2.5 2.5 0 0 1 9 18.5v-7A2.5 2.5 0 0 1 11.5 9z', 'M5 15V5a2 2 0 0 1 2-2h10'],
    eye: ['M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z', 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z'],
    eyeOff: 'M3 3l18 18M10.6 5.1A9.8 9.8 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.2M6.6 6.6A17 17 0 0 0 2 12s3.5 7 10 7a9.6 9.6 0 0 0 5.4-1.6M9.9 9.9a3 3 0 0 0 4.2 4.2',
    edit: 'M4 20h4L19 9l-4-4L4 16zM14 6l4 4',
    trash: 'M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3',
    open: 'M14 4h6v6M20 4l-9 9M18 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h5',
    key: 'M15 7a4 4 0 1 1-3.9 4.9L4 19v2h3v-2h2v-2h2l1.1-1.1A4 4 0 0 1 15 7z',
    chevron: 'm9 6 6 6-6 6',
    back: 'M15 6l-6 6 6 6',
    refresh: 'M21 12a9 9 0 1 1-2.6-6.4M21 4v5h-5',
    shield: ['M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z', 'm9 12 2 2 4-4'],
    close: 'M6 6l12 12M18 6 6 18',
  };

  /** « GitHub » → GH, « Banque perso » → BP, « notion.so » → NO (comme les cartes de codes). */
  function initials(name) {
    const text = String(name || '?').trim();
    const words = (/\s/.test(text) ? text : text.split('.')[0]).split(/[\s_@-]+/).filter(Boolean);
    if (words.length > 1) return (words[0][0] + words[1][0]).toUpperCase();
    const word = words[0] || '?';
    const inner = word.slice(1).match(/[A-Z]/);
    return (word[0] + (inner ? inner[0] : word.slice(1, 2))).toUpperCase();
  }

  function tile(name, size = '') {
    let hash = 0;
    for (const ch of String(name || '').toLowerCase()) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
    const node = h('span', { class: `tile cred-tile ${size}`, text: initials(name), 'aria-hidden': 'true' });
    node.style.color = `hsl(${hash % 360} 62% 36%)`;
    return node;
  }

  function iconButton(label, d, onclick, extra = '') {
    return h('button', { type: 'button', class: `icon-btn small ${extra}`, 'aria-label': label, title: label, onclick }, icon(d));
  }

  const hostOf = (origin) => Store.hostOf(origin);
  const date = (iso) => (iso ? new Intl.DateTimeFormat(I18n.getLocale(), { dateStyle: 'medium' }).format(new Date(iso)) : '');

  /* ───────────── Générateur et solidité ───────────── */

  const LETTERS = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const DIGITS = '23456789';
  const SYMBOLS = '-_.!@#%+=?*';
  const CONSONANTS = 'bcdfghjklmnprstvz';
  const VOWELS = 'aeiou';

  /** Entier uniforme dans [0, n) (rejet des valeurs qui biaiseraient le modulo). */
  function randomBelow(n) {
    const limit = Math.floor(0x100000000 / n) * n;
    const buf = new Uint32Array(1);
    do crypto.getRandomValues(buf);
    while (buf[0] >= limit);
    return buf[0] % n;
  }

  const pick = (chars) => chars[randomBelow(chars.length)];

  /** options : { length, digits, symbols, words } — words : phrase de syllabes, `length` mots. */
  function generatePassword(options = {}) {
    const opts = { length: 20, digits: true, symbols: true, words: false, ...options };
    if (opts.words) {
      const words = Array.from({ length: opts.length }, () => Array.from({ length: 3 }, () => pick(CONSONANTS) + pick(VOWELS)).join(''));
      const capital = randomBelow(words.length);
      words[capital] = words[capital][0].toUpperCase() + words[capital].slice(1);
      if (opts.digits) words[randomBelow(words.length)] += pick(DIGITS);
      return words.join(opts.symbols ? '-' : '');
    }
    const pool = LETTERS + (opts.digits ? DIGITS : '') + (opts.symbols ? SYMBOLS : '');
    for (;;) {
      const out = Array.from({ length: opts.length }, () => pick(pool)).join('');
      // Au moins un caractère de chaque famille demandée, et majuscules comme minuscules.
      if (!/[A-Z]/.test(out) || !/[a-z]/.test(out)) continue;
      if (opts.digits && !/[2-9]/.test(out)) continue;
      if (opts.symbols && !/[-_.!@#%+=?*]/.test(out)) continue;
      return out;
    }
  }

  /** Jauge à 4 segments, mise à jour à chaque saisie (l'estimation vit dans Vault, partagée). */
  function meter() {
    const bars = [0, 1, 2, 3].map(() => h('span', { class: 'meter-bar' }));
    const label = h('span', { class: 'meter-label' });
    const node = h('div', { class: 'meter' }, [h('span', { class: 'meter-bars', 'aria-hidden': 'true' }, bars), label]);
    return {
      node,
      update(password) {
        const { level } = Vault.passwordStrength(password);
        node.dataset.level = String(level);
        bars.forEach((bar, i) => bar.classList.toggle('is-on', i < level));
        label.textContent = level ? t(`security.strength.${level}`) : '';
      },
    };
  }

  /** Bloc « Générateur » : longueur, familles, phrase ; onGenerate(motDePasse) à chaque changement. */
  function generatorBlock(onGenerate) {
    // Politique du tableau de bord : longueur minimale, chiffres et symboles exigés.
    const policy = Audit.normalizePolicy(ctx.store.setting('policy'));
    const opts = { length: Math.min(40, Math.max(20, policy.minLength)), digits: true, symbols: true, words: false };
    const value = h('span', { class: 'gen-value' });
    const range = h('input', { type: 'range', class: 'gen-range', 'aria-label': t('credentials.length') });
    const lengthLabel = h('span', { class: 'gen-label' });
    const sync = () => {
      range.min = opts.words ? 3 : Math.max(12, policy.minLength);
      range.max = opts.words ? 8 : 40;
      range.value = String(opts.length);
      value.textContent = String(opts.length);
      lengthLabel.textContent = t(opts.words ? 'credentials.words' : 'credentials.length');
    };
    const regenerate = () => {
      sync();
      onGenerate(generatePassword(opts));
    };
    range.addEventListener('input', () => {
      opts.length = Number(range.value);
      regenerate();
    });
    const option = (key, labelKey) =>
      h('label', { class: 'gen-chip' }, [
        h('input', {
          type: 'checkbox',
          checked: opts[key],
          onchange: (event) => {
            opts[key] = event.target.checked;
            if (key === 'words') opts.length = opts.words ? 5 : 20;
            regenerate();
          },
        }),
        h('span', { text: t(labelKey) }),
      ]);
    sync();
    return {
      node: h('fieldset', { class: 'gen' }, [
        h('legend', { text: t('credentials.generator') }),
        h('label', { class: 'gen-length' }, [lengthLabel, range, value]),
        h('div', { class: 'gen-options' }, [
          option('digits', 'credentials.digits'),
          option('symbols', 'credentials.symbols'),
          option('words', 'credentials.passphrase'),
          h('button', { type: 'button', class: 'btn btn-ghost btn-sm gen-new', onclick: regenerate }, [icon(ICONS.refresh), h('span', { text: t('credentials.regenerate') })]),
        ]),
      ]),
      generate: () => generatePassword(opts),
    };
  }

  /* ───────────── Données ───────────── */

  /** Ce qui dépend d'un site : comptes 2FA et passkeys. */
  function related(host) {
    const site = Store.siteOf(host);
    return {
      accounts: ctx.store.list().filter((a) => a.type !== 'hotp' && Store.accountMatchesHost(a, host)),
      passkeys: ctx.store.passkeys().filter((p) => Store.siteOf(p.rpId) === site),
    };
  }

  /** Nom d'un site : celui donné, sinon le service de son compte 2FA (« GitHub »), sinon son domaine. */
  function siteName(host, title, accounts) {
    if (title) return title;
    const account = accounts.find((a) => a.issuer && Store.accountMatchesHost(a, host));
    return account ? account.issuer : Store.siteOf(host);
  }

  /** Éléments de la liste : mots de passe, et passkeys seules pour leur site (« Tout »). */
  function entries() {
    const accounts = ctx.store.list();
    const logins = ctx.store.logins().map((login) => {
      const host = hostOf(login.origin);
      return { kind: 'login', id: login.id, name: siteName(host, login.title, accounts), host, sub: login.username || t('credentials.noUsername'), login, usedAt: login.usedAt };
    });
    const loginSites = new Set(logins.map((e) => Store.siteOf(e.host)));
    const passkeys = ctx.store.passkeys().map((passkey) => ({
      kind: 'passkey',
      id: passkey.id,
      name: siteName(passkey.rpId, passkey.rpName !== passkey.rpId ? passkey.rpName : '', accounts),
      host: passkey.rpId,
      sub: passkey.userDisplayName || passkey.userName || passkey.rpId,
      passkey,
      standalone: !loginSites.has(Store.siteOf(passkey.rpId)),
    }));
    return { logins, passkeys, all: [...logins, ...passkeys.filter((p) => p.standalone)] };
  }

  function visible(list) {
    const q = view.query.trim().toLowerCase();
    const byName = (a, b) => a.name.localeCompare(b.name, I18n.getLocale(), { sensitivity: 'base' });
    return list.filter((e) => !q || [e.name, e.host, e.sub, e.login && e.login.note].some((v) => (v || '').toLowerCase().includes(q))).sort(byName);
  }

  /* ───────────── Rendu ───────────── */

  function render() {
    if (!ctx || !$('cred-list')) return;
    const status = Lock.status();
    $('cred-plain').hidden = status !== 'plain';
    $('cred-content').hidden = status !== 'unlocked';
    // Ajouter un mot de passe exige un coffre : les deux points d'entrée sont fermés sinon.
    $('btn-add-login').disabled = status !== 'unlocked';
    $('btn-add-login-fab').disabled = status !== 'unlocked';
    if (status !== 'unlocked') return stopTicker();

    const data = entries();
    $('count-all').textContent = String(data.all.length);
    $('count-logins').textContent = String(data.logins.length);
    $('count-passkeys').textContent = String(data.passkeys.length);
    document.querySelectorAll('#cred-tabs [data-filter]').forEach((tab) => tab.setAttribute('aria-selected', String(tab.dataset.filter === view.filter)));

    const list = visible(view.filter === 'logins' ? data.logins : view.filter === 'passkeys' ? data.passkeys : data.all);
    const since = new Date(Date.now() - RECENT_DAYS * 86400000).toISOString();
    const recent = view.filter === 'all' && !view.query.trim()
      ? data.logins.filter((e) => e.usedAt && e.usedAt > since).sort((a, b) => b.usedAt.localeCompare(a.usedAt)).slice(0, RECENT_MAX)
      : [];
    const rest = list.filter((e) => !recent.includes(e));

    // Bureau : un site toujours affiché ; mobile : la liste, ou le détail demandé par l'adresse.
    const known = [...data.logins, ...data.passkeys];
    let current = known.find((e) => e.id === view.selected) || null;
    const desktop = window.matchMedia('(min-width: 900px)').matches;
    if (!current && desktop) current = recent[0] || rest[0] || null;
    $('view-passwords').classList.toggle('has-detail', Boolean(view.selected && current));

    const sections = [];
    if (recent.length) sections.push(listSection(t('credentials.recent'), recent, current));
    if (rest.length) sections.push(listSection(recent.length ? t('credentials.allSites') : t(`credentials.section.${view.filter}`), rest, current));
    if (!list.length) sections.push(h('p', { class: 'empty', text: known.length ? t('list.noMatch') : t('credentials.empty') }));
    sections.push(h('p', { class: 'panel-hint', text: t('credentials.extensionHint') }));
    $('cred-list').replaceChildren(...sections);
    renderDetail(current);
  }

  function listSection(title, items, current) {
    return h('section', { class: 'cred-section' }, [
      h('h2', { class: 'section-label', text: title }),
      h('ul', { class: 'panel panel-list cred-items' }, items.map((e) => listItem(e, current))),
    ]);
  }

  function listItem(entry, current) {
    const { accounts, passkeys } = related(entry.host);
    const chips = [];
    if (accounts.length) chips.push(h('span', { class: 'cred-chip chip-2fa', text: '2FA' }));
    if (entry.kind === 'passkey' || passkeys.length) chips.push(h('span', { class: 'cred-chip chip-passkey', text: 'Passkey' }));
    const selected = current && current.id === entry.id;
    return h('li', {}, [
      h('a', { href: `#/passwords/${entry.id}`, class: `cred-item${selected ? ' is-selected' : ''}`, 'aria-current': selected ? 'true' : null }, [
        tile(entry.name),
        h('span', { class: 'cred-item-text' }, [h('span', { class: 'cred-item-name', text: entry.name }), h('span', { class: 'cred-item-sub', text: entry.sub })]),
        chips.length ? h('span', { class: 'cred-chips' }, chips) : null,
        icon(ICONS.chevron),
      ]),
    ]);
  }

  function renderDetail(entry) {
    const pane = $('cred-detail');
    stopTicker();
    if (!entry) {
      pane.replaceChildren();
      pane.hidden = true;
      return;
    }
    pane.hidden = false;
    const { accounts, passkeys } = related(entry.host);
    const login = entry.login;
    const origin = login ? login.origin : `https://${entry.host}`;
    const blocks = [
      h('div', { class: 'cred-detail-head' }, [
        h('a', { href: '#/passwords', class: 'icon-btn boxed only-mobile cred-back', 'aria-label': t('credentials.back') }, icon(ICONS.back)),
        tile(entry.name, 'lg'),
        h('div', { class: 'cred-detail-title' }, [
          h('h2', { text: entry.name }),
          h('a', { href: origin, target: '_blank', rel: 'noopener noreferrer', text: entry.host }),
        ]),
        login ? iconButton(t('credentials.edit'), ICONS.edit, () => openEditor(login), 'boxed') : null,
      ]),
    ];

    if (login) {
      const shown = view.revealed.has(login.id);
      blocks.push(
        h('div', { class: 'cred-fields' }, [
          h('div', { class: 'cred-field' }, [
            h('div', { class: 'cred-field-main' }, [h('span', { class: 'cred-field-label', text: t('credentials.username') }), h('span', { class: 'cred-field-value', text: login.username || t('credentials.noUsername') })]),
            login.username ? iconButton(t('credentials.copyUser'), ICONS.copy, () => copy(login.username, 'credentials.copiedUser')) : null,
          ]),
          h('div', { class: 'cred-field' }, [
            h('div', { class: 'cred-field-main' }, [
              h('span', { class: 'cred-field-label', text: t('credentials.password') }),
              h('span', { class: `cred-field-value cred-secret${shown ? ' is-shown' : ''}`, text: shown ? login.password : '•'.repeat(12) }),
            ]),
            iconButton(t(shown ? 'credentials.hide' : 'credentials.show'), shown ? ICONS.eyeOff : ICONS.eye, () => {
              if (shown) view.revealed.delete(login.id);
              else view.revealed.add(login.id);
              render();
            }),
            iconButton(t('credentials.copyPassword'), ICONS.copy, () => {
              copy(login.password, 'credentials.copiedPassword');
              ctx.store.touchLogin(login.id);
            }),
          ]),
        ])
      );
    }

    if (accounts.length) {
      blocks.push(
        h('section', { class: 'cred-block' }, [
          h('h3', { class: 'section-label', text: t('credentials.code') }),
          ...accounts.map((account) => codeRow(account)),
          h('p', { class: 'cred-note', text: t('credentials.codeNote', { name: [account0Name(accounts[0]), accounts[0].account].filter(Boolean).join(' — ') }) }),
        ])
      );
    }

    const keys = entry.kind === 'passkey' ? [entry.passkey, ...passkeys.filter((p) => p.id !== entry.passkey.id)] : passkeys;
    if (keys.length) {
      blocks.push(
        h('section', { class: 'cred-block' }, [
          h('h3', { class: 'section-label', text: t(keys.length > 1 ? 'credentials.passkeysTitle' : 'credentials.passkeyTitle') }),
          ...keys.map((passkey) =>
            h('div', { class: 'cred-passkey' }, [
              h('span', { class: 'cred-passkey-icon' }, icon(ICONS.key)),
              h('div', { class: 'cred-field-main' }, [
                h('span', { class: 'cred-field-value', text: [passkey.userDisplayName, passkey.userName].filter(Boolean).join(' · ') || passkey.rpId }),
                h('span', { class: 'cred-field-label', text: t('credentials.passkeyCreated', { date: date(passkey.createdAt), site: passkey.rpId }) }),
              ]),
              iconButton(t('credentials.removePasskey'), ICONS.trash, () => removePasskey(passkey), 'danger'),
            ])
          ),
        ])
      );
    }

    const meta = login
      ? t(login.source === 'extension' ? 'credentials.metaExtension' : 'credentials.meta', { date: date(login.updatedAt) })
      : t('credentials.passkeyOnly');
    blocks.push(
      h('div', { class: 'cred-meta' }, [
        h('span', { text: meta }),
        h('a', { class: 'btn btn-ghost btn-sm', href: origin, target: '_blank', rel: 'noopener noreferrer' }, [icon(ICONS.open), h('span', { text: t('credentials.openSite') })]),
      ])
    );
    pane.replaceChildren(...blocks);
    if (accounts.length) startTicker(accounts);
  }

  const account0Name = (account) => account.issuer || account.account;

  /* Code 2FA en direct : même compte que l'onglet Codes. */

  function codeRow(account) {
    const ring = h('span', { class: 'ring', role: 'img' }, [
      (() => {
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', '0 0 46 46');
        svg.setAttribute('aria-hidden', 'true');
        for (const cls of ['ring-track', 'ring-value']) {
          const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
          c.setAttribute('class', cls);
          c.setAttribute('cx', '23');
          c.setAttribute('cy', '23');
          c.setAttribute('r', '19');
          svg.append(c);
        }
        return svg;
      })(),
      h('span', { class: 'ring-secs' }),
    ]);
    const code = h('span', { class: 'cred-code', text: '— — —' });
    return h('div', { class: 'cred-code-row', 'data-account': account.id }, [
      h('span', { class: 'cred-code-main' }, [h('span', { class: 'cred-code-name', text: [account0Name(account), account.account].filter(Boolean).join(' · ') }), code]),
      ring,
      iconButton(t('credentials.copyCode'), ICONS.copy, async () => {
        const value = code.dataset.value;
        if (!value) return;
        await copy(value, 'credentials.copiedCode');
        ctx.store.log('copy', account);
      }, 'accent'),
    ]);
  }

  async function tick(accounts) {
    const now = Date.now();
    for (const account of accounts) {
      const row = document.querySelector(`#cred-detail [data-account="${CSS.escape(account.id)}"]`);
      if (!row) continue;
      const period = account.period || 30;
      const remaining = OTP.remainingSeconds(period, now);
      const step = Math.floor(now / 1000 / period);
      const codeNode = row.querySelector('.cred-code');
      if (codeNode.dataset.step !== String(step)) {
        try {
          const value = await OTP.totp(account.secret, { ...account, timestamp: now });
          codeNode.dataset.value = value;
          codeNode.dataset.step = String(step);
          codeNode.textContent = `${value.slice(0, Math.floor(value.length / 2))} ${value.slice(Math.floor(value.length / 2))}`;
        } catch {
          codeNode.textContent = '—';
        }
      }
      const ring = row.querySelector('.ring');
      const length = 2 * Math.PI * 19;
      const value = ring.querySelector('.ring-value');
      value.style.strokeDasharray = String(length);
      value.style.strokeDashoffset = String(length * (1 - remaining / period));
      ring.querySelector('.ring-secs').textContent = String(remaining);
      ring.classList.toggle('is-expiring', remaining <= 5);
      ring.setAttribute('aria-label', t('list.remaining', { count: remaining }));
    }
  }

  function startTicker(accounts) {
    tick(accounts);
    view.timer = setInterval(() => {
      if ($('view-passwords').hidden) return stopTicker();
      tick(accounts);
    }, 1000);
  }

  function stopTicker() {
    clearInterval(view.timer);
    view.timer = null;
  }

  async function copy(text, key) {
    try {
      await ctx.copyText(text);
      if (key === 'credentials.copiedPassword') clearClipboardSoon();
      ctx.toast(t(key));
    } catch (err) {
      ctx.toast(ctx.errorMessage(err));
    }
  }

  /* Mot de passe copié : presse-papiers vidé peu après, si l'onglet a encore le focus
     (l'utilisateur parti coller ailleurs n'a pas le focus : on ne lui coupe rien). */
  const CLIPBOARD_CLEAR_DELAY = 30000;
  let clipboardClear = null;

  function clearClipboardSoon() {
    clearTimeout(clipboardClear);
    clipboardClear = setTimeout(async () => {
      if (!document.hasFocus() || !navigator.clipboard || !navigator.clipboard.writeText) return;
      try {
        await navigator.clipboard.writeText('');
      } catch {
        /* presse-papiers indisponible : il gardera le mot de passe */
      }
    }, CLIPBOARD_CLEAR_DELAY);
  }

  /* ───────────── Fenêtres : confirmation, éditeur, générateur ───────────── */

  function dialogShell(titleKey, body, actions) {
    const dialog = $('login-dialog');
    const form = $('login-form');
    form.replaceChildren(
      h('div', { class: 'dialog-head' }, [h('h2', { id: 'login-title', text: t(titleKey) }), iconButton(t('credentials.close'), ICONS.close, () => dialog.close())]),
      ...body,
      h('div', { class: 'dialog-actions' }, actions)
    );
    if (!dialog.open) dialog.showModal();
    return { dialog, form };
  }

  /** Confirmation dans l'interface (jamais window.confirm). */
  function confirmAction(titleKey, text, labelKey, onConfirm) {
    const { dialog, form } = dialogShell(titleKey, [h('p', { class: 'dialog-text', text })], [
      h('span', { class: 'spacer' }),
      h('button', { type: 'button', class: 'btn btn-ghost', text: t('edit.cancel'), onclick: () => dialog.close() }),
      h('button', { type: 'submit', class: 'btn btn-danger', text: t(labelKey) }),
    ]);
    form.onsubmit = (event) => {
      event.preventDefault();
      dialog.close();
      onConfirm();
    };
  }

  function passwordInput(value, reveal) {
    const input = h('input', { class: 'input input-mono', name: 'password', type: reveal ? 'text' : 'password', autocomplete: 'new-password', spellcheck: 'false', required: true, value, id: 'cred-password' });
    const toggle = iconButton(t('credentials.show'), ICONS.eye, () => {
      input.type = input.type === 'password' ? 'text' : 'password';
      toggle.replaceChildren(icon(input.type === 'password' ? ICONS.eye : ICONS.eyeOff));
    });
    if (reveal) toggle.replaceChildren(icon(ICONS.eyeOff));
    const field = h('div', { class: 'cred-password' }, [input, toggle, iconButton(t('credentials.copyPassword'), ICONS.copy, () => copy(input.value, 'credentials.copiedPassword'))]);
    return { input, field };
  }

  function openEditor(login, presetPassword) {
    const gauge = meter();
    const pw = passwordInput(login ? login.password : '', !login);
    const generator = generatorBlock((value) => {
      pw.input.value = value;
      pw.input.type = 'text';
      gauge.update(value);
    });
    if (!login) pw.input.value = presetPassword || generator.generate();
    gauge.update(pw.input.value);
    pw.input.addEventListener('input', () => gauge.update(pw.input.value));

    const url = h('input', { class: 'input', name: 'url', inputmode: 'url', autocomplete: 'off', spellcheck: 'false', required: true, placeholder: 'https://exemple.fr', value: login ? login.origin : '' });
    const link = h('p', { class: 'cred-link', hidden: true });
    const updateLink = () => {
      const host = hostFromInput(url.value);
      const account = host && related(host).accounts[0];
      link.hidden = !account;
      link.replaceChildren(icon(ICONS.shield), h('span', { text: account ? t('credentials.linkedOtp', { name: account0Name(account) }) : '' }));
    };
    url.addEventListener('input', updateLink);
    updateLink();
    const error = h('p', { class: 'form-error', role: 'alert', hidden: true });
    const field = (labelKey, input) => h('label', { class: 'field-label' }, [h('span', { text: t(labelKey) }), input]);
    const { dialog, form } = dialogShell(
      login ? 'credentials.editTitle' : 'credentials.addTitle',
      [
        field('credentials.url', url),
        field('credentials.username', h('input', { class: 'input', name: 'username', autocomplete: 'off', spellcheck: 'false', value: login ? login.username : '' })),
        h('div', { class: 'field-label' }, [h('label', { for: 'cred-password', text: t('credentials.password') }), pw.field, gauge.node]),
        generator.node,
        field('credentials.titleField', h('input', { class: 'input', name: 'title', placeholder: t('credentials.titlePlaceholder'), value: login ? login.title : '' })),
        link,
        error,
      ],
      [
        login ? h('button', { type: 'button', class: 'btn btn-ghost danger', text: t('credentials.remove'), onclick: () => remove(login) }) : null,
        h('span', { class: 'spacer' }),
        h('button', { type: 'button', class: 'btn btn-ghost', text: t('edit.cancel'), onclick: () => dialog.close() }),
        h('button', { type: 'submit', class: 'btn btn-primary', text: t(login ? 'credentials.save' : 'credentials.add') }),
      ]
    );
    form.onsubmit = (event) => {
      event.preventDefault();
      const v = Object.fromEntries(new FormData(form));
      const address = /^[a-z]+:\/\//i.test(v.url.trim()) ? v.url.trim() : `https://${v.url.trim()}`;
      try {
        let saved;
        if (login) saved = ctx.store.updateLogin(login.id, { origin: address, username: v.username, password: v.password, title: v.title });
        else saved = ctx.store.addLogin({ url: address, username: v.username, password: v.password, title: v.title }, 'app');
        dialog.close();
        ctx.toast(t(login ? 'credentials.updated' : 'credentials.added'));
        select(saved.id);
      } catch (err) {
        error.textContent = ctx.errorMessage(err);
        error.hidden = false;
      }
    };
    (login ? form.querySelector('input[name="password"]') : url).focus();
  }

  function hostFromInput(value) {
    const text = String(value || '').trim();
    if (!text) return '';
    try {
      return new URL(/^[a-z]+:\/\//i.test(text) ? text : `https://${text}`).hostname.replace(/^www\./, '');
    } catch {
      return '';
    }
  }

  /** « Générer » : un mot de passe à copier, ou à enregistrer pour un site. */
  function openGenerator() {
    const gauge = meter();
    const pw = passwordInput('', true);
    const generator = generatorBlock((value) => {
      pw.input.value = value;
      gauge.update(value);
    });
    pw.input.value = generator.generate();
    gauge.update(pw.input.value);
    pw.input.addEventListener('input', () => gauge.update(pw.input.value));
    const { dialog, form } = dialogShell('credentials.generateTitle', [h('div', { class: 'field-label' }, [pw.field, gauge.node]), generator.node], [
      Lock.status() === 'unlocked'
        ? h('button', { type: 'button', class: 'btn btn-ghost', text: t('credentials.saveForSite'), onclick: () => openEditor(null, pw.input.value) })
        : null,
      h('span', { class: 'spacer' }),
      h('button', { type: 'submit', class: 'btn btn-primary', text: t('credentials.copyPassword') }),
    ]);
    form.onsubmit = async (event) => {
      event.preventDefault();
      await copy(pw.input.value, 'credentials.copiedPassword');
      dialog.close();
    };
  }

  function remove(login) {
    confirmAction('credentials.removeTitle', t('credentials.removeConfirm', { name: login.title || hostOf(login.origin) }), 'credentials.remove', () => {
      ctx.store.removeLogin(login.id);
      ctx.toast(t('credentials.removed'));
      select(null);
    });
  }

  function removePasskey(passkey) {
    const name = [passkey.rpName || passkey.rpId, passkey.userName || passkey.userDisplayName].filter(Boolean).join(' — ');
    confirmAction('credentials.removePasskey', t('credentials.removePasskeyConfirm', { name }), 'credentials.remove', () => {
      ctx.store.removePasskey(passkey.id);
      ctx.toast(t('credentials.passkeyRemoved'));
      if (view.selected === passkey.id) select(null);
      else render();
    });
  }

  /* ───────────── Navigation ───────────── */

  /** Site choisi : l'adresse le porte (#/passwords/<id>), pour le retour arrière sur mobile. */
  function select(id) {
    const target = id ? `#/passwords/${id}` : '#/passwords';
    if (location.hash !== target) location.hash = target;
    else show(id);
  }

  /** Appelé par le routeur de l'app. */
  function show(id) {
    view.selected = id || null;
    render();
    if (id && !window.matchMedia('(min-width: 900px)').matches) window.scrollTo(0, 0);
  }

  function init(options) {
    ctx = options;
    $('btn-cred-enable').addEventListener('click', () => Lock.openEnable());
    for (const id of ['btn-add-login', 'btn-add-login-fab']) $(id).addEventListener('click', () => openEditor(null));
    for (const id of ['btn-generate', 'btn-generate-m']) $(id).addEventListener('click', openGenerator);
    $('cred-search').addEventListener('input', (event) => {
      view.query = event.target.value;
      render();
    });
    document.querySelectorAll('#cred-tabs [data-filter]').forEach((tab) =>
      tab.addEventListener('click', () => {
        view.filter = tab.dataset.filter;
        render();
      })
    );
    window.matchMedia('(min-width: 900px)').addEventListener('change', render);
    I18n.onChange(render);
  }

  /** Verrouillage : rien ne reste affiché en clair. */
  function reset() {
    view.revealed.clear();
    stopTicker();
    if ($('login-dialog') && $('login-dialog').open) $('login-dialog').close();
    if ($('cred-detail')) $('cred-detail').replaceChildren();
  }

  window.Credentials = { init, render, reset, show, generatePassword, meter };
})();
