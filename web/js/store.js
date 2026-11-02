/*
 * Persistance localStorage : comptes OTP, mots de passe et passkeys des sites, journal d'historique.
 * Mots de passe et passkeys n'existent que dans un coffre chiffré (voir Lock et l'extension).
 * createStore(storage) accepte n'importe quel objet compatible Web Storage
 * (localStorage dans le navigateur, un faux en mémoire dans les tests).
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Store = api;
})(typeof self !== 'undefined' ? self : globalThis, function () {
  'use strict';

  const ACCOUNTS_KEY = 'mymfa.accounts.v1';
  const HISTORY_KEY = 'mymfa.history.v1';
  // Suppressions et vidage d'historique : nécessaires pour fusionner deux copies (app ↔ extension)
  // sans faire réapparaître ce qui a été supprimé d'un côté.
  const DELETED_KEY = 'mymfa.deleted.v1';
  const LOGINS_KEY = 'mymfa.logins.v1';
  const PASSKEYS_KEY = 'mymfa.passkeys.v1'; // passkeys des sites (myMFA fournisseur), pas celles qui déverrouillent le coffre
  // Réglages qui suivent le coffre (sauvegarde Drive, export chiffré, extension) : politique du tableau
  // de bord, résultats de fuite, copie des préférences d'affichage. { nom → { value, at } }.
  const SETTINGS_KEY = 'mymfa.settings.v1';
  const HISTORY_MAX = 500;

  /** Erreur porteuse d'un code traduisible (clé i18n `error.<code>`). */
  function storeError(code) {
    const err = new Error(code);
    err.code = code;
    err.params = {};
    return err;
  }

  function uid() {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) return crypto.randomUUID();
    return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  }

  /** Origine d'une adresse (https://exemple.fr), ou '' si elle n'en a pas. */
  function originOf(url) {
    try {
      const { origin } = new URL(url);
      return origin === 'null' ? '' : origin;
    } catch {
      return '';
    }
  }

  function normalizeTag(tag) {
    return String(tag || '').trim().replace(/\s+/g, '-').toLowerCase();
  }

  function createStore(storage) {
    function read(key) {
      try {
        const raw = storage.getItem(key);
        const parsed = raw ? JSON.parse(raw) : [];
        return Array.isArray(parsed) ? parsed : [];
      } catch {
        return [];
      }
    }

    function write(key, value) {
      storage.setItem(key, JSON.stringify(value));
    }

    function log(action, account, details) {
      const history = read(HISTORY_KEY);
      history.unshift({
        id: uid(),
        at: new Date().toISOString(),
        action,
        accountId: account ? account.id : null,
        label: account ? describe(account) : null,
        tag: account ? account.tag : null,
        details: details || null,
      });
      write(HISTORY_KEY, history.slice(0, HISTORY_MAX));
    }

    function describe(account) {
      return [account.issuer, account.account].filter(Boolean).join(' — ');
    }

    function list() {
      return read(ACCOUNTS_KEY);
    }

    function get(id) {
      return list().find((a) => a.id === id) || null;
    }

    function findDuplicate(secret, issuer, account) {
      return list().find(
        (a) => a.secret === secret && (a.issuer || '') === (issuer || '') && (a.account || '') === (account || '')
      ) || null;
    }

    function add(data, source) {
      const now = new Date().toISOString();
      const account = {
        id: uid(),
        type: data.type || 'totp',
        issuer: (data.issuer || '').trim(),
        account: (data.account || '').trim(),
        secret: data.secret,
        algorithm: data.algorithm || 'SHA1',
        digits: data.digits || 6,
        period: data.period || 30,
        counter: data.counter || 0,
        tag: normalizeTag(data.tag),
        description: (data.description || '').trim(),
        favorite: Boolean(data.favorite),
        createdAt: now,
        updatedAt: now,
      };
      const accounts = list();
      accounts.push(account);
      write(ACCOUNTS_KEY, accounts);
      log('create', account, source ? { source } : null);
      return account;
    }

    function update(id, patch) {
      const accounts = list();
      const idx = accounts.findIndex((a) => a.id === id);
      if (idx === -1) throw storeError('accountNotFound');
      const before = accounts[idx];
      const next = { ...before };
      const changes = [];
      for (const field of ['issuer', 'account', 'tag', 'description']) {
        if (!(field in patch)) continue;
        const value = field === 'tag' ? normalizeTag(patch[field]) : String(patch[field] || '').trim();
        if (value !== before[field]) {
          changes.push({ field, from: before[field] || '', to: value });
          next[field] = value;
        }
      }
      if ('counter' in patch && patch.counter !== before.counter) next.counter = patch.counter;
      // Favori : simple préférence d'affichage, non journalisée.
      if ('favorite' in patch) next.favorite = Boolean(patch.favorite);
      if (changes.length === 0 && next.counter === before.counter && next.favorite === Boolean(before.favorite)) return before;
      next.updatedAt = new Date().toISOString();
      accounts[idx] = next;
      write(ACCOUNTS_KEY, accounts);
      if (changes.length) log('update', next, { changes });
      return next;
    }

    /* ───── Mots de passe ───── */

    function logins() {
      return read(LOGINS_KEY);
    }

    function findLogin(origin, username) {
      return logins().find((l) => l.origin === origin && (l.username || '') === (username || '')) || null;
    }

    function addLogin(data, source) {
      const origin = originOf(data.origin || data.url);
      if (!origin) throw storeError('invalidUrl');
      if (!data.password) throw storeError('passwordEmpty');
      const now = new Date().toISOString();
      const login = {
        id: uid(),
        origin,
        username: String(data.username || '').trim(),
        password: String(data.password),
        title: String(data.title || '').trim(),
        note: String(data.note || '').trim(),
        tag: normalizeTag(data.tag),
        source: source || '',
        createdAt: now,
        updatedAt: now,
        passwordChangedAt: now, // politique de renouvellement (tableau de bord)
      };
      write(LOGINS_KEY, [...logins(), login]);
      log('create', loginLabel(login), { kind: 'login', ...(source ? { source } : {}) });
      return login;
    }

    function updateLogin(id, patch) {
      const list = logins();
      const idx = list.findIndex((l) => l.id === id);
      if (idx === -1) throw storeError('accountNotFound');
      const before = list[idx];
      const next = { ...before };
      for (const field of ['username', 'password', 'title', 'note']) {
        if (!(field in patch)) continue;
        next[field] = field === 'password' ? String(patch[field] || '') : String(patch[field] || '').trim();
      }
      if ('tag' in patch) next.tag = normalizeTag(patch.tag);
      if ('origin' in patch) {
        next.origin = originOf(patch.origin);
        if (!next.origin) throw storeError('invalidUrl');
      }
      if (!next.password) throw storeError('passwordEmpty');
      // Favori : simple préférence d'affichage, non journalisée (comme pour les comptes).
      if ('favorite' in patch) next.favorite = Boolean(patch.favorite);
      const changed = ['origin', 'username', 'password', 'title', 'note', 'tag'].filter((f) => (next[f] || '') !== (before[f] || ''));
      if (!changed.length && Boolean(next.favorite) === Boolean(before.favorite)) return before;
      next.updatedAt = new Date().toISOString();
      if (changed.includes('password')) next.passwordChangedAt = next.updatedAt;
      list[idx] = next;
      write(LOGINS_KEY, list);
      // Jamais de mot de passe dans l'historique : seulement les champs modifiés.
      if (changed.length) log('update', loginLabel(next), { kind: 'login', fields: changed });
      return next;
    }

    /** Élément utilisé (rempli, copié, connexion) : pour « Récemment utilisés ». Ni modification ni historique. */
    function touch(key, id) {
      const list = read(key);
      const item = list.find((x) => x.id === id);
      if (!item) return;
      item.usedAt = new Date().toISOString();
      write(key, list);
    }
    const touchLogin = (id) => touch(LOGINS_KEY, id);
    const touchAccount = (id) => touch(ACCOUNTS_KEY, id);
    const touchPasskey = (id) => touch(PASSKEYS_KEY, id);

    function removeLogin(id) {
      const login = logins().find((l) => l.id === id);
      if (!login) return false;
      write(LOGINS_KEY, logins().filter((l) => l.id !== id));
      bury(id);
      log('delete', loginLabel(login), { kind: 'login' });
      return true;
    }

    function loginLabel(login) {
      return { id: login.id, issuer: hostOf(login.origin), account: login.username, tag: '' };
    }

    /* ───── Passkeys des sites ───── */

    function passkeys() {
      return read(PASSKEYS_KEY);
    }

    function addPasskey(data, source) {
      const now = new Date().toISOString();
      const passkey = {
        id: uid(),
        credentialId: data.credentialId,
        rpId: data.rpId,
        rpName: String(data.rpName || '').trim(),
        origin: data.origin || '',
        userHandle: data.userHandle || '',
        userName: String(data.userName || '').trim(),
        userDisplayName: String(data.userDisplayName || '').trim(),
        algorithm: data.algorithm || -7,
        privateKey: data.privateKey,
        createdAt: now,
        updatedAt: now,
      };
      // Un même compte (rp + identifiant utilisateur) n'a qu'une passkey : la nouvelle remplace l'ancienne.
      const current = passkeys();
      const replaced = current.filter((p) => p.rpId === passkey.rpId && passkey.userHandle && p.userHandle === passkey.userHandle);
      write(PASSKEYS_KEY, [...current.filter((p) => !replaced.includes(p)), passkey]);
      replaced.forEach((p) => bury(p.id));
      log('create', passkeyLabel(passkey), { kind: 'passkey', ...(source ? { source } : {}) });
      return passkey;
    }

    function removePasskey(id) {
      const passkey = passkeys().find((p) => p.id === id);
      if (!passkey) return false;
      write(PASSKEYS_KEY, passkeys().filter((p) => p.id !== id));
      bury(id);
      log('delete', passkeyLabel(passkey), { kind: 'passkey' });
      return true;
    }

    function passkeyLabel(passkey) {
      return { id: passkey.id, issuer: passkey.rpName || passkey.rpId, account: passkey.userName || passkey.userDisplayName, tag: '' };
    }

    function bury(id) {
      const t = tombstones();
      t.accounts[id] = new Date().toISOString();
      storage.setItem(DELETED_KEY, JSON.stringify(t));
    }

    function tombstones() {
      try {
        const parsed = JSON.parse(storage.getItem(DELETED_KEY) || '{}');
        return { accounts: parsed.accounts || {}, historyClearedAt: parsed.historyClearedAt || null };
      } catch {
        return { accounts: {}, historyClearedAt: null };
      }
    }

    function remove(id) {
      const accounts = list();
      const account = accounts.find((a) => a.id === id);
      if (!account) return false;
      write(ACCOUNTS_KEY, accounts.filter((a) => a.id !== id));
      bury(id);
      log('delete', account);
      return true;
    }

    function history() {
      return read(HISTORY_KEY);
    }

    function clearHistory() {
      write(HISTORY_KEY, []);
      storage.setItem(DELETED_KEY, JSON.stringify({ ...tombstones(), historyClearedAt: new Date().toISOString() }));
    }

    function tags() {
      return [...new Set(list().map((a) => a.tag).filter(Boolean))].sort();
    }

    /* ───── Réglages (dans le coffre) ───── */

    function settings() {
      try {
        const value = JSON.parse(storage.getItem(SETTINGS_KEY) || '{}');
        return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
      } catch {
        return {};
      }
    }

    function setting(name) {
      const entry = settings()[name];
      return entry && 'value' in entry ? entry.value : undefined;
    }

    /** Réglage modifié : daté, pour que la fusion (Sync) garde le plus récent. Ni historique ni écriture inutile. */
    function setSetting(name, value) {
      const all = settings();
      if (all[name] && JSON.stringify(all[name].value) === JSON.stringify(value)) return;
      all[name] = { value, at: new Date().toISOString() };
      storage.setItem(SETTINGS_KEY, JSON.stringify(all));
    }

    function exportAll() {
      return { app: 'myMFA', version: 1, exportedAt: new Date().toISOString(), accounts: list(), history: history() };
    }

    /** Importe un export JSON : ajoute les comptes absents, ignore les doublons. */
    function importAll(payload) {
      if (!payload || !Array.isArray(payload.accounts)) throw storeError('invalidImport');
      let added = 0;
      let skipped = 0;
      for (const a of payload.accounts) {
        if (!a || !a.secret || findDuplicate(a.secret, a.issuer, a.account)) {
          skipped++;
          continue;
        }
        add(a, 'import');
        added++;
      }
      log('import', null, { added, skipped });
      return { added, skipped };
    }

    return {
      list, get, add, update, remove, findDuplicate, history, clearHistory, tags, log, exportAll, importAll, describe, tombstones,
      logins, findLogin, addLogin, updateLogin, touchLogin, touchAccount, touchPasskey, removeLogin, passkeys, addPasskey, removePasskey,
      settings, setting, setSetting,
    };
  }

  function hostOf(origin) {
    try {
      return new URL(origin).hostname.replace(/^www\./, '');
    } catch {
      return origin || '';
    }
  }

  // Suffixes publics à plusieurs niveaux (extrait de la Public Suffix List) : deux sites voisins sous l'un
  // d'eux (impots.gouv.fr et ameli.gouv.fr, alice.github.io et bob.github.io) ne sont jamais le même site.
  const MULTI_SUFFIXES = new Set([
    'gouv.fr', 'asso.fr', 'nom.fr', 'com.fr', 'tm.fr', 'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'net.uk',
    'com.au', 'net.au', 'org.au', 'gov.au', 'edu.au', 'co.nz', 'co.jp', 'ne.jp', 'or.jp', 'com.br', 'com.mx',
    'co.in', 'co.za', 'com.cn', 'com.tr', 'co.kr', 'com.sg', 'com.hk', 'co.il', 'gv.at', 'co.at',
    'github.io', 'gitlab.io', 'herokuapp.com', 'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev', 'web.app',
    'firebaseapp.com', 'appspot.com', 'blogspot.com', 'azurewebsites.net', 'cloudfront.net', 's3.amazonaws.com',
    'onrender.com', 'fly.dev', 'glitch.me', 'ngrok.io', 'ngrok-free.app',
  ]);

  /** Site d'un hôte (domaine enregistrable, approché) : accounts.google.com → google.com, a.b.co.uk → b.co.uk. */
  function siteOf(host) {
    const labels = String(host || '').toLowerCase().replace(/\.$/, '').split('.');
    // Hôtes de développement (idp.exemple.fr.localhost) : même découpage qu'en production.
    if (labels.length > 1 && labels[labels.length - 1] === 'localhost') return `${siteOf(labels.slice(0, -1).join('.'))}.localhost`;
    if (labels.length <= 2 || /^\d+$/.test(labels[labels.length - 1])) return labels.join('.');
    for (const n of [3, 2]) {
      if (labels.length > n && MULTI_SUFFIXES.has(labels.slice(-n).join('.'))) return labels.slice(-(n + 1)).join('.');
    }
    const [second, top] = labels.slice(-2);
    return labels.slice(top.length === 2 && second.length <= 3 ? -3 : -2).join('.');
  }

  // Morceaux d'adresse trop génériques pour désigner un service (mail.exemple.fr n'est pas « Gmail »).
  const IGNORED_LABELS = new Set([
    'www', 'app', 'apps', 'accounts', 'account', 'login', 'signin', 'auth', 'id', 'sso', 'secure', 'my', 'mon', 'portal', 'admin',
    'mail', 'webmail', 'web', 'cloud', 'api', 'mobile', 'home', 'online', 'connect', 'client', 'clients', 'user', 'users',
    'espace', 'compte', 'service', 'services', 'com', 'net', 'org', 'fr', 'io', 'dev',
  ]);

  /** Libellés significatifs d'un hôte : « accounts.github.com » → ['github']. */
  function hostLabels(host) {
    return String(host || '').toLowerCase().split('.').filter((label) => label.length >= 3 && !IGNORED_LABELS.has(label));
  }

  /** Hôte comparable : minuscules, sans point final ni suffixe de développement « .localhost ». */
  function plainHost(host) {
    return String(host || '').toLowerCase().replace(/\.$/, '').replace(/^www\./, '').replace(/(.)\.localhost$/, '$1');
  }

  /** Service nommé par une adresse (« idp.exemple.fr », « https://exemple.fr/ ») : cette adresse, sinon null. */
  function issuerHost(issuer) {
    const value = String(issuer || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/:].*$/, '');
    return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(value) && !/^\d+$/.test(value.split('.').pop()) ? plainHost(value) : null;
  }

  /**
   * Clés de rattachement d'un compte OTP, tirées de son seul service (issuer) — jamais de l'identifiant
   * ni de la description : une adresse « jacques@… » ne rattache pas un compte à tous les sites dont
   * l'adresse contient « jacques ». Service nommé par une adresse : cette adresse (« host:… ») ; sinon
   * ses mots significatifs et son nom compact (« word:… »).
   */
  function accountKeys(account) {
    const host = issuerHost(account.issuer);
    if (host) return [`host:${host}`];
    const issuer = String(account.issuer || '').toLowerCase();
    const words = issuer.split(/[^a-z0-9]+/).filter((w) => w.length >= 3 && !IGNORED_LABELS.has(w));
    const compact = issuer.replace(/[^a-z0-9]/g, '');
    if (compact.length >= 3 && !words.includes(compact)) words.push(compact);
    return words.map((w) => `word:${w}`);
  }

  /**
   * Clés qu'un site présente : son adresse et chacun de ses domaines parents (« host:… »), et les débuts
   * de ses libellés significatifs (« word:… » : ovhcloud.com présente « ovh »). Un compte est celui du site
   * si une de ses clés y figure. Comparaison exacte : l'index salé du coffre verrouillé s'en sert aussi.
   */
  function hostKeys(host) {
    const plain = plainHost(host);
    const labels = plain.split('.');
    const keys = [];
    for (let i = 0; i < labels.length - 1; i += 1) keys.push(`host:${labels.slice(i).join('.')}`);
    for (const label of hostLabels(plain)) {
      for (let n = 3; n <= label.length; n += 1) keys.push(`word:${label.slice(0, n)}`);
    }
    return keys;
  }

  /**
   * Compte OTP de ce site (« GitHub » ↔ github.com, « OVH » ↔ ovhcloud.com, « Google Workspace » ↔
   * accounts.google.com, « idp.exemple.fr » ↔ idp.exemple.fr seulement). Ce test décide quels codes une
   * page peut proposer : un libellé de l'adresse simplement contenu dans le service ne suffit pas
   * (orp.exemple.fr n'est pas idp.exemple.fr).
   */
  function accountMatchesHost(account, host) {
    const keys = new Set(hostKeys(host));
    return accountKeys(account).some((key) => keys.has(key));
  }

  return { createStore, normalizeTag, originOf, hostOf, siteOf, hostLabels, accountKeys, hostKeys, accountMatchesHost, ACCOUNTS_KEY, HISTORY_KEY, DELETED_KEY, LOGINS_KEY, PASSKEYS_KEY, SETTINGS_KEY, HISTORY_MAX };
});
