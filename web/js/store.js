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

  /* ───── Synchro v2 (SYN-07) ─────
   * createStore(storage, temps) : quand `temps` est fourni ({ tampon(plancher) }),
   * chaque modification tamponne ses champs au format v2 (item.h, item.t) —
   * c'est ce format que fusionne js/sync2.js. Sans `temps`, le store écrit la
   * forme v1 historique (updatedAt seul) : l'extension reste en v1 jusqu'à son
   * adoption (EXT-12), les tests v1 ne bougent pas. La règle de vie (un élément
   * vit si max(tampons de ses champs) > trace) est reprise de js/sync2.js —
   * store.js ne peut pas l'importer : sync2.js dépend de store.js pour les clés. */
  const SYNC_V2_KEY = 'mymfa.sync.v2'; // constante de js/sync2.js

  const tamponDe = (item, champ) => (item && item.h && typeof item.h[champ] === 'string' ? item.h[champ] : '');

  const plusGrandTampon = (item) => {
    let sommet = '';
    if (item && item.h && typeof item.h === 'object') {
      for (const t of Object.values(item.h)) if (typeof t === 'string' && t > sommet) sommet = t;
    }
    return sommet;
  };

  const traceDe = (item) => (item && typeof item.t === 'string' && item.t ? item.t : null);

  const estVivant = (item) => {
    const trace = traceDe(item);
    if (!trace) return true;
    return plusGrandTampon(item) > trace;
  };

  const isoDeTampon = (tampon) => new Date(Number(String(tampon).slice(0, 13))).toISOString();

  function createStore(storage, temps = null) {
    const v2 = () => temps && typeof temps.tampon === 'function';

    function marqueur() {
      try {
        const value = JSON.parse(storage.getItem(SYNC_V2_KEY) || '{}');
        return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
      } catch {
        return {};
      }
    }

    function ecrireMarqueur(marqueurCourant) {
      storage.setItem(SYNC_V2_KEY, JSON.stringify(marqueurCourant));
    }

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
        // Appareil auteur (SYN-09) : la source affichée dans l'espace Synchro.
        ...(temps && typeof temps.appareil === 'string' && temps.appareil ? { appareil: temps.appareil } : {}),
      });
      write(HISTORY_KEY, history.slice(0, HISTORY_MAX));
    }

    function describe(account) {
      return [account.issuer, account.account].filter(Boolean).join(' — ');
    }

    /** Éléments vivants d'une collection : les morts (trace plus récente que
     * leurs champs) restent dans la copie pour propager leur trace, invisibles. */
    function vivants(key) {
      return v2() ? read(key).filter(estVivant) : read(key);
    }

    function list() {
      return vivants(ACCOUNTS_KEY);
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
      if (v2()) {
        const tampon = temps.tampon(null);
        account.h = {};
        for (const champ of ['type', 'issuer', 'account', 'secret', 'algorithm', 'digits', 'period', 'counter', 'tag', 'description', 'favorite']) {
          account.h[champ] = tampon;
        }
        account.updatedAt = isoDeTampon(tampon);
      }
      const accounts = read(ACCOUNTS_KEY);
      accounts.push(account);
      write(ACCOUNTS_KEY, accounts);
      log('create', account, source ? { source } : null);
      return account;
    }

    function update(id, patch) {
      // Liste brute : modifier un élément supprimé (trace) le fait revivre —
      // une modification plus récente que sa suppression gagne (v2).
      const accounts = read(ACCOUNTS_KEY);
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
      if (v2()) {
        next.h = { ...(before.h || {}) };
        const champsChanges = [...changes.map((c) => c.field)];
        if (next.counter !== before.counter) champsChanges.push('counter');
        if (next.favorite !== before.favorite) champsChanges.push('favorite');
        for (const champ of champsChanges) next.h[champ] = temps.tampon(tamponDe(before, champ));
        next.updatedAt = isoDeTampon(plusGrandTampon(next));
      } else {
        next.updatedAt = new Date().toISOString();
      }
      accounts[idx] = next;
      write(ACCOUNTS_KEY, accounts);
      if (changes.length) log('update', next, { changes });
      return next;
    }

    /* ───── Mots de passe ───── */

    function logins() {
      return vivants(LOGINS_KEY);
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
      if (v2()) {
        const tampon = temps.tampon(null);
        login.h = {};
        for (const champ of ['origin', 'username', 'password', 'title', 'note', 'tag', 'source', 'favorite']) {
          login.h[champ] = tampon;
        }
        login.updatedAt = isoDeTampon(tampon);
        login.passwordChangedAt = login.updatedAt;
      }
      write(LOGINS_KEY, [...read(LOGINS_KEY), login]);
      log('create', loginLabel(login), { kind: 'login', ...(source ? { source } : {}) });
      return login;
    }

    function updateLogin(id, patch) {
      // Liste brute, comme update : une modification fait revivre (v2).
      const list = read(LOGINS_KEY);
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
      if (v2()) {
        next.h = { ...(before.h || {}) };
        const champsChanges = [...changed];
        if (Boolean(next.favorite) !== Boolean(before.favorite)) champsChanges.push('favorite');
        for (const champ of champsChanges) next.h[champ] = temps.tampon(tamponDe(before, champ));
        next.updatedAt = isoDeTampon(plusGrandTampon(next));
        if (changed.includes('password')) next.passwordChangedAt = isoDeTampon(next.h.password);
      } else {
        next.updatedAt = new Date().toISOString();
        if (changed.includes('password')) next.passwordChangedAt = next.updatedAt;
      }
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
      if (v2()) {
        write(LOGINS_KEY, read(LOGINS_KEY).map((l) => (l.id === id ? { ...l, t: temps.tampon(plusGrandTampon(l)) } : l)));
      } else {
        write(LOGINS_KEY, logins().filter((l) => l.id !== id));
        bury(id);
      }
      log('delete', loginLabel(login), { kind: 'login' });
      return true;
    }

    function loginLabel(login) {
      return { id: login.id, issuer: hostOf(login.origin), account: login.username, tag: '' };
    }

    /* ───── Passkeys des sites ───── */

    function passkeys() {
      return vivants(PASSKEYS_KEY);
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
      const tous = read(PASSKEYS_KEY);
      const replaced = tous.filter((p) => estVivant(p) && p.rpId === passkey.rpId && passkey.userHandle && p.userHandle === passkey.userHandle);
      if (v2()) {
        const tampon = temps.tampon(null);
        passkey.h = {};
        for (const champ of ['credentialId', 'rpId', 'rpName', 'origin', 'userHandle', 'userName', 'userDisplayName', 'algorithm', 'privateKey']) {
          passkey.h[champ] = tampon;
        }
        passkey.updatedAt = isoDeTampon(tampon);
        const trace = temps.tampon(tampon);
        const restants = tous.map((p) =>
          replaced.includes(p) ? { ...p, t: temps.tampon(plusGrandTampon(p)) } : p
        );
        write(PASSKEYS_KEY, [...restants, passkey]);
        const _ = trace;
      } else {
        write(PASSKEYS_KEY, [...tous.filter((p) => !replaced.includes(p)), passkey]);
        replaced.forEach((p) => bury(p.id));
      }
      log('create', passkeyLabel(passkey), { kind: 'passkey', ...(source ? { source } : {}) });
      return passkey;
    }

    function removePasskey(id) {
      const passkey = passkeys().find((p) => p.id === id);
      if (!passkey) return false;
      if (v2()) {
        write(PASSKEYS_KEY, read(PASSKEYS_KEY).map((p) => (p.id === id ? { ...p, t: temps.tampon(plusGrandTampon(p)) } : p)));
      } else {
        write(PASSKEYS_KEY, passkeys().filter((p) => p.id !== id));
        bury(id);
      }
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
      if (v2()) {
        write(ACCOUNTS_KEY, read(ACCOUNTS_KEY).map((a) => (a.id === id ? { ...a, t: temps.tampon(plusGrandTampon(a)) } : a)));
      } else {
        write(ACCOUNTS_KEY, accounts.filter((a) => a.id !== id));
        bury(id);
      }
      log('delete', account);
      return true;
    }

    function history() {
      return read(HISTORY_KEY);
    }

    function clearHistory() {
      write(HISTORY_KEY, []);
      if (v2()) {
        const m = marqueur();
        m.historiqueVideLe = temps.tampon(typeof m.historiqueVideLe === 'string' ? m.historiqueVideLe : null);
        ecrireMarqueur(m);
      } else {
        storage.setItem(DELETED_KEY, JSON.stringify({ ...tombstones(), historyClearedAt: new Date().toISOString() }));
      }
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
      if (v2()) {
        const avant = all[name] && typeof all[name].h === 'string' ? all[name].h : null;
        const tampon = temps.tampon(avant);
        all[name] = { value, at: isoDeTampon(tampon), h: tampon };
      } else {
        all[name] = { value, at: new Date().toISOString() };
      }
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
