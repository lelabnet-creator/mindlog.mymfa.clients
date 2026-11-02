/*
 * Import depuis d'autres gestionnaires (CSV ou JSON) : mots de passe des sites et comptes 2FA.
 *  - parse(text) reconnaît le format (en-tête CSV, forme du JSON) et le traduit en éléments
 *    myMFA, sans rien écrire : { format, name, passwords, logins, accounts, ignored }.
 *  - apply(store, result, { logins }) ajoute ce qui manque, ignore les doublons. Les mots de passe
 *    n'entrent que dans un coffre chiffré : sans lui (logins: false), ils sont comptés, pas importés.
 * Formats : Proton Pass (CSV), Proton Authenticator (JSON). Un format = sa reconnaissance
 * (en-tête CSV `headers`, ou `matches` et `items` pour un JSON) et une conversion élément → { login, account, ignored }.
 * Dépend de : OTP, Store.
 */
(function (root, factory) {
  const deps = typeof module === 'object' && module.exports
    ? [require('./otp.js'), require('./store.js')]
    : [root.OTP, root.Store];
  const api = factory(...deps);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Importers = api;
})(typeof self !== 'undefined' ? self : globalThis, function (OTP, Store) {
  'use strict';

  function importError(code, params = {}) {
    const err = new Error(code);
    err.code = code;
    err.params = params;
    return err;
  }

  /** CSV (RFC 4180) : guillemets, "" échappés, retours à la ligne dans un champ, CRLF, BOM. */
  function parseCsv(text) {
    const src = String(text || '').replace(/^﻿/, '');
    const rows = [];
    let row = [];
    let field = '';
    let quoted = false;
    for (let i = 0; i < src.length; i++) {
      const ch = src[i];
      if (quoted) {
        if (ch === '"' && src[i + 1] === '"') {
          field += '"';
          i++;
        } else if (ch === '"') quoted = false;
        else field += ch;
      } else if (ch === '"') quoted = true;
      else if (ch === ',') {
        row.push(field);
        field = '';
      } else if (ch === '\n' || ch === '\r') {
        if (ch === '\r' && src[i + 1] === '\n') i++;
        row.push(field);
        rows.push(row);
        row = [];
        field = '';
      } else field += ch;
    }
    if (field || row.length) {
      row.push(field);
      rows.push(row);
    }
    // Lignes vides (fin de fichier, séparateurs) : sans intérêt.
    return rows.filter((r) => r.some((cell) => cell.trim()));
  }

  /** Lignes → objets indexés par l'en-tête (en minuscules). */
  function records(rows) {
    const [header = [], ...body] = rows;
    const keys = header.map((h) => h.trim().toLowerCase());
    return { keys, items: body.map((cells) => Object.fromEntries(keys.map((k, i) => [k, (cells[i] || '').trim()]))) };
  }

  /** Première adresse web d'une liste (séparateurs : virgules, espaces) ; « exemple.fr » vaut https://exemple.fr. */
  function firstOrigin(...lists) {
    for (const value of lists.join(',').split(/[\s,]+/).filter(Boolean)) {
      const url = /^[a-z][a-z0-9+.-]*:/i.test(value) ? value : `https://${value}`;
      if (!/^https?:/i.test(url)) continue; // android://, ios:// : pas une page web
      const origin = Store.originOf(url);
      if (origin) return origin;
    }
    return '';
  }

  /** Champ OTP : URI otpauth:// ou clé seule. null s'il est vide ou illisible. */
  function totpOf(value, fallback) {
    if (!value) return null;
    try {
      const data = /^otpauth:/i.test(value) ? OTP.parseOtpauthUri(value) : { type: 'totp', secret: OTP.normalizeSecret(value) };
      if (!OTP.isValidSecret(data.secret)) return null;
      return { ...data, issuer: data.issuer || fallback.issuer, account: data.account || fallback.account };
    } catch {
      return null;
    }
  }

  const FORMATS = {
    protonpass: {
      name: 'Proton Pass',
      passwords: true,
      // type,name,url,autofillUrls,email,username,password,note,totp,createTime,modifyTime,vault
      // (autofillUrls et email manquent dans les exports plus anciens : pas exigés).
      headers: ['type', 'name', 'url', 'username', 'password', 'note', 'totp', 'vault'],
      convert(item) {
        if (item.type !== 'login') return { ignored: item.type || 'unknown' };
        const origin = firstOrigin(item.url, item.autofillurls || '');
        const username = item.username || item.email || '';
        const out = {};
        if (item.password) {
          out.login = origin
            ? { origin, username, password: item.password, title: item.name, note: item.note }
            : null;
          if (!origin) out.ignored = 'noUrl';
        }
        const otp = totpOf(item.totp, { issuer: item.name || Store.hostOf(origin), account: username });
        if (otp) out.account = otp;
        if (!out.login && !out.account && !out.ignored) out.ignored = 'empty';
        return out;
      },
    },
    protonauthenticator: {
      name: 'Proton Authenticator',
      // Export non chiffré : { version: 1, entries: [{ id, content: { uri, entry_type, name }, note }] }
      matches: (payload) => Boolean(payload) && payload.version === 1 && Array.isArray(payload.entries),
      items: (payload) => payload.entries,
      convert(entry) {
        const content = (entry && entry.content) || {};
        // Steam Guard : 5 caractères d'un alphabet propre à Steam, pas un TOTP standard.
        if (content.entry_type === 'Steam') return { ignored: 'steam' };
        const otp = /^otpauth:/i.test(content.uri || '') ? totpOf(content.uri, { issuer: '', account: content.name || '' }) : null;
        if (!otp) return { ignored: 'invalid' };
        return { account: { ...otp, description: String((entry && entry.note) || '').trim() } };
      },
    },
  };

  function fromCsv(text) {
    const { keys, items } = records(parseCsv(text));
    const format = Object.keys(FORMATS).find((id) => FORMATS[id].headers && FORMATS[id].headers.every((h) => keys.includes(h)));
    return { format, items };
  }

  function fromJson(text) {
    let payload;
    try {
      payload = JSON.parse(text);
    } catch {
      throw importError('invalidImport');
    }
    const format = Object.keys(FORMATS).find((id) => FORMATS[id].matches && FORMATS[id].matches(payload));
    return { format, items: format ? FORMATS[format].items(payload) : [] };
  }

  /** Analyse un export ; lève unknownImportFormat s'il n'est d'aucun format connu. */
  function parse(text) {
    const src = String(text || '').replace(/^\uFEFF/, '');
    const { format, items } = /^\s*[{[]/.test(src) ? fromJson(src) : fromCsv(src);
    if (!format) throw importError('unknownImportFormat');
    const result = { format, name: FORMATS[format].name, passwords: Boolean(FORMATS[format].passwords), logins: [], accounts: [], ignored: {} };
    for (const item of items) {
      const out = FORMATS[format].convert(item);
      if (out.login) result.logins.push(out.login);
      if (out.account) result.accounts.push(out.account);
      if (out.ignored) result.ignored[out.ignored] = (result.ignored[out.ignored] || 0) + 1;
    }
    return result;
  }

  const BATCH = 20; // éléments entre deux mises à jour de la progression

  /**
   * Ajoute au store ce qui n'y est pas. options.logins : le coffre est chiffré et ouvert.
   * options.onProgress(done, total) : appelé tous les BATCH éléments, la page se redessine entre deux.
   * Résout en { logins, accounts, skipped, needVault } (skipped : doublons et lignes inexploitables).
   */
  async function apply(store, result, { logins: allowLogins = false, onProgress = () => {} } = {}) {
    const source = result.format;
    const stats = { logins: 0, accounts: 0, skipped: 0, needVault: 0 };
    const total = result.logins.length + result.accounts.length;
    let done = 0;
    async function advance() {
      done++;
      if (done % BATCH && done < total) return;
      onProgress(done, total);
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
    onProgress(0, total);
    for (const login of result.logins) {
      if (!allowLogins) stats.needVault++;
      else if (store.findLogin(login.origin, login.username)) stats.skipped++;
      else {
        store.addLogin(login, source);
        stats.logins++;
      }
      await advance();
    }
    for (const account of result.accounts) {
      if (store.findDuplicate(account.secret, account.issuer, account.account)) stats.skipped++;
      else {
        store.add(account, source);
        stats.accounts++;
      }
      await advance();
    }
    stats.skipped += Object.values(result.ignored).reduce((sum, n) => sum + n, 0);
    store.log('import', null, { format: source, added: stats.logins + stats.accounts, skipped: stats.skipped });
    return stats;
  }

  return { parseCsv, parse, apply, FORMATS };
});
