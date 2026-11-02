/*
 * Fusion de deux copies des données myMFA (app ↔ extension).
 * Entrées et sortie : { clé localStorage → valeur brute (JSON en texte) }, comme
 * stockées par Store, pour les clés comptes, mots de passe, passkeys, historique et suppressions.
 *  - comptes, mots de passe, passkeys : union par id ; même id → la version modifiée le plus récemment ;
 *  - un id présent dans les suppressions (de l'un ou l'autre côté) ne revient jamais ;
 *  - même élément sous deux id (ajout des deux côtés) → on garde le plus ancien : même clé + service
 *    + compte, même site + identifiant, même passkey ;
 *  - historique : union par id, sans ce qui précède le dernier vidage, plafonné ;
 *  - réglages : par nom, le plus récent (`at`).
 */
(function (root, factory) {
  const api = factory(root.Store || (typeof require === 'function' ? require('./store.js') : null));
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Sync = api;
})(typeof self !== 'undefined' ? self : globalThis, function (Store) {
  'use strict';

  const { ACCOUNTS_KEY, HISTORY_KEY, DELETED_KEY, LOGINS_KEY, PASSKEYS_KEY, SETTINGS_KEY, HISTORY_MAX } = Store;
  const KEYS = [ACCOUNTS_KEY, HISTORY_KEY, DELETED_KEY, LOGINS_KEY, PASSKEYS_KEY, SETTINGS_KEY];
  const TOMBSTONES_MAX = 1000;
  // Collections fusionnées élément par élément ; `same` repère un même élément ajouté sous deux id.
  const COLLECTIONS = [
    { key: ACCOUNTS_KEY, same: (a) => [a.secret, a.issuer || '', a.account || ''].join('\u0000') },
    { key: LOGINS_KEY, same: (l) => [l.origin, l.username || ''].join('\u0000') },
    { key: PASSKEYS_KEY, same: (p) => p.credentialId },
  ];

  function parseJson(raw, fallback) {
    try {
      const value = JSON.parse(raw);
      return value === null || value === undefined ? fallback : value;
    } catch {
      return fallback;
    }
  }

  function list(map, key) {
    const value = parseJson((map || {})[key], []);
    return Array.isArray(value) ? value : [];
  }

  function read(map) {
    const deleted = parseJson((map || {})[DELETED_KEY], {});
    const history = parseJson((map || {})[HISTORY_KEY], []);
    return {
      accounts: list(map, ACCOUNTS_KEY),
      history: Array.isArray(history) ? history : [],
      deleted: { accounts: deleted.accounts || {}, historyClearedAt: deleted.historyClearedAt || null },
    };
  }

  const later = (x, y) => ((x || '') > (y || '') ? x : y);

  function merge(left, right, now = new Date().toISOString()) {
    const a = read(left);
    const b = read(right);

    const tombs = { ...a.deleted.accounts };
    for (const [id, at] of Object.entries(b.deleted.accounts)) tombs[id] = later(tombs[id], at);
    const historyClearedAt = later(a.deleted.historyClearedAt, b.deleted.historyClearedAt);

    const merged = {};
    for (const { key, same } of COLLECTIONS) {
      // Collections récentes : absentes des deux côtés, elles le restent (pas de réécriture inutile).
      if (key !== ACCOUNTS_KEY && (left || {})[key] == null && (right || {})[key] == null) continue;
      const byId = new Map();
      for (const item of [...list(left, key), ...list(right, key)]) {
        if (!item || !item.id || tombs[item.id]) continue;
        const current = byId.get(item.id);
        let chosen = !current || (item.updatedAt || '') > (current.updatedAt || '') ? item : current;
        // Dernière utilisation : la plus récente des deux copies, sans compter comme une modification.
        const usedAt = later(current && current.usedAt, item.usedAt);
        if (usedAt && chosen.usedAt !== usedAt) chosen = { ...chosen, usedAt };
        byId.set(item.id, chosen);
      }
      const ordered = [...byId.values()].sort((x, y) => (x.createdAt || '').localeCompare(y.createdAt || ''));
      const seen = new Set();
      const items = [];
      for (const item of ordered) {
        const identity = same(item);
        if (seen.has(identity)) {
          tombs[item.id] = now; // doublon : l'autre côté le retirera aussi
          continue;
        }
        seen.add(identity);
        items.push(item);
      }
      merged[key] = JSON.stringify(items);
    }

    const entries = new Map();
    for (const entry of [...a.history, ...b.history]) {
      if (!entry || !entry.id || entries.has(entry.id)) continue;
      if (historyClearedAt && (entry.at || '') <= historyClearedAt) continue;
      entries.set(entry.id, entry);
    }
    const history = [...entries.values()].sort((x, y) => (y.at || '').localeCompare(x.at || '')).slice(0, HISTORY_MAX);

    const keptTombs = Object.fromEntries(
      Object.entries(tombs).sort((x, y) => y[1].localeCompare(x[1])).slice(0, TOMBSTONES_MAX)
    );

    const settings = mergeSettings(left, right);
    return {
      ...merged,
      ...(settings ? { [SETTINGS_KEY]: settings } : {}),
      [HISTORY_KEY]: JSON.stringify(history),
      [DELETED_KEY]: JSON.stringify({ accounts: keptTombs, historyClearedAt }),
    };
  }

  /** Réglages : union par nom, le plus récent l'emporte. Absents des deux côtés : rien. */
  function mergeSettings(left, right) {
    if ((left || {})[SETTINGS_KEY] == null && (right || {})[SETTINGS_KEY] == null) return null;
    const object = (map) => {
      const value = parseJson((map || {})[SETTINGS_KEY], {});
      return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
    };
    const out = { ...object(left) };
    for (const [name, entry] of Object.entries(object(right))) {
      if (!entry || typeof entry !== 'object') continue;
      if (!out[name] || (entry.at || '') > (out[name].at || '')) out[name] = entry;
    }
    return JSON.stringify(out);
  }

  /** Sous-ensemble des clés de données d'un objet clé → valeur. */
  function pick(map) {
    const out = {};
    for (const key of KEYS) if (map && map[key] != null) out[key] = map[key];
    return out;
  }

  function same(left, right) {
    return KEYS.every((key) => ((left || {})[key] ?? null) === ((right || {})[key] ?? null));
  }

  /** Les données contiennent-elles des mots de passe ou des passkeys (qui exigent un coffre chiffré) ? */
  function hasCredentials(map) {
    return list(map, LOGINS_KEY).length > 0 || list(map, PASSKEYS_KEY).length > 0;
  }

  return { KEYS, merge, pick, same, read, hasCredentials };
});
