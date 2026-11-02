/*
 * Audit des mots de passe et statistiques d'usage, pour le tableau de bord.
 *  - Politique de complexité (longueur, familles de caractères, solidité minimale) et de
 *    renouvellement (âge maximal d'un mot de passe) : réglage du coffre (Store.setting('policy')),
 *    donc sauvegardé avec lui.
 *  - Résultats de fuite : réglage du coffre aussi (Store.setting('breaches')), chacun lié à la date
 *    du mot de passe vérifié : changer le mot de passe invalide son résultat.
 *  - Analyse du coffre : mots de passe faibles, réutilisés, à renouveler, compromis ; usage
 *    tiré de l'historique (jamais de valeur de mot de passe).
 *  - Fuites : Have I Been Pwned « Pwned Passwords » par k-anonymat. Seuls les 5 premiers
 *    caractères de l'empreinte SHA-1 partent, avec remplissage (Add-Padding) ; la comparaison
 *    se fait ici. Mozilla Monitor et Google Password Checkup n'ont pas d'API publique : l'app
 *    n'y renvoie que par des liens, sans rien leur transmettre.
 * Fonctions pures (sauf pwnedCount, qui reçoit son fetch) : testées sous Node.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Audit = api;
})(typeof self !== 'undefined' ? self : globalThis, function () {
  'use strict';

  const DAY = 86400000;
  const PWNED_RANGE_URL = 'https://api.pwnedpasswords.com/range/';
  const MAX_AGES = [0, 30, 90, 180, 365]; // 0 : jamais à renouveler
  const DEFAULT_POLICY = { minLength: 12, upper: true, digits: true, symbols: false, minStrength: 3, maxAgeDays: 365 };

  function clamp(value, min, max, fallback) {
    const n = Number(value);
    return Number.isFinite(n) ? Math.min(max, Math.max(min, Math.round(n))) : fallback;
  }

  /** Politique complète et bornée, quelle que soit la valeur lue (stockage ancien, corrompu…). */
  function normalizePolicy(raw) {
    const p = raw && typeof raw === 'object' ? raw : {};
    const bool = (key) => (typeof p[key] === 'boolean' ? p[key] : DEFAULT_POLICY[key]);
    return {
      minLength: clamp(p.minLength, 8, 64, DEFAULT_POLICY.minLength),
      upper: bool('upper'),
      digits: bool('digits'),
      symbols: bool('symbols'),
      minStrength: clamp(p.minStrength, 1, 4, DEFAULT_POLICY.minStrength),
      maxAgeDays: MAX_AGES.includes(Number(p.maxAgeDays)) ? Number(p.maxAgeDays) : DEFAULT_POLICY.maxAgeDays,
    };
  }

  /** Résultats enregistrés → Map id → nombre, pour les seuls mots de passe inchangés depuis la vérification. */
  function savedBreaches(saved, logins) {
    const out = new Map();
    const results = (saved && saved.results) || {};
    for (const login of logins) {
      const entry = results[login.id];
      if (entry && entry.at === passwordDate(login)) out.set(login.id, Number(entry.count) || 0);
    }
    return out;
  }

  /** Map id → nombre (une vérification) → réglage à enregistrer : ni mot de passe ni empreinte. */
  function breachRecord(results, logins, checkedAt) {
    const out = {};
    for (const login of logins) {
      if (results.has(login.id)) out[login.id] = { count: results.get(login.id), at: passwordDate(login) };
    }
    return { checkedAt, results: out };
  }

  /**
   * Règles de la politique que ce mot de passe enfreint : 'length', 'upper', 'digits',
   * 'symbols', 'strength'. `strength(password)` → { level } (Vault.passwordStrength).
   */
  function violations(password, policy, strength) {
    const text = String(password || '');
    const out = [];
    if (text.length < policy.minLength) out.push('length');
    if (policy.upper && !(/[A-Z]/.test(text) && /[a-z]/.test(text))) out.push('upper');
    if (policy.digits && !/[0-9]/.test(text)) out.push('digits');
    if (policy.symbols && !/[^a-zA-Z0-9]/.test(text)) out.push('symbols');
    if (strength && strength(text).level < policy.minStrength) out.push('strength');
    return out;
  }

  /** Date du dernier changement du mot de passe (les plus anciens n'ont que createdAt). */
  function passwordDate(login) {
    return login.passwordChangedAt || login.createdAt || login.updatedAt || null;
  }

  function ageDays(login, now) {
    const at = passwordDate(login);
    return at ? Math.floor((now - new Date(at).getTime()) / DAY) : 0;
  }

  /** Mot de passe à renouveler : plus vieux que l'âge maximal (0 : jamais). */
  function isExpired(login, policy, now) {
    return policy.maxAgeDays > 0 && ageDays(login, now) >= policy.maxAgeDays;
  }

  /**
   * Analyse du coffre.
   * data : { accounts, logins, passkeys, history } ; opts : { now, strength, matchesHost, hostOf, breaches }
   * breaches : Map id de mot de passe → nombre d'apparitions dans des fuites (absent : non vérifié).
   */
  function analyze(data, policy, opts = {}) {
    const now = opts.now || Date.now();
    const accounts = data.accounts || [];
    const logins = data.logins || [];
    const passkeys = data.passkeys || [];
    const history = data.history || [];
    const breaches = opts.breaches || new Map();

    // Réutilisation : même mot de passe sur plusieurs entrées.
    const byPassword = new Map();
    for (const login of logins) {
      const ids = byPassword.get(login.password) || [];
      ids.push(login.id);
      byPassword.set(login.password, ids);
    }

    const items = logins.map((login) => {
      const issues = violations(login.password, policy, opts.strength);
      const reused = (byPassword.get(login.password) || []).length > 1;
      const expired = isExpired(login, policy, now);
      const pwned = breaches.has(login.id) ? breaches.get(login.id) : null;
      const host = opts.hostOf ? opts.hostOf(login.origin) : login.origin;
      const has2fa = Boolean(opts.matchesHost) && accounts.some((a) => a.type !== 'hotp' && opts.matchesHost(a, host));
      return { login, host, issues, reused, expired, age: ageDays(login, now), pwned, has2fa };
    });

    const weak = items.filter((i) => i.issues.length);
    const reused = items.filter((i) => i.reused);
    const expired = items.filter((i) => i.expired);
    const pwned = items.filter((i) => i.pwned > 0);
    const checked = items.filter((i) => i.pwned !== null);
    const at = items.filter((i) => i.issues.length || i.reused || i.expired || i.pwned > 0);

    // Note sur 100 : la part des mots de passe sans aucun problème connu.
    const score = logins.length ? Math.round((100 * (logins.length - at.length)) / logins.length) : null;

    return {
      counts: {
        accounts: accounts.length,
        logins: logins.length,
        passkeys: passkeys.length,
        tags: new Set(accounts.map((a) => a.tag).filter(Boolean)).size,
        with2fa: items.filter((i) => i.has2fa).length,
      },
      score,
      items,
      weak,
      reused,
      expired,
      pwned,
      checked: checked.length,
      atRisk: at,
      usage: usage(history, now, 30),
    };
  }

  /** Usage sur `days` jours : activité par jour (du plus ancien au plus récent) et répartition par action. */
  function usage(history, now, days) {
    const start = new Date(now);
    start.setHours(0, 0, 0, 0);
    const first = start.getTime() - (days - 1) * DAY;
    const perDay = Array.from({ length: days }, (_, i) => ({ date: new Date(first + i * DAY), count: 0 }));
    const byAction = {};
    let total = 0;
    for (const entry of history) {
      const time = new Date(entry.at).getTime();
      if (!(time >= first)) continue;
      const index = Math.min(days - 1, Math.floor((time - first) / DAY));
      perDay[index].count += 1;
      byAction[entry.action] = (byAction[entry.action] || 0) + 1;
      total += 1;
    }
    return { days, perDay, byAction, total, copies: byAction.copy || 0 };
  }

  /* ───────────── Have I Been Pwned (k-anonymat) ───────────── */

  async function sha1Hex(text) {
    const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(text));
    return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  }

  /** Réponse de /range/<préfixe> : « SUFFIXE:NOMBRE » par ligne ; les lignes de remplissage valent 0. */
  function rangeCount(body, suffix) {
    for (const line of String(body).split(/\r?\n/)) {
      const [hash, count] = line.trim().split(':');
      if (hash && hash.toUpperCase() === suffix) return Number(count) || 0;
    }
    return 0;
  }

  /**
   * Nombre d'apparitions du mot de passe dans les fuites connues de HIBP.
   * Seul le préfixe de 5 caractères de l'empreinte quitte l'appareil.
   */
  async function pwnedCount(password, fetchImpl) {
    const hash = await sha1Hex(String(password));
    const response = await fetchImpl(PWNED_RANGE_URL + hash.slice(0, 5), { headers: { 'Add-Padding': 'true' }, cache: 'no-store', referrerPolicy: 'no-referrer' });
    if (!response.ok) {
      const err = new Error('pwnedUnavailable');
      err.code = 'pwnedUnavailable';
      err.params = {};
      throw err;
    }
    return rangeCount(await response.text(), hash.slice(5));
  }

  return {
    DEFAULT_POLICY,
    MAX_AGES,
    PWNED_RANGE_URL,
    normalizePolicy,
    savedBreaches,
    breachRecord,
    violations,
    passwordDate,
    ageDays,
    isExpired,
    analyze,
    usage,
    sha1Hex,
    rangeCount,
    pwnedCount,
  };
});
