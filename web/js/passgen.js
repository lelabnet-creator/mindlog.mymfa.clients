/*
 * Génération d'un mot de passe selon la politique d'un site.
 *  - policy : { minLength, maxLength, required: [classe…], symbols: chaîne autorisée ('' = aucun),
 *    pattern, maxConsecutive } ; classes : lower, upper, digit, symbol.
 *  - Sources de la politique, de la plus sûre à la plus floue : l'attribut `passwordrules`
 *    (proposition WHATWG / Apple), les attributs HTML (minlength, maxlength, pattern), le texte
 *    d'aide du formulaire (français, anglais). Le script de contenu rassemble ces sources ; ce
 *    module, sans DOM, les interprète et les fusionne.
 *  - Aléa Web Crypto, sans biais ; chaque classe exigée est présente ; `pattern` est vérifié.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Passgen = api;
})(typeof self !== 'undefined' ? self : globalThis, function () {
  'use strict';

  const SETS = {
    lower: 'abcdefghijkmnopqrstuvwxyz',
    upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
    digit: '23456789',
  };
  const DEFAULT_SYMBOLS = '-_.!@#%+=?*';
  const ASCII_SYMBOLS = '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~';
  const TARGET_LENGTH = 20;

  /** Entier uniforme dans [0, n) (rejet des valeurs qui biaiseraient le modulo). */
  function randomBelow(n) {
    const limit = Math.floor(0x100000000 / n) * n;
    const buf = new Uint32Array(1);
    do crypto.getRandomValues(buf);
    while (buf[0] >= limit);
    return buf[0] % n;
  }

  const pick = (chars) => chars[randomBelow(chars.length)];

  function shuffle(list) {
    for (let i = list.length - 1; i > 0; i--) {
      const j = randomBelow(i + 1);
      [list[i], list[j]] = [list[j], list[i]];
    }
    return list;
  }

  const unique = (chars) => [...new Set(chars)].join('');
  const toInt = (value) => {
    const n = parseInt(value, 10);
    return Number.isFinite(n) && n > 0 ? n : null;
  };

  /* ───────────── Sources ───────────── */

  /**
   * Attribut passwordrules : « minlength: 8; maxlength: 20; required: lower; required: upper;
   * required: digit; required: [-!@]; allowed: ascii-printable; max-consecutive: 2 ».
   */
  function fromPasswordRules(text) {
    const policy = { required: [] };
    let symbols = null;
    const addSymbols = (chars) => (symbols = unique((symbols || '') + chars));
    for (const rule of String(text || '').split(';')) {
      const sep = rule.indexOf(':');
      if (sep === -1) continue;
      const name = rule.slice(0, sep).trim().toLowerCase();
      const value = rule.slice(sep + 1).trim();
      if (name === 'minlength') policy.minLength = toInt(value);
      else if (name === 'maxlength') policy.maxLength = toInt(value);
      else if (name === 'max-consecutive') policy.maxConsecutive = toInt(value);
      else if (name === 'required' || name === 'allowed') {
        for (const part of value.match(/\[[^\]]*\]|[\w-]+/g) || []) {
          const key = part.toLowerCase();
          let cls = null;
          if (part.startsWith('[')) {
            addSymbols(part.slice(1, -1).replace(/[a-z0-9\s]/gi, ''));
            cls = 'symbol';
          } else if (key === 'lower' || key === 'upper' || key === 'digit') cls = key;
          else if (key === 'special') {
            addSymbols(ASCII_SYMBOLS);
            cls = 'symbol';
          } else if (key === 'ascii-printable' || key === 'unicode') addSymbols(ASCII_SYMBOLS);
          if (cls && name === 'required' && !policy.required.includes(cls)) policy.required.push(cls);
        }
      }
    }
    // Des symboles cités (requis ou permis) : seulement ceux-là ; des classes citées sans symbole : aucun.
    if (symbols !== null) policy.symbols = symbols;
    else if (/\b(required|allowed)\s*:/i.test(text)) policy.symbols = '';
    return clean(policy);
  }

  /** Attributs HTML du champ. Un motif qui finit par {min,max} donne aussi les longueurs. */
  function fromAttributes({ minLength, maxLength, pattern } = {}) {
    const bounds = String(pattern || '').match(/\{(\d+),(\d*)\}\)*\$?$/);
    return clean({
      minLength: toInt(minLength) || (bounds && toInt(bounds[1])),
      maxLength: toInt(maxLength) || (bounds && toInt(bounds[2])),
      pattern: pattern || null,
      required: [],
    });
  }

  const N = '(\\d{1,3})';
  const CHARS = '(?:caract[eè]res?|signes?|characters?|chars?)';

  /** Texte d'aide (« 8 à 20 caractères, dont une majuscule et un chiffre »), en français ou en anglais. */
  function fromText(text) {
    const src = String(text || '').toLowerCase().replace(/\s+/g, ' ').slice(0, 4000);
    const policy = { required: [] };
    const match = (re) => src.match(re);
    let m;
    if ((m = match(new RegExp(`(?:entre |between )?${N} ?(?:à|a|-|–|to|and|et) ?${N} ${CHARS}`)))) {
      policy.minLength = toInt(m[1]);
      policy.maxLength = toInt(m[2]);
    }
    if (!policy.minLength && (m = match(new RegExp(`(?:au moins|au minimum|minimum(?: de)?|min\\.?|at least|a minimum of|minimum of) ${N} ${CHARS}`)) || match(new RegExp(`${N} ${CHARS} (?:minimum|min\\b|ou plus|or more|at least)`)) || match(new RegExp(`${N} (?:or more|ou plus) ${CHARS}`)))) {
      policy.minLength = toInt(m[1]);
    }
    if (!policy.maxLength && (m = match(new RegExp(`(?:au plus|au maximum|maximum(?: de)?|max\\.?|at most|no more than|up to|maximum of) ${N} ${CHARS}`)) || match(new RegExp(`${N} ${CHARS} (?:maximum|max\\b)`)))) {
      policy.maxLength = toInt(m[1]);
    }
    const noSymbols = /(?:pas de|sans|aucun) caract[eè]res? sp[eé]ciaux|no (?:special characters|symbols)|(?:lettres et chiffres|letters and (?:numbers|digits)) (?:uniquement|seulement|only)|(?:only|uniquement) (?:letters and (?:numbers|digits)|alphanum)/.test(src);
    if (/majuscule|uppercase|upper-case|upper case|capital/.test(src)) policy.required.push('upper');
    if (/minuscule|lowercase|lower-case|lower case/.test(src)) policy.required.push('lower');
    if (/chiffre|digit|number|num[eé]rique|numeric/.test(src)) policy.required.push('digit');
    if (noSymbols) policy.symbols = '';
    else if (/caract[eè]res? sp[eé]ci(?:al|aux)|special char|symbol|symbole/.test(src)) {
      policy.required.push('symbol');
      // Liste de symboles permis citée : « (!@#$%) », « parmi : ! @ # $ ».
      m = match(/(?:sp[eé]ci(?:al|aux)|symbol(?:e)?s?)[^.;]{0,40}?[:(]\s*((?:[!-/:-@[-`{-~]\s*){3,})/);
      if (m) policy.symbols = unique(m[1].replace(/\s+/g, '').replace(/[()]/g, ''));
    }
    return clean(policy);
  }

  function clean(policy) {
    const out = {};
    for (const [key, value] of Object.entries(policy)) {
      if (value === null || value === undefined || (Array.isArray(value) && !value.length)) continue;
      out[key] = value;
    }
    if (!out.required) out.required = [];
    return out;
  }

  /** Fusion : la première source qui fixe une valeur l'emporte ; les classes exigées s'additionnent. */
  function merge(...policies) {
    const out = { required: [] };
    for (const policy of policies.filter(Boolean)) {
      for (const key of ['minLength', 'maxLength', 'pattern', 'maxConsecutive', 'symbols']) {
        if (out[key] === undefined && policy[key] !== undefined) out[key] = policy[key];
      }
      for (const cls of policy.required || []) if (!out.required.includes(cls)) out.required.push(cls);
    }
    // Symboles exigés mais interdits par une autre source : la plus sûre (la première) a parlé.
    if (out.symbols === '') out.required = out.required.filter((c) => c !== 'symbol');
    if (out.minLength && out.maxLength && out.minLength > out.maxLength) delete out.minLength;
    return out;
  }

  /* ───────────── Génération ───────────── */

  function patternTest(pattern) {
    if (!pattern) return () => true;
    for (const flags of ['v', 'u']) {
      try {
        const re = new RegExp(`^(?:${pattern})$`, flags);
        return (value) => re.test(value);
      } catch {
        /* drapeau non pris en charge, ou motif invalide pour ce drapeau */
      }
    }
    return () => true; // motif illisible : le navigateur l'ignore aussi
  }

  function tooManyRepeats(value, max) {
    if (!max) return false;
    let run = 1;
    for (let i = 1; i < value.length; i++) {
      run = value[i] === value[i - 1] ? run + 1 : 1;
      if (run > max) return true;
    }
    return false;
  }

  /** Longueur retenue : 20, ramenée dans [minLength, maxLength]. */
  function lengthFor(policy) {
    let length = TARGET_LENGTH;
    if (policy.minLength) length = Math.max(length, policy.minLength);
    if (policy.maxLength) length = Math.min(length, policy.maxLength);
    return Math.max(length, 4);
  }

  // Un motif peut refuser une classe (pas de symbole, par exemple) : on retire alors des classes,
  // de la plus à la moins risquée, jusqu'à le satisfaire.
  const FALLBACKS = [[], ['symbol'], ['symbol', 'upper'], ['symbol', 'lower'], ['symbol', 'digit'], ['symbol', 'upper', 'digit'], ['symbol', 'lower', 'digit']];

  /** Mot de passe conforme à la politique (chaque classe utilisée présente, motif vérifié si possible). */
  function generate(policy = {}) {
    const symbols = policy.symbols === undefined ? DEFAULT_SYMBOLS : policy.symbols;
    const pools = { ...SETS, symbol: symbols };
    const length = lengthFor(policy);
    const ok = patternTest(policy.pattern);
    let value = '';
    for (const without of policy.pattern ? FALLBACKS : [[]]) {
      // Toutes les classes disponibles servent (robustesse) ; chacune est présente au moins une fois.
      const classes = ['lower', 'upper', 'digit', 'symbol'].filter((c) => pools[c] && !without.includes(c));
      const all = classes.map((c) => pools[c]).join('');
      for (let attempt = 0; attempt < 60; attempt++) {
        const chars = classes.slice(0, length).map((c) => pick(pools[c]));
        while (chars.length < length) chars.push(pick(all));
        const candidate = shuffle(chars).join('');
        if (!value) value = candidate;
        if (ok(candidate) && !tooManyRepeats(candidate, policy.maxConsecutive)) return candidate;
      }
    }
    return value; // motif jamais satisfait : le site le dira, l'utilisateur peut régénérer
  }

  /** Résumé de la politique, pour l'affichage : { length, min, max, symbols, classes }. */
  function describe(policy = {}) {
    const symbols = policy.symbols === undefined ? DEFAULT_SYMBOLS : policy.symbols;
    return {
      length: lengthFor(policy),
      min: policy.minLength || null,
      max: policy.maxLength || null,
      symbols,
      classes: ['lower', 'upper', 'digit', 'symbol'].filter((c) => (c === 'symbol' ? symbols : true)),
      detected: Boolean(policy.minLength || policy.maxLength || policy.pattern || (policy.required || []).length || policy.symbols !== undefined),
    };
  }

  return { fromPasswordRules, fromAttributes, fromText, merge, generate, describe, lengthFor, DEFAULT_SYMBOLS };
});
