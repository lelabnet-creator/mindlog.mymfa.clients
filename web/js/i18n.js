/*
 * i18n minimal sans dépendance.
 *  - I18n.register(locale, dict)        : enregistre un dictionnaire (js/locales/*.js)
 *  - I18n.t('a.b', { n: 2 })            : traduit, interpole {param}, gère les pluriels
 *                                         ({ one: '…', other: '…' } choisi via Intl.PluralRules sur `count`)
 *  - I18n.apply(root)                   : traduit le DOM via les attributs
 *        data-i18n="clé"                     → textContent
 *        data-i18n-attr="placeholder:clé;aria-label:clé2"
 *  - I18n.setLocale('en')               : change de langue, persiste, notifie onChange
 * Langue initiale : choix enregistré > langues du navigateur > langue par défaut.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.I18n = api;
})(typeof self !== 'undefined' ? self : globalThis, function () {
  'use strict';

  const STORAGE_KEY = 'mymfa.locale';
  const DEFAULT_LOCALE = 'fr';
  const dictionaries = {};
  const listeners = [];
  let current = DEFAULT_LOCALE;

  function register(locale, dict) {
    dictionaries[locale] = dict;
  }

  function locales() {
    return Object.keys(dictionaries).map((code) => ({ code, name: (dictionaries[code].meta || {}).name || code }));
  }

  function lookup(dict, key) {
    return key.split('.').reduce((node, part) => (node && typeof node === 'object' ? node[part] : undefined), dict);
  }

  function interpolate(text, params) {
    return text.replace(/\{(\w+)\}/g, (match, name) => (name in params ? String(params[name]) : match));
  }

  function t(key, params = {}) {
    let value = lookup(dictionaries[current], key);
    if (value === undefined) value = lookup(dictionaries[DEFAULT_LOCALE], key);
    if (value === undefined) return key;
    if (value && typeof value === 'object') {
      const rule = new Intl.PluralRules(current).select(Number(params.count) || 0);
      value = value[rule] !== undefined ? value[rule] : value.other;
    }
    return typeof value === 'string' ? interpolate(value, params) : key;
  }

  function apply(rootNode) {
    const scope = rootNode || document;
    scope.querySelectorAll('[data-i18n]').forEach((el) => {
      el.textContent = t(el.dataset.i18n);
    });
    scope.querySelectorAll('[data-i18n-attr]').forEach((el) => {
      for (const pair of el.dataset.i18nAttr.split(';')) {
        const [attr, key] = pair.split(':').map((s) => s.trim());
        if (attr && key) el.setAttribute(attr, t(key));
      }
    });
    if (typeof document !== 'undefined') {
      document.documentElement.lang = current;
      const title = t('meta.title');
      if (title !== 'meta.title') document.title = title;
    }
  }

  /** Meilleure langue disponible parmi une liste de préférences (« fr-CA » → « fr »). */
  function match(preferred) {
    for (const tag of preferred || []) {
      if (!tag) continue;
      const lower = String(tag).toLowerCase();
      if (dictionaries[lower]) return lower;
      const base = lower.split('-')[0];
      if (dictionaries[base]) return base;
    }
    return null;
  }

  function readStored() {
    try {
      return localStorage.getItem(STORAGE_KEY);
    } catch {
      return null;
    }
  }

  /**
   * preferred : langue imposée (ex. réglage de l'extension), prioritaire si disponible.
   * stored=false : n'utilise ni ne modifie localStorage (scripts injectés dans des pages tierces).
   */
  let persist = true;
  function init(preferred, { stored = true } = {}) {
    persist = stored;
    const nav = typeof navigator !== 'undefined' ? navigator.languages || [navigator.language] : [];
    current = match([preferred]) || (stored && match([readStored()])) || match(nav) || DEFAULT_LOCALE;
    return current;
  }

  function setLocale(locale) {
    if (!dictionaries[locale] || locale === current) return;
    current = locale;
    if (persist) {
      try {
        localStorage.setItem(STORAGE_KEY, locale);
      } catch {
        /* stockage indisponible : la langue ne sera simplement pas mémorisée */
      }
    }
    listeners.forEach((fn) => fn(current));
  }

  function getLocale() {
    return current;
  }

  function onChange(fn) {
    listeners.push(fn);
  }

  function formatDateTime(value) {
    return new Intl.DateTimeFormat(current, { dateStyle: 'short', timeStyle: 'medium' }).format(new Date(value));
  }

  return { register, locales, t, apply, init, match, setLocale, getLocale, onChange, formatDateTime, DEFAULT_LOCALE, _dictionaries: dictionaries };
});
