const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const I18n = require('../js/i18n.js');

const ROOT = path.join(__dirname, '..');
const LOCALES_DIR = path.join(ROOT, 'js/locales');
const locales = Object.fromEntries(
  fs.readdirSync(LOCALES_DIR).filter((f) => f.endsWith('.js'))
    .map((f) => [path.basename(f, '.js'), require(path.join(LOCALES_DIR, f))])
);
for (const [code, dict] of Object.entries(locales)) I18n.register(code, dict);

/** Clés feuilles ; un objet { one, other } (pluriel) compte pour une seule clé. */
function leafKeys(node, prefix = '') {
  return Object.entries(node).flatMap(([k, v]) => {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !('other' in v)) return leafKeys(v, key);
    return [key];
  });
}

test('toutes les langues ont exactement les mêmes clés que le français', () => {
  const ref = new Set(leafKeys(locales.fr));
  for (const [code, dict] of Object.entries(locales)) {
    const keys = new Set(leafKeys(dict));
    assert.deepEqual([...ref].filter((k) => !keys.has(k)), [], `${code} : clés manquantes`);
    assert.deepEqual([...keys].filter((k) => !ref.has(k)), [], `${code} : clés en trop`);
  }
});

test('les paramètres {x} sont identiques d’une langue à l’autre', () => {
  const params = (s) => [...String(s).matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(',');
  const lookup = (dict, key) => key.split('.').reduce((n, p) => n[p], dict);
  for (const key of leafKeys(locales.fr)) {
    const refValue = lookup(locales.fr, key);
    for (const [code, dict] of Object.entries(locales)) {
      const value = lookup(dict, key);
      const flat = (v) => (typeof v === 'object' ? v.other : v);
      assert.equal(params(flat(value)), params(flat(refValue)), `${code}:${key}`);
    }
  }
});

test('chaque clé utilisée par les pages et les scripts de l’app existe', () => {
  const known = new Set(leafKeys(locales.fr));
  const html = ['index.html', 'extension.html'].map((f) => fs.readFileSync(path.join(ROOT, f), 'utf8')).join('\n');
  const js = ['js/app.js', 'js/lock.js', 'js/credentials.js', 'js/dashboard.js']
    .map((f) => fs.readFileSync(path.join(ROOT, f), 'utf8'))
    .join('\n');
  const used = new Set();
  for (const [, key] of html.matchAll(/data-i18n="([^"]+)"/g)) used.add(key);
  for (const [, pairs] of html.matchAll(/data-i18n-attr="([^"]+)"/g)) {
    for (const pair of pairs.split(';')) used.add(pair.split(':')[1].trim());
  }
  for (const [, key] of js.matchAll(/\bt\('([\w.]+)'/g)) used.add(key);
  assert.deepEqual([...used].filter((k) => !known.has(k)), []);
});

test('chaque code d’erreur levé par otp.js / store.js est traduit', () => {
  const known = new Set(leafKeys(locales.fr));
  const src = ['js/otp.js', 'js/store.js', 'js/importers.js', 'js/app.js', 'js/vault.js', 'js/lock.js', 'js/drive.js']
    .map((f) => fs.readFileSync(path.join(ROOT, f), 'utf8'))
    .join('\n');
  const codes = new Set();
  for (const [, code] of src.matchAll(/(?:fail|storeError|importError|VaultError|DriveError|ExtError)\('(\w+)'/g)) codes.add(code);
  for (const [, code] of src.matchAll(/code: '(\w+)'/g)) codes.add(code);
  assert.ok(codes.size > 5);
  assert.deepEqual([...codes].filter((c) => !known.has(`error.${c}`)), []);
});

test('t() : interpolation, pluriels, repli', () => {
  I18n.setLocale('fr');
  assert.equal(I18n.t('list.copy', { name: 'GitHub' }), 'Copier le code de GitHub');
  assert.equal(I18n.t('list.remaining', { count: 1 }), '1 seconde restante');
  assert.equal(I18n.t('list.remaining', { count: 3 }), '3 secondes restantes');
  I18n.setLocale('en');
  assert.equal(I18n.t('list.remaining', { count: 1 }), '1 second left');
  assert.equal(I18n.t('list.remaining', { count: 0 }), '0 seconds left');
  assert.equal(I18n.t('cle.inexistante'), 'cle.inexistante');
});

test('match() : choix de la langue depuis les préférences navigateur', () => {
  assert.equal(I18n.match(['fr-CA', 'en']), 'fr');
  assert.equal(I18n.match(['de-DE', 'en-GB']), 'en');
  assert.equal(I18n.match(['de', 'ja']), null);
});
