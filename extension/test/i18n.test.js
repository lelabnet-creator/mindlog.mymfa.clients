// L'extension n'a pas de dictionnaire à elle : ses textes sont ceux de l'app web (../web/js/locales,
// copiés par scripts/build.mjs). Chaque clé qu'elle emploie doit donc y exister.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const SRC = path.join(ROOT, 'src');
const fr = require(path.join(ROOT, '..', 'web', 'js', 'locales', 'fr.js'));

/** Clés feuilles ; un objet { one, other } (pluriel) compte pour une seule clé. */
function leafKeys(node, prefix = '') {
  return Object.entries(node).flatMap(([k, v]) => {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !('other' in v)) return leafKeys(v, key);
    return [key];
  });
}

const read = (files) => files.map((f) => fs.readFileSync(path.join(SRC, f), 'utf8')).join('\n');

test('chaque clé utilisée par le popup et les scripts de contenu existe', () => {
  const known = new Set(leafKeys(fr));
  const html = read(['popup.html']);
  const js = read(['popup.js', 'content.js', 'passwords.js', 'webauthn.js', 'ui.js']);
  const used = new Set();
  for (const [, key] of html.matchAll(/data-i18n="([^"]+)"/g)) used.add(key);
  for (const [, pairs] of html.matchAll(/data-i18n-attr="([^"]+)"/g)) {
    for (const pair of pairs.split(';')) used.add(pair.split(':')[1].trim());
  }
  for (const [, key] of js.matchAll(/\bt\('([\w.]+)'/g)) used.add(key);
  assert.ok(used.size > 20);
  assert.deepEqual([...used].filter((k) => !known.has(k)), []);
});

test('chaque code d’erreur levé par le service d’arrière-plan est traduit', () => {
  const known = new Set(leafKeys(fr));
  const codes = new Set();
  for (const [, code] of read(['background.js']).matchAll(/ExtError\('(\w+)'/g)) codes.add(code);
  assert.ok(codes.size > 5);
  assert.deepEqual([...codes].filter((c) => !known.has(`error.${c}`)), []);
});
