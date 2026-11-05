/*
 * Convertit web/js/locales/{fr,en}.js en modules Rust (crates/mymfa-core/src/texts/).
 * Patron du dépôt : web/ est l'unique source des textes, les copies sont générées
 * et non versionnées — comme celles de l'extension (extension/scripts/build.mjs).
 *
 *   node scripts/sync-locales.mjs     (depuis android/)
 */
import { createRequire } from 'node:module';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const webLocales = join(here, '..', '..', 'web', 'js', 'locales');
const outDir = join(here, '..', 'crates', 'mymfa-core', 'src', 'texts');

/** Échappe une chaîne pour un littéral Rust. */
function rustString(text) {
  return `"${String(text)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\r/g, '\\r')
    .replace(/\n/g, '\\n')
    .replace(/\t/g, '\\t')}"`;
}

/** Aplatit l'arbre de textes : feuilles → clés « a.b.c » ; { one, other } → pluriels. */
function flatten(tree, prefix = '', strings = [], plurals = []) {
  const keys = Object.keys(tree).sort();
  for (const key of keys) {
    const value = tree[key];
    const path = prefix ? `${prefix}.${key}` : key;
    if (typeof value === 'string') {
      strings.push([path, value]);
    } else if (value && typeof value === 'object' && !Array.isArray(value)) {
      const sub = Object.keys(value);
      if (sub.length === 2 && sub.includes('one') && sub.includes('other')) {
        plurals.push([path, value.one, value.other]);
      } else {
        flatten(value, path, strings, plurals);
      }
    }
  }
  return { strings, plurals };
}

mkdirSync(outDir, { recursive: true });

for (const locale of ['fr', 'en']) {
  const source = require(join(webLocales, `${locale}.js`));
  const { strings, plurals } = flatten(source);
  const lines = [
    `// GÉNÉRÉ par scripts/sync-locales.mjs — ne pas éditer à la main.`,
    `// Source unique : web/js/locales/${locale}.js (${strings.length} textes, ${plurals.length} pluriels).`,
    '',
    'pub static STRINGS: &[(&str, &str)] = &[',
    ...strings.map(([key, text]) => `    (${rustString(key)}, ${rustString(text)}),`),
    '];',
    '',
    'pub static PLURALS: &[(&str, &str, &str)] = &[',
    ...plurals.map(([key, one, other]) => `    (${rustString(key)}, ${rustString(one)}, ${rustString(other)}),`),
    '];',
    '',
  ];
  writeFileSync(join(outDir, `${locale}.rs`), lines.join('\n'));
  console.log(`${locale}.rs : ${strings.length} textes, ${plurals.length} pluriels`);
}
