#!/usr/bin/env node
/*
 * Construit l'extension navigateur :
 *  - copie dans src/lib les modules qu'elle partage avec l'app web (../web/js), et jsQR et la
 *    police depuis ses propres dépendances ;
 *  - reprend la configuration de déploiement de l'app (../web/js/config.js) dans src/lib/config.js ;
 *  - embarque l'app web complète dans src/app/ (page de l'extension, reliée à elle par
 *    src/app-host.js) : l'extension n'a besoin d'aucune app hébergée ;
 *  - dessine les icônes PNG du logo (deux arches « m » en dégradé turquoise) ;
 *  - produit dist/mymfa-extension.zip (si la commande `zip` est disponible).
 * Ensuite : chrome://extensions → mode développeur → « Charger l'extension non empaquetée » → dossier src/.
 */
import { copyFileSync, cpSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import { PNG } from 'pngjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const EXT = join(ROOT, 'src');
// Les modules partagés ont une seule source, l'app web : l'extension n'en garde que des copies.
const WEB = join(ROOT, '..', 'web');
const MODULES = join(ROOT, 'node_modules');

const COPIES = [
  [join(MODULES, 'jsqr/dist/jsQR.js'), 'lib/jsQR.js'],
  [join(WEB, 'js/otp.js'), 'lib/otp.js'],
  [join(WEB, 'js/store.js'), 'lib/store.js'],
  [join(WEB, 'js/vault.js'), 'lib/vault.js'],
  [join(WEB, 'js/sync.js'), 'lib/sync.js'],
  [join(WEB, 'js/sync2.js'), 'lib/sync2.js'],
  [join(WEB, 'js/heure.js'), 'lib/heure.js'],
  [join(WEB, 'js/drivesync.js'), 'lib/drivesync.js'],
  [join(WEB, 'js/drive.js'), 'lib/drive.js'],
  [join(WEB, 'js/webauthn.js'), 'lib/webauthn.js'],
  [join(WEB, 'js/passgen.js'), 'lib/passgen.js'],
  [join(WEB, 'js/i18n.js'), 'lib/i18n.js'],
  [join(WEB, 'js/locales/fr.js'), 'lib/locales/fr.js'],
  [join(WEB, 'js/locales/en.js'), 'lib/locales/en.js'],
  [join(MODULES, '@fontsource-variable/manrope/files/manrope-latin-wght-normal.woff2'), 'fonts/manrope-latin-wght-normal.woff2'],
  [join(MODULES, '@fontsource-variable/manrope/files/manrope-latin-ext-wght-normal.woff2'), 'fonts/manrope-latin-ext-wght-normal.woff2'],
];

for (const dir of ['lib', 'fonts', 'icons', 'app']) rmSync(join(EXT, dir), { recursive: true, force: true });
for (const [from, to] of COPIES) {
  mkdirSync(dirname(join(EXT, to)), { recursive: true });
  copyFileSync(from, join(EXT, to));
}

// js/config.js s'adresse à `window`, absent du service d'arrière-plan : on n'en garde que les valeurs.
const config = { window: {} };
runInNewContext(readFileSync(join(WEB, 'js/config.js'), 'utf8'), config);
writeFileSync(
  join(EXT, 'lib/config.js'),
  `/* Généré par scripts/build.mjs depuis web/js/config.js. */\nself.MYMFA_CONFIG = ${JSON.stringify(config.window.MYMFA_CONFIG || {}, null, 2)};\n`
);

/* ───── App embarquée ───── */

// L'app telle que la sert web/, plus le script hôte, chargé avant lock.js et app.js qui le lisent.
const APP = join(EXT, 'app');
const HOST_TAG = '<script src="../app-host.js"></script>';
const ANCHOR = '<script src="js/vault.js"></script>';
const page = readFileSync(join(WEB, 'index.html'), 'utf8');
if (!page.includes(ANCHOR)) throw new Error(`web/index.html : ${ANCHOR} introuvable, le script hôte ne saurait où se placer`);
mkdirSync(APP, { recursive: true });
writeFileSync(join(APP, 'index.html'), page.replace(ANCHOR, `${HOST_TAG}\n  ${ANCHOR}`));
cpSync(join(WEB, 'css'), join(APP, 'css'), { recursive: true });
cpSync(join(WEB, 'js'), join(APP, 'js'), { recursive: true });
mkdirSync(join(APP, 'vendor', 'fonts'), { recursive: true });
copyFileSync(join(EXT, 'lib/jsQR.js'), join(APP, 'vendor/jsQR.js'));
for (const font of ['manrope-latin-wght-normal.woff2', 'manrope-latin-ext-wght-normal.woff2']) {
  copyFileSync(join(EXT, 'fonts', font), join(APP, 'vendor/fonts', font));
}

/* ───── Icônes ───── */

// Logo dans un repère 30×22 : deux arches (centres x=8.75 et 20.25, rayon 5.75) et trois jambages, trait de 4.
const ARCHES = [8.75, 20.25];
const RADIUS = 5.75;
const HALF_STROKE = 2;
const LEGS = [3, 14.5, 26];

function distanceToLogo(x, y) {
  let d = Infinity;
  for (const cx of ARCHES) {
    if (y <= 10.5) d = Math.min(d, Math.abs(Math.hypot(x - cx, y - 10.5) - RADIUS));
    else d = Math.min(d, Math.hypot(Math.abs(x - cx) - RADIUS, y - 10.5)); // bouts de l'arche
  }
  for (const lx of LEGS) {
    const cy = Math.min(Math.max(y, 10.5), 19);
    d = Math.min(d, Math.hypot(x - lx, y - cy));
  }
  return d;
}

const mix = (a, b, k) => Math.round(a + (b - a) * k);

function drawIcon(size) {
  const png = new PNG({ width: size, height: size });
  const radius = size * 0.22;
  const scale = (size * 0.72) / 30; // logo sur 72 % de la largeur
  const ox = (size - 30 * scale) / 2;
  const oy = (size - 22 * scale) / 2 + size * 0.02;
  const SS = 4; // suréchantillonnage pour l'anticrénelage
  for (let py = 0; py < size; py++) {
    for (let px = 0; px < size; px++) {
      let bg = 0;
      let fg = 0;
      for (let sy = 0; sy < SS; sy++) {
        for (let sx = 0; sx < SS; sx++) {
          const x = px + (sx + 0.5) / SS;
          const y = py + (sy + 0.5) / SS;
          // carré arrondi
          const qx = Math.max(Math.abs(x - size / 2) - (size / 2 - radius), 0);
          const qy = Math.max(Math.abs(y - size / 2) - (size / 2 - radius), 0);
          if (Math.hypot(qx, qy) > radius) continue;
          bg++;
          if (distanceToLogo((x - ox) / scale, (y - oy) / scale) <= HALF_STROKE) fg++;
        }
      }
      const i = (py * size + px) * 4;
      const coverage = bg / (SS * SS);
      const k = fg / Math.max(bg, 1);
      const g = Math.min(1, Math.max(0, (px + py) / (2 * size))); // dégradé diagonal
      const r = mix(0x8a, 0x2b, g);
      const gg = mix(0xf5, 0xb3, g);
      const b = mix(0xe0, 0xc0, g);
      png.data[i] = mix(0x07, r, k);
      png.data[i + 1] = mix(0x0b, gg, k);
      png.data[i + 2] = mix(0x13, b, k);
      png.data[i + 3] = Math.round(255 * coverage);
    }
  }
  return PNG.sync.write(png);
}

mkdirSync(join(EXT, 'icons'), { recursive: true });
for (const size of [16, 32, 48, 128]) writeFileSync(join(EXT, 'icons', `icon-${size}.png`), drawIcon(size));

/* ───── Archive ───── */

const DIST = join(ROOT, 'dist');
mkdirSync(DIST, { recursive: true });
const zipPath = join(DIST, 'mymfa-extension.zip');
rmSync(zipPath, { force: true });
try {
  execFileSync('zip', ['-qr', zipPath, '.', '-x', '.*'], { cwd: EXT });
  console.log(`Extension construite : src/  ·  archive : dist/mymfa-extension.zip`);
} catch {
  console.log('Extension construite : src/  (commande `zip` absente : archive non générée)');
}
if (!existsSync(join(EXT, 'lib', 'jsQR.js'))) process.exit(1);
