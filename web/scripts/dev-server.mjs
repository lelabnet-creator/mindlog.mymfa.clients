#!/usr/bin/env node
/*
 * Serveur de développement myMFA : fichiers statiques + rechargement à chaud.
 *  - CSS modifié  → feuille de style remplacée à chaud, sans recharger la page
 *  - autre fichier → rechargement complet de la page
 * Le navigateur écoute /__reload (Server-Sent Events) via un script injecté
 * dans les pages HTML servies. Aucune dépendance.
 *
 *   PORT=4173 HOST=127.0.0.1 node scripts/dev-server.mjs
 */
import { createServer } from 'node:http';
import { readdirSync, statSync, watch } from 'node:fs';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)));
const PORT = Number(process.env.PORT) || 4173;
const HOST = process.env.HOST || '127.0.0.1';
const RELOAD_PATH = '/__reload';
// L'archive que propose extension.html est construite par le client voisin (`cd ../extension && npm run build`) ;
// en production, l'image la place dans dist/.
const EXTENSION_ZIP_PATH = '/dist/mymfa-extension.zip';
const EXTENSION_ZIP = resolve(ROOT, '..', 'extension', 'dist', 'mymfa-extension.zip');
// Dossiers hors du site, fichiers d'éditeur et fichiers temporaires d'écriture atomique (x.tmp.123.abc, sedXXXXXX).
const IGNORED = /(^|[\\/])(node_modules|\.git|\.dual-graph|\.claude|test|dist)([\\/]|$)|(~|\.sw[px]|\.tmp)$|\.tmp\.\d+\.\w+$|(^|[\\/])sed\w{6}$/;

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.zip': 'application/zip',
};

const CLIENT = `<script>
(() => {
  const source = new EventSource('${RELOAD_PATH}');
  let lost = false;
  source.onerror = () => { lost = true; };
  source.onopen = () => { if (lost) location.reload(); }; // serveur redémarré
  source.addEventListener('reload', () => location.reload());
  source.addEventListener('css', (event) => {
    let swapped = false;
    for (const link of document.querySelectorAll('link[rel="stylesheet"]')) {
      const url = new URL(link.href);
      if (url.origin !== location.origin || url.pathname !== '/' + event.data) continue;
      url.searchParams.set('v', Date.now());
      link.href = url.href;
      swapped = true;
    }
    if (!swapped) location.reload();
  });
})();
</script>`;

const clients = new Set();

function broadcast(event, data = '') {
  for (const res of clients) res.write(`event: ${event}\ndata: ${data}\n\n`);
}

/** Résout une URL vers un fichier sous ROOT ; null si elle tente d'en sortir. */
function resolvePath(urlPath) {
  let pathname;
  try {
    pathname = decodeURIComponent(urlPath.split('?')[0]);
  } catch {
    return null;
  }
  const file = resolve(ROOT, '.' + pathname);
  return file === ROOT || file.startsWith(ROOT + sep) ? file : null;
}

const server = createServer(async (req, res) => {
  if (req.url === RELOAD_PATH) {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-store',
      Connection: 'keep-alive',
    });
    res.write('retry: 500\n\n');
    clients.add(res);
    req.on('close', () => clients.delete(res));
    return;
  }

  let file = req.url.split('?')[0] === EXTENSION_ZIP_PATH ? EXTENSION_ZIP : resolvePath(req.url);
  if (!file) {
    res.writeHead(403).end('Interdit');
    return;
  }
  try {
    if ((await stat(file)).isDirectory()) file = join(file, 'index.html');
    let body = await readFile(file);
    const type = TYPES[extname(file).toLowerCase()] || 'application/octet-stream';
    if (type.startsWith('text/html')) {
      const html = body.toString('utf8');
      body = html.includes('</body>') ? html.replace('</body>', `${CLIENT}\n</body>`) : html + CLIENT;
    }
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' });
    res.end(body);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Introuvable');
  }
});

// Surveillance par dossier (et non `recursive: true`) : sous Linux, le mode
// récursif de Node suit les fichiers par inode et perd ceux remplacés par un
// renommage atomique (vim, JetBrains, outils d'écriture). Un watcher posé sur
// le dossier, lui, voit toujours les fichiers par leur nom.
const watchers = new Map();

function watchTree(dir) {
  if (watchers.has(dir) || IGNORED.test(relative(ROOT, dir))) return;
  let watcher;
  try {
    watcher = watch(dir, (event, filename) => onFsEvent(dir, event, filename));
  } catch {
    return;
  }
  watchers.set(dir, watcher);
  watcher.on('error', () => {
    watcher.close();
    watchers.delete(dir);
  });
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) watchTree(join(dir, entry.name));
  }
}

function onFsEvent(dir, event, filename) {
  if (!filename) return;
  const full = join(dir, filename.toString());
  const rel = relative(ROOT, full);
  if (IGNORED.test(rel)) return;
  if (event === 'rename') {
    try {
      if (statSync(full).isDirectory()) watchTree(full); // nouveau dossier
    } catch {
      if (watchers.has(full)) {
        watchers.get(full).close();
        watchers.delete(full);
      }
      return; // fichier supprimé ou renommé ailleurs : son remplaçant émettra son propre événement
    }
  }
  queueChange(rel);
}

// Une sauvegarde émet souvent plusieurs événements : on regroupe.
let pending = new Set();
let timer = null;
function queueChange(rel) {
  pending.add(rel.split(sep).join('/'));
  clearTimeout(timer);
  timer = setTimeout(() => {
    const files = [...pending];
    pending = new Set();
    if (files.every((f) => f.endsWith('.css'))) {
      files.forEach((f) => broadcast('css', f));
      console.log(`🎨 CSS à chaud : ${files.join(', ')}`);
    } else {
      broadcast('reload');
      console.log(`↻ rechargement : ${files.join(', ')}`);
    }
  }, 80);
}

watchTree(ROOT);

// Garde les connexions SSE ouvertes derrière d'éventuels proxys.
setInterval(() => {
  for (const res of clients) res.write(': ping\n\n');
}, 25_000).unref();

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`Le port ${PORT} est déjà utilisé. Essayez : PORT=5000 npm start`);
    process.exit(1);
  }
  throw err;
});

server.listen(PORT, HOST, () => {
  console.log(`myMFA — http://localhost:${PORT}  (rechargement à chaud actif, Ctrl+C pour arrêter)`);
});
