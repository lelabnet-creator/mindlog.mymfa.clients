/*
 * Coffre chiffré dans Google Drive (dossier caché appDataFolder) :
 *  - mymfa-vault.json : la copie de synchronisation, réécrite à chaque synchro (v2) ;
 *  - mymfa-backup-<date>.json : les archives — chacune écrite une fois, jamais modifiée
 *    ensuite (ni la synchro ni rien d'autre n'y touche), restaurables une à une ; seule
 *    la rétention (les plus anciennes au-delà d'un nombre gardé) en supprime.
 *  - Scope drive.appdata : l'app ne voit que ses propres fichiers, rien d'autre du Drive.
 *  - Seul l'enregistrement du coffre (déjà chiffré par le mot de passe maître) est envoyé.
 *  - createClient({ fetch, getToken }) est testable sans navigateur ;
 *    googleTokenProvider() charge Google Identity Services à la première utilisation.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Drive = api;
})(typeof self !== 'undefined' ? self : globalThis, function () {
  'use strict';

  const FILE_NAME = 'mymfa-vault.json';
  // Espace caché réservé à l'application : invisible dans l'interface de Google Drive.
  const FOLDER = 'appDataFolder';
  // Ce que l'on demande à Drive sur le fichier : de quoi l'identifier et le décrire.
  // headRevisionId : la version lue, revérifiée avant d'écrire (synchro v2).
  const FIELDS = 'id,name,size,createdTime,modifiedTime,headRevisionId';
  const SCOPE = 'https://www.googleapis.com/auth/drive.appdata';
  const API = 'https://www.googleapis.com/drive/v3/files';
  const UPLOAD = 'https://www.googleapis.com/upload/drive/v3/files';
  const GIS_SRC = 'https://accounts.google.com/gsi/client';
  const ARCHIVE_PREFIX = 'mymfa-backup-';
  const ARCHIVE_FIELDS = 'id,name,size,createdTime,modifiedTime,appProperties';

  /** Nom d'archive horodaté, triable : mymfa-backup-2026-11-12T08-05-11Z.json */
  function archiveName(date = new Date()) {
    return `${ARCHIVE_PREFIX}${date.toISOString().replace(/\.\d{3}Z$/, 'Z').replace(/:/g, '-')}.json`;
  }

  class DriveError extends Error {
    constructor(code, params) {
      super(code);
      this.name = 'DriveError';
      this.code = code;
      this.params = params || {};
    }
  }

  function createClient({ fetch, getToken }) {
    async function call(url, options = {}) {
      const token = await getToken();
      const res = await fetch(url, { ...options, headers: { ...(options.headers || {}), Authorization: `Bearer ${token}` } });
      if (res.status === 401 || res.status === 403) throw new DriveError('driveAuth');
      if (!res.ok) throw new DriveError('driveHttp', { status: res.status });
      return res;
    }

    /** Dernière sauvegarde : { id, name, size, createdTime, modifiedTime } ou null. */
    async function find() {
      const params = new URLSearchParams({
        spaces: FOLDER,
        q: `name = '${FILE_NAME}' and trashed = false`,
        fields: `files(${FIELDS})`,
        orderBy: 'modifiedTime desc',
        pageSize: '1',
      });
      const data = await (await call(`${API}?${params}`)).json();
      return (data.files && data.files[0]) || null;
    }

    /** Envoie le coffre ; `existing` (résultat de find(), ou null) évite une
     *  relecture quand l'appelant vient de vérifier la version. */
    async function upload(content, existing) {
      if (existing === undefined) existing = await find();
      if (existing) {
        const res = await call(`${UPLOAD}/${existing.id}?uploadType=media&fields=${FIELDS}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: content,
        });
        return res.json();
      }
      const boundary = `mymfa-${Math.random().toString(36).slice(2)}`;
      const metadata = JSON.stringify({ name: FILE_NAME, parents: [FOLDER], mimeType: 'application/json' });
      const body =
        `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n` +
        `--${boundary}\r\nContent-Type: application/json\r\n\r\n${content}\r\n--${boundary}--`;
      const res = await call(`${UPLOAD}?uploadType=multipart&fields=${FIELDS}`, {
        method: 'POST',
        headers: { 'Content-Type': `multipart/related; boundary=${boundary}` },
        body,
      });
      return res.json();
    }

    /** Création multipart d'un nouveau fichier dans appDataFolder. */
    async function create(metadata, content, fields) {
      const boundary = `mymfa-${Math.random().toString(36).slice(2)}`;
      const meta = JSON.stringify({ ...metadata, parents: [FOLDER], mimeType: 'application/json' });
      const body =
        `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${meta}\r\n` +
        `--${boundary}\r\nContent-Type: application/json\r\n\r\n${content}\r\n--${boundary}--`;
      const res = await call(`${UPLOAD}?uploadType=multipart&fields=${fields}`, {
        method: 'POST',
        headers: { 'Content-Type': `multipart/related; boundary=${boundary}` },
        body,
      });
      return res.json();
    }

    /** Archives, la plus récente d'abord : { id, name, size, createdTime, appProperties }. */
    async function listArchives() {
      const params = new URLSearchParams({
        spaces: FOLDER,
        q: `name contains '${ARCHIVE_PREFIX}' and trashed = false`,
        fields: `files(${ARCHIVE_FIELDS})`,
        orderBy: 'createdTime desc',
        pageSize: '200',
      });
      const data = await (await call(`${API}?${params}`)).json();
      return (data.files || []).filter((f) => typeof f.name === 'string' && f.name.startsWith(ARCHIVE_PREFIX));
    }

    /** Nouvelle archive (jamais réécrite) ; `proprietes` : qui l'a faite (appProperties). */
    async function createArchive(content, proprietes = {}, date = new Date()) {
      return create({ name: archiveName(date), appProperties: proprietes }, content, ARCHIVE_FIELDS);
    }

    /** Contenu d'un fichier par son identifiant (une archive). */
    async function read(id) {
      return (await call(`${API}/${encodeURIComponent(id)}?alt=media`)).text();
    }

    async function remove(id) {
      await call(`${API}/${encodeURIComponent(id)}`, { method: 'DELETE' });
    }

    async function download(existing) {
      if (existing === undefined) existing = await find();
      if (!existing) throw new DriveError('driveEmpty');
      const res = await call(`${API}/${existing.id}?alt=media`);
      // file : les métadonnées Drive du fichier lu (nom, taille, dates).
      return { content: await res.text(), modifiedTime: existing.modifiedTime, file: existing };
    }

    return { find, upload, download, listArchives, createArchive, read, remove };
  }

  /* ───── Google Identity Services (navigateur uniquement) ───── */

  let gisLoading = null;

  function loadGis() {
    if (globalThis.google && google.accounts && google.accounts.oauth2) return Promise.resolve();
    if (!gisLoading) {
      gisLoading = new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = GIS_SRC;
        script.async = true;
        script.onload = resolve;
        script.onerror = () => {
          gisLoading = null;
          reject(new DriveError('driveLoad'));
        };
        document.head.append(script);
      });
    }
    return gisLoading;
  }

  /** Fournisseur de jeton OAuth : un jeton en mémoire, redemandé à expiration. */
  function googleTokenProvider(clientId) {
    let token = null;
    let expiresAt = 0;
    let client = null;

    async function getToken() {
      if (token && Date.now() < expiresAt - 60000) return token;
      await loadGis();
      return new Promise((resolve, reject) => {
        if (!client) {
          client = google.accounts.oauth2.initTokenClient({ client_id: clientId, scope: SCOPE, callback: () => {} });
        }
        client.callback = (response) => {
          if (response.error) {
            reject(new DriveError('driveAuth'));
            return;
          }
          token = response.access_token;
          expiresAt = Date.now() + Number(response.expires_in || 3600) * 1000;
          resolve(token);
        };
        client.error_callback = () => reject(new DriveError('driveCancelled'));
        client.requestAccessToken({ prompt: '' });
      });
    }

    function signOut() {
      if (token && globalThis.google) google.accounts.oauth2.revoke(token, () => {});
      token = null;
      expiresAt = 0;
    }

    /** Un jeton valide est-il en mémoire (synchro possible sans fenêtre Google) ? */
    const hasToken = () => Boolean(token && Date.now() < expiresAt - 60000);

    return { getToken, signOut, hasToken };
  }

  return { FILE_NAME, FOLDER, ARCHIVE_PREFIX, archiveName, SCOPE, DriveError, createClient, googleTokenProvider };
});
