/*
 * Sauvegarde du coffre chiffré dans Google Drive (dossier caché appDataFolder).
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
  const SCOPE = 'https://www.googleapis.com/auth/drive.appdata';
  const API = 'https://www.googleapis.com/drive/v3/files';
  const UPLOAD = 'https://www.googleapis.com/upload/drive/v3/files';
  const GIS_SRC = 'https://accounts.google.com/gsi/client';

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

    /** Dernière sauvegarde : { id, modifiedTime, size } ou null. */
    async function find() {
      const params = new URLSearchParams({
        spaces: 'appDataFolder',
        q: `name = '${FILE_NAME}' and trashed = false`,
        fields: 'files(id,modifiedTime,size)',
        orderBy: 'modifiedTime desc',
        pageSize: '1',
      });
      const data = await (await call(`${API}?${params}`)).json();
      return (data.files && data.files[0]) || null;
    }

    async function upload(content) {
      const existing = await find();
      if (existing) {
        const res = await call(`${UPLOAD}/${existing.id}?uploadType=media&fields=id,modifiedTime,size`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: content,
        });
        return res.json();
      }
      const boundary = `mymfa-${Math.random().toString(36).slice(2)}`;
      const metadata = JSON.stringify({ name: FILE_NAME, parents: ['appDataFolder'], mimeType: 'application/json' });
      const body =
        `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadata}\r\n` +
        `--${boundary}\r\nContent-Type: application/json\r\n\r\n${content}\r\n--${boundary}--`;
      const res = await call(`${UPLOAD}?uploadType=multipart&fields=id,modifiedTime,size`, {
        method: 'POST',
        headers: { 'Content-Type': `multipart/related; boundary=${boundary}` },
        body,
      });
      return res.json();
    }

    async function download() {
      const existing = await find();
      if (!existing) throw new DriveError('driveEmpty');
      const res = await call(`${API}/${existing.id}?alt=media`);
      return { content: await res.text(), modifiedTime: existing.modifiedTime };
    }

    return { find, upload, download };
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

    return { getToken, signOut };
  }

  return { FILE_NAME, SCOPE, DriveError, createClient, googleTokenProvider };
});
