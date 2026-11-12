/*
 * Service d'arrière-plan de l'extension myMFA.
 *  - Garde une copie des données de l'app (chrome.storage.local), sous la même forme :
 *    coffre chiffré (mymfa.vault.v1) ou données en clair si l'app n'est pas chiffrée.
 *  - La clé de coffre déverrouillée vit dans chrome.storage.session : en mémoire,
 *    inaccessible aux scripts de contenu, effacée à la fermeture du navigateur.
 *  - Seul ce service manipule les secrets. Les scripts de contenu ne reçoivent que
 *    le code du compte correspondant au QR affiché par la page elle-même.
 *  - Synchronisation avec l'app via le pont du script de contenu, uniquement depuis
 *    l'origine configurée (réglage « Adresse de l'app »).
 *  - Synchronisation par la sauvegarde Google Drive de l'app (même fichier chiffré,
 *    dossier caché appDataFolder) : récupérée, fusionnée, renvoyée si elle a changé.
 *  - Synchro v2 (EXT-12) : toutes les fusions (app ↔ extension, Drive) passent par
 *    Sync2.fusion, les écritures du service sont tamponnées (horloge hybride de cet
 *    appareil, persistée dans chrome.storage.local) ; le marqueur v2 voyage avec les
 *    données ; les éléments supprimés (gardés avec leur trace) ne sont jamais servis.
 *  - Mots de passe et passkeys des sites, uniquement dans un coffre chiffré. Un script de
 *    contenu n'obtient que ce qui concerne le site de son onglet (origine donnée par Chrome),
 *    et un mot de passe seulement au moment de le remplir.
 */
importScripts(
  'lib/jsQR.js', 'lib/otp.js', 'lib/store.js', 'lib/vault.js', 'lib/sync.js', 'lib/sync2.js', 'lib/heure.js',
  'lib/config.js', 'lib/drive.js', 'lib/drivesync.js', 'lib/webauthn.js'
);

const VAULT_KEY = Vault.VAULT_KEY;
// Clés de données échangées avec l'app : v1 historiques, plus le marqueur v2 (registre des appareils).
const DATA_KEYS = [...Sync.KEYS, Sync2.SYNC_KEY];
const PAGE_KEYS = [VAULT_KEY, ...DATA_KEYS];
const K = {
  snapshot: 'ext.snapshot',
  settings: 'ext.settings',
  dirty: 'ext.dirty', // l'app n'a peut-être pas encore nos changements
  lastSync: 'ext.lastSync',
  driveLastSync: 'ext.driveLastSync',
  driveFile: 'ext.driveFile', // métadonnées Drive du fichier (nom, taille, dates), pour l'app
  driveError: 'ext.driveError',
  dek: 'ext.dek', // session
  lastUse: 'ext.lastUse', // session
  vaultLocal: 'ext.vaultLocal', // coffre créé ici, pas encore adopté par l'app
  siteIndex: 'ext.siteIndex', // empreintes salées des sites connus, pour proposer de déverrouiller
  pending: 'ext.pending', // session : données à fusionner au prochain déverrouillage
  driveToken: 'ext.driveToken', // session
  captures: 'ext.captures', // session : mots de passe saisis, par onglet, en attente de « Enregistrer »
  temps: 'ext.temps', // identifiant d'appareil, horloge hybride, repère, décalage d'heure (jamais synchronisés)
  syncJournal: 'ext.syncJournal', // journal des synchros Drive, chiffré par la clé du coffre
};
const CAPTURE_TTL = 5 * 60000;
const AUTOLOCK_CHOICES = [1, 5, 15, 60, 0]; // minutes ; 0 = jamais (mêmes choix que l'app et le popup)
const DRIVE_EVERY_CHOICES = [0, 1, 6, 12, 24, 72, 168]; // heures entre deux sauvegardes Drive ; 0 = à la demande
const CLIENT_ID_RE = /^[\w-]+\.apps\.googleusercontent\.com$/;
const MAX_DECODE_BYTES = 10 * 1024 * 1024; // décodage QR : au-delà, ce n'est plus une image à lire
// drive : synchronisation Drive automatique, activée par la première synchronisation manuelle réussie.
const DEFAULT_SETTINGS = {
  detect: true,
  fill: true,
  appUrl: '', // app hébergée à synchroniser en plus de celle de l'extension ; vide = aucune
  theme: 'auto',
  lang: '',
  autoLock: 15,
  drive: false,
  driveEvery: 24, // sauvegarde automatique : toutes les N heures (DRIVE_EVERY_CHOICES)
  driveClientId: '',
  savePasswords: true,
  generate: true, // proposer un mot de passe fort à l'inscription
  passkeys: true,
  neverSave: [], // sites pour lesquels ne jamais proposer d'enregistrer un mot de passe
};
const DEPLOY_CLIENT_ID = (self.MYMFA_CONFIG && self.MYMFA_CONFIG.googleClientId) || '';
const EXTENSION_ORIGIN = new URL(chrome.runtime.getURL('')).origin;
const APP_PAGE = chrome.runtime.getURL('app/index.html'); // l'app embarquée (scripts/build.mjs)

class ExtError extends Error {
  constructor(code, params) {
    super(code);
    this.code = code;
    this.params = params || {};
  }
}

/* ───────────── Stockage ───────────── */

async function getSettings() {
  const { [K.settings]: saved } = await chrome.storage.local.get(K.settings);
  return { ...DEFAULT_SETTINGS, ...(saved || {}) };
}

async function saveSettings(patch) {
  const next = { ...(await getSettings()), ...patch };
  await chrome.storage.local.set({ [K.settings]: next });
  return next;
}

async function getSnapshot() {
  const { [K.snapshot]: snap } = await chrome.storage.local.get(K.snapshot);
  return snap || {};
}

async function getDek() {
  const { [K.dek]: raw } = await chrome.storage.session.get(K.dek);
  if (!raw) return null;
  return crypto.subtle.importKey('raw', Vault.fromB64(raw), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
}

async function setDek(key) {
  if (!key) {
    await chrome.storage.session.remove([K.dek, K.lastUse]);
    return;
  }
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
  await chrome.storage.session.set({ [K.dek]: Vault.toB64(raw), [K.lastUse]: Date.now() });
  raw.fill(0);
}

/* ───────────── Synchro v2 : état de cet appareil ─────────────
 * Le service n'a pas de Web Storage : l'état d'appareil de Sync2.etatPersistant vit dans un
 * cache mémoire recopié dans chrome.storage.local à chaque écriture, rechargé au réveil. */

function pick(map) {
  const out = {};
  for (const key of DATA_KEYS) if (map && map[key] != null) out[key] = map[key];
  return out;
}

function descriptionExtension() {
  const ua = (self.navigator && navigator.userAgent) || '';
  const navigateur = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Chrome\//.test(ua) ? 'Chrome' : '';
  const systeme = /Android/.test(ua) ? 'Android' : /Mac OS X/.test(ua) ? 'macOS' : /Windows/.test(ua) ? 'Windows'
    : /Linux|X11|CrOS/.test(ua) ? 'Linux' : '';
  const nom = [navigateur, systeme].filter(Boolean).join(' · ');
  return { type: 'extension', ...(nom ? { nom } : {}) };
}

let tempsPret = null;
function chargerTemps() {
  if (!tempsPret) {
    tempsPret = chrome.storage.local.get(K.temps).then(({ [K.temps]: sauve }) => {
      const cache = new Map(Object.entries((sauve && sauve.cles) || {}));
      const decalage = sauve && Number.isFinite(sauve.decalageMs) ? sauve.decalageMs : null;
      const horloge = Heure.create({ decalageInitial: decalage });
      const heure = { horloge, decalage };
      const ecrire = () => chrome.storage.local.set({ [K.temps]: { cles: Object.fromEntries(cache), decalageMs: heure.decalage } }).catch(() => {});
      const shim = {
        getItem: (k) => (cache.has(k) ? cache.get(k) : null),
        setItem: (k, v) => {
          cache.set(k, String(v));
          ecrire();
        },
        removeItem: (k) => {
          cache.delete(k);
          ecrire();
        },
      };
      const temps = Sync2.etatPersistant(shim, () => horloge.maintenant(), descriptionExtension());
      return {
        temps,
        maintenant: () => horloge.maintenant(),
        /** Heure des serveurs Google de la réponse à un envoi Drive (SYN-08) : corrige T(), conservée. */
        noterHeure(fichier) {
          const ms = Heure.heureDrive(fichier);
          if (ms === null) return;
          heure.decalage = horloge.recevoirReference(ms).decalageMs;
          ecrire();
        },
      };
    });
  }
  return tempsPret;
}

/** Fusion v2 de deux copies locales (app, en attente, Drive) : l'état de l'appareil avance. */
async function fusionner(a, b) {
  const { temps, maintenant } = await chargerTemps();
  const { donnees } = Sync2.fusion(a || {}, b || {}, temps.etat, maintenant());
  temps.persister();
  return donnees;
}

/** Même contenu (JSON parsé), clés de données seulement. */
const memesDonnees = (a, b) => !Sync2.differentDe(pick(a), pick(b));

/** Une opération à la fois sur les données : lecture, fusion, écriture. */
let chain = Promise.resolve();
function serial(task) {
  const run = chain.then(task, task);
  chain = run.catch(() => {});
  return run;
}

/**
 * État et données lisibles : { status: 'empty'|'plain'|'locked'|'unlocked', map, record, dek }.
 * touch : compte comme une utilisation (repousse le verrouillage automatique) ; pas pour une
 * simple visite de page.
 */
async function readData({ touch = true } = {}) {
  const snap = await getSnapshot();
  const record = Vault.parse(snap[VAULT_KEY]);
  const { temps } = await chargerTemps();
  // Copie v1 (ancienne extension, app d'avant) : migrée à la lecture — rejouable sans effet.
  const migree = (map) => (map[Sync2.SYNC_KEY] ? map : Sync2.migrer(map, 0, temps.appareil));
  if (!record) {
    const brut = pick(snap);
    const map = Object.keys(brut).length ? migree(brut) : brut;
    return { status: Object.keys(map).length ? 'plain' : 'empty', map, record: null, dek: null };
  }
  const dek = await getDek();
  if (!dek) return { status: 'locked', record };
  try {
    const map = migree(await Vault.decryptData(dek, record.data));
    if (touch) await chrome.storage.session.set({ [K.lastUse]: Date.now() });
    return { status: 'unlocked', map, record, dek };
  } catch {
    await setDek(null);
    return { status: 'locked', record };
  }
}

async function writeData(map, ctx) {
  const snap = {};
  if (ctx.record) {
    // Enveloppe v2 dès que les données portent le marqueur : un client d'avant refuse d'écrire.
    const v = map[Sync2.SYNC_KEY] ? 2 : ctx.record.v;
    snap[VAULT_KEY] = JSON.stringify({ ...ctx.record, v, data: await Vault.encryptData(ctx.dek, map) });
  } else {
    Object.assign(snap, pick(map));
  }
  await chrome.storage.local.set({ [K.snapshot]: snap });
  await updateSiteIndex(map);
}

function mapStorage(map) {
  return {
    map,
    getItem: (key) => (key in map ? map[key] : null),
    setItem: (key, value) => {
      map[key] = String(value);
    },
    removeItem: (key) => {
      delete map[key];
    },
  };
}

/** Fusionne d'éventuelles données en attente (voir handleSync) dès qu'elles sont lisibles. */
async function applyPending(ctx) {
  const { [K.pending]: pending } = await chrome.storage.session.get(K.pending);
  if (!pending || ctx.status === 'locked') return ctx;
  const map = await fusionner(ctx.map || {}, pending);
  await writeData(map, ctx);
  await chrome.storage.session.remove(K.pending);
  await chrome.storage.local.set({ [K.dirty]: true });
  return { ...ctx, map };
}

/**
 * Modifie les données via un Store, puis enregistre et pousse vers l'app.
 * secure : l'opération touche des mots de passe ou des passkeys, qui exigent un coffre chiffré.
 */
function mutate(fn, { secure = false } = {}) {
  return serial(async () => {
    let ctx = await readData();
    if (ctx.status === 'locked') throw new ExtError('locked');
    if (secure && !ctx.record) throw new ExtError('credentialsNeedVault');
    ctx = await applyPending(ctx);
    const storage = mapStorage({ ...(ctx.map || {}) });
    const { temps } = await chargerTemps();
    const result = fn(Store.createStore(storage, temps)); // écritures tamponnées (v2)
    await writeData(storage.map, ctx);
    await chrome.storage.local.set({ [K.dirty]: true });
    pushToApp();
    autoDrive();
    return result;
  });
}

/** Comptes vivants : un élément supprimé reste dans la copie (avec sa trace) pour propager
 *  la suppression, mais n'est jamais servi. */
function accountsOf(map) {
  return listOf(map, Store.ACCOUNTS_KEY);
}

/* ───────────── Codes ───────────── */

async function codeFor(account, now = Date.now()) {
  return account.type === 'hotp'
    ? OTP.hotp(account.secret, account.counter, account)
    : OTP.totp(account.secret, { ...account, timestamp: now });
}

/** Résumé sans secret, pour un script de contenu (carte QR : la page a déjà affiché le secret elle-même). */
async function publicSummary(account) {
  const now = Date.now();
  return {
    id: account.id,
    issuer: account.issuer,
    account: account.account,
    tag: account.tag,
    type: account.type,
    digits: account.digits,
    period: account.period,
    code: await codeFor(account, now),
    remaining: account.type === 'hotp' ? null : OTP.remainingSeconds(account.period, now),
  };
}

/** Méta sans le code : il ne part au script de contenu qu'à la demande, derrière un vrai clic. */
async function publicMeta(account, now = Date.now()) {
  return {
    id: account.id,
    issuer: account.issuer,
    account: account.account,
    tag: account.tag,
    type: account.type,
    digits: account.digits,
    period: account.period,
    remaining: account.type === 'hotp' ? null : OTP.remainingSeconds(account.period, now),
  };
}

function errorPayload(err) {
  return { error: { code: (err && err.code) || 'generic', params: (err && err.params) || { message: String(err && err.message) } } };
}

async function lookup(uri) {
  let parsed;
  try {
    parsed = OTP.parseOtpauthUri(uri);
  } catch (err) {
    return errorPayload(err);
  }
  const ctx = await readData();
  const label = { issuer: parsed.issuer, account: parsed.account, type: parsed.type };
  if (ctx.status === 'locked') return { status: 'locked', parsed: label };
  const accounts = accountsOf(ctx.map);
  const match = accounts.find((a) => OTP.normalizeSecret(a.secret) === parsed.secret);
  const tags = [...new Set(accounts.map((a) => a.tag).filter(Boolean))].sort();
  return { status: ctx.status, parsed: label, known: match ? await publicSummary(match) : null, tags };
}

/* ───────────── Décodage de QR ───────────── */

async function decodeBlob(blob) {
  const bitmap = await createImageBitmap(blob);
  const longest = Math.max(bitmap.width, bitmap.height);
  const targets = [Math.min(longest, 1600), 800, 400].filter((s, i, arr) => s <= longest && arr.indexOf(s) === i);
  for (const target of targets) {
    const scale = target / longest;
    const width = Math.max(1, Math.round(bitmap.width * scale));
    const height = Math.max(1, Math.round(bitmap.height * scale));
    const canvas = new OffscreenCanvas(width, height);
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    ctx.fillStyle = '#fff';
    ctx.fillRect(0, 0, width, height);
    ctx.drawImage(bitmap, 0, 0, width, height);
    const result = jsQR(ctx.getImageData(0, 0, width, height).data, width, height, { inversionAttempts: 'attemptBoth' });
    if (result && result.data) return result.data;
  }
  return null;
}

async function scanTab(windowId) {
  const dataUrl = await chrome.tabs.captureVisibleTab(windowId, { format: 'png' });
  const text = await decodeBlob(await (await fetch(dataUrl)).blob());
  if (!text) return { found: false };
  if (!/^\s*otpauth:/i.test(text)) return { found: false, notOtp: true };
  return { found: true, uri: text.trim(), lookup: await lookup(text.trim()) };
}

/* ───────────── Synchronisation avec l'app ───────────── */

/** Origine de l'app hébergée à synchroniser, si un réglage en donne une. */
async function appOrigin() {
  const { appUrl } = await getSettings();
  if (!appUrl) return null;
  try {
    return new URL(appUrl).origin;
  } catch {
    return null;
  }
}

/** Message aux pages de l'extension (l'app embarquée, le popup), sans réponse attendue. */
function notifyPages(type) {
  chrome.runtime.sendMessage({ type }).catch(() => {});
}

/** Demande aux onglets de l'app (embarquée, et hébergée s'il y en a une) de se synchroniser. */
async function pushToApp() {
  const origin = await appOrigin();
  const tabs = await chrome.tabs.query({});
  // Onglets de l'app embarquée : leur adresse n'est visible que par les contextes de l'extension.
  const own = (await chrome.runtime.getContexts({ contextTypes: ['TAB'] })).filter((c) => c.documentUrl && c.documentUrl.startsWith(APP_PAGE));
  const hosted = tabs.filter((tab) => {
    try {
      return origin && tab.url && new URL(tab.url).origin === origin;
    } catch {
      return false;
    }
  });
  notifyPages('mymfa:push');
  await Promise.all(hosted.map((tab) => chrome.tabs.sendMessage(tab.id, { type: 'mymfa:push' }).catch(() => {})));
  return own.length + hosted.length;
}

async function stashPending(map) {
  if (map && Object.keys(pick(map)).length) await chrome.storage.session.set({ [K.pending]: pick(map) });
}

/**
 * Fusion d'une copie distante (l'app, ou sa sauvegarde Google Drive) avec celle de l'extension.
 * Le mode (clair / chiffré) suit la copie distante ; les données sont fusionnées quand les deux
 * côtés sont lisibles, sinon l'extension adopte la copie distante et garde ses propres ajouts en
 * attente jusqu'au prochain déverrouillage.
 * dirty : la copie distante n'a peut-être pas nos changements ; verrouillé, on demande alors le
 * déverrouillage plutôt que d'adopter une copie qui les perdrait.
 * Réponse : { snap, writeBack } (nouvelle copie de l'extension ; writeBack = la copie distante doit
 * la recevoir), ou { needsUnlock }.
 */
async function reconcile(page, dirty) {
  const ext = await getSnapshot();
  const pageRecord = Vault.parse(page[VAULT_KEY]);
  const extRecord = Vault.parse(ext[VAULT_KEY]);
  const finish = (snap, writeBack) => ({ snap, writeBack });

  if (!pageRecord && !extRecord) {
    const merged = await fusionner(pick(page), pick(ext));
    return finish(merged, !memesDonnees(merged, page));
  }

  if (pageRecord && !extRecord) {
    // L'app vient d'être chiffrée : on adopte son coffre ; nos ajouts attendent le déverrouillage.
    if (dirty) await stashPending(pick(ext));
    await setDek(null);
    return finish({ [VAULT_KEY]: page[VAULT_KEY] }, false);
  }

  const dek = await getDek();

  if (!pageRecord && extRecord) {
    // Chiffrement désactivé dans l'app… ou coffre créé ici, que l'app n'a pas encore.
    const { [K.vaultLocal]: vaultLocal } = await chrome.storage.local.get(K.vaultLocal);
    if (dek) {
      try {
        const merged = await fusionner(pick(page), await Vault.decryptData(dek, extRecord.data));
        if (vaultLocal || Sync.hasCredentials(merged)) {
          // Jamais de retour au clair avec des mots de passe ou des passkeys : l'app reçoit le coffre,
          // ses données en clair y sont fusionnées.
          const record = { ...extRecord, v: 2, data: await Vault.encryptData(dek, merged) };
          return finish({ [VAULT_KEY]: JSON.stringify(record) }, true);
        }
        await setDek(null);
        return finish(merged, !memesDonnees(merged, page));
      } catch {
        /* clé périmée : traité comme verrouillé */
      }
    }
    if (dirty || vaultLocal) return { needsUnlock: true };
    await setDek(null);
    return finish(pick(page), false);
  }

  // Les deux côtés chiffrés.
  if (dek) {
    try {
      const pageMap = await Vault.decryptData(dek, pageRecord.data);
      let extMap = {};
      try {
        extMap = await Vault.decryptData(dek, extRecord.data);
      } catch {
        /* copie locale illisible : seule celle de l'app compte */
      }
      const merged = await fusionner(pageMap, extMap);
      if (memesDonnees(merged, pageMap)) return finish({ [VAULT_KEY]: page[VAULT_KEY] }, false);
      // Enveloppes de l'app (mot de passe, passkeys à jour), données fusionnées.
      const record = { ...pageRecord, v: 2, data: await Vault.encryptData(dek, merged) };
      return finish({ [VAULT_KEY]: JSON.stringify(record) }, true);
    } catch {
      // Nouvelle clé de coffre dans l'app (chiffrement réactivé) : on adopte, nos ajouts en attente.
      try {
        if (dirty) await stashPending(await Vault.decryptData(dek, extRecord.data));
      } catch {
        /* rien à récupérer */
      }
      await setDek(null);
      return finish({ [VAULT_KEY]: page[VAULT_KEY] }, false);
    }
  }
  if (dirty && page[VAULT_KEY] !== ext[VAULT_KEY]) return { needsUnlock: true };
  return finish({ [VAULT_KEY]: page[VAULT_KEY] }, false);
}

/** Les données ont-elles changé ? Un même contenu simplement rechiffré ne compte pas. */
async function dataChanged(before, after) {
  if (PAGE_KEYS.every((key) => (before[key] ?? null) === (after[key] ?? null))) return false;
  const a = Vault.parse(before[VAULT_KEY]);
  const b = Vault.parse(after[VAULT_KEY]);
  const dek = a && b ? await getDek() : null;
  if (!dek) return true;
  try {
    return !memesDonnees(await Vault.decryptData(dek, a.data), await Vault.decryptData(dek, b.data));
  } catch {
    return true;
  }
}

/** Synchronisation avec un onglet de l'app. Réponse : { write } = valeurs à écrire dans la page (null = supprimer), ou { needsUnlock }. */
function handleSync(page) {
  return serial(async () => {
    const before = await getSnapshot();
    const { [K.dirty]: dirty } = await chrome.storage.local.get(K.dirty);
    const res = await reconcile(page, Boolean(dirty));
    if (res.needsUnlock) return res;
    await chrome.storage.local.set({ [K.snapshot]: res.snap, [K.dirty]: false, [K.lastSync]: new Date().toISOString() });
    // L'app a désormais un coffre (le sien ou le nôtre) : il n'est plus « local ».
    if (Vault.parse(page[VAULT_KEY]) || res.writeBack) await chrome.storage.local.remove(K.vaultLocal);
    if (await dataChanged(before, res.snap)) {
      autoDrive();
      refreshIndex();
    }
    if (!res.writeBack) return { write: null };
    return { write: Object.fromEntries(PAGE_KEYS.map((key) => [key, res.snap[key] != null ? res.snap[key] : null])) };
  });
}

/* ───────────── Synchronisation par Google Drive ───────────── */

const GOOGLE_AUTH = 'https://accounts.google.com/o/oauth2/v2/auth';

async function driveClientId() {
  return DEPLOY_CLIENT_ID || (await getSettings()).driveClientId || '';
}

/**
 * Jeton OAuth Google (flux implicite par chrome.identity), gardé en session.
 * Même identifiant client « Application Web » que l'app ; l'URI de redirection de
 * l'extension (chrome.identity.getRedirectURL()) doit y être autorisée.
 */
async function driveToken(interactive, requestedClientId) {
  const { [K.driveToken]: saved } = await chrome.storage.session.get(K.driveToken);
  if (saved && Date.now() < saved.expiresAt - 60000) return saved.token;
  // L'app embarquée demande pour l'identifiant qu'elle affiche (collé dans ses réglages, peut-être).
  const clientId = requestedClientId || (await driveClientId());
  if (!clientId) throw new ExtError('driveNotConfigured');
  const url = new URL(GOOGLE_AUTH);
  url.search = new URLSearchParams({
    client_id: clientId,
    response_type: 'token',
    redirect_uri: chrome.identity.getRedirectURL(),
    scope: Drive.SCOPE,
    ...(interactive ? {} : { prompt: 'none' }),
  });
  let redirect;
  try {
    redirect = await chrome.identity.launchWebAuthFlow({ url: url.href, interactive });
  } catch {
    throw new ExtError(interactive ? 'driveCancelled' : 'driveAuth');
  }
  const params = new URLSearchParams(new URL(redirect).hash.slice(1));
  const token = params.get('access_token');
  if (!token) throw new ExtError('driveAuth');
  const expiresAt = Date.now() + Number(params.get('expires_in') || 3600) * 1000;
  await chrome.storage.session.set({ [K.driveToken]: { token, expiresAt } });
  return token;
}

/* Journal des synchros Drive de l'extension : même forme et même AAD que celui de l'app
 * (js/lock.js), chiffré par la clé du coffre, jamais synchronisé, 200 cycles. */
const AAD_JOURNAL = 'mymfa:sync:journal:v1';
const JOURNAL_MAX = 200;

async function lireJournal() {
  const dek = await getDek();
  if (!dek) return [];
  const { [K.syncJournal]: enveloppe } = await chrome.storage.local.get(K.syncJournal);
  if (!enveloppe || !enveloppe.data) return [];
  try {
    const contenu = await Vault.decryptJson(dek, enveloppe.data, AAD_JOURNAL);
    return Array.isArray(contenu.entrees) ? contenu.entrees : [];
  } catch {
    return []; // autre coffre : journal illisible, repart de zéro
  }
}

async function ajouterJournal(entree) {
  const dek = await getDek();
  if (!dek) return;
  const entrees = [entree, ...(await lireJournal())].slice(0, JOURNAL_MAX);
  await chrome.storage.local.set({ [K.syncJournal]: { v: 1, data: await Vault.encryptJson(dek, { entrees }, AAD_JOURNAL) } });
}

const totalChangements = (t) => (t ? t.ajout + t.modification + t.suppression : 0);

/**
 * Synchro avec la copie Drive. Coffre ouvert : le cycle v2 commun (js/drivesync.js) —
 * lecture, fusion champ par champ, revérification de la version, envoi, journal.
 * Verrouillé : rien (needsUnlock). Extension en clair : la copie Drive (toujours chiffrée)
 * est adoptée comme le coffre de l'app, nos ajouts attendent le déverrouillage ; Drive vide
 * et extension en clair → driveEmpty (jamais de clair sur Drive).
 */
async function driveExchange(client) {
  const ctx = await serial(() => readData({ touch: false }));
  if (ctx.status === 'locked') return { needsUnlock: true };

  if (ctx.status === 'unlocked') {
    const { temps, maintenant, noterHeure } = await chargerTemps();
    const coffre = {
      donnees: async () => {
        const c = await serial(() => readData({ touch: false }));
        if (c.status !== 'unlocked') throw new ExtError('locked');
        return c.map;
      },
      dechiffrerAutre: async (record) => {
        const dek = await getDek();
        if (!dek) throw new ExtError('locked');
        return Vault.decryptData(dek, record.data);
      },
      remplacerDonnees: (map, avant) =>
        serial(async () => {
          const c = await readData({ touch: false });
          if (c.status !== 'unlocked') throw new ExtError('locked');
          // Écriture locale faite pendant l'échange avec Drive : refusionnée, rien de perdu.
          const final = avant && !memesDonnees(c.map, avant) ? await fusionner(c.map, map) : map;
          await writeData(final, c);
          await chrome.storage.local.set({ [K.dirty]: true });
        }),
      exporter: async () => (await getSnapshot())[VAULT_KEY],
      ajouterJournal,
    };
    const entree = await DriveSync.creer({ client, coffre, temps, maintenant, source: 'extension', surHeure: noterHeure }).cycle();
    const recus = totalChangements(entree.totaux && entree.totaux.recus);
    if (recus) {
      pushToApp();
      refreshIndex();
    }
    return { ...entree, changed: recus > 0, uploaded: entree.resultat === 'envoye' || entree.resultat === 'premier' };
  }

  // Extension sans coffre : adopter celui de Drive (comme celui de l'app).
  const fichier = await client.find();
  if (!fichier) throw new ExtError('driveEmpty');
  const backup = await client.download(fichier);
  if (!Vault.parse(backup.content)) throw new ExtError('invalidBackup');
  const res = await serial(async () => {
    const merged = await reconcile({ [VAULT_KEY]: backup.content }, true);
    if (merged.needsUnlock) return merged;
    await chrome.storage.local.set({ [K.snapshot]: merged.snap, [K.dirty]: true });
    return { changed: true };
  });
  if (res.needsUnlock) return res;
  pushToApp();
  refreshIndex();
  return { changed: true, uploaded: false, fichier };
}

let driveRun = null;

/** Une synchronisation Drive à la fois. Réponse : { changed, uploaded, status } ou { needsUnlock, status }. */
function syncDrive(interactive, options) {
  if (!driveRun) driveRun = runDriveSync(interactive, options).finally(() => (driveRun = null));
  return driveRun;
}

/**
 * Archive (sauvegarde figée, mymfa-backup-<date>.json) à côté de la copie de synchro : due
 * selon la politique automatique (toutes les N heures ; à la demande seulement : une par
 * jour), ou forcée par « Sauvegarder maintenant ». Jamais de clair : sans coffre, rien.
 */
async function archiverDrive(client, { force = false } = {}) {
  const { temps, maintenant } = await chargerTemps();
  const { driveEvery } = await getSettings();
  return DriveSync.archiver({
    client,
    coffre: { exporter: async () => (await getSnapshot())[VAULT_KEY], ajouterJournal },
    appareil: temps.appareil,
    source: 'extension',
    force,
    intervalleMs: (driveEvery || 24) * 3600000,
    maintenant,
  });
}

async function runDriveSync(interactive, { archiver = false } = {}) {
  const client = Drive.createClient({ fetch: (...args) => fetch(...args), getToken: () => driveToken(interactive) });
  try {
    const res = await driveExchange(client);
    if (!res.needsUnlock) {
      try {
        res.archive = (await archiverDrive(client, { force: archiver })).archive;
      } catch (err) {
        if (archiver) throw err; // demandée : l'échec se voit ; automatique : la synchro suffit
      }
    }
    const fichier = res.fichier || null;
    await chrome.storage.local.set(
      res.needsUnlock
        ? { [K.driveError]: 'locked' }
        : { [K.driveError]: null, [K.driveLastSync]: new Date().toISOString(), ...(fichier ? { [K.driveFile]: fichier } : {}) }
    );
    if (interactive) await saveSettings({ drive: true });
    return res;
  } catch (err) {
    if (err.code === 'driveAuth') await chrome.storage.session.remove(K.driveToken);
    await chrome.storage.local.set({ [K.driveError]: err.code || 'generic' });
    throw err;
  }
}

/** Prochaine sauvegarde automatique (ISO), ou null : Drive pas encore relié, ou sauvegarde à la demande. */
async function nextDriveBackup() {
  const { drive, driveEvery } = await getSettings();
  if (!drive || !driveEvery) return null;
  const { [K.driveLastSync]: last } = await chrome.storage.local.get(K.driveLastSync);
  return new Date((last ? Date.parse(last) : 0) + driveEvery * 3600000).toISOString();
}

/**
 * Sauvegarde Drive silencieuse (sans fenêtre Google), quand elle est due selon la politique choisie
 * (toutes les N heures). Vérifiée par l'alarme et après chaque modification.
 */
async function autoDrive() {
  const next = await nextDriveBackup();
  if (!next || Date.parse(next) > Date.now()) return;
  // Verrouillé, on ne pourrait rien fusionner : inutile de solliciter Drive.
  if (Vault.parse((await getSnapshot())[VAULT_KEY]) && !(await getDek())) return;
  syncDrive(false).catch(() => {});
}

async function disconnectDrive() {
  const { [K.driveToken]: saved } = await chrome.storage.session.get(K.driveToken);
  await chrome.storage.session.remove(K.driveToken);
  await chrome.storage.local.remove([K.driveError, K.driveLastSync, K.driveFile]);
  await saveSettings({ drive: false });
  if (saved) fetch(`https://oauth2.googleapis.com/revoke?token=${encodeURIComponent(saved.token)}`, { method: 'POST' }).catch(() => {});
}

/* ───────────── Sites ───────────── */

function listOf(map, key) {
  try {
    const list = JSON.parse((map || {})[key] || '[]');
    return Array.isArray(list) ? list.filter((item) => item && Sync2.estVivant(item)) : [];
  } catch {
    return [];
  }
}

const hostOf = (origin) => new URL(origin).hostname.replace(/^www\./, '');

const { siteOf, accountMatchesHost } = Store;

/** Origine de l'onglet qui demande, donnée par Chrome et jamais par la page ; cadre principal seulement. */
function senderOrigin(sender) {
  if (!sender.tab || sender.frameId) throw new ExtError('forbidden');
  const origin = sender.origin || new URL(sender.url).origin;
  if (!/^https?:\/\//.test(origin)) throw new ExtError('forbidden');
  return origin;
}

/** 2 : même origine ; 1 : même site, sans redescendre de https à http ; 0 : rien à voir. */
function loginMatch(login, origin) {
  if (login.origin === origin) return 2;
  try {
    const saved = new URL(login.origin);
    const page = new URL(origin);
    if (saved.protocol === 'https:' && page.protocol !== 'https:') return 0;
    return siteOf(saved.hostname) === siteOf(page.hostname) ? 1 : 0;
  } catch {
    return 0;
  }
}

function loginsFor(map, origin) {
  return listOf(map, Store.LOGINS_KEY)
    .map((login) => [login, loginMatch(login, origin)])
    .filter(([, score]) => score)
    .sort((x, y) => y[1] - x[1])
    .map(([login]) => login);
}

/* Index des sites connus : empreintes salées, en clair, pour proposer de déverrouiller sur les bons
   sites quand le coffre est fermé. Il ne dit rien des comptes eux-mêmes. */

async function digest(text) {
  const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  return Array.from(bytes.slice(0, 12), (b) => b.toString(16).padStart(2, '0')).join('');
}

async function updateSiteIndex(map) {
  const { [K.siteIndex]: index } = await chrome.storage.local.get(K.siteIndex);
  const salt = (index && index.salt) || Vault.toB64(crypto.getRandomValues(new Uint8Array(16)));
  const hashAll = (values) => Promise.all([...new Set(values)].map((value) => digest(`${salt}:${value}`)));
  await chrome.storage.local.set({
    [K.siteIndex]: {
      salt,
      logins: await hashAll(listOf(map, Store.LOGINS_KEY).map((l) => siteOf(new URL(l.origin).hostname))),
      rps: await hashAll(listOf(map, Store.PASSKEYS_KEY).map((p) => p.rpId)),
      otp: await hashAll(accountsOf(map).flatMap(Store.accountKeys)), // mêmes clés que accountMatchesHost
    },
  });
}

async function indexHas(kind, values) {
  const { [K.siteIndex]: index } = await chrome.storage.local.get(K.siteIndex);
  if (!index || !index[kind]) return false;
  for (const value of [].concat(values)) if (index[kind].includes(await digest(`${index.salt}:${value}`))) return true;
  return false;
}

/** Après une synchronisation ou un déverrouillage : index à jour si les données sont lisibles. */
async function refreshIndex() {
  const ctx = await readData({ touch: false });
  if (ctx.map) await updateSiteIndex(ctx.map);
}

/** Prévient les onglets ouverts (déverrouillage, enregistrement) : leurs toasts se mettent à jour. */
async function broadcast(message) {
  const tabs = await chrome.tabs.query({});
  await Promise.all(tabs.map((tab) => chrome.tabs.sendMessage(tab.id, message).catch(() => {})));
}

/* ───────────── Mots de passe ───────────── */

async function getCaptures() {
  const { [K.captures]: captures } = await chrome.storage.session.get(K.captures);
  const now = Date.now();
  return Object.fromEntries(Object.entries(captures || {}).filter(([, c]) => now - c.at < CAPTURE_TTL));
}

async function setCapture(tabId, capture) {
  const captures = await getCaptures();
  if (capture) captures[tabId] = capture;
  else delete captures[tabId];
  await chrome.storage.session.set({ [K.captures]: captures });
}

/** Que faire de ce mot de passe saisi : 'save' (nouveau), 'update' (a changé) ou 'same' (déjà connu). */
async function captureAction(capture) {
  const ctx = await readData({ touch: false });
  if (ctx.status !== 'unlocked') return { status: ctx.status, action: 'save' };
  const candidates = loginsFor(ctx.map, capture.origin).filter((l) => (l.username || '') === capture.username);
  if (candidates.some((l) => l.password === capture.password)) return { status: ctx.status, action: 'same' };
  const exact = candidates.find((l) => l.origin === capture.origin);
  return { status: ctx.status, action: exact ? 'update' : 'save' };
}

function pickFields(patch, fields) {
  const out = {};
  for (const field of fields) if (patch && field in patch) out[field] = patch[field];
  return out;
}

/** Mot de passe rempli ou copié : « Récemment utilisés » dans l'app (sans attendre la réponse). */
function touchLogin(id) {
  mutate((store) => store.touchLogin(id), { secure: true }).catch(() => {});
}

/** Code 2FA affiché ou copié, passkey utilisée : dernier usage (tri du popup), sans attendre. */
function touchAccount(id) {
  mutate((store) => store.touchAccount(id)).catch(() => {});
}

function touchPasskey(id) {
  mutate((store) => store.touchPasskey(id), { secure: true }).catch(() => {});
}

function saveCapture(capture) {
  return mutate((store) => {
    const existing = store.findLogin(capture.origin, capture.username);
    if (existing) store.updateLogin(existing.id, { password: capture.password });
    else store.addLogin({ origin: capture.origin, username: capture.username, password: capture.password }, 'extension');
  }, { secure: true });
}

/** Enregistrements demandés pendant que le coffre était fermé (ou absent) : faits dès qu'il s'ouvre. */
async function completeRequests() {
  const captures = await getCaptures();
  for (const [tabId, capture] of Object.entries(captures)) {
    if (!capture.requested) continue;
    try {
      await saveCapture(capture);
      delete captures[tabId];
      chrome.tabs.sendMessage(Number(tabId), { type: 'mymfa:loginSaved' }).catch(() => {});
    } catch {
      /* reste en attente */
    }
  }
  await chrome.storage.session.set({ [K.captures]: captures });
}

async function afterUnlock() {
  await completeRequests();
  await refreshIndex();
  pushToApp();
  autoDrive();
  broadcast({ type: 'mymfa:state' });
}

/* ───────────── Passkeys des sites ───────────── */

function rpIdFor(origin, requested) {
  try {
    return Authn.checkRpId(origin, requested);
  } catch {
    return null; // demande inhabituelle : laissée au navigateur
  }
}

async function webauthnCreate({ options, confirmed }, sender) {
  const origin = senderOrigin(sender);
  if (!(await getSettings()).passkeys || !options) return { fallback: true };
  const rpId = rpIdFor(origin, options.rpId);
  const params = options.pubKeyCredParams || [];
  if (!rpId || (params.length && !params.some((p) => p.alg === Authn.ES256))) return { fallback: true };
  const ctx = await readData({ touch: Boolean(confirmed) });
  if (!confirmed) {
    return { ask: { rpId, rpName: options.rpName || rpId, userName: (options.user && (options.user.name || options.user.displayName)) || '', status: ctx.status } };
  }
  if (ctx.status === 'locked') throw new ExtError('locked');
  if (!ctx.record) throw new ExtError('credentialsNeedVault');
  const known = listOf(ctx.map, Store.PASSKEYS_KEY).filter((p) => p.rpId === rpId).map((p) => p.credentialId);
  const { passkey, response } = await Authn.create({ ...options, origin, rpId }, known);
  await mutate((store) => store.addPasskey(passkey, 'extension'), { secure: true });
  return { credential: response };
}

async function webauthnGet({ options, passkeyId }, sender) {
  const origin = senderOrigin(sender);
  if (!(await getSettings()).passkeys || !options) return { fallback: true };
  const rpId = rpIdFor(origin, options.rpId);
  if (!rpId) return { fallback: true };
  const ctx = await readData({ touch: Boolean(passkeyId) });
  if (ctx.status === 'locked') return (await indexHas('rps', rpId)) ? { offer: { status: 'locked', rpId, passkeys: [] } } : { fallback: true };
  if (ctx.status !== 'unlocked') return { fallback: true };
  const usable = Authn.usable(listOf(ctx.map, Store.PASSKEYS_KEY), rpId, options.allowCredentials);
  if (!usable.length) return { fallback: true };
  if (!passkeyId) {
    return {
      offer: {
        status: 'unlocked',
        rpId,
        passkeys: usable.map((p) => ({ id: p.id, userName: p.userName, userDisplayName: p.userDisplayName, rpName: p.rpName })),
      },
    };
  }
  const passkey = usable.find((p) => p.id === passkeyId);
  if (!passkey) throw new ExtError('forbidden');
  touchPasskey(passkey.id);
  return { credential: await Authn.get({ origin, rpId, challenge: options.challenge }, passkey) };
}

/* ───────────── Coffre créé dans l'extension ───────────── */

/** Premier mot de passe maître choisi ici : l'app recevra ce coffre à la prochaine synchronisation. */
async function createVault(password) {
  await serial(async () => {
    const ctx = await readData();
    if (ctx.record) throw new ExtError('alreadyEncrypted');
    // Données migrées (readData) : marqueur v2 présent, enveloppe v2.
    const { record, dek } = await Vault.create(password, pick(ctx.map || {}));
    await chrome.storage.local.set({ [K.snapshot]: { [VAULT_KEY]: JSON.stringify(record) }, [K.vaultLocal]: true, [K.dirty]: true });
    await setDek(dek);
  });
  await afterUnlock();
}

/* ───────────── Verrouillage ───────────── */

/** Verrouillage demandé (popup, app embarquée, délai écoulé) : l'app embarquée suit, les toasts aussi. */
async function lockAll() {
  await setDek(null);
  notifyPages('mymfa:lock');
  broadcast({ type: 'mymfa:state' });
}

/** Clé du coffre confiée par l'app embarquée, qui vient de le déverrouiller. Rien si c'est un autre coffre. */
async function unlockWithKey(raw) {
  const key = await crypto.subtle.importKey('raw', Vault.fromB64(raw), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
  const unlocked = await serial(async () => {
    const record = Vault.parse((await getSnapshot())[VAULT_KEY]);
    if (!record || (await getDek())) return false;
    try {
      await Vault.decryptData(key, record.data);
    } catch {
      return false; // coffre différent de celui de l'extension : chacun garde le sien
    }
    await setDek(key);
    await applyPending(await readData());
    return true;
  });
  if (unlocked) await afterUnlock();
  return unlocked;
}

async function unlock(password) {
  return serial(async () => {
    const record = Vault.parse((await getSnapshot())[VAULT_KEY]);
    if (!record) throw new ExtError('notEncrypted');
    const key = await Vault.unlockWithPassword(record, password);
    await Vault.decryptData(key, record.data); // vérifie aussi les données
    await setDek(key);
    await applyPending(await readData());
  }).then(afterUnlock);
}

chrome.alarms.create('mymfa-autolock', { periodInMinutes: 1 });
chrome.alarms.create('mymfa-drive', { periodInMinutes: 15 }); // vérifie si une sauvegarde est due
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'mymfa-drive') autoDrive();
  if (alarm.name !== 'mymfa-autolock') return;
  const { autoLock } = await getSettings();
  const { [K.lastUse]: lastUse } = await chrome.storage.session.get(K.lastUse);
  if (autoLock > 0 && lastUse && Date.now() - lastUse > autoLock * 60000 && (await getDek())) await lockAll();
});

/* ───────────── Messages ───────────── */

const isExtensionPage = (sender) => Boolean(sender.url && sender.url.startsWith(EXTENSION_ORIGIN + '/'));

async function popupList() {
  const ctx = await applyPending(await readData());
  const stored = await chrome.storage.local.get([K.lastSync, K.driveLastSync, K.driveError]);
  // Mots de passe dont l'enregistrement attend le coffre (affichés à sa création ou à son déverrouillage).
  const pending = Object.values(await getCaptures()).filter((c) => c.requested && !c.partial).map((c) => hostOf(c.origin));
  return {
    pending: [...new Set(pending)],
    status: ctx.status,
    accounts: ctx.status === 'locked' ? [] : accountsOf(ctx.map), // avec secrets : page de l'extension uniquement
    logins: ctx.status === 'locked' ? [] : listOf(ctx.map, Store.LOGINS_KEY),
    passkeys: ctx.status === 'locked' ? [] : listOf(ctx.map, Store.PASSKEYS_KEY).map(({ privateKey, ...rest }) => rest),
    settings: await getSettings(),
    lastSync: stored[K.lastSync] || null,
    drive: {
      clientId: await driveClientId(),
      deployed: Boolean(DEPLOY_CLIENT_ID),
      redirectUrl: chrome.identity.getRedirectURL(),
      lastSync: stored[K.driveLastSync] || null,
      error: stored[K.driveError] || null,
      next: await nextDriveBackup(),
    },
  };
}

const handlers = {
  /* Scripts de contenu */
  'content:state': async () => ({ settings: await getSettings(), appOrigin: await appOrigin() }),
  'content:lookup': async ({ uri }) => lookup(uri),
  'content:add': async ({ uri, issuer, account, tag, description }) => {
    const parsed = OTP.parseOtpauthUri(uri);
    await mutate((store) => {
      const data = { ...parsed, issuer: issuer || parsed.issuer, account: account || parsed.account, tag, description };
      if (!store.findDuplicate(parsed.secret, data.issuer.trim(), data.account.trim())) store.add(data, 'extension');
    });
    return lookup(uri);
  },
  'content:found': async ({ count }, sender) => {
    if (!sender.tab) return {};
    await chrome.action.setBadgeBackgroundColor({ tabId: sender.tab.id, color: '#0B7A72' });
    await chrome.action.setBadgeText({ tabId: sender.tab.id, text: count ? String(count) : '' });
    return {};
  },
  'content:injectDecoder': async (_msg, sender) => {
    await chrome.scripting.executeScript({ target: { tabId: sender.tab.id, frameIds: [sender.frameId || 0] }, files: ['lib/jsQR.js'] });
    return { ok: true };
  },
  'content:decodeUrl': async ({ url }) => {
    if (!/^https?:/i.test(url)) return { text: null };
    const res = await fetch(url, { credentials: 'omit' });
    if (!res.ok) return { text: null };
    // Seule une image est décodée, et à taille bornée : la page ne doit pas pouvoir
    // faire du service d'arrière-plan un proxy de téléchargement arbitraire.
    const type = (res.headers.get('content-type') || '').split(';')[0].trim();
    if (!type.startsWith('image/')) return { text: null };
    const length = Number(res.headers.get('content-length'));
    if (Number.isFinite(length) && length > MAX_DECODE_BYTES) return { text: null };
    const blob = await res.blob();
    if (blob.size > MAX_DECODE_BYTES) return { text: null };
    return { text: await decodeBlob(blob) };
  },
  'content:openPopup': async ({ intent }) => {
    // Le popup lit l'intention (déverrouiller, créer le coffre) à son ouverture.
    await chrome.storage.session.set({ 'ext.popupIntent': intent || null });
    try {
      await chrome.action.openPopup();
      return { opened: true };
    } catch {
      return { opened: false };
    }
  },
  'content:sync': async ({ page }, sender) => {
    const origin = await appOrigin();
    if (!origin || sender.origin !== origin) throw new ExtError('untrustedOrigin');
    return handleSync(page || {});
  },

  'content:codes': async (_msg, sender) => {
    const host = hostOf(senderOrigin(sender));
    const ctx = await readData({ touch: false });
    if (ctx.status === 'locked') return { status: 'locked', known: await indexHas('otp', Store.hostKeys(host)) };
    const now = Date.now();
    const accounts = accountsOf(ctx.map).filter((a) => accountMatchesHost(a, host));
    // Sans le code : il ne part au script de contenu qu'au clic (content:revealCode),
    // jamais d'avance à une page qui imiterait un champ de vérification.
    return { status: ctx.status, codes: await Promise.all(accounts.map((a) => publicMeta(a, now))) };
  },
  'content:revealCode': async ({ id }, sender) => {
    const host = hostOf(senderOrigin(sender));
    const ctx = await readData();
    if (ctx.status !== 'unlocked') throw new ExtError('locked');
    const account = accountsOf(ctx.map).find((a) => a.id === id && accountMatchesHost(a, host));
    if (!account) throw new ExtError('forbidden');
    const now = Date.now();
    touchAccount(account.id);
    return {
      code: await codeFor(account, now),
      remaining: account.type === 'hotp' ? null : OTP.remainingSeconds(account.period, now),
    };
  },
  'content:logins': async (_msg, sender) => {
    const origin = senderOrigin(sender);
    const settings = await getSettings();
    const ctx = await readData({ touch: false });
    const base = { status: ctx.status, savePasswords: settings.savePasswords };
    if (ctx.status === 'locked') return { ...base, logins: [], known: await indexHas('logins', siteOf(hostOf(origin))) };
    const accounts = accountsOf(ctx.map);
    return {
      ...base,
      logins: loginsFor(ctx.map, origin).map((l) => ({
        id: l.id,
        username: l.username,
        title: l.title,
        host: hostOf(l.origin),
        hasOtp: accounts.some((a) => accountMatchesHost(a, hostOf(l.origin))),
      })),
    };
  },
  'content:fillLogin': async ({ id }, sender) => {
    const origin = senderOrigin(sender);
    const ctx = await readData();
    if (ctx.status !== 'unlocked') throw new ExtError('locked');
    const login = loginsFor(ctx.map, origin).find((l) => l.id === id);
    if (!login) throw new ExtError('forbidden');
    touchLogin(id);
    return { username: login.username, password: login.password };
  },
  'content:capture': async ({ username, password }, sender) => {
    const origin = senderOrigin(sender);
    const settings = await getSettings();
    if (!settings.savePasswords || settings.neverSave.includes(siteOf(hostOf(origin)))) return { action: 'none' };
    const previous = (await getCaptures())[sender.tab.id];
    if (!password) {
      // Connexion en deux temps : l'identifiant seul, gardé pour l'écran du mot de passe.
      if (username) await setCapture(sender.tab.id, { origin, username: String(username).trim(), password: '', at: Date.now(), partial: true });
      return { action: 'none' };
    }
    const sameSite = previous && siteOf(hostOf(previous.origin)) === siteOf(hostOf(origin));
    const name = String(username || '').trim() || (sameSite ? previous.username : '');
    const capture = { origin, username: name, password: String(password), at: Date.now(), requested: false };
    const { action } = await captureAction(capture);
    await setCapture(sender.tab.id, action === 'same' ? null : capture);
    return { action: action === 'same' ? 'none' : action };
  },
  'content:pendingLogin': async (_msg, sender) => {
    const origin = senderOrigin(sender);
    const capture = (await getCaptures())[sender.tab.id];
    if (!capture || capture.partial || siteOf(hostOf(capture.origin)) !== siteOf(hostOf(origin))) return { pending: null };
    const { status, action } = await captureAction(capture);
    if (action === 'same') {
      await setCapture(sender.tab.id, null);
      return { pending: null };
    }
    return { status, pending: { host: hostOf(capture.origin), username: capture.username, length: capture.password.length, action, requested: capture.requested } };
  },
  'content:saveLogin': async ({ username }, sender) => {
    senderOrigin(sender);
    const capture = (await getCaptures())[sender.tab.id];
    if (!capture || capture.partial) throw new ExtError('captureExpired');
    if (typeof username === 'string') capture.username = username.trim();
    const ctx = await readData();
    if (ctx.status === 'unlocked') {
      await saveCapture(capture);
      await setCapture(sender.tab.id, null);
      return { saved: true };
    }
    // Coffre fermé ou absent : enregistré dès qu'il sera ouvert (ou créé).
    await setCapture(sender.tab.id, { ...capture, requested: true });
    return { saved: false, status: ctx.status };
  },
  'content:dismissLogin': async ({ never }, sender) => {
    const origin = senderOrigin(sender);
    await setCapture(sender.tab.id, null);
    if (never) {
      const settings = await getSettings();
      await saveSettings({ neverSave: [...new Set([...settings.neverSave, siteOf(hostOf(origin))])] });
    }
    return {};
  },
  'webauthn:create': webauthnCreate,
  'webauthn:get': webauthnGet,

  /* Popup (pages de l'extension uniquement) */
  'popup:list': popupList,
  'popup:unlock': async ({ password }) => {
    await unlock(password);
    return popupList();
  },
  'popup:lock': async () => {
    await lockAll();
    return popupList();
  },
  'popup:scanTab': async ({ windowId }) => scanTab(windowId),
  'popup:add': async (msg) => handlers['content:add'](msg),
  'popup:logCopy': async ({ id }) => {
    await mutate((store) => {
      const account = store.get(id);
      if (account) {
        store.log('copy', account);
        store.touchAccount(account.id);
      }
    });
    return {};
  },
  'popup:saveSettings': async ({ settings }) => {
    if (settings && 'driveEvery' in settings && !DRIVE_EVERY_CHOICES.includes(settings.driveEvery)) throw new ExtError('forbidden');
    return { settings: await saveSettings(settings) };
  },
  'popup:syncNow': async () => ({ tabs: await pushToApp() }),
  'popup:createVault': async ({ password }) => {
    await createVault(password);
    return popupList();
  },
  'popup:intent': async () => {
    const { 'ext.popupIntent': intent } = await chrome.storage.session.get('ext.popupIntent');
    await chrome.storage.session.remove('ext.popupIntent');
    return { intent: intent || null };
  },
  'popup:fillLogin': async ({ tabId, id }) => {
    const tab = await chrome.tabs.get(tabId);
    const origin = new URL(tab.url).origin;
    const ctx = await readData();
    if (ctx.status !== 'unlocked') throw new ExtError('locked');
    const login = loginsFor(ctx.map, origin).find((l) => l.id === id);
    if (!login) throw new ExtError('forbidden');
    touchLogin(id);
    return chrome.tabs.sendMessage(tabId, { type: 'mymfa:fillLogin', username: login.username, password: login.password }, { frameId: 0 });
  },
  // Modification depuis le popup : seulement les champs prévus (jamais la clé secrète d'un compte).
  'popup:updateAccount': async ({ id, patch }) => {
    await mutate((store) => store.update(id, pickFields(patch, ['issuer', 'account', 'tag', 'description', 'favorite'])));
    return popupList();
  },
  'popup:updateLogin': async ({ id, patch }) => {
    await mutate((store) => store.updateLogin(id, pickFields(patch, ['origin', 'username', 'password', 'title', 'note', 'tag', 'favorite'])), { secure: true });
    return popupList();
  },
  'popup:touchLogin': async ({ id }) => {
    touchLogin(id);
    return {};
  },
  'popup:forgetSite': async ({ site }) => {
    const settings = await getSettings();
    return { settings: await saveSettings({ neverSave: settings.neverSave.filter((s) => s !== site) }) };
  },
  // « Sauvegarder maintenant » : synchro, puis une archive figée à côté.
  'popup:driveSync': async () => syncDrive(true, { archiver: true }),
  'popup:driveDisconnect': async () => {
    await disconnectDrive();
    return popupList();
  },

  /* App embarquée (pages de l'extension uniquement, voir app-host.js) */
  'app:sync': async ({ page }) => handleSync(page || {}),
  'app:key': async () => {
    const ctx = await readData({ touch: false });
    if (ctx.status !== 'unlocked') return { key: null };
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', ctx.dek));
    const key = Vault.toB64(raw);
    raw.fill(0);
    return { key };
  },
  'app:unlocked': async ({ key }) => ({ unlocked: await unlockWithKey(key) }),
  'app:locked': async () => {
    if (await getDek()) await lockAll();
    return {};
  },
  'app:touch': async () => {
    if (await getDek()) await chrome.storage.session.set({ [K.lastUse]: Date.now() });
    return {};
  },
  'app:settings': async () => {
    const settings = await getSettings();
    const { [K.driveLastSync]: driveLastSync, [K.driveFile]: driveFile } = await chrome.storage.local.get([K.driveLastSync, K.driveFile]);
    return {
      autoLock: settings.autoLock,
      driveLinked: Boolean(settings.drive),
      driveFile: driveFile || null,
      driveEvery: settings.driveEvery,
      driveNext: await nextDriveBackup(),
      driveLastSync: driveLastSync || null,
      driveClientId: DEPLOY_CLIENT_ID ? '' : settings.driveClientId,
    };
  },
  // Identifiant client Google saisi dans l'app : le même pour l'extension.
  'app:driveClientId': async ({ clientId }) => {
    const value = String(clientId || '');
    if (value && !CLIENT_ID_RE.test(value)) throw new ExtError('forbidden');
    await saveSettings({ driveClientId: value });
    return {};
  },
  'app:driveEvery': async ({ hours }) => {
    if (!DRIVE_EVERY_CHOICES.includes(hours)) throw new ExtError('forbidden');
    await saveSettings({ driveEvery: hours });
    return { next: await nextDriveBackup() };
  },
  // Sauvegarde faite par l'app (même fichier) : elle compte pour la politique, et Drive est relié.
  'app:driveBackedUp': async () => {
    await chrome.storage.local.set({ [K.driveError]: null, [K.driveLastSync]: new Date().toISOString() });
    await saveSettings({ drive: true });
    return { next: await nextDriveBackup() };
  },
  'app:autoLock': async ({ minutes }) => {
    if (!AUTOLOCK_CHOICES.includes(minutes)) throw new ExtError('forbidden');
    await saveSettings({ autoLock: minutes });
    return {};
  },
  'app:driveToken': async ({ clientId }) => ({ token: await driveToken(true, clientId) }),
  // Synchro demandée par l'app embarquée : l'arrière-plan est le seul écrivain Drive de l'extension.
  'app:driveSync': async () => ({ entree: await syncDrive(true), next: await nextDriveBackup() }),
  // Journal des synchros conduites par l'arrière-plan, pour l'espace Synchro de l'app.
  'app:syncJournal': async () => ({ entrees: await lireJournal(), appareil: (await chargerTemps()).temps.appareil }),
  // Métadonnées du fichier de sauvegarde relues sur Drive, sans fenêtre Google (jeton silencieux).
  'app:driveInfo': async () => {
    const client = Drive.createClient({ fetch: (...args) => fetch(...args), getToken: () => driveToken(false) });
    const file = await client.find();
    if (file) await chrome.storage.local.set({ [K.driveFile]: file });
    else await chrome.storage.local.remove(K.driveFile);
    return { file };
  },
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const type = message && message.type;
  const handler = handlers[type];
  if (!handler || ((type.startsWith('popup:') || type.startsWith('app:')) && !isExtensionPage(sender))) {
    sendResponse(errorPayload(new ExtError('forbidden')));
    return false;
  }
  handler(message, sender).then(sendResponse, (err) => sendResponse(errorPayload(err)));
  return true;
});

chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === 'loading') chrome.action.setBadgeText({ tabId, text: '' }).catch(() => {});
});
