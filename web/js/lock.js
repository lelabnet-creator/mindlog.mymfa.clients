/*
 * Verrouillage de myMFA : mot de passe maître, passkeys (WebAuthn PRF),
 * écran de verrouillage, réglages de sécurité et verrouillage automatique.
 * Dépend de : I18n, Vault, Store.
 *
 * Lock.storage remplace localStorage pour le store :
 *  - coffre absent      → lecture/écriture directes dans localStorage ;
 *  - coffre déverrouillé → comptes et historique en mémoire, rechiffrés à chaque écriture ;
 *  - coffre verrouillé   → aucune donnée lisible, toute écriture refusée.
 * Les préférences d'affichage (thème, langue, masquage, délai) restent en clair :
 * elles servent avant le déverrouillage et ne contiennent rien de sensible.
 *
 * Hôte (window.MYMFA_HOST, défini par l'extension quand elle embarque l'app) : un seul
 * verrou pour l'app et l'extension. Chaque déverrouillage ou verrouillage d'ici lui est
 * signalé, et il en signale autant (unlockFromHost, lockFromHost) ; le délai de
 * verrouillage automatique est le sien, l'activité d'ici le repousse. Sans hôte (app
 * hébergée), rien de tout cela.
 */
(function () {
  'use strict';

  const { t } = I18n;
  const SENSITIVE = [Store.ACCOUNTS_KEY, Store.HISTORY_KEY, Store.DELETED_KEY, Store.LOGINS_KEY, Store.PASSKEYS_KEY, Store.SETTINGS_KEY];
  // Jamais de mots de passe ni de passkeys hors du coffre : toute écriture de ces clés
  // sans coffre est refusée (les comptes OTP et l'historique restent tolérés en clair).
  const PLAIN_FORBIDDEN = [Store.LOGINS_KEY, Store.PASSKEYS_KEY];
  const AUTOLOCK_KEY = 'mymfa.autoLock';
  const MODIFIED_KEY = 'mymfa.vaultModifiedAt'; // date seule, sans contenu : sert au rappel de sauvegarde
  const PREVIOUS_KEY = 'mymfa.vault.previous'; // coffre remplacé par une restauration, pour l'annuler
  const PASSKEY_PROMPT_KEY = 'mymfa.passkeyPrompt'; // 'never', ou date avant laquelle ne pas reproposer de passkey
  const PASSKEY_PROMPT_DAYS = 7;
  const AUTOLOCK_CHOICES = [1, 5, 15, 60, 0]; // minutes ; 0 = jamais
  const DEFAULT_AUTOLOCK = 5;

  let record = Vault.parse(localStorage.getItem(Vault.VAULT_KEY));
  let dek = null;
  let mem = new Map();
  let queue = Promise.resolve();
  let hooks = { toast() {}, errorMessage: String, log() {}, onPrefs() {}, onUnlock() {}, onLock() {} };
  let lastActivity = Date.now();
  let failures = 0;
  let restoreUndo = false; // une restauration vient de remplacer le coffre : « Annuler » proposé
  const host = window.MYMFA_HOST || null;

  /* ───── Temps (SYN-07/08) ─────
   * Heure de référence T() : horloge locale corrigée par l'heure des serveurs
   * Google renvoyée par Drive (app.noteHeureDrive reçoit chaque réponse) ; le
   * dernier décalage connu survit à la session (« hors ligne : non vérifié »).
   * Horloge hybride et identifiant d'appareil : hors des données du coffre,
   * jamais synchronisés — le repère et l'horloge reprennent au démarrage. */
  const TEMPS_KEY = 'mymfa.temps.v1';
  let decalageConnu = null;
  try {
    const sauvegarde = JSON.parse(localStorage.getItem(TEMPS_KEY) || 'null');
    if (sauvegarde && Number.isFinite(sauvegarde.decalageMs)) decalageConnu = sauvegarde.decalageMs;
  } catch {
    /* dernier décalage illisible : horloge locale non corrigée */
  }
  const heure = Heure.create({ decalageInitial: decalageConnu });
  const temps = Sync2.etatPersistant(localStorage, () => heure.maintenant());
  /** Reçoit l'heure des serveurs Google (ms) d'une réponse Drive : corrige T(),
   * alerte au-delà de 5 min, dernier décalage conservé pour la session suivante. */
  function noterHeureServeur(heureServeurMs) {
    if (!Number.isFinite(heureServeurMs)) return null;
    const mesure = heure.recevoirReference(heureServeurMs);
    try {
      localStorage.setItem(TEMPS_KEY, JSON.stringify({ decalageMs: mesure.decalageMs }));
    } catch {
      /* décalage non conservé : re-mesuré au prochain échange */
    }
    return mesure;
  }

  /* ───────────── Stockage ───────────── */

  const isSensitive = (key) => SENSITIVE.includes(key);
  const isPlainForbidden = (key) => PLAIN_FORBIDDEN.includes(key);

  const storage = {
    getItem(key) {
      if (!record || !isSensitive(key)) return localStorage.getItem(key);
      return mem.has(key) ? mem.get(key) : null;
    },
    setItem(key, value) {
      if (!record) {
        if (isPlainForbidden(key)) throw new Vault.VaultError('credentialsNeedVault');
        localStorage.setItem(key, value);
        return;
      }
      if (!dek) throw new Vault.VaultError('locked');
      mem.set(key, String(value));
      persist();
    },
    removeItem(key) {
      if (!record || !isSensitive(key)) {
        localStorage.removeItem(key);
        return;
      }
      if (!dek) throw new Vault.VaultError('locked');
      mem.delete(key);
      persist();
    },
  };

  /** Sérialise les écritures du coffre : un chiffrement à la fois, dans l'ordre. */
  function enqueue(task) {
    queue = queue.then(task).catch((err) => {
      console.error('[myMFA] écriture du coffre impossible', err);
      hooks.toast(hooks.errorMessage(err));
    });
    return queue;
  }

  function writeRecord() {
    localStorage.setItem(Vault.VAULT_KEY, JSON.stringify(record));
    localStorage.setItem(MODIFIED_KEY, new Date().toISOString());
  }

  // Écritures en rafale (un import : deux par élément) : un seul chiffrement en attente, qui prend
  // l'état du moment où il démarre. Celles faites pendant un chiffrement en programment un autre.
  let pendingPersist = null;
  function persist() {
    if (pendingPersist) return pendingPersist;
    const key = dek;
    pendingPersist = enqueue(async () => {
      pendingPersist = null;
      if (!record || dek !== key) return; // verrouillé ou désactivé entre-temps
      record = { ...record, data: await Vault.encryptData(key, Object.fromEntries(mem)) };
      writeRecord();
    });
    return pendingPersist;
  }

  function status() {
    if (!record) return 'plain';
    return dek ? 'unlocked' : 'locked';
  }

  /* ───────────── Passkeys (WebAuthn PRF) ───────────── */

  function passkeysAvailable() {
    const host = location.hostname;
    const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes(':');
    return Boolean(window.PublicKeyCredential && window.isSecureContext && navigator.credentials && !isIp);
  }

  /** Appareil capable de créer un passkey qui chiffre le coffre : authentificateur intégré, PRF non exclue. */
  async function passkeyCompatible() {
    if (!passkeysAvailable()) return false;
    try {
      if (PublicKeyCredential.getClientCapabilities) {
        const caps = await PublicKeyCredential.getClientCapabilities();
        if (caps['extension:prf'] === false) return false;
      }
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
      return false;
    }
  }

  function setPasskeyPrompt(value) {
    try {
      localStorage.setItem(PASSKEY_PROMPT_KEY, value);
    } catch {
      /* stockage indisponible : on reproposera */
    }
  }

  /** Après une saisie du mot de passe : propose un passkey, si l'appareil s'y prête et qu'il n'y en a aucun. */
  async function suggestPasskey() {
    if (status() !== 'unlocked' || (record.passkeys || []).length) return;
    let prompt = null;
    try {
      prompt = localStorage.getItem(PASSKEY_PROMPT_KEY);
    } catch {
      /* stockage indisponible */
    }
    if (prompt === 'never' || (prompt && prompt > new Date().toISOString())) return;
    if (!(await passkeyCompatible()) || status() !== 'unlocked' || $('security-dialog').open) return;
    // Reporté dès l'affichage : « Plus tard », Échap ou un échec ne la font pas revenir à chaque déverrouillage.
    setPasskeyPrompt(new Date(Date.now() + PASSKEY_PROMPT_DAYS * 86400000).toISOString());
    openDialog('suggestPasskey');
  }

  function webauthnError(err) {
    if (err instanceof Vault.VaultError) return err;
    const map = { NotAllowedError: 'passkeyCancelled', AbortError: 'passkeyCancelled', SecurityError: 'passkeyDomain', InvalidStateError: 'passkeyExists' };
    return new Vault.VaultError(map[err && err.name] || 'passkeyFailed');
  }

  /** Demande une assertion et la sortie PRF pour l'un des passkeys donnés. */
  async function evaluatePrf(entries) {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: Vault.randomBytes(32),
        rpId: location.hostname,
        userVerification: 'required',
        timeout: 120000,
        allowCredentials: entries.map((e) => ({ type: 'public-key', id: Vault.fromB64Url(e.id) })),
        extensions: { prf: { evalByCredential: Object.fromEntries(entries.map((e) => [e.id, { first: e.salt }])) } },
      },
    });
    const prf = assertion.getClientExtensionResults().prf;
    const output = prf && prf.results && prf.results.first;
    if (!output) throw new Vault.VaultError('prfUnsupported');
    return { id: Vault.toB64Url(new Uint8Array(assertion.rawId)), output: new Uint8Array(output) };
  }

  async function registerPasskey(name) {
    if (!passkeysAvailable()) throw new Vault.VaultError('passkeyUnsupported');
    const prfSalt = Vault.randomBytes(32);
    let credential;
    try {
      credential = await navigator.credentials.create({
        publicKey: {
          rp: { name: 'myMFA', id: location.hostname },
          user: { id: Vault.randomBytes(16), name: `myMFA · ${name}`, displayName: name },
          challenge: Vault.randomBytes(32),
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
          authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
          excludeCredentials: (record.passkeys || []).map((p) => ({ type: 'public-key', id: Vault.fromB64Url(p.id) })),
          extensions: { prf: { eval: { first: prfSalt } } },
          timeout: 120000,
        },
      });
    } catch (err) {
      throw webauthnError(err);
    }
    const id = Vault.toB64Url(new Uint8Array(credential.rawId));
    const prf = credential.getClientExtensionResults().prf;
    if (!prf || prf.enabled === false) {
      // Passkey inutilisable pour chiffrer : on signale qu'il peut être oublié.
      if (PublicKeyCredential.signalUnknownCredential) {
        PublicKeyCredential.signalUnknownCredential({ rpId: location.hostname, credentialId: id }).catch(() => {});
      }
      throw new Vault.VaultError('prfUnsupported');
    }
    let output = prf.results && prf.results.first ? new Uint8Array(prf.results.first) : null;
    if (!output) {
      // Beaucoup d'authentificateurs ne calculent la PRF qu'à l'authentification.
      try {
        output = (await evaluatePrf([{ id, salt: prfSalt }])).output;
      } catch (err) {
        throw webauthnError(err);
      }
    }
    await enqueue(async () => {
      record = await Vault.addPasskey(record, dek, { id, name, prfSalt, prfOutput: output });
      writeRecord();
    });
    hooks.log('passkeyAdded');
  }

  /* ───────────── Actions ───────────── */

  async function finishUnlock(key, { fromHost = false } = {}) {
    const brut = await Vault.decryptData(key, record.data);
    // Migration v1 → v2 (SYN-07) : tampons par champ, marqueur, tombstones v1
    // rattachés. Rejouable sans effet sur un coffre déjà v2.
    const data = Sync2.migrer(brut, 0, temps.appareil);
    const migre = !brut[Sync2.SYNC_KEY];
    dek = key;
    mem = new Map(Object.entries(data));
    failures = 0;
    // Le coffre importé est déverrouillé avec succès : l'annulation de la restauration n'a plus de sens.
    localStorage.removeItem(PREVIOUS_KEY);
    restoreUndo = false;
    lastActivity = Date.now();
    if (migre) {
      await enqueue(async () => {
        if (!record || dek !== key) return; // verrouillé entre-temps
        record = { ...record, v: 2, data: await Vault.encryptData(key, data) };
        writeRecord();
      });
    }
    updateChrome();
    hooks.onUnlock();
    if (host && !fromHost) host.unlocked(key);
  }

  /** Clé du coffre transmise par l'hôte, déjà déverrouillé de son côté. Faux si elle n'ouvre pas ce coffre. */
  async function unlockFromHost(key) {
    if (status() !== 'locked') return false;
    try {
      await finishUnlock(key, { fromHost: true });
      return true;
    } catch {
      return false;
    }
  }

  async function unlockWithPassword(password) {
    await finishUnlock(await Vault.unlockWithPassword(record, password));
  }

  async function unlockWithPasskey() {
    if (!passkeysAvailable()) throw new Vault.VaultError('passkeyUnsupported');
    let result;
    try {
      result = await evaluatePrf(record.passkeys.map((p) => ({ id: p.id, salt: Vault.fromB64(p.prfSalt) })));
    } catch (err) {
      throw webauthnError(err);
    }
    await finishUnlock(await Vault.unlockWithPrf(record, result.id, result.output));
  }

  function lock({ fromHost = false } = {}) {
    if (status() !== 'unlocked') return;
    dek = null;
    mem = new Map();
    hooks.onLock();
    updateChrome();
    if (host && !fromHost) host.locked();
  }

  const lockFromHost = () => lock({ fromHost: true });

  async function enable(password) {
    const collecte = {};
    for (const key of SENSITIVE) {
      const value = localStorage.getItem(key);
      if (value !== null) collecte[key] = value;
    }
    const data = Sync2.migrer(collecte, 0, temps.appareil);
    const created = await Vault.create(password, data);
    // Coffre écrit d'abord, données en clair supprimées ensuite : jamais d'état sans copie.
    record = created.record;
    writeRecord();
    dek = created.dek;
    mem = new Map(Object.entries(data));
    for (const key of SENSITIVE) localStorage.removeItem(key);
    lastActivity = Date.now();
    hooks.log('enabled');
    updateChrome();
    if (host) host.unlocked(dek);
  }

  async function changePassword(current, next) {
    await Vault.unlockWithPassword(record, current); // vérifie l'actuel
    await enqueue(async () => {
      record = await Vault.changePassword(record, dek, next);
      writeRecord();
    });
    hooks.log('passwordChanged');
  }

  async function disable(password) {
    await Vault.unlockWithPassword(record, password);
    await queue;
    // Mots de passe et passkeys ne sont jamais stockés en clair.
    if (Sync.hasCredentials(Object.fromEntries(mem))) throw new Vault.VaultError('credentialsNeedVault');
    for (const [key, value] of mem) localStorage.setItem(key, value);
    localStorage.removeItem(Vault.VAULT_KEY);
    localStorage.removeItem(PREVIOUS_KEY);
    restoreUndo = false;
    record = null;
    dek = null;
    mem = new Map();
    hooks.log('disabled');
    updateChrome();
  }

  /** Mot de passe perdu : efface le coffre et tout ce qu'il contient. Irréversible. */
  async function reset() {
    await queue;
    localStorage.removeItem(Vault.VAULT_KEY);
    localStorage.removeItem(MODIFIED_KEY);
    localStorage.removeItem(PREVIOUS_KEY);
    restoreUndo = false;
    for (const key of SENSITIVE) localStorage.removeItem(key);
    record = null;
    dek = null;
    mem = new Map();
    failures = 0;
    hooks.log('reset'); // premier événement du nouvel historique, en clair
    updateChrome();
    hooks.onUnlock();
  }

  async function removePasskey(id) {
    await enqueue(async () => {
      record = Vault.removePasskey(record, id);
      writeRecord();
    });
    hooks.log('passkeyRemoved');
  }

  /** Enregistrement chiffré tel que stocké, une fois les écritures en cours terminées. */
  async function exportVault() {
    await queue;
    return record ? localStorage.getItem(Vault.VAULT_KEY) : null;
  }

  /** Remplace le coffre local par une sauvegarde chiffrée, puis verrouille.
   *  Le coffre remplacé est conservé pour permettre d'annuler (undoRestore),
   *  tant que la sauvegarde n'a pas été déverrouillée avec succès. */
  async function importVault(raw) {
    const parsed = Vault.parse(raw);
    if (!parsed) throw new Vault.VaultError('invalidBackup');
    await queue;
    if (record) localStorage.setItem(PREVIOUS_KEY, JSON.stringify(record));
    localStorage.setItem(Vault.VAULT_KEY, raw);
    localStorage.setItem(MODIFIED_KEY, new Date().toISOString());
    for (const key of SENSITIVE) localStorage.removeItem(key);
    record = parsed;
    dek = null;
    mem = new Map();
    restoreUndo = Boolean(localStorage.getItem(PREVIOUS_KEY));
    hooks.onLock();
    updateChrome();
  }

  /** Annule la dernière restauration : rétablit le coffre précédent, verrouillé. */
  async function undoRestore() {
    const raw = localStorage.getItem(PREVIOUS_KEY);
    const parsed = Vault.parse(raw);
    if (!parsed) {
      localStorage.removeItem(PREVIOUS_KEY);
      restoreUndo = false;
      return false;
    }
    await queue;
    localStorage.setItem(Vault.VAULT_KEY, raw);
    localStorage.removeItem(PREVIOUS_KEY);
    localStorage.setItem(MODIFIED_KEY, new Date().toISOString());
    record = parsed;
    dek = null;
    mem = new Map();
    restoreUndo = false;
    hooks.onLock();
    updateChrome();
    return true;
  }

  function canUndoRestore() {
    return restoreUndo && Boolean(localStorage.getItem(PREVIOUS_KEY));
  }

  function modifiedAt() {
    return localStorage.getItem(MODIFIED_KEY);
  }

  /* ───────────── Synchronisation entre onglets ───────────── */

  async function onStorage(event) {
    if (event.key !== Vault.VAULT_KEY && event.key !== null) return;
    const next = Vault.parse(localStorage.getItem(Vault.VAULT_KEY));
    const refresh = hooks.onRefresh || hooks.onUnlock;
    if (!next) {
      // Pas de coffre : données en clair modifiées ailleurs, ou chiffrement désactivé ailleurs.
      const wasVault = Boolean(record);
      record = null;
      dek = null;
      mem = new Map();
      updateChrome();
      (wasVault ? hooks.onUnlock : refresh)();
      return;
    }
  const wasPlain = !record;
  record = next;
  if (wasPlain || !dek) {
    if (wasPlain) {
      // Un coffre existe désormais ailleurs : toute donnée sensible restée en clair ici est périmée.
      for (const key of SENSITIVE) localStorage.removeItem(key);
      hooks.onLock();
    }
    updateChrome();
    return;
  }
    try {
      mem = new Map(Object.entries(await Vault.decryptData(dek, record.data)));
      refresh();
    } catch {
      lock();
    }
  }

  /* ───────────── Verrouillage automatique ───────────── */

  function autoLockMinutes() {
    const value = parseInt(localStorage.getItem(AUTOLOCK_KEY), 10);
    return AUTOLOCK_CHOICES.includes(value) ? value : DEFAULT_AUTOLOCK;
  }

  function setupAutoLock() {
    const touch = () => {
      lastActivity = Date.now();
      if (host && status() === 'unlocked') host.touch();
    };
    ['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach((type) =>
      window.addEventListener(type, touch, { passive: true, capture: true })
    );
    // Le délai est celui de l'hôte, qui verrouille tout à la fois.
    if (host) return;
    setInterval(() => {
      const minutes = autoLockMinutes();
      if (status() === 'unlocked' && minutes > 0 && Date.now() - lastActivity > minutes * 60000) lock();
    }, 10000);
  }

  /* ───────────── Interface ───────────── */

  const $ = (id) => document.getElementById(id);

  function h(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? '' : value);
    }
    for (const child of [].concat(children)) if (child) node.append(child);
    return node;
  }

  function icon(d) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    for (const part of [].concat(d)) {
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('d', part);
      svg.append(path);
    }
    return svg;
  }

  const ICONS = {
    lock: ['M6 10h12a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2z', 'M8 10V7a4 4 0 0 1 8 0v3'],
    shield: ['M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6z', 'm8.5 12 2.5 2.5 4.5-5'],
    key: ['M8 19a4 4 0 1 0 0-8 4 4 0 0 0 0 8z', 'm10.8 12.2 8.2-8.2M17 6l2 2M15 8l2 2'],
    trash: ['M4 7h16M6 7l1 13h10l1-13M9 7V4h6v3'],
    plus: ['M12 5v14M5 12h14'],
  };

  /** Barre latérale, bouton « Verrouiller », écran de verrouillage. */
  function updateChrome() {
    const st = status();
    $('lock-screen').hidden = st !== 'locked';
    document.querySelector('.app').inert = st === 'locked';
    $('sidebar-warning').hidden = st !== 'plain';
    $('btn-lock-side').hidden = st !== 'unlocked';
    $('btn-lock').hidden = st !== 'unlocked';
    $('lock-passkey').hidden = !(st === 'locked' && record.passkeys && record.passkeys.length && passkeysAvailable());
    if (st === 'locked') {
      $('lock-password').value = '';
      showLockError('');
      setTimeout(() => $('lock-password').focus(), 50);
    }
    renderSettings();
    if (hooks.onChange) hooks.onChange();
  }

  function showLockError(message) {
    $('lock-error').textContent = message || '';
    $('lock-error').hidden = !message;
  }

  async function withBusy(button, task) {
    button.disabled = true;
    button.classList.add('is-busy');
    try {
      return await task();
    } finally {
      button.disabled = false;
      button.classList.remove('is-busy');
    }
  }

  function setupLockScreen() {
    $('lock-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const submit = event.submitter || $('lock-form').querySelector('[type="submit"]');
      await withBusy(submit, async () => {
        try {
          await unlockWithPassword($('lock-password').value);
          suggestPasskey();
        } catch (err) {
          failures += 1;
          showLockError(hooks.errorMessage(err));
          $('lock-password').select();
          // Ralentit les essais répétés (en plus du coût de PBKDF2).
          if (failures >= 3) await new Promise((r) => setTimeout(r, Math.min(30, 2 ** (failures - 3)) * 1000));
        }
      });
    });
    $('lock-passkey').addEventListener('click', (event) =>
      withBusy(event.currentTarget, async () => {
        try {
          await unlockWithPasskey();
        } catch (err) {
          showLockError(hooks.errorMessage(err));
        }
      })
    );
    $('lock-forgot').addEventListener('click', () => openDialog('reset'));
    $('btn-lock').addEventListener('click', () => lock());
    $('btn-lock-side').addEventListener('click', () => lock());
  }

  /* Réglages > Sécurité */

  function row({ iconName, tone, title, text, action }) {
    return h('div', { class: 'row row-tall' }, [
      iconName ? h('span', { class: `row-icon ${tone || ''}` }, icon(ICONS[iconName])) : null,
      h('span', { class: 'row-main' }, [h('span', { text: title }), text ? h('small', { text }) : null]),
      action,
    ]);
  }

  function renderSettings() {
    const panel = $('security-rows');
    const passkeys = $('passkeys-section');
    const st = status();
    if (st === 'plain') {
      panel.replaceChildren(
        row({
          iconName: 'lock',
          tone: 'warn',
          title: t('security.masterPassword'),
          text: t('security.plainText'),
          action: h('button', { type: 'button', class: 'btn btn-primary btn-sm', text: t('security.enable'), onclick: () => openDialog('enable') }),
        })
      );
      passkeys.hidden = true;
      return;
    }
    if (st !== 'unlocked') return;
    const autoLock = h(
      'select',
      { class: 'row-select', 'aria-label': t('security.autoLock') },
      AUTOLOCK_CHOICES.map((m) =>
        h('option', { value: String(m), text: m === 0 ? t('security.autoLockNever') : t('security.autoLockMinutes', { count: m }) })
      )
    );
    autoLock.value = String(autoLockMinutes());
    autoLock.addEventListener('change', () => {
      localStorage.setItem(AUTOLOCK_KEY, autoLock.value);
      if (host) host.autoLockChanged(Number(autoLock.value));
      hooks.onPrefs();
    });
    panel.replaceChildren(
      row({
        iconName: 'shield',
        tone: 'accent',
        title: t('security.masterPassword'),
        text: t('security.enabledText'),
        action: h('button', { type: 'button', class: 'btn btn-ghost btn-sm', text: t('security.change'), onclick: () => openDialog('change') }),
      }),
      h('label', { class: 'row' }, [h('span', { class: 'row-main', text: t('security.autoLock') }), autoLock]),
      h('button', { type: 'button', class: 'row', onclick: () => lock() }, [
        icon(ICONS.lock),
        h('span', { class: 'row-main', text: t('security.lockNow') }),
      ]),
      h('button', { type: 'button', class: 'row danger', onclick: () => openDialog('disable') }, [
        h('span', { class: 'row-main', text: t('security.disable') }),
      ])
    );

    passkeys.hidden = false;
    const list = $('passkeys-list');
    const dateFormat = new Intl.DateTimeFormat(I18n.getLocale(), { dateStyle: 'medium' });
    const rows = (record.passkeys || []).map((p) =>
      row({
        iconName: 'key',
        tone: 'accent',
        title: p.name,
        text: t('security.passkeyAdded', { date: dateFormat.format(new Date(p.createdAt)) }),
        action: h('button', {
          type: 'button',
          class: 'icon-btn small danger',
          'aria-label': t('security.passkeyRemove', { name: p.name }),
          title: t('security.passkeyRemove', { name: p.name }),
          onclick: () => openDialog('removePasskey', p),
        }, icon(ICONS.trash)),
      })
    );
    const available = passkeysAvailable();
    rows.push(
      h('button', { type: 'button', class: 'row', disabled: !available, onclick: () => openDialog('passkey') }, [
        icon(ICONS.plus),
        h('span', { class: 'row-main', text: t('security.passkeyAdd') }),
      ])
    );
    list.replaceChildren(...rows);
    $('passkeys-note').textContent = available ? t('security.passkeyNote') : t('security.passkeyUnavailableHere');
  }

  /* Dialogue de sécurité */

  function passwordField(name, labelKey, autocomplete, { gauge = false } = {}) {
    const input = h('input', {
      name,
      type: 'password',
      class: 'input',
      autocomplete,
      required: true,
      minlength: name === 'current' ? null : String(Vault.PASSWORD_MIN_LENGTH),
    });
    if (!gauge) return h('label', { class: 'field-label' }, [h('span', { text: t(labelKey) }), input]);
    // Jauge de solidité (générée par la vue Mots de passe) : conseil à la saisie, pas un bloquant.
    const meter = Credentials.meter();
    input.addEventListener('input', () => meter.update(input.value));
    return h('div', { class: 'field-label' }, [h('span', { text: t(labelKey) }), input, meter.node]);
  }

  function defaultPasskeyName() {
    const ua = navigator.userAgent;
    const os = /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac/.test(ua) ? 'macOS' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : '';
    return os ? t('security.passkeyDefaultName', { os }) : t('security.passkeyDefaultNameGeneric');
  }

  function openDialog(mode, passkey) {
    const dialog = $('security-dialog');
    const form = $('security-form');
    const error = h('p', { class: 'form-error', role: 'alert', hidden: true });
    // Champ utilisateur caché : permet aux gestionnaires de mots de passe d'associer l'entrée.
    const username = h('input', { type: 'text', name: 'username', autocomplete: 'username', value: 'myMFA', hidden: true, 'aria-hidden': 'true', tabindex: '-1' });
    const fields = {
      enable: [username, h('p', { class: 'dialog-text', text: t('security.enableText') }), passwordField('next', 'security.newPassword', 'new-password', { gauge: true }), passwordField('confirm', 'security.confirmPassword', 'new-password'), h('p', { class: 'muted small', text: t('security.passwordHint') })],
      change: [username, passwordField('current', 'security.currentPassword', 'current-password'), passwordField('next', 'security.newPassword', 'new-password', { gauge: true }), passwordField('confirm', 'security.confirmPassword', 'new-password')],
      disable: [username, h('p', { class: 'dialog-text', text: t('security.disableText') }), passwordField('current', 'security.currentPassword', 'current-password')],
      passkey: [
        h('p', { class: 'dialog-text', text: t('security.passkeyText') }),
        h('label', { class: 'field-label' }, [h('span', { text: t('security.passkeyName') }), h('input', { name: 'name', class: 'input', value: defaultPasskeyName(), required: true, maxlength: '40' })]),
      ],
      suggestPasskey: [
        h('p', { class: 'dialog-text', text: t('security.suggestText') }),
        h('label', { class: 'field-label' }, [h('span', { text: t('security.passkeyName') }), h('input', { name: 'name', class: 'input', value: defaultPasskeyName(), required: true, maxlength: '40' })]),
      ],
      removePasskey: [h('p', { class: 'dialog-text', text: t('security.passkeyRemoveText', { name: passkey ? passkey.name : '' }) })],
      reset: [
        h('p', { class: 'dialog-text', text: t('security.resetText') }),
        h('p', { class: 'muted small', text: t('security.resetNote') }),
        h('label', { class: 'check-line' }, [h('input', { type: 'checkbox', name: 'understood' }), h('span', { text: t('security.resetConfirm') })]),
      ],
    }[mode];
    const danger = mode === 'disable' || mode === 'removePasskey' || mode === 'reset';
    const submit = h('button', { type: 'submit', class: `btn ${danger ? 'btn-danger' : 'btn-primary'}`, text: t(`security.submit.${mode}`) });
    form.replaceChildren(
      h('h2', { id: 'security-title', text: t(`security.title.${mode}`) }),
      ...fields,
      error,
      h('div', { class: mode === 'suggestPasskey' ? 'dialog-actions is-stacked' : 'dialog-actions' }, [
        mode === 'suggestPasskey'
          ? h('button', { type: 'button', class: 'btn btn-ghost', text: t('security.suggestNever'), onclick: () => { setPasskeyPrompt('never'); dialog.close(); } })
          : null,
        h('span', { class: 'spacer' }),
        h('button', { type: 'button', class: 'btn btn-ghost', text: t(mode === 'suggestPasskey' ? 'security.suggestLater' : 'edit.cancel'), onclick: () => dialog.close() }),
        submit,
      ])
    );
    form.onsubmit = async (event) => {
      event.preventDefault();
      error.hidden = true;
      const v = Object.fromEntries(new FormData(form));
      if ('confirm' in v && v.next !== v.confirm) {
        error.textContent = t('error.passwordMismatch');
        error.hidden = false;
        return;
      }
      if (mode === 'reset' && !v.understood) {
        error.textContent = t('error.resetUnconfirmed');
        error.hidden = false;
        return;
      }
      await withBusy(submit, async () => {
        try {
          if (mode === 'enable') await enable(v.next);
          else if (mode === 'change') await changePassword(v.current, v.next);
          else if (mode === 'disable') await disable(v.current);
          else if (mode === 'passkey' || mode === 'suggestPasskey') await registerPasskey(v.name.trim() || defaultPasskeyName());
          else if (mode === 'removePasskey') await removePasskey(passkey.id);
          else if (mode === 'reset') await reset();
          dialog.close();
          hooks.toast(t(`security.done.${mode}`));
          renderSettings();
          if (mode === 'enable') suggestPasskey();
        } catch (err) {
          error.textContent = hooks.errorMessage(err);
          error.hidden = false;
        }
      });
    };
    dialog.showModal();
    const first = form.querySelector('input:not([hidden])');
    if (first) first.focus();
  }

  /* ───────────── Initialisation ───────────── */

  function init(options) {
    hooks = { ...hooks, ...options };
    setupLockScreen();
    setupAutoLock();
    window.addEventListener('storage', onStorage);
    // Écritures de l'extension myMFA dans cette page (aucun événement « storage » dans le même onglet).
    window.addEventListener('mymfa:external-change', () => onStorage({ key: null }));
    I18n.onChange(renderSettings);
    // Un coffre existant rend toute donnée sensible restée en clair périmée — crash, par exemple,
    // entre l'écriture du coffre et la suppression des clés par enable(). Sans ce nettoyage,
    // la copie en clair resterait sur le disque pour toujours.
    if (record) for (const key of SENSITIVE) localStorage.removeItem(key);
    updateChrome();
  }

  window.Lock = {
    storage,
    temps,
    heure,
    noterHeureServeur,
    init,
    lock,
    status,
    isLocked: () => status() === 'locked',
    passkeysAvailable,
    exportVault,
    importVault,
    undoRestore,
    canUndoRestore,
    modifiedAt,
    flush: () => queue, // écritures du coffre terminées
    openEnable: () => openDialog('enable'),
    unlockFromHost,
    lockFromHost,
  };
})();
