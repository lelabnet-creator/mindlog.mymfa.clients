/* Contrôleur de l'interface myMFA. Dépend de : jsQR, I18n, OTP, Store, Vault, Lock. */
(function () {
  'use strict';

  const { t } = I18n;
  // Lock.storage : localStorage en clair, ou coffre chiffré une fois le mot de passe maître activé.
  const store = Store.createStore(Lock.storage, Lock.temps);
  const VERSION = '0.4.0';
  const VIEWS = ['home', 'scan', 'new', 'passwords', 'dashboard', 'activity', 'settings'];
  const RING_LENGTH = 2 * Math.PI * 19;
  const EXPIRING_SECONDS = 5;
  const THEME_KEY = 'mymfa.theme';
  const DRIVE_LAST_KEY = 'mymfa.driveLastBackup';
  const EXTENSION_SYNC_KEY = 'mymfa.extensionSync';
  const DRIVE_CLIENT_KEY = 'mymfa.googleClientId';
  // config.js (déploiement) prime ; sinon identifiant collé dans les réglages.
  const DRIVE_DEPLOY_ID = (window.MYMFA_CONFIG && window.MYMFA_CONFIG.googleClientId) || '';
  // L'extension, quand elle embarque l'app (voir lock.js) : jeton Drive, verrou partagé.
  const HOST = window.MYMFA_HOST || null;
  const CLIENT_ID_RE = /^[\w-]+\.apps\.googleusercontent\.com$/;
  const HIDE_KEY = 'mymfa.hideCodes';
  // Préférences en clair (lues avant le déverrouillage), copiées aussi dans le coffre pour que la
  // sauvegarde Drive et l'export chiffré les emportent. PREFS_AT_KEY : date du dernier changement
  // local, sans contenu, pour savoir qui l'emporte au déverrouillage.
  const PREFS_AT_KEY = 'mymfa.prefsAt';
  const MIRRORED_PREFS = { theme: 'mymfa.theme', locale: 'mymfa.locale', hideCodes: 'mymfa.hideCodes', autoLock: 'mymfa.autoLock', googleClientId: 'mymfa.googleClientId' };
  const OTPAUTH_RE = /^\s*otpauth(-migration)?:/i;

  const state = {
    view: 'home',
    search: '',
    filter: '', // '' | 'fav' | nom de tag
    activityFilter: '',
    codes: new Map(), // id → { step, code, secret } : cache entre deux secondes
    revealed: new Map(), // id → step pendant lequel le code masqué est affiché
    draft: { source: 'key', tag: '', newTag: false },
    editingId: null,
    lastBadQr: '',
  };

  const $ = (id) => document.getElementById(id);
  const el = {
    banner: $('insecure-banner'),
    navLinks: document.querySelectorAll('[data-nav]'),
    views: document.querySelectorAll('[data-view]'),
    searchToggle: $('btn-search-toggle'),
    searchWrap: $('search-wrap'),
    search: $('search'),
    filters: $('filters'),
    accounts: $('accounts'),
    accountsEmpty: $('accounts-empty'),
    firstRun: $('first-run'),
    cardTpl: $('tpl-card'),
    viewfinder: $('viewfinder'),
    video: $('camera'),
    cameraBtn: $('btn-camera'),
    scanStatus: $('scan-status'),
    qrFile: $('qr-file'),
    newHero: $('new-hero'),
    form: $('add-form'),
    secretField: $('secret-field'),
    secret: $('f-secret'),
    issuer: $('f-issuer'),
    account: $('f-account'),
    newTile: $('new-tile'),
    tagChips: $('tag-chips'),
    newTag: $('f-tag-new'),
    description: $('f-description'),
    preview: $('code-preview'),
    previewCode: $('preview-code'),
    previewHint: $('preview-hint'),
    previewRing: $('preview-ring'),
    advanced: $('advanced'),
    paramsSummary: $('params-summary'),
    type: $('f-type'),
    algorithm: $('f-algorithm'),
    digits: $('f-digits'),
    period: $('f-period'),
    counter: $('f-counter'),
    addError: $('add-error'),
    activity: $('activity'),
    activityEmpty: $('activity-empty'),
    activityFilters: $('activity-filters'),
    clearHistory: $('btn-clear-history'),
    themeButtons: document.querySelectorAll('[data-theme-value]'),
    themeHint: $('theme-hint'),
    lang: $('lang'),
    hideSwitch: $('switch-hide'),
    exportBtn: $('btn-export'),
    importFile: $('import-file'),
    settingsFoot: $('settings-foot'),
    tagList: $('tag-list'),
    dialog: $('edit-dialog'),
    editForm: $('edit-form'),
    deleteConfirm: $('delete-confirm'),
    toast: $('toast'),
  };

  /* ───────────── Utilitaires ───────────── */

  function h(tag, attrs = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? '' : value);
    }
    for (const child of [].concat(children)) {
      if (child) node.append(child);
    }
    return node;
  }

  function readPref(key) {
    try {
      return localStorage.getItem(key);
    } catch {
      return null;
    }
  }

  function writePref(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch {
      /* stockage indisponible : préférence non mémorisée */
    }
  }

  /* Préférences ↔ coffre */

  function snapshotPrefs() {
    const out = {};
    for (const [name, key] of Object.entries(MIRRORED_PREFS)) {
      const value = readPref(key);
      if (value !== null) out[name] = value;
    }
    return out;
  }

  /** Une préférence a changé ici : la copie du coffre suit, s'il est lisible. */
  function notePrefsChanged() {
    writePref(PREFS_AT_KEY, new Date().toISOString());
    if (!Lock.isLocked()) savePrefsToVault();
  }

  function savePrefsToVault() {
    try {
      store.setSetting('prefs', snapshotPrefs());
    } catch {
      /* coffre verrouillé entre-temps : la copie suivra au prochain déverrouillage */
    }
  }

  /**
   * Au déverrouillage (et donc après une restauration) : la copie du coffre, si elle est plus récente
   * que les préférences de cet appareil, les remplace ; sinon c'est elle qui est mise à jour.
   */
  function syncPrefsWithVault() {
    const entry = store.settings().prefs;
    const localAt = readPref(PREFS_AT_KEY);
    if (!entry || !entry.value || (localAt && localAt >= (entry.at || ''))) return savePrefsToVault();
    for (const [name, key] of Object.entries(MIRRORED_PREFS)) {
      if (typeof entry.value[name] === 'string') writePref(key, entry.value[name]);
    }
    writePref(PREFS_AT_KEY, entry.at);
    applyTheme(currentTheme());
    el.hideSwitch.setAttribute('aria-checked', String(readPref(HIDE_KEY) === '1'));
    if (entry.value.locale && entry.value.locale !== I18n.getLocale()) I18n.setLocale(entry.value.locale);
  }

  function errorMessage(err) {
    if (err && err.code) return t(`error.${err.code}`, err.params || {});
    return t('error.generic', { message: (err && err.message) || String(err) });
  }

  let toastTimer = null;
  function toast(message) {
    el.toast.textContent = message;
    el.toast.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (el.toast.hidden = true), 2600);
  }

  function displayName(account) {
    return account.issuer || account.account || t('list.noName');
  }

  /** 123456 → « 123 456 », 12345678 → « 1234 5678 ». */
  function formatCode(code) {
    const half = Math.floor(code.length / 2);
    return `${code.slice(0, half)} ${code.slice(half)}`;
  }

  function maskCode(digits) {
    const half = Math.floor(digits / 2);
    return `${'•'.repeat(half)} ${'•'.repeat(digits - half)}`;
  }

  function formatSecret(secret) {
    return OTP.normalizeSecret(secret).replace(/(.{4})(?=.)/g, '$1 ');
  }

  function tagLabel(tag) {
    return tag ? tag.charAt(0).toUpperCase() + tag.slice(1) : '';
  }

  /** Initiales du service : « Google Cloud » → GC, « GitHub » → GH, « Proton » → PR. */
  function initials(name) {
    const words = String(name || '?').trim().split(/[\s._-]+/).filter(Boolean);
    if (words.length > 1) return (words[0][0] + words[1][0]).toUpperCase();
    const word = words[0] || '?';
    const inner = word.slice(1).match(/[A-Z]/);
    return (word[0] + (inner ? inner[0] : word.slice(1, 2))).toUpperCase();
  }

  /** Couleur stable par service, lisible sur la tuile blanche. */
  function brandColor(name) {
    let hash = 0;
    for (const ch of String(name || '').toLowerCase()) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
    return `hsl(${hash % 360} 62% 36%)`;
  }

  function paintTile(tile, name) {
    tile.textContent = initials(name);
    tile.style.color = brandColor(name);
  }

  function setRing(ring, remaining, period, label) {
    const value = ring.querySelector('.ring-value');
    value.style.strokeDasharray = String(RING_LENGTH);
    value.style.strokeDashoffset = String(RING_LENGTH * (1 - remaining / period));
    ring.querySelector('.ring-secs').textContent = String(remaining);
    ring.classList.toggle('is-expiring', remaining <= EXPIRING_SECONDS);
    if (label) ring.setAttribute('aria-label', label);
  }

  async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return;
    }
    const area = h('textarea', { class: 'visually-hidden', readonly: true });
    area.value = text;
    document.body.append(area);
    area.select();
    const ok = document.execCommand('copy');
    area.remove();
    if (!ok) throw new Error('copy');
  }

  /* ───────────── Thème ───────────── */

  const darkQuery = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

  function currentTheme() {
    const saved = readPref(THEME_KEY);
    return saved === 'light' || saved === 'dark' ? saved : 'auto';
  }

  function applyTheme(theme) {
    if (theme === 'auto') delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = theme;
    const dark = theme === 'dark' || (theme === 'auto' && (!darkQuery || darkQuery.matches));
    document.querySelector('meta[name="theme-color"]').setAttribute('content', dark ? '#070B13' : '#F2F5F9');
    el.themeButtons.forEach((button) => {
      button.setAttribute('aria-checked', String(button.dataset.themeValue === theme));
    });
    const mode = t(dark ? 'settings.modeDark' : 'settings.modeLight');
    el.themeHint.textContent = theme === 'auto' ? t('settings.themeHintAuto', { mode }) : t(`settings.themeHint.${theme}`);
  }

  function setupTheme() {
    el.themeButtons.forEach((button) =>
      button.addEventListener('click', () => {
        writePref(THEME_KEY, button.dataset.themeValue);
        applyTheme(button.dataset.themeValue);
        notePrefsChanged();
      })
    );
    if (darkQuery) darkQuery.addEventListener('change', () => applyTheme(currentTheme()));
    applyTheme(currentTheme());
  }

  /* ───────────── Langue ───────────── */

  function setupLanguages() {
    el.lang.replaceChildren(...I18n.locales().map(({ code, name }) => h('option', { value: code, text: name })));
    el.lang.value = I18n.getLocale();
    el.lang.addEventListener('change', () => {
      I18n.setLocale(el.lang.value);
      notePrefsChanged();
    });
    I18n.onChange(() => {
      el.lang.value = I18n.getLocale();
      I18n.apply(document);
      applyTheme(currentTheme());
      renderAll();
      renderDraft();
    });
  }

  /* ───────────── Navigation ───────────── */

  function route() {
    // « #/passwords/<id> » : la vue, puis l'élément choisi.
    const [name, arg] = (location.hash.replace(/^#\/?/, '') || 'home').split('/');
    showView(VIEWS.includes(name) ? name : 'home');
    if (name === 'passwords') Credentials.show(arg || null);
    if (name === 'dashboard') Dashboard.render();
    if (name === 'settings' && arg === 'import') pointToImport();
  }

  /** « #/settings/import » (lien du popup de l'extension) : la ligne Importer, en évidence. */
  function pointToImport() {
    const row = document.querySelector('label[for="import-file"]');
    row.scrollIntoView({ block: 'center' });
    row.focus({ preventScroll: true });
    row.classList.remove('row-flash');
    void row.offsetWidth; // relance l'animation
    row.classList.add('row-flash');
  }

  function showView(view) {
    const previous = state.view;
    state.view = view;
    el.views.forEach((section) => (section.hidden = section.dataset.view !== view));
    el.navLinks.forEach((link) => {
      // Mobile : le tableau de bord s'ouvre depuis Activité, qui reste allumée.
      const dashboardFromActivity = view === 'dashboard' && link.dataset.nav === 'activity' && !window.matchMedia('(min-width: 900px)').matches;
      const active = link.dataset.nav === view || (view === 'new' && link.dataset.nav === 'scan') || dashboardFromActivity;
      if (active) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
    if (previous === 'scan' && view !== 'scan') stopCamera();
    if (view === 'scan' && !Lock.isLocked()) {
      if (previous !== 'new') resetDraft();
      state.lastBadQr = '';
      setScanStatus('');
      startCamera();
    }
    if (view === 'new') {
      renderDraft();
      // Saisie manuelle : focus sur la clé. Après un QR, pas de focus (évite d'ouvrir le clavier mobile).
      if (state.draft.source === 'key') el.secret.focus({ preventScroll: true });
    }
    if (view === 'activity') renderActivity();
    if (view === 'home') renderAccounts();
    window.scrollTo(0, 0);
  }

  /* ───────────── Accueil : liste ───────────── */

  function visibleAccounts() {
    const query = state.search.trim().toLowerCase();
    return store.list().filter((a) => {
      if (state.filter === 'fav' && !a.favorite) return false;
      if (state.filter && state.filter !== 'fav' && a.tag !== state.filter) return false;
      if (!query) return true;
      return [a.issuer, a.account, a.description, a.tag].some((v) => (v || '').toLowerCase().includes(query));
    });
  }

  function renderFilters() {
    const tags = store.tags();
    if (state.filter && state.filter !== 'fav' && !tags.includes(state.filter)) state.filter = '';
    const options = [
      { value: '', label: t('list.allTags') },
      { value: 'fav', label: t('list.favorites') },
      ...tags.map((tag) => ({ value: tag, label: tagLabel(tag) })),
    ];
    el.filters.replaceChildren(
      ...options.map((o) =>
        h('button', {
          type: 'button',
          class: 'chip',
          'aria-pressed': String(state.filter === o.value),
          text: o.label,
          onclick: () => {
            state.filter = o.value;
            renderFilters();
            renderAccounts();
          },
        })
      )
    );
    el.filters.hidden = store.list().length === 0;
    el.tagList.replaceChildren(...tags.map((tag) => h('option', { value: tag })));
  }

  function accountCard(account) {
    const node = el.cardTpl.content.firstElementChild.cloneNode(true);
    const name = displayName(account);
    node.dataset.id = account.id;
    paintTile(node.querySelector('.tile'), name);
    node.querySelector('.card-issuer').textContent = name;
    node.querySelector('.card-account').textContent = account.issuer ? account.account : '';
    node.querySelectorAll('[data-action="edit"]').forEach((b) => b.setAttribute('aria-label', t('list.edit', { name })));
    const desc = node.querySelector('.card-desc');
    const descText = [account.tag ? `#${account.tag}` : '', account.description].filter(Boolean).join(' · ');
    desc.textContent = descText;
    desc.hidden = !descText;
    const star = node.querySelector('[data-action="fav"]');
    star.setAttribute('aria-pressed', String(Boolean(account.favorite)));
    star.setAttribute('aria-label', t(account.favorite ? 'list.favRemove' : 'list.favAdd', { name }));
    node.querySelector('[data-action="copy"]').setAttribute('aria-label', t('list.copy', { name }));
    const hotp = account.type === 'hotp';
    node.querySelector('.ring').hidden = hotp;
    const next = node.querySelector('[data-action="next"]');
    next.hidden = !hotp;
    next.setAttribute('aria-label', t('list.next'));
    const cached = state.codes.get(account.id);
    node.querySelector('.code').textContent = cached ? formatCode(cached.code) : maskCode(account.digits);
    return node;
  }

  function renderAccounts() {
    const all = store.list();
    const visible = visibleAccounts();
    el.accounts.replaceChildren(...visible.map(accountCard));
    el.firstRun.hidden = all.length > 0;
    el.accountsEmpty.hidden = all.length === 0 || visible.length > 0;
    el.accountsEmpty.textContent = state.filter === 'fav' && !state.search ? t('list.noFav') : t('list.noMatch');
    tick();
  }

  async function onCardAction(event) {
    const button = event.target.closest('[data-action]');
    const card = event.target.closest('.card');
    if (!button || !card) return;
    const account = store.get(card.dataset.id);
    if (!account) return;
    switch (button.dataset.action) {
      case 'edit':
        openEdit(account.id);
        break;
      case 'fav':
        store.update(account.id, { favorite: !account.favorite });
        renderAccounts();
        break;
      case 'next':
        store.update(account.id, { counter: account.counter + 1 });
        renderAccounts();
        break;
      case 'code':
        if (isMasked(account)) {
          state.revealed.set(account.id, stepOf(account));
          tick();
          break;
        }
        copyCode(account);
        break;
      case 'copy':
        copyCode(account);
        break;
    }
  }

  /* ───────────── Codes ───────────── */

  function stepOf(account, now = Date.now()) {
    return account.type === 'hotp' ? `c${account.counter}` : Math.floor(now / 1000 / account.period);
  }

  function isMasked(account) {
    return el.hideSwitch.getAttribute('aria-checked') === 'true' && state.revealed.get(account.id) !== stepOf(account);
  }

  async function computeCode(account, now) {
    const step = stepOf(account, now);
    const cached = state.codes.get(account.id);
    if (cached && cached.step === step && cached.secret === account.secret) return cached.code;
    const code = account.type === 'hotp'
      ? await OTP.hotp(account.secret, account.counter, account)
      : await OTP.totp(account.secret, { ...account, timestamp: now });
    state.codes.set(account.id, { step, code, secret: account.secret });
    return code;
  }

  let ticking = false;
  let tickAgain = false;
  async function tick() {
    if (Lock.isLocked()) return;
    // Un rendu pendant un calcul en cours relance un tour juste après, au lieu d'attendre la seconde suivante.
    if (ticking) {
      tickAgain = true;
      return;
    }
    ticking = true;
    try {
      const now = Date.now();
      if (state.view === 'home') {
        const byId = new Map(store.list().map((a) => [a.id, a]));
        for (const card of el.accounts.children) {
          const account = byId.get(card.dataset.id);
          if (!account) continue;
          const codeButton = card.querySelector('.code');
          let expiring = false;
          if (account.type !== 'hotp') {
            const remaining = OTP.remainingSeconds(account.period, now);
            expiring = remaining <= EXPIRING_SECONDS;
            setRing(card.querySelector('.ring'), remaining, account.period, t('list.remaining', { count: remaining }));
          }
          try {
            const code = await computeCode(account, now);
            const masked = isMasked(account);
            const text = masked ? maskCode(code.length) : formatCode(code);
            if (codeButton.textContent !== text) codeButton.textContent = text;
            const name = displayName(account);
            codeButton.setAttribute('aria-label', t(masked ? 'list.reveal' : 'list.copy', { name }));
            codeButton.classList.toggle('is-masked', masked);
            codeButton.classList.toggle('is-expiring', expiring && !masked);
            codeButton.classList.remove('is-error');
          } catch (err) {
            codeButton.textContent = errorMessage(err);
            codeButton.classList.add('is-error');
          }
        }
      }
      if (state.view === 'new') await updatePreview(now);
    } finally {
      ticking = false;
      if (tickAgain) {
        tickAgain = false;
        tick();
      }
    }
  }

  function startClock() {
    const loop = () => {
      tick();
      setTimeout(loop, 1000 - (Date.now() % 1000) + 5);
    };
    loop();
  }

  async function copyCode(account) {
    try {
      const code = await computeCode(account, Date.now());
      await copyText(code);
      store.log('copy', account);
      toast(t('toast.copied', { name: displayName(account) }));
      const card = el.accounts.querySelector(`[data-id="${CSS.escape(account.id)}"]`);
      if (card) {
        card.classList.add('is-copied');
        setTimeout(() => card.classList.remove('is-copied'), 1600);
      }
    } catch (err) {
      toast(err && err.code ? errorMessage(err) : t('error.clipboard'));
    }
  }

  /* ───────────── Scanner ───────────── */

  let stream = null;
  let scanTimer = null;
  const scanCanvas = document.createElement('canvas');
  const scanCtx = scanCanvas.getContext('2d', { willReadFrequently: true });

  function setScanStatus(message, kind) {
    el.scanStatus.textContent = message || '';
    el.scanStatus.dataset.kind = kind || '';
  }

  async function startCamera() {
    if (stream) return;
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      setScanStatus(t('error.noCamera'));
      return;
    }
    try {
      const media = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } }, audio: false });
      if (state.view !== 'scan') {
        media.getTracks().forEach((track) => track.stop());
        return;
      }
      stream = media;
      el.video.srcObject = stream;
      await el.video.play();
      el.viewfinder.classList.add('is-live');
      setScanStatus(t('scan.searching'));
      scanLoop();
    } catch (err) {
      stopCamera();
      setScanStatus(t(err && err.name === 'NotAllowedError' ? 'error.cameraDenied' : 'error.noCamera'));
    }
  }

  function stopCamera() {
    clearTimeout(scanTimer);
    if (stream) stream.getTracks().forEach((track) => track.stop());
    stream = null;
    el.video.srcObject = null;
    el.viewfinder.classList.remove('is-live');
  }

  function scanLoop() {
    if (!stream) return;
    const video = el.video;
    if (video.readyState >= 2 && video.videoWidth) {
      const scale = Math.min(1, 640 / Math.max(video.videoWidth, video.videoHeight));
      scanCanvas.width = Math.round(video.videoWidth * scale);
      scanCanvas.height = Math.round(video.videoHeight * scale);
      scanCtx.drawImage(video, 0, 0, scanCanvas.width, scanCanvas.height);
      const { data, width, height } = scanCtx.getImageData(0, 0, scanCanvas.width, scanCanvas.height);
      const result = jsQR(data, width, height, { inversionAttempts: 'dontInvert' });
      if (result && result.data && onQrText(result.data, true)) return;
    }
    scanTimer = setTimeout(scanLoop, 220);
  }

  /** Traite le contenu d'un QR ou d'un lien otpauth ; true si un compte a été reconnu. */
  function onQrText(text, fromCamera, source = 'qr') {
    if (!OTPAUTH_RE.test(text)) {
      if (state.lastBadQr !== text) setScanStatus(t('error.qrNotOtp'), 'error');
      state.lastBadQr = text;
      return false;
    }
    try {
      fillDraft(OTP.parseOtpauthUri(text), source);
    } catch (err) {
      if (state.lastBadQr !== text) setScanStatus(errorMessage(err), 'error');
      state.lastBadQr = text;
      return false;
    }
    if (fromCamera) stopCamera();
    location.hash = '#/new';
    return true;
  }

  function loadImage(blob) {
    return new Promise((resolve, reject) => {
      const url = URL.createObjectURL(blob);
      const img = new Image();
      img.onload = () => {
        URL.revokeObjectURL(url);
        resolve(img);
      };
      img.onerror = () => {
        URL.revokeObjectURL(url);
        reject(Object.assign(new Error('imageLoad'), { code: 'imageLoad' }));
      };
      img.src = url;
    });
  }

  /** Essaie plusieurs tailles : jsQR échoue parfois sur les très grandes captures. */
  function scanImage(img) {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    const longest = Math.max(img.naturalWidth, img.naturalHeight);
    const targets = [Math.min(longest, 1600), 800, 400].filter((s, i, arr) => s <= longest && arr.indexOf(s) === i);
    for (const target of targets) {
      const scale = target / longest;
      canvas.width = Math.max(1, Math.round(img.naturalWidth * scale));
      canvas.height = Math.max(1, Math.round(img.naturalHeight * scale));
      ctx.fillStyle = '#fff'; // fond blanc pour les PNG transparents
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      const { data, width, height } = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const result = jsQR(data, width, height, { inversionAttempts: 'attemptBoth' });
      if (result && result.data) return result.data;
    }
    return null;
  }

  async function handleImage(blob) {
    if (state.view !== 'scan') location.hash = '#/scan';
    setScanStatus(t('scan.decoding'));
    try {
      const text = scanImage(await loadImage(blob));
      if (!text) {
        setScanStatus(t('error.qrNotFound'), 'error');
        return;
      }
      state.lastBadQr = '';
      onQrText(text, false);
    } catch (err) {
      setScanStatus(errorMessage(err), 'error');
    }
  }

  async function pasteFromClipboard() {
    try {
      if (!navigator.clipboard || !navigator.clipboard.read) throw new Error('unsupported');
      for (const item of await navigator.clipboard.read()) {
        const type = item.types.find((ty) => ty.startsWith('image/'));
        if (type) {
          handleImage(await item.getType(type));
          return;
        }
        if (item.types.includes('text/plain')) {
          const text = await (await item.getType('text/plain')).text();
          if (OTPAUTH_RE.test(text)) {
            onQrText(text, false, 'uri');
            return;
          }
        }
      }
      setScanStatus(t('error.clipboardEmpty'), 'error');
    } catch {
      setScanStatus(t('error.clipboardRead'), 'error');
    }
  }

  function setupScanner() {
    el.cameraBtn.addEventListener('click', startCamera);
    $('btn-pick-image').addEventListener('click', () => el.qrFile.click());
    $('btn-paste').addEventListener('click', pasteFromClipboard);
    el.qrFile.addEventListener('change', () => {
      const file = el.qrFile.files[0];
      el.qrFile.value = '';
      if (file) handleImage(file);
    });
    $('link-manual').addEventListener('click', () => resetDraft());

    ['dragenter', 'dragover'].forEach((type) =>
      el.viewfinder.addEventListener(type, (event) => {
        event.preventDefault();
        el.viewfinder.classList.add('is-over');
      })
    );
    ['dragleave', 'drop'].forEach((type) =>
      el.viewfinder.addEventListener(type, () => el.viewfinder.classList.remove('is-over'))
    );
    el.viewfinder.addEventListener('drop', (event) => {
      event.preventDefault();
      const file = [...event.dataTransfer.files].find((f) => f.type.startsWith('image/'));
      if (file) handleImage(file);
    });

    // Collage n'importe où : image → QR ; texte otpauth (hors champ de saisie) → nouveau compte.
    document.addEventListener('paste', (event) => {
      const data = event.clipboardData;
      if (!data || el.dialog.open) return;
      const image = [...data.items].find((item) => item.kind === 'file' && item.type.startsWith('image/'));
      if (image) {
        event.preventDefault();
        handleImage(image.getAsFile());
        return;
      }
      const text = data.getData('text');
      const inField = event.target.closest && event.target.closest('input, textarea');
      if (text && OTPAUTH_RE.test(text) && (!inField || event.target === el.secret)) {
        event.preventDefault();
        onQrText(text, false, 'uri');
      }
    });
  }

  /* ───────────── Nouveau compte ───────────── */

  function resetDraft() {
    el.form.reset();
    state.draft = { source: 'key', tag: '', newTag: false };
    el.newTag.value = '';
    showAddError('');
    el.advanced.open = false;
  }

  /** Pré-remplit le formulaire depuis une URI otpauth:// parsée. */
  function fillDraft(parsed, source) {
    resetDraft();
    state.draft.source = source;
    el.secret.value = formatSecret(parsed.secret);
    el.issuer.value = parsed.issuer;
    el.account.value = parsed.account;
    el.type.value = parsed.type;
    el.algorithm.value = parsed.algorithm;
    el.digits.value = String(parsed.digits);
    el.period.value = String(parsed.period);
    el.counter.value = String(parsed.counter);
    // Paramètres non standard : on ouvre la section pour que ça se voie.
    el.advanced.open = parsed.type !== 'totp' || parsed.algorithm !== 'SHA1' || parsed.digits !== 6 || parsed.period !== 30;
    renderDraft();
  }

  function draftAccount() {
    return {
      type: el.type.value,
      issuer: el.issuer.value.trim(),
      account: el.account.value.trim(),
      secret: OTP.normalizeSecret(el.secret.value),
      algorithm: el.algorithm.value,
      digits: parseInt(el.digits.value, 10),
      period: Math.max(1, parseInt(el.period.value, 10) || 30),
      counter: Math.max(0, parseInt(el.counter.value, 10) || 0),
      tag: state.draft.newTag ? el.newTag.value : state.draft.tag,
      description: el.description.value,
    };
  }

  function renderDraft() {
    const recognized = state.draft.source === 'qr' || state.draft.source === 'uri';
    el.newHero.hidden = !recognized;
    $('new-hero-title').textContent = t(state.draft.source === 'uri' ? 'new.recognizedUri' : 'new.recognized');
    el.secretField.hidden = recognized;
    paintTile(el.newTile, el.issuer.value || el.account.value || '?');
    document.querySelectorAll('[data-for-type]').forEach((node) => {
      node.hidden = node.dataset.forType !== el.type.value;
    });
    const d = draftAccount();
    el.paramsSummary.textContent = t(d.type === 'hotp' ? 'new.summaryHotp' : 'new.summaryTotp', {
      algorithm: d.algorithm,
      digits: d.digits,
      period: d.period,
      counter: d.counter,
    });
    renderTagChips();
    updatePreview(Date.now());
  }

  function renderTagChips() {
    const tags = store.tags();
    const chips = tags.map((tag) =>
      h('button', {
        type: 'button',
        class: 'chip',
        'aria-pressed': String(!state.draft.newTag && state.draft.tag === tag),
        text: tagLabel(tag),
        onclick: () => {
          state.draft.tag = state.draft.tag === tag && !state.draft.newTag ? '' : tag;
          state.draft.newTag = false;
          renderTagChips();
        },
      })
    );
    chips.push(
      h('button', {
        type: 'button',
        class: 'chip chip-dashed',
        'aria-pressed': String(state.draft.newTag),
        onclick: () => {
          state.draft.newTag = !state.draft.newTag;
          renderTagChips();
          if (state.draft.newTag) el.newTag.focus();
        },
      }, [svgPlus(), document.createTextNode(t('field.newTag'))])
    );
    el.tagChips.replaceChildren(...chips);
    el.newTag.hidden = !state.draft.newTag;
  }

  function svgPlus() {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', 'M12 5v14M5 12h14');
    svg.append(path);
    return svg;
  }

  async function updatePreview(now) {
    const d = draftAccount();
    if (!OTP.isValidSecret(d.secret)) {
      el.preview.hidden = true;
      return;
    }
    try {
      const code = d.type === 'hotp' ? await OTP.hotp(d.secret, d.counter, d) : await OTP.totp(d.secret, { ...d, timestamp: now });
      el.preview.hidden = false;
      el.previewCode.textContent = formatCode(code);
      el.previewHint.textContent = d.issuer ? t('new.currentCodeHint', { issuer: d.issuer }) : t('new.currentCodeHintGeneric');
      el.previewRing.hidden = d.type === 'hotp';
      if (d.type !== 'hotp') {
        const remaining = OTP.remainingSeconds(d.period, now);
        setRing(el.previewRing, remaining, d.period, t('list.remaining', { count: remaining }));
        el.preview.classList.toggle('is-expiring', remaining <= EXPIRING_SECONDS);
      }
    } catch {
      el.preview.hidden = true;
    }
  }

  function showAddError(message) {
    el.addError.textContent = message || '';
    el.addError.hidden = !message;
  }

  function onAddSubmit(event) {
    event.preventDefault();
    showAddError('');
    if (OTPAUTH_RE.test(el.secret.value)) {
      onQrText(el.secret.value, false, 'uri');
      return;
    }
    const data = draftAccount();
    try {
      OTP.base32Decode(data.secret);
    } catch (err) {
      showAddError(errorMessage(err));
      el.secretField.hidden = false;
      el.secret.focus();
      return;
    }
    if (store.findDuplicate(data.secret, data.issuer, data.account)) {
      showAddError(t('error.duplicate'));
      return;
    }
    store.add(data, state.draft.source);
    resetDraft();
    toast(t('toast.added'));
    location.hash = '#/';
    renderFilters();
  }

  function setupNewAccount() {
    el.form.addEventListener('submit', onAddSubmit);
    el.secret.addEventListener('input', () => {
      if (OTPAUTH_RE.test(el.secret.value)) {
        onQrText(el.secret.value, false, 'uri');
        return;
      }
      if (state.draft.source === 'uri') state.draft.source = 'key';
      renderDraft();
    });
    [el.issuer, el.account, el.type, el.algorithm, el.digits, el.period, el.counter].forEach((input) =>
      input.addEventListener('input', renderDraft)
    );
  }

  /* ───────────── Édition ───────────── */

  function openEdit(id) {
    const account = store.get(id);
    if (!account) return;
    state.editingId = id;
    const f = el.editForm.elements;
    f.issuer.value = account.issuer;
    f.account.value = account.account;
    f.tag.value = account.tag;
    f.description.value = account.description;
    $('e-secret').textContent = formatSecret(account.secret);
    $('e-uri').textContent = OTP.buildOtpauthUri(account);
    el.deleteConfirm.hidden = true;
    el.editForm.querySelector('.advanced').open = false;
    el.dialog.showModal();
  }

  function closeEdit() {
    state.editingId = null;
    el.dialog.close();
  }

  function setupEdit() {
    el.accounts.addEventListener('click', onCardAction);
    el.editForm.addEventListener('submit', (event) => {
      event.preventDefault();
      if (!state.editingId) return;
      const f = el.editForm.elements;
      try {
        store.update(state.editingId, {
          issuer: f.issuer.value,
          account: f.account.value,
          tag: f.tag.value,
          description: f.description.value,
        });
        toast(t('toast.updated'));
      } catch (err) {
        toast(errorMessage(err));
      }
      closeEdit();
      renderAll();
    });
    $('btn-cancel-edit').addEventListener('click', closeEdit);
    $('btn-delete').addEventListener('click', () => {
      el.deleteConfirm.hidden = false;
      $('btn-delete-no').focus();
    });
    $('btn-delete-no').addEventListener('click', () => (el.deleteConfirm.hidden = true));
    $('btn-delete-yes').addEventListener('click', () => {
      if (state.editingId) {
        store.remove(state.editingId);
        state.codes.delete(state.editingId);
        toast(t('toast.deleted'));
      }
      closeEdit();
      renderAll();
    });
    el.dialog.addEventListener('close', () => (state.editingId = null));
    el.dialog.addEventListener('click', (event) => {
      if (event.target === el.dialog) closeEdit();
    });
  }

  /* ───────────── Activité ───────────── */

  const TRANSFER = ['import', 'export'];

  function matchesActivity(entry, filter) {
    return !filter || entry.action === filter || (filter === 'transfer' && TRANSFER.includes(entry.action));
  }

  function historyDetails(entry) {
    const d = entry.details;
    if (!d) return '';
    if (typeof d === 'string') return d;
    // Mot de passe ou passkey : la nature, puis l'origine (jamais le secret, absent de l'historique).
    if (d.kind) return [t(`history.kind.${d.kind}`), d.source ? t(`history.source.${d.source}`) : ''].filter(Boolean).join(' · ');
    if (d.source) return t(`history.source.${d.source}`);
    if (d.changes) {
      return d.changes
        .map((c) => t('history.change', { field: t(`field.${c.field}`), from: c.from, to: c.to }))
        .join(' · ');
    }
    if ('added' in d) return t('history.imported', d);
    if (d.event) return t(`activity.security.${d.event}`);
    return '';
  }

  function dayLabel(date) {
    const today = new Date();
    const startOf = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
    const diff = Math.round((startOf(today) - startOf(date)) / 86400000);
    if (diff === 0) return t('activity.today');
    if (diff === 1) return t('activity.yesterday');
    const options = { day: 'numeric', month: 'long' };
    if (date.getFullYear() !== today.getFullYear()) options.year = 'numeric';
    return new Intl.DateTimeFormat(I18n.getLocale(), options).format(date);
  }

  const ACTIVITY_ICONS = {
    create: 'M12 5v14M5 12h14',
    update: 'M4 20h4L18.5 9.5a2.1 2.1 0 0 0-4-4L4 16v4z',
    delete: 'M4 7h16M6 7l1 13h10l1-13M9 7V4h6v3',
    copy: 'M9 9h12v12H9zM5 15V5a2 2 0 0 1 2-2h10',
    import: 'M7 4v13M3 13l4 4 4-4M17 20V7M13 11l4-4 4 4',
    export: 'M7 4v13M3 13l4 4 4-4M17 20V7M13 11l4-4 4 4',
    security: 'M12 3 4 6v6c0 4.5 3.4 8.3 8 9 4.6-.7 8-4.5 8-9V6zM8.5 12l2.5 2.5 4.5-5',
  };

  function activityIcon(action) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', ACTIVITY_ICONS[action] || ACTIVITY_ICONS.update);
    svg.append(path);
    return h('span', { class: `activity-icon kind-${TRANSFER.includes(action) ? 'transfer' : action}` }, svg);
  }

  function renderActivityFilters() {
    const options = ['', 'create', 'update', 'delete', 'copy', 'transfer'];
    el.activityFilters.replaceChildren(
      ...options.map((value) =>
        h('button', {
          type: 'button',
          class: 'chip',
          'aria-pressed': String(state.activityFilter === value),
          text: t(`activity.filter.${value || 'all'}`),
          onclick: () => {
            state.activityFilter = value;
            renderActivityFilters();
            renderActivity();
          },
        })
      )
    );
  }

  function renderActivity() {
    const entries = store.history().filter((e) => matchesActivity(e, state.activityFilter));
    const timeFormat = new Intl.DateTimeFormat(I18n.getLocale(), { hour: '2-digit', minute: '2-digit' });
    const groups = [];
    for (const entry of entries) {
      const date = new Date(entry.at);
      const label = dayLabel(date);
      let group = groups[groups.length - 1];
      if (!group || group.label !== label) {
        group = { label, items: [] };
        groups.push(group);
      }
      const details = historyDetails(entry);
      const format = entry.details && Importers.FORMATS[entry.details.format];
      const subject = format
        ? t('activity.subject.importFrom', { name: format.name })
        : TRANSFER.includes(entry.action) || entry.action === 'security'
        ? t(`activity.subject.${entry.action}`)
        : entry.label || t('list.noName');
      group.items.push(
        h('li', { class: 'activity-item' }, [
          activityIcon(entry.action),
          h('div', { class: 'activity-body' }, [
            h('div', { class: 'activity-top' }, [
              h('span', { class: 'activity-subject', text: subject }),
              h('time', { datetime: entry.at, text: timeFormat.format(date) }),
            ]),
            h('div', { class: 'activity-line' }, [
              h('span', { text: t(`activity.verb.${entry.action}`) }),
              entry.tag ? h('span', { class: 'tag', text: tagLabel(entry.tag) }) : null,
            ]),
            details ? h('span', { class: 'activity-detail', text: details }) : null,
          ]),
        ])
      );
    }
    el.activity.replaceChildren(
      ...groups.map((g) => h('section', { class: 'activity-group' }, [h('h2', { class: 'section-label', text: g.label }), h('ol', { class: 'panel activity-list' }, g.items)]))
    );
    el.activityEmpty.hidden = entries.length > 0;
  }

  function setupActivity() {
    // Double appui de confirmation plutôt qu'une boîte de dialogue native.
    let armed = null;
    el.clearHistory.addEventListener('click', () => {
      if (!armed) {
        el.clearHistory.classList.add('is-armed');
        toast(t('activity.clearConfirm'));
        armed = setTimeout(() => {
          armed = null;
          el.clearHistory.classList.remove('is-armed');
        }, 3000);
        return;
      }
      clearTimeout(armed);
      armed = null;
      el.clearHistory.classList.remove('is-armed');
      store.clearHistory();
      renderActivity();
      toast(t('toast.historyCleared'));
    });
  }

  /* ───────────── Réglages ───────────── */

  function setupSettings() {
    const hide = readPref(HIDE_KEY) === '1';
    el.hideSwitch.setAttribute('aria-checked', String(hide));
    el.hideSwitch.addEventListener('click', () => {
      const next = el.hideSwitch.getAttribute('aria-checked') !== 'true';
      el.hideSwitch.setAttribute('aria-checked', String(next));
      writePref(HIDE_KEY, next ? '1' : '0');
      notePrefsChanged();
      state.revealed.clear();
    });

    el.exportBtn.addEventListener('click', () => {
      store.log('export', null);
      const blob = new Blob([JSON.stringify(store.exportAll(), null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = h('a', { href: url, download: `mymfa-export-${new Date().toISOString().slice(0, 10)}.json` });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast(t('toast.exported'));
    });
    // Export du coffre lui-même : chiffré par le mot de passe maître, réimportable tel quel.
    $('btn-export-vault').addEventListener('click', async () => {
      const raw = await Lock.exportVault();
      if (!raw) return;
      const blob = new Blob([raw], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = h('a', { href: url, download: `mymfa-vault-${new Date().toISOString().slice(0, 10)}.json` });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast(t('toast.vaultExported'));
    });
    // Ligne Importer au clavier (le champ fichier est masqué).
    document.querySelector('label[for="import-file"]').addEventListener('keydown', (event) => {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      event.preventDefault();
      el.importFile.click();
    });
    el.importFile.addEventListener('change', async () => {
      const file = el.importFile.files[0];
      el.importFile.value = '';
      if (!file) return;
      try {
        const text = await file.text();
        // Export d'un autre gestionnaire en CSV : le format se reconnaît à son en-tête.
        if (/\.csv$/i.test(file.name) || !/^\s*[{[]/.test(text)) {
          await importOther(text);
          return;
        }
        const payload = JSON.parse(text);
        // Un coffre chiffré (export de coffre, sauvegarde Drive) : remplace le coffre local, puis verrouille.
        if (payload && payload.password && payload.data) {
          await Lock.importVault(JSON.stringify(payload));
          toast(t('toast.vaultImported'));
          renderAll();
          return;
        }
        // Ni coffre ni export myMFA : un JSON d'un autre gestionnaire (Proton Authenticator).
        if (!payload || !Array.isArray(payload.accounts)) {
          await importOther(text);
          return;
        }
        const { added, skipped } = await withProgress(t('importing.running', { name: 'myMFA' }), async () => store.importAll(payload));
        toast(t('toast.imported', { count: added, skipped }));
        renderAll();
      } catch (err) {
        toast(err instanceof SyntaxError ? t('error.invalidImport') : errorMessage(err));
      }
    });
  }

  /**
   * Barre de progression sous la ligne Importer, le temps de task(onProgress), puis du chiffrement
   * du coffre (un import, c'est beaucoup d'écritures). Un import à la fois.
   */
  async function withProgress(label, task) {
    const box = $('import-progress');
    const bar = $('import-progress-bar');
    const text = $('import-progress-text');
    const count = $('import-progress-count');
    const onProgress = (done, total) => {
      bar.max = total || 1;
      bar.value = done;
      count.textContent = total ? t('importing.count', { done, total }) : '';
    };
    text.textContent = label;
    count.textContent = '';
    bar.removeAttribute('value'); // indéterminée tant qu'on ne connaît pas le total
    box.hidden = false;
    el.importFile.disabled = true;
    try {
      const out = await task(onProgress);
      if (Lock.status() !== 'plain') {
        text.textContent = t('importing.encrypting');
        count.textContent = '';
        bar.removeAttribute('value');
        await Lock.flush();
      }
      return out;
    } finally {
      box.hidden = true;
      el.importFile.disabled = false;
    }
  }

  /** Mots de passe et comptes 2FA d'un autre gestionnaire ; les mots de passe exigent le coffre ouvert. */
  async function importOther(text) {
    const result = Importers.parse(text);
    const stats = await withProgress(t('importing.running', { name: result.name }), (onProgress) =>
      Importers.apply(store, result, { logins: Lock.status() === 'unlocked', onProgress })
    );
    const parts = [t(result.passwords ? 'toast.importedFrom' : 'toast.importedAccountsFrom', { name: result.name, ...stats })];
    if (result.ignored.steam) parts.push(t('toast.importSteam', { count: result.ignored.steam }));
    if (stats.needVault) parts.push(t('toast.importNeedVault', { count: stats.needVault }));
    if (stats.logins) parts.push(t('toast.importDeleteFile'));
    toast(parts.join(' '));
    renderAll();
  }

  /* ───────────── Sauvegarde Google Drive ───────────── */

  let driveClient = null;
  let driveClientFor = '';
  // Dans l'extension : politique de sauvegarde automatique (heures) et prochaine échéance, tenues par elle.
  const DRIVE_EVERY_CHOICES = [0, 1, 6, 12, 24, 72, 168];
  let hostDrive = null; // { every, next }
  let pendingRestore = null;
  let editingClientId = false;

  function driveClientId() {
    return DRIVE_DEPLOY_ID || readPref(DRIVE_CLIENT_KEY) || '';
  }

  function drive() {
    const clientId = driveClientId();
    if (!driveClient || driveClientFor !== clientId) {
      // Dans l'extension, pas de script Google distant (interdit en MV3) : le jeton vient de l'hôte.
      const tokens = HOST ? HOST.driveTokens(clientId) : Drive.googleTokenProvider(clientId);
      driveClient = Drive.createClient({ fetch: (...args) => window.fetch(...args), getToken: tokens.getToken });
      driveClientFor = clientId;
    }
    return driveClient;
  }

  function renderDrive() {
    const configured = Boolean(driveClientId());
    const encrypted = Lock.status() !== 'plain';
    const last = readPref(DRIVE_LAST_KEY);
    const modified = Lock.modifiedAt();
    const dateTime = (iso) => I18n.formatDateTime(iso);
    let status;
    let hint;
    if (!configured) {
      status = t('drive.notConfigured');
      hint = t('drive.configureHint');
    } else if (!encrypted) {
      status = t('drive.needsPassword');
      hint = t('drive.privacy');
    } else if (!last) {
      status = t('drive.never');
      hint = t('drive.suggest');
    } else {
      status = t('drive.lastBackup', { date: dateTime(last) });
      hint = modified && modified > last ? t('drive.pending') : t('drive.upToDate');
    }
    $('drive-status').textContent = status;
    $('drive-hint').textContent = hint;
    $('drive-card').classList.toggle('is-suggested', configured && encrypted && (!last || (modified && modified > last)));
    const setup = !configured || editingClientId;
    $('drive-setup').hidden = !setup;
    $('drive-actions').hidden = setup;
    $('drive-origin').textContent = HOST ? t('drive.redirect', { url: HOST.driveRedirect }) : t('drive.origin', { origin: location.origin });
    $('btn-drive-backup').hidden = !encrypted;
    $('btn-drive-enable').hidden = encrypted;
    $('btn-drive-undo').hidden = !Lock.canUndoRestore();
    $('btn-drive-edit').hidden = Boolean(DRIVE_DEPLOY_ID);
    $('drive-confirm').hidden = !pendingRestore;
    if (pendingRestore) {
      $('drive-confirm-text').textContent = t('drive.confirmRestore', { date: dateTime(pendingRestore.modifiedTime) });
    }
    // Sauvegarde automatique : seulement dans l'extension (elle tourne sans l'app ouverte).
    $('drive-every-row').hidden = !(hostDrive && configured && encrypted && !setup);
    if (hostDrive) {
      const select = $('drive-every');
      select.replaceChildren(...DRIVE_EVERY_CHOICES.map((hours) => h('option', { value: String(hours), text: t(`ext.settings.every.${hours}`) })));
      select.value = String(hostDrive.every);
      $('drive-next').textContent = !hostDrive.every
        ? t('drive.everyOff')
        : !hostDrive.next
          ? t('drive.everyFirst')
          : Date.parse(hostDrive.next) > Date.now()
          ? t('ext.settings.driveNext', { date: dateTime(hostDrive.next) })
          : t('ext.settings.driveDue');
    }
  }

  async function busy(button, task) {
    button.disabled = true;
    button.classList.add('is-busy');
    try {
      await task();
    } catch (err) {
      toast(errorMessage(err));
    } finally {
      button.classList.remove('is-busy');
      renderDrive();
    }
  }

  function setupDrive() {
    $('drive-setup').addEventListener('submit', (event) => {
      event.preventDefault();
      const value = $('drive-client-id').value.trim();
      if (value && !CLIENT_ID_RE.test(value)) {
        toast(t('error.invalidClientId'));
        return;
      }
      if (value) writePref(DRIVE_CLIENT_KEY, value);
      else {
        try {
          localStorage.removeItem(DRIVE_CLIENT_KEY);
        } catch {
          /* stockage indisponible */
        }
      }
      if (HOST) HOST.driveClientChanged(value); // le même identifiant pour l'extension
      notePrefsChanged();
      editingClientId = false;
      renderDrive();
    });
    if (HOST) {
      // Réglages Drive de l'extension : son identifiant client (si l'app n'en a pas), sa dernière sauvegarde.
      HOST.ready.then((settings) => {
        if (!settings) return;
        if (settings.driveClientId && !readPref(DRIVE_CLIENT_KEY)) writePref(DRIVE_CLIENT_KEY, settings.driveClientId);
        if (settings.driveLastSync && settings.driveLastSync > (readPref(DRIVE_LAST_KEY) || '')) writePref(DRIVE_LAST_KEY, settings.driveLastSync);
        hostDrive = { every: settings.driveEvery, next: settings.driveNext };
        renderDrive();
      });
      $('drive-every').addEventListener('change', async () => {
        const every = Number($('drive-every').value);
        try {
          const { next } = await HOST.driveEvery(every);
          hostDrive = { every, next };
          toast(t('ext.settings.driveEverySaved'));
        } catch (err) {
          toast(errorMessage(err));
        }
        renderDrive();
      });
    }
    $('btn-drive-edit').addEventListener('click', () => {
      editingClientId = true;
      $('drive-client-id').value = driveClientId();
      renderDrive();
      $('drive-client-id').focus();
    });
    $('btn-drive-enable').addEventListener('click', () => Lock.openEnable());
  // Heure des serveurs Google reçue d'une réponse Drive (SYN-08) : corrige T(),
  // alerte au-delà de 5 min de décalage, dernier décalage conservé hors ligne.
  function noterHeureDrive(entreeDrive) {
    const ms = Heure.heureDrive(entreeDrive);
    if (ms === null) return;
    const mesure = Lock.noterHeureServeur(ms);
    if (mesure && mesure.alerte) toast(t('toast.horlogeDecalee', { minutes: Math.round(Math.abs(mesure.decalageMs) / 60000) }));
  }
    $('btn-drive-backup').addEventListener('click', (event) =>
      busy(event.currentTarget, async () => {
        // Journalisé avant l'export : la sauvegarde contient sa propre trace.
        store.log('security', null, { event: 'driveBackup' });
        const content = await Lock.exportVault();
        if (!content) throw Object.assign(new Error('needsPassword'), { code: 'locked' });
        const envoye = await drive().upload(content);
        noterHeureDrive(envoye);
        writePref(DRIVE_LAST_KEY, new Date().toISOString());
        // Dans l'extension : la sauvegarde compte pour sa politique automatique.
        if (HOST) {
          const res = await HOST.driveBackedUp();
          if (res && hostDrive) hostDrive.next = res.next;
        }
        toast(t('toast.driveSaved'));
      })
    );
    $('btn-drive-restore').addEventListener('click', (event) =>
      busy(event.currentTarget, async () => {
        const backup = await drive().download();
        if (!Vault.parse(backup.content)) throw new Vault.VaultError('invalidBackup');
        noterHeureDrive(backup);
        pendingRestore = backup;
      })
    );
    $('btn-drive-cancel').addEventListener('click', () => {
      pendingRestore = null;
      renderDrive();
    });
    $('btn-drive-undo').addEventListener('click', (event) =>
      busy(event.currentTarget, async () => {
        if (await Lock.undoRestore()) toast(t('toast.restoreUndone'));
      })
    );
    $('btn-drive-replace').addEventListener('click', (event) =>
      busy(event.currentTarget, async () => {
        const backup = pendingRestore;
        pendingRestore = null;
        await Lock.importVault(backup.content);
        writePref(DRIVE_LAST_KEY, new Date().toISOString());
        toast(t('toast.driveRestored'));
      })
    );
  }

  /* ───────────── Démarrage ───────────── */

  function renderAll() {
    renderFilters();
    renderAccounts();
    renderActivityFilters();
    if (state.view === 'activity') renderActivity();
    if (state.view === 'passwords') Credentials.render();
    if (state.view === 'dashboard') Dashboard.render();
    el.settingsFoot.textContent = t('settings.foot', { version: VERSION });
    renderDrive();
    renderExtension();
    renderExportVault();
  }

  /** Export du coffre chiffré : seulement le coffre déverrouillé le propose. */
  function renderExportVault() {
    const button = $('btn-export-vault');
    if (button) button.hidden = Lock.status() !== 'unlocked';
  }

  /* Dernier passage de l'extension myMFA (écrit par son pont, sur cet appareil). */
  function renderExtension() {
    const at = HOST ? null : readPref(EXTENSION_SYNC_KEY); // dans l'extension, rien à signaler
    const card = document.getElementById('sidebar-ext');
    card.hidden = !at;
    if (!at) return;
    const minutes = Math.round((Date.now() - new Date(at).getTime()) / 60000);
    const relative = new Intl.RelativeTimeFormat(I18n.getLocale(), { numeric: 'auto' });
    const when = minutes < 60 ? relative.format(-minutes, 'minute') : minutes < 1440 ? relative.format(-Math.round(minutes / 60), 'hour') : relative.format(-Math.round(minutes / 1440), 'day');
    document.getElementById('sidebar-ext-text').textContent = t('sidebar.extensionSynced', { when });
  }

  function setupSearch() {
    el.searchToggle.addEventListener('click', () => {
      const open = !el.searchWrap.classList.contains('is-open');
      el.searchWrap.classList.toggle('is-open', open);
      el.searchToggle.setAttribute('aria-expanded', String(open));
      if (open) el.search.focus();
      else if (state.search) {
        el.search.value = '';
        state.search = '';
        renderAccounts();
      }
    });
    el.search.addEventListener('input', () => {
      state.search = el.search.value;
      renderAccounts();
    });
    document.addEventListener('keydown', (event) => {
      if (event.key !== '/' || state.view !== 'home' || event.target.closest('input, textarea, select') || el.dialog.open) return;
      event.preventDefault();
      el.searchWrap.classList.add('is-open');
      el.searchToggle.setAttribute('aria-expanded', 'true');
      el.search.focus();
    });
  }

  function init() {
    I18n.init();
    I18n.apply(document);
    setupTheme();
    setupLanguages();
    setupSearch();
    setupScanner();
    setupNewAccount();
    setupEdit();
    setupActivity();
    setupSettings();
    setupDrive();
    Credentials.init({ store, toast, errorMessage, copyText });
    Dashboard.init({ store, toast, errorMessage });

    el.banner.hidden = Boolean(window.crypto && window.crypto.subtle);
    Lock.init({
      toast,
      errorMessage,
      log: (event) => store.log('security', null, { event }),
      onPrefs: notePrefsChanged,
      onChange: () => {
        renderDrive();
        Credentials.render();
        renderExportVault();
      },
      onRefresh: renderAll,
      onUnlock: () => {
        syncPrefsWithVault();
        state.codes.clear();
        renderAll();
        route();
      },
      onLock: () => {
        // Plus rien de lisible en mémoire ni à l'écran.
        state.codes.clear();
        state.revealed.clear();
        el.accounts.replaceChildren();
        el.activity.replaceChildren();
        resetDraft();
        stopCamera();
        Credentials.reset();
        Dashboard.reset();
        if (el.dialog.open) el.dialog.close();
      },
    });

    // Synchronisation entre onglets du navigateur (le coffre est géré par Lock).
    window.addEventListener('storage', (event) => {
      if (!event.key || !event.key.startsWith('mymfa.') || event.key === Vault.VAULT_KEY || Sync.KEYS.includes(event.key)) {
        if (event.key && Sync.KEYS.includes(event.key) && Lock.status() === 'plain') renderAll();
        return;
      }
      if (event.key === THEME_KEY) applyTheme(currentTheme());
      else if (event.key !== 'mymfa.locale') renderAll();
    });
    window.addEventListener('hashchange', route);
    window.addEventListener('mymfa:extension-sync', renderExtension);
    // Déjà dans l'extension : sa page d'installation n'a rien à proposer.
    if (HOST) document.querySelector('[aria-labelledby="s-extension"]').hidden = true;
    setInterval(renderExtension, 60000);

    renderAll();
    if (!Lock.isLocked()) route();
    startClock();
  }

  init();
})();
