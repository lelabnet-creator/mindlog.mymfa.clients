// Scénario de bout en bout de l'extension autonome : aucune app hébergée, l'app web est celle que
// l'extension embarque (chrome-extension://…/app/index.html). Couvre : ouverture depuis le popup,
// synchronisation app ↔ extension, un seul verrou (déverrouiller ou verrouiller d'un côté vaut pour
// l'autre), passkey du coffre dans la page de l'extension, sauvegarde Drive par chrome.identity
// (API Google simulée), délai de verrouillage partagé, rechargement sans redemander le mot de passe.
// Prérequis : `npm run build`. Aucun serveur. Lancement : node test/e2e/app.e2e.mjs
import { chromium } from 'playwright-core';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const EXT = join(ROOT, 'src');
const PASSWORD = 'phrase de test longue 1';
const SECRET = 'JBSWY3DPEHPK3PXP';
const OTHER = 'KRSXG5CTMVRXEZLU';

function findChromium() {
  if (process.env.CHROMIUM) return process.env.CHROMIUM;
  const cache = join(homedir(), '.cache', 'ms-playwright');
  const dirs = existsSync(cache) ? readdirSync(cache).filter((d) => /^chromium-\d+$/.test(d)).sort().reverse() : [];
  for (const dir of dirs) {
    const exe = join(cache, dir, 'chrome-linux64', 'chrome');
    if (existsSync(exe)) return exe;
  }
  throw new Error('Chromium introuvable : définissez CHROMIUM=/chemin/vers/chrome');
}

if (!existsSync(join(EXT, 'app', 'index.html'))) throw new Error('Extension non construite : lancez `npm run build`');

const steps = [];
async function step(name, fn) {
  await fn();
  steps.push(name);
  console.log(`  ✓ ${name}`);
}

async function until(fn, { timeout = 10000, label = 'condition' } = {}) {
  const end = Date.now() + timeout;
  let last;
  while (Date.now() < end) {
    try {
      last = await fn();
      if (last) return last;
    } catch {
      /* on réessaie */
    }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`Délai dépassé : ${label} (dernière valeur : ${JSON.stringify(last)})`);
}

const userDataDir = mkdtempSync(join(process.env.E2E_TMP || tmpdir(), 'mymfa-app-'));
const context = await chromium.launchPersistentContext(userDataDir, {
  executablePath: findChromium(),
  headless: true,
  args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`],
  viewport: { width: 1280, height: 900 },
  locale: 'fr-FR',
});
const errors = [];
const watch = (page) => {
  page.on('pageerror', (e) => errors.push(`${page.url()} : ${e.message}`));
  page.on('console', (m) => m.type() === 'error' && !/favicon/.test(m.text()) && errors.push(`${page.url()} : ${m.text()}`));
  return page;
};

let worker = context.serviceWorkers()[0];
if (!worker) worker = await context.waitForEvent('serviceworker');
const extId = new URL(worker.url()).host;
const APP = `chrome-extension://${extId}/app/index.html`;
const popupData = () => worker.evaluate(() => popupList());
const extStatus = async () => (await popupData()).status;

// API Google Drive simulée ; le jeton, lui, est celui que chrome.identity aurait laissé en session.
let driveFile = null;
const driveCalls = [];
const cors = { 'access-control-allow-origin': '*', 'access-control-allow-headers': '*', 'access-control-allow-methods': '*' };
await context.route('https://www.googleapis.com/**', async (route) => {
  const req = route.request();
  const url = req.url();
  if (req.method() === 'OPTIONS') return route.fulfill({ status: 204, headers: cors });
  driveCalls.push({ method: req.method(), url, auth: req.headers().authorization });
  const json = (body) => route.fulfill({ status: 200, headers: cors, contentType: 'application/json', body: JSON.stringify(body) });
  if (url.includes('/upload/') && req.method() === 'POST') {
    driveFile = { id: 'f1', modifiedTime: '2026-10-31T10:00:00.000Z', content: req.postData().split('\r\n\r\n')[2].split('\r\n--')[0] };
    return json({ id: 'f1', modifiedTime: driveFile.modifiedTime });
  }
  if (url.includes('/upload/') && req.method() === 'PATCH') {
    driveFile = { ...driveFile, content: req.postData() };
    return json({ id: 'f1', modifiedTime: driveFile.modifiedTime });
  }
  if (url.includes('alt=media')) return route.fulfill({ status: 200, headers: cors, contentType: 'application/json', body: driveFile.content });
  return json({ files: driveFile ? [{ id: driveFile.id, modifiedTime: driveFile.modifiedTime }] : [] });
});

const popup = watch(await context.newPage());
let app = null;
const toast = () => app.locator('#toast');
const lockScreen = () => app.locator('#lock-screen');
const appAccounts = () => app.evaluate(() => Store.createStore(Lock.storage).list().map((a) => a.issuer).sort());

/** Authentificateur de plateforme virtuel (vérification utilisateur, PRF) pour la page de l'app. */
async function addAuthenticator(page) {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
      hasResidentKey: true, hasUserVerification: true, isUserVerified: true, hasPrf: true,
      automaticPresenceSimulation: true,
    },
  });
}

async function unlockApp(password) {
  await app.fill('#lock-password', password);
  await app.click('#lock-form button[type="submit"]');
}

try {
  await step('extension seule : aucune app hébergée à synchroniser', async () => {
    assert.match(extId, /^[a-p]{32}$/);
    const { settings, status } = await popupData();
    assert.equal(settings.appUrl, '');
    assert.equal(status, 'empty');
  });

  await step('« Ouvrir myMFA » dans le popup : l’app s’ouvre dans l’extension', async () => {
    // Le popup se ferme une fois l'app ouverte : une page à part.
    const launcher = watch(await context.newPage());
    await launcher.goto(`chrome-extension://${extId}/popup.html`);
    const [opened] = await Promise.all([context.waitForEvent('page'), launcher.click('#open-app')]);
    app = watch(opened);
    await app.waitForLoadState();
    assert.equal(app.url(), APP);
    await until(() => launcher.isClosed(), { label: 'popup refermé' });
    await addAuthenticator(app);
    await app.evaluate(() => localStorage.setItem('mymfa.locale', 'fr'));
    await app.reload();
    assert.equal(await app.locator('[aria-labelledby="s-extension"]').count(), 1);
    assert.equal(await app.isVisible('[aria-labelledby="s-extension"]'), false, 'pas de page d’installation dans l’extension');
  });

  await step('compte ajouté dans l’app : l’extension l’a, le popup affiche son code', async () => {
    await app.goto(`${APP}#/new`);
    await app.fill('#f-secret', SECRET);
    await app.fill('#f-issuer', 'Proton');
    await app.fill('#f-account', 'moi@exemple.fr');
    await app.click('#add-form button[type="submit"]');
    await until(async () => (await popupData()).accounts.some((a) => a.secret === SECRET), { label: 'synchro app → extension' });
    const p = watch(await context.newPage());
    await p.goto(`chrome-extension://${extId}/popup.html`);
    await until(async () => (await p.locator('#all-list li').count()) === 1, { label: 'compte dans le popup' });
    const code = await app.evaluate((s) => OTP.totp(s), SECRET);
    assert.equal((await p.locator('#all-list .item-code').first().textContent()).replace(' ', ''), code);
    await p.close();
  });

  await step('compte ajouté depuis une page web : il apparaît dans l’app', async () => {
    await worker.evaluate((uri) => handlers['content:add']({ uri }), `otpauth://totp/Nimbus:bob?secret=${OTHER}&issuer=Nimbus`);
    await until(async () => (await appAccounts()).join() === 'Nimbus,Proton', { label: 'Nimbus dans l’app' });
  });

  await step('mot de passe maître activé dans l’app : coffre chiffré partout, extension déverrouillée elle aussi', async () => {
    await app.goto(`${APP}#/settings`);
    await app.click('#security-rows button');
    await app.fill('#security-form input[name="next"]', PASSWORD);
    await app.fill('#security-form input[name="confirm"]', PASSWORD);
    await app.click('#security-form button[type="submit"]');
    await toast().filter({ hasText: 'Coffre chiffré' }).waitFor();
    // Appareil compatible : la passkey est proposée tout de suite ; plus tard.
    const dialog = app.locator('#security-dialog');
    await dialog.locator('h2', { hasText: 'Déverrouiller d’un geste ?' }).waitFor();
    await dialog.getByRole('button', { name: 'Plus tard' }).click();
    await until(async () => (await extStatus()) === 'unlocked', { label: 'extension déverrouillée' });
    const snap = (await worker.evaluate(() => chrome.storage.local.get('ext.snapshot')))['ext.snapshot'];
    assert.ok(snap['mymfa.vault.v1'] && !JSON.stringify(snap).includes(SECRET), 'aucun secret en clair dans l’extension');
    assert.equal(await app.evaluate(() => localStorage.getItem('mymfa.accounts.v1')), null, 'aucun secret en clair dans l’app');
  });

  await step('verrouillé depuis le popup : l’app se verrouille', async () => {
    await popup.goto(`chrome-extension://${extId}/popup.html`);
    await popup.click('#btn-lock');
    await popup.locator('[data-view="unlock"]').waitFor();
    await lockScreen().waitFor();
    assert.equal(await app.locator('#accounts .card').count(), 0);
  });

  await step('déverrouillé dans l’app : l’extension s’ouvre aussi', async () => {
    await unlockApp('mauvais mot de passe');
    await app.locator('#lock-error', { hasText: 'Mot de passe incorrect' }).waitFor();
    await unlockApp(PASSWORD);
    await lockScreen().waitFor({ state: 'hidden' });
    await until(async () => (await extStatus()) === 'unlocked', { label: 'extension déverrouillée par l’app' });
  });

  await step('verrouillé dans l’app : l’extension se verrouille', async () => {
    await app.click('#btn-lock-side');
    await lockScreen().waitFor();
    await until(async () => (await extStatus()) === 'locked', { label: 'extension verrouillée par l’app' });
  });

  await step('déverrouillé dans le popup : l’app s’ouvre d’elle-même', async () => {
    await popup.reload();
    await popup.fill('#unlock-password', PASSWORD);
    await popup.click('#unlock-form button[type="submit"]');
    await popup.locator('[data-view="main"]').waitFor();
    await lockScreen().waitFor({ state: 'hidden' });
    await app.goto(`${APP}#/`);
    await until(async () => (await app.locator('#accounts .card').count()) === 2, { label: 'comptes dans l’app' });
  });

  await step('passkey du coffre dans la page de l’extension : ajout, puis déverrouillage d’un geste', async () => {
    await app.goto(`${APP}#/settings`);
    await app.locator('#passkeys-list button.row').click();
    await app.click('#security-form button[type="submit"]');
    await toast().filter({ hasText: 'Passkey ajouté' }).waitFor({ timeout: 15000 });
    const record = JSON.parse(await app.evaluate(() => localStorage.getItem('mymfa.vault.v1')));
    assert.equal(record.passkeys.length, 1);
    await app.click('#btn-lock-side');
    await until(async () => (await extStatus()) === 'locked', { label: 'extension verrouillée' });
    await app.locator('#lock-passkey').click();
    await lockScreen().waitFor({ state: 'hidden', timeout: 15000 });
    await until(async () => (await extStatus()) === 'unlocked', { label: 'extension déverrouillée par la passkey' });
  });

  await step('sauvegarde Drive depuis l’app : jeton de l’extension, coffre chiffré envoyé', async () => {
    await worker.evaluate(() => chrome.storage.session.set({ 'ext.driveToken': { token: 'jeton', expiresAt: Date.now() + 3600000 } }));
    await app.goto(`${APP}#/settings`);
    assert.match(await app.textContent('#drive-origin'), new RegExp(`https://${extId}\\.chromiumapp\\.org/`));
    await app.click('#btn-drive-backup');
    await toast().filter({ hasText: 'Google Drive' }).waitFor();
    assert.ok(driveFile, 'fichier envoyé');
    assert.ok(!driveFile.content.includes(SECRET) && !driveFile.content.includes('Proton'), 'aucun secret en clair sur Drive');
    assert.equal(JSON.parse(driveFile.content).v, 1);
    assert.ok(driveCalls.length && driveCalls.every((c) => c.auth === 'Bearer jeton'));
  });

  await step('sauvegarde automatique : politique réglée dans l’app, tenue par l’extension, visible dans le popup', async () => {
    // La sauvegarde de l'app compte pour l'extension : Drive relié, prochaine échéance dans 24 h (défaut).
    const row = app.locator('#drive-every-row');
    await row.waitFor();
    assert.equal(await app.inputValue('#drive-every'), '24');
    await until(async () => /^Prochaine : /.test(await app.textContent('#drive-next')), { label: 'prochaine sauvegarde affichée' });
    await app.selectOption('#drive-every', '6');
    await until(async () => (await popupData()).settings.driveEvery === 6, { label: 'politique enregistrée par l’extension' });
    const { drive, settings } = await popupData();
    assert.equal(settings.drive, true);
    assert.equal(Date.parse(drive.next) - Date.parse(drive.lastSync), 6 * 3600000);
    // Popup : bouton explicite, même politique, prochaine date.
    const p = watch(await context.newPage());
    await p.goto(`chrome-extension://${extId}/popup.html`);
    await p.click('#btn-settings');
    assert.equal((await p.textContent('#btn-drive-sync')).trim(), 'Sauvegarder maintenant');
    await until(async () => (await p.inputValue('#drive-every')) === '6', { label: 'politique dans le popup' });
    assert.match(await p.textContent('#drive-next'), /^Prochaine : /);
    await p.selectOption('#drive-every', '168');
    await until(async () => (await popupData()).settings.driveEvery === 168, { label: 'politique changée depuis le popup' });
    await p.close();
    // Échéance : rien tant qu'elle n'est pas passée ; sauvegarde silencieuse ensuite.
    const runs = await worker.evaluate(async () => {
      const calls = [];
      const real = syncDrive;
      syncDrive = async (interactive) => calls.push(interactive);
      await autoDrive(); // sauvegarde récente : pas due
      await chrome.storage.local.set({ 'ext.driveLastSync': new Date(Date.now() - 169 * 3600000).toISOString() });
      await autoDrive(); // plus d'une semaine : due
      await saveSettings({ driveEvery: 0 });
      await autoDrive(); // désactivée
      syncDrive = real;
      return calls;
    });
    assert.deepEqual(runs, [false]);
  });

  await step('délai de verrouillage choisi dans l’app : c’est celui de l’extension', async () => {
    await app.locator('#security-rows select').selectOption('60');
    await until(async () => (await popupData()).settings.autoLock === 60, { label: 'délai enregistré par l’extension' });
  });

  await step('app rechargée, extension déverrouillée : rien à redemander', async () => {
    await app.goto(`${APP}#/`);
    await until(async () => (await app.locator('#accounts .card').count()) === 2, { label: 'comptes après rechargement' });
    assert.equal(await lockScreen().isVisible(), false);
  });

  await step('import depuis le popup : l’app montre la ligne Importer, le CSV Proton Pass arrive dans l’extension', async () => {
    const launcher = watch(await context.newPage());
    await launcher.goto(`chrome-extension://${extId}/popup.html`);
    await launcher.click('#btn-settings');
    await launcher.click('#btn-import');
    await until(() => launcher.isClosed(), { label: 'popup refermé' });
    // L'onglet de l'app déjà ouvert est réutilisé, sur la ligne Importer.
    await until(() => app.url() === `${APP}#/settings/import`, { label: 'app sur #/settings/import' });
    const row = app.locator('label[for="import-file"]');
    await until(async () => (await row.getAttribute('class')).includes('row-flash'), { label: 'ligne en évidence' });
    assert.equal(await row.evaluate((node) => node === document.activeElement), true);
    const csv = [
      'type,name,url,autofillUrls,email,username,password,note,totp,createTime,modifyTime,vault',
      'login,GitHub,https://github.com/login,,,octocat,gh-secret-1,,otpauth://totp/GitHub:octocat?secret=GEZDGNBVGY3TQOJQ,1700000000,1700000000,Personal',
    ].join('\n');
    await app.setInputFiles('#import-file', { name: 'Proton Pass_export.csv', mimeType: 'text/csv', buffer: Buffer.from(csv) });
    await toast().filter({ hasText: 'Proton Pass : 1 mot(s) de passe et 1 compte(s) 2FA importés' }).waitFor();
    await until(async () => {
      const data = await popupData();
      return data.logins.some((l) => l.origin === 'https://github.com' && l.username === 'octocat')
        && data.accounts.some((a) => a.secret === 'GEZDGNBVGY3TQOJQ');
    }, { label: 'import synchronisé vers l’extension' });
    const snap = JSON.stringify((await worker.evaluate(() => chrome.storage.local.get('ext.snapshot')))['ext.snapshot']);
    assert.ok(!snap.includes('gh-secret-1'), 'mot de passe chiffré dans l’extension');
    // « Synchroniser » du popup compte l'onglet de l'app embarquée.
    assert.equal(await worker.evaluate(() => pushToApp()), 1);
  });

  await step('JSON Proton Authenticator dans l’app embarquée : barre de progression, compte et note dans l’extension', async () => {
    await app.evaluate(() => {
      window.__progress = [];
      const box = document.getElementById('import-progress');
      new MutationObserver(() => {
        if (!box.hidden) window.__progress.push(box.textContent.replace(/\s+/g, ' ').trim());
      }).observe(box, { subtree: true, childList: true, characterData: true, attributes: true });
    });
    const json = JSON.stringify({
      version: 1,
      entries: [
        { id: 'a1', content: { uri: 'otpauth://totp/Notion:moi%40exemple.fr?secret=MFRGGZDFMZTWQ2LK&issuer=Notion', entry_type: 'Totp', name: 'moi@exemple.fr' }, note: 'compte pro' },
        { id: 'a2', content: { uri: 'otpauth://totp/Steam:joueur?secret=KRSXG5CTMVRXEZLU&issuer=Steam', entry_type: 'Steam', name: 'joueur' }, note: null },
      ],
    });
    await app.setInputFiles('#import-file', { name: 'Proton_Authenticator_backup.json', mimeType: 'application/json', buffer: Buffer.from(json) });
    await toast().filter({ hasText: 'Proton Authenticator : 1 compte(s) 2FA importé(s), 1 ignoré(s).' }).waitFor();
    const seen = await app.evaluate(() => window.__progress);
    assert.ok(seen.includes('Import Proton Authenticator… 1 / 1'), `progression : ${seen.join(' · ')}`);
    assert.ok(seen.includes('Chiffrement du coffre…'), 'phase de chiffrement');
    assert.equal(await app.isVisible('#import-progress'), false);
    await until(async () => (await popupData()).accounts.some((a) => a.secret === 'MFRGGZDFMZTWQ2LK' && a.description === 'compte pro'), { label: 'compte importé dans l’extension' });
  });

  assert.deepEqual(errors, [], `erreurs console : ${errors.join(' | ')}`);
  console.log(`\n${steps.length} étapes réussies, aucune erreur console.`);
} catch (err) {
  console.error(`\n✗ Échec après « ${steps[steps.length - 1] || 'démarrage'} »\n`, err);
  if (errors.length) console.error('Erreurs console :', errors);
  for (const [i, page] of context.pages().entries()) {
    await page.screenshot({ path: join(process.env.E2E_SHOTS || '.', `app-failure-${i}.png`) }).catch(() => {});
  }
  process.exitCode = 1;
} finally {
  await context.close();
  rmSync(userDataDir, { recursive: true, force: true });
}
