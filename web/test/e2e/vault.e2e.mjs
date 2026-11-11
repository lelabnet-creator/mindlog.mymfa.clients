// Scénario de bout en bout : mot de passe maître, passkey (authentificateur virtuel WebAuthn
// avec PRF), sauvegarde/restauration Google Drive (API et connexion Google simulées).
// Lancement : serveur de dev démarré, puis `npm run test:e2e`.
//   BASE_URL (défaut http://localhost:4173) · CHROMIUM (chemin d'un Chromium, sinon cache Playwright)
import { chromium } from 'playwright-core';
import { existsSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';

const BASE = process.env.BASE_URL || 'http://localhost:4173';
const PASSWORD = 'phrase de test longue 1';
const NEW_PASSWORD = 'autre phrase de test 2';
const SECRET = 'JBSWY3DPEHPK3PXP';

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

const steps = [];
async function step(name, fn) {
  await fn();
  steps.push(name);
  console.log(`  ✓ ${name}`);
}

const browser = await chromium.launch({ executablePath: findChromium(), headless: true });
const context = await browser.newContext({ viewport: { width: 1280, height: 900 }, locale: 'fr-FR' });
const page = await context.newPage();
const errors = [];
page.on('pageerror', (e) => errors.push(e.message));
page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));

// Authentificateur de plateforme virtuel, avec vérification utilisateur et extension PRF.
const cdp = await context.newCDPSession(page);
await cdp.send('WebAuthn.enable');
await cdp.send('WebAuthn.addVirtualAuthenticator', {
  options: {
    protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
    hasResidentKey: true, hasUserVerification: true, isUserVerified: true, hasPrf: true,
    automaticPresenceSimulation: true,
  },
});

// Google : script de connexion et API Drive simulés (l'identifiant client est collé dans les réglages).
let driveFile = null;
const driveCalls = [];
// Configuration de déploiement neutralisée : le scénario part d'un Drive non configuré.
await page.route('**/js/config.js', (route) =>
  route.fulfill({ contentType: 'text/javascript', body: "window.MYMFA_CONFIG = { googleClientId: '' };" })
);
await page.route('https://accounts.google.com/gsi/client', (route) =>
  route.fulfill({
    contentType: 'text/javascript',
    body: `window.google = { accounts: { oauth2: {
      initTokenClient(cfg) { const c = { callback: cfg.callback, requestAccessToken() { setTimeout(() => c.callback({ access_token: 'jeton', expires_in: 3600 })); } }; return c; },
      revoke() {} } } };`,
  })
);
const cors = { 'access-control-allow-origin': '*', 'access-control-allow-headers': '*', 'access-control-allow-methods': '*' };
await page.route('https://www.googleapis.com/**', async (route) => {
  const req = route.request();
  const url = req.url();
  if (req.method() === 'OPTIONS') return route.fulfill({ status: 204, headers: cors });
  driveCalls.push({ method: req.method(), url, auth: req.headers().authorization });
  const json = (body) => route.fulfill({ status: 200, headers: cors, contentType: 'application/json', body: JSON.stringify(body) });
  if (url.includes('/upload/') && req.method() === 'POST') {
    driveFile = { id: 'f1', modifiedTime: '2026-10-30T20:00:00.000Z', content: req.postData().split('\r\n\r\n')[2].split('\r\n--')[0] };
    return json({ id: 'f1', modifiedTime: driveFile.modifiedTime });
  }
  if (url.includes('/upload/') && req.method() === 'PATCH') {
    driveFile = { ...driveFile, content: req.postData() };
    return json({ id: 'f1', modifiedTime: driveFile.modifiedTime });
  }
  if (url.includes('alt=media')) return route.fulfill({ status: 200, headers: cors, contentType: 'application/json', body: driveFile.content });
  return json({ files: driveFile ? [{ id: driveFile.id, modifiedTime: driveFile.modifiedTime }] : [] });
});

const toast = page.locator('#toast');
const lockScreen = page.locator('#lock-screen');
const vaultRaw = () => page.evaluate(() => localStorage.getItem('mymfa.vault.v1'));
const plainAccounts = () => page.evaluate(() => localStorage.getItem('mymfa.accounts.v1'));
const expectedCode = () => page.evaluate(async (s) => OTP.totp(s), SECRET);
const shownCode = () => page.locator('#accounts .code').first().textContent();

async function unlockWith(password) {
  await page.fill('#lock-password', password);
  await page.click('#lock-form button[type="submit"]');
}

try {
  await step('page vierge, ajout d’un compte en clair', async () => {
    await page.goto(`${BASE}/`);
    await page.evaluate(() => { localStorage.clear(); localStorage.setItem('mymfa.locale', 'fr'); });
    await page.goto(`${BASE}/#/new`);
    await page.fill('#f-secret', SECRET);
    await page.fill('#f-issuer', 'GitHub');
    await page.click('#add-form button[type="submit"]');
    await page.waitForURL(/#\/$/);
    assert.match(await plainAccounts(), new RegExp(SECRET));
  });

  await step('Drive : identifiant client collé dans les réglages, puis mot de passe maître proposé', async () => {
    await page.goto(`${BASE}/#/settings`);
    assert.equal(await page.textContent('#drive-status'), 'Google Drive n’est pas configuré.');
    assert.equal(await page.isVisible('#btn-drive-backup'), false);
    await page.fill('#drive-client-id', 'pas-un-identifiant');
    await page.click('#drive-setup button[type="submit"]');
    await toast.filter({ hasText: 'Identifiant invalide' }).waitFor();
    await page.fill('#drive-client-id', 'test.apps.googleusercontent.com');
    await page.click('#drive-setup button[type="submit"]');
    assert.equal(await page.textContent('#drive-status'), 'Activez d’abord le mot de passe maître.');
    assert.equal(await page.isVisible('#drive-setup'), false);
    assert.equal(await page.isVisible('#btn-drive-backup'), false);
  });

  await step('activation du mot de passe maître depuis la carte Drive : plus rien en clair', async () => {
    await page.click('#btn-drive-enable');
    await page.fill('#security-form input[name="next"]', PASSWORD);
    await page.fill('#security-form input[name="confirm"]', PASSWORD);
    await page.click('#security-form button[type="submit"]');
    await toast.filter({ hasText: 'Coffre chiffré' }).waitFor();
    assert.equal(await plainAccounts(), null);
    const raw = await vaultRaw();
    assert.ok(raw && !raw.includes(SECRET) && !raw.includes('GitHub'), 'coffre sans donnée lisible');
    assert.equal(JSON.parse(raw).password.iterations, 1000000);
  });

  await step('appareil compatible : passkey proposé après le mot de passe, « Plus tard » reporte', async () => {
    const dialog = page.locator('#security-dialog');
    await dialog.locator('h2', { hasText: 'Déverrouiller d’un geste ?' }).waitFor();
    await dialog.getByRole('button', { name: 'Plus tard' }).click();
    await dialog.waitFor({ state: 'hidden' });
    const until = await page.evaluate(() => localStorage.getItem('mymfa.passkeyPrompt'));
    assert.ok(until > new Date(Date.now() + 6 * 86400000).toISOString(), `report d’une semaine (${until})`);
    assert.equal(JSON.parse(await vaultRaw()).passkeys.length, 0);
  });

  await step('Drive proposé : carte mise en avant, sauvegarde envoie le coffre chiffré', async () => {
    assert.equal(await page.isVisible('#drive-card.is-suggested'), true);
    await page.click('#btn-drive-backup');
    await toast.filter({ hasText: 'Google Drive' }).waitFor();
    assert.ok(driveFile, 'fichier envoyé');
    assert.ok(!driveFile.content.includes(SECRET), 'aucun secret en clair sur Drive');
    // SYN-07 : le coffre porte le marqueur de synchro v2, l'enveloppe passe à v: 2 —
    // un client d'avant (v: 1 exigée) refuse de l'ouvrir, donc d'écrire.
    assert.equal(JSON.parse(driveFile.content).v, 2);
    assert.ok(driveCalls.every((c) => c.auth === 'Bearer jeton'));
    assert.match(await page.textContent('#drive-status'), /Dernière sauvegarde/);
  });

  await step('verrouillage : écran de verrouillage, codes effacés', async () => {
    await page.click('#btn-lock-side');
    await lockScreen.waitFor();
    assert.equal(await page.locator('#accounts .card').count(), 0);
  });

  await step('mauvais mot de passe refusé, bon mot de passe accepté', async () => {
    await unlockWith('mauvais mot de passe');
    await page.locator('#lock-error', { hasText: 'Mot de passe incorrect' }).waitFor();
    await unlockWith(PASSWORD);
    await lockScreen.waitFor({ state: 'hidden' });
    await page.waitForTimeout(300);
    assert.equal(await page.isVisible('#security-dialog'), false, 'proposition reportée : pas de nouvelle demande');
    await page.goto(`${BASE}/#/`);
    await page.waitForFunction(() => /\d{3} \d{3}/.test(document.querySelector('#accounts .code')?.textContent || ''));
    assert.equal((await shownCode()).replace(' ', ''), await expectedCode());
  });

  await step('ajout d’un passkey (PRF)', async () => {
    await page.goto(`${BASE}/#/settings`);
    await page.locator('#passkeys-list button.row').click();
    await page.click('#security-form button[type="submit"]');
    await toast.filter({ hasText: 'Passkey ajouté' }).waitFor({ timeout: 15000 });
    assert.equal(JSON.parse(await vaultRaw()).passkeys.length, 1);
  });

  await step('déverrouillage par passkey', async () => {
    await page.click('#btn-lock-side');
    await page.locator('#lock-passkey').click();
    await lockScreen.waitFor({ state: 'hidden', timeout: 15000 });
  });

  await step('changement de mot de passe : ancien refusé, nouveau accepté', async () => {
    await page.goto(`${BASE}/#/settings`);
    await page.locator('#security-rows button', { hasText: 'Modifier' }).click();
    await page.fill('#security-form input[name="current"]', PASSWORD);
    await page.fill('#security-form input[name="next"]', NEW_PASSWORD);
    await page.fill('#security-form input[name="confirm"]', NEW_PASSWORD);
    await page.click('#security-form button[type="submit"]');
    await toast.filter({ hasText: 'Mot de passe changé' }).waitFor();
    await page.click('#btn-lock-side');
    await unlockWith(PASSWORD);
    await page.locator('#lock-error', { hasText: 'Mot de passe incorrect' }).waitFor();
    await unlockWith(NEW_PASSWORD);
    await lockScreen.waitFor({ state: 'hidden' });
  });

  await step('rechargement : coffre verrouillé, le passkey reste valide', async () => {
    await page.reload();
    await lockScreen.waitFor();
    await page.locator('#lock-passkey').click();
    await lockScreen.waitFor({ state: 'hidden', timeout: 15000 });
  });

  await step('restauration Drive : remplace le coffre puis verrouille (mot de passe de la sauvegarde)', async () => {
    await page.goto(`${BASE}/#/settings`);
    await page.click('#btn-drive-restore');
    await page.locator('#drive-confirm').waitFor();
    await page.click('#btn-drive-replace');
    await lockScreen.waitFor();
    // La sauvegarde date d'avant le changement de mot de passe et l'ajout du passkey.
    await unlockWith(NEW_PASSWORD);
    await page.locator('#lock-error', { hasText: 'Mot de passe incorrect' }).waitFor();
    await unlockWith(PASSWORD);
    await lockScreen.waitFor({ state: 'hidden' });
    assert.equal(JSON.parse(await vaultRaw()).passkeys.length, 0);
  });

  await step('activité : événements de sécurité tracés', async () => {
    await page.goto(`${BASE}/#/activity`);
    const text = await page.textContent('#activity');
    assert.match(text, /Mot de passe maître activé/);
    assert.match(text, /Sauvegarde envoyée sur Google Drive/);
  });

  await step('désactivation : données remises en clair, coffre supprimé', async () => {
    await page.goto(`${BASE}/#/settings`);
    await page.click('#security-rows button.row.danger');
    await page.fill('#security-form input[name="current"]', PASSWORD);
    await page.click('#security-form button[type="submit"]');
    await toast.filter({ hasText: 'Chiffrement désactivé' }).waitFor();
    assert.equal(await vaultRaw(), null);
    assert.match(await plainAccounts(), new RegExp(SECRET));
  });

  await step('mot de passe oublié : réinitialisation confirmée, coffre et comptes effacés', async () => {
    await page.click('#security-rows button');
    await page.fill('#security-form input[name="next"]', PASSWORD);
    await page.fill('#security-form input[name="confirm"]', PASSWORD);
    await page.click('#security-form button[type="submit"]');
    await toast.filter({ hasText: 'Coffre chiffré' }).waitFor();
    await page.click('#btn-lock-side');
    await lockScreen.waitFor();
    await page.click('#lock-forgot');
    await page.click('#security-form button[type="submit"]');
    await page.locator('#security-form .form-error', { hasText: 'Cochez la case' }).waitFor();
    assert.ok(await vaultRaw(), 'rien d’effacé sans confirmation');
    await page.check('#security-form input[name="understood"]');
    await page.click('#security-form button[type="submit"]');
    await toast.filter({ hasText: 'Coffre réinitialisé' }).waitFor();
    await lockScreen.waitFor({ state: 'hidden' });
    assert.equal(await vaultRaw(), null);
    assert.ok(!(await plainAccounts() || '').includes(SECRET), 'aucun compte restant');
    await page.goto(`${BASE}/#/`);
    assert.equal(await page.locator('#accounts .card').count(), 0);
    await page.goto(`${BASE}/#/activity`);
    assert.match(await page.textContent('#activity'), /Coffre réinitialisé \(mot de passe oublié\)/);
  });

  assert.deepEqual(errors, [], `erreurs console : ${errors.join(' | ')}`);
  console.log(`\n${steps.length} étapes réussies, aucune erreur console.`);
} catch (err) {
  console.error(`\n✗ Échec après « ${steps[steps.length - 1] || 'démarrage'} »\n`, err);
  if (errors.length) console.error('Erreurs console :', errors);
  await page.screenshot({ path: join(process.env.E2E_SHOTS || '.', 'e2e-failure.png') }).catch(() => {});
  process.exitCode = 1;
} finally {
  await browser.close();
}
