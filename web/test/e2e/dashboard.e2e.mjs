// Scénario de bout en bout : tableau de bord (usage, santé, politique, fuites HIBP simulées) et
// réglages emportés par le coffre — un coffre recopié sur un autre appareil rend politique,
// résultats de fuite, historique et préférences.
// Lancement : serveur de dev démarré, puis `node test/e2e/dashboard.e2e.mjs`.
//   BASE_URL (défaut http://localhost:4173) · CHROMIUM (chemin d'un Chromium, sinon cache Playwright)
//   E2E_SHOTS : dossier des captures (défaut : dossier temporaire du système — une capture écrite dans
//   web/ ferait recharger la page par le serveur de dev, donc verrouiller le coffre en plein scénario)
import { chromium } from 'playwright-core';
import { existsSync, readdirSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';

const BASE = process.env.BASE_URL || 'http://localhost:4173';
const SHOTS = process.env.E2E_SHOTS || tmpdir();
const PASSWORD = 'phrase de test longue 1';
const CSV = [
  'type,name,url,autofillUrls,email,username,password,note,totp,createTime,modifyTime,vault',
  'login,GitHub,https://github.com/login,,,octocat,Correct-Horse-7-Battery,,otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub,1700000000,1700000100,Personal',
  'login,Banque,https://www.banque.fr,,,client,Mauve-Tiroir-58-Lune,,,1700000000,1700000000,Personal',
  'login,Forum,https://forum.example,,,client,Mauve-Tiroir-58-Lune,,,1700000000,1700000000,Personal',
  'login,Vieux,https://vieux.example,,,moi,azerty,,,1700000000,1700000000,Personal',
].join('\n');
const PWNED = createHash('sha1').update('azerty').digest('hex').toUpperCase();

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
const errors = [];
const asked = [];

async function newPage(viewport = { width: 1280, height: 900 }) {
  const context = await browser.newContext({ viewport, locale: 'fr-FR' });
  const page = await context.newPage();
  page.on('pageerror', (e) => errors.push(e.message));
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  await page.route('**/js/config.js', (route) =>
    route.fulfill({ contentType: 'text/javascript', body: "window.MYMFA_CONFIG = { googleClientId: '' };" })
  );
  // HIBP simulé : « azerty » fuité, le reste non ; on note ce qui part.
  await page.route('https://api.pwnedpasswords.com/range/*', (route) => {
    const prefix = route.request().url().split('/').pop();
    asked.push({ prefix, padding: route.request().headers()['add-padding'] });
    const body = prefix === PWNED.slice(0, 5) ? `${PWNED.slice(5)}:1234567\r\n0000000000000000000000000000000000A:0` : '0000000000000000000000000000000000A:0';
    route.fulfill({ status: 200, contentType: 'text/plain', headers: { 'access-control-allow-origin': '*' }, body });
  });
  return page;
}

const healthCount = (page, label) => page.locator('#dashboard .dash-row', { hasText: label }).locator('.dash-row-count').textContent();

async function unlock(page) {
  await page.fill('#lock-password', PASSWORD);
  await page.click('#lock-form button[type="submit"]');
  await page.locator('#lock-form').waitFor({ state: 'hidden' });
}

let vaultRaw = null;
const page = await newPage();
const toast = page.locator('#toast');

try {
  await step('coffre activé, quatre mots de passe importés', async () => {
    await page.goto(`${BASE}/`);
    await page.evaluate(() => { localStorage.clear(); localStorage.setItem('mymfa.locale', 'fr'); });
    await page.goto(`${BASE}/#/passwords`);
    await page.click('#btn-cred-enable');
    await page.fill('#security-form input[name="next"]', PASSWORD);
    await page.fill('#security-form input[name="confirm"]', PASSWORD);
    await page.click('#security-form button[type="submit"]');
    await toast.filter({ hasText: 'Coffre chiffré' }).waitFor();
    const later = page.locator('#security-form button', { hasText: 'Plus tard' });
    if (await later.isVisible().catch(() => false)) await later.click();
    await page.goto(`${BASE}/#/settings`);
    await page.setInputFiles('#import-file', { name: 'Proton Pass_export.csv', mimeType: 'text/csv', buffer: Buffer.from(CSV) });
    await toast.filter({ hasText: '4 mot(s) de passe' }).waitFor();
  });

  await step('tableau de bord : chiffres, usage et santé', async () => {
    await page.goto(`${BASE}/#/dashboard`);
    const tiles = await page.locator('.dash-tile').allTextContents();
    assert.match(tiles[0], /Comptes 2FA\s*1/);
    assert.match(tiles[1], /Mots de passe\s*4.*1 sur 4 avec 2FA/);
    assert.match(await page.textContent('.dash-usage-head'), /événements/);
    assert.equal(await page.locator('.dash-bar').count(), 30);
    assert.equal(await healthCount(page, 'Hors politique'), '1');
    assert.equal(await healthCount(page, 'Réutilisés'), '2');
    assert.equal(await healthCount(page, 'Compromis'), 'Non vérifié');
    await page.screenshot({ path: join(SHOTS, 'dashboard-desktop.png'), fullPage: true });
  });

  await step('détail : la ligne dépliée mène aux sites concernés', async () => {
    await page.click('#dashboard .dash-row:has-text("Réutilisés")');
    const sites = await page.locator('.dash-sites').textContent();
    assert.match(sites, /Banque/);
    assert.match(sites, /Forum/);
  });

  await step('politique : 22 caractères et symboles exigés, renouvellement désactivé', async () => {
    await page.check('#dashboard .gen-chip:has-text("Symboles") input');
    await page.locator('#dashboard .gen-range').fill('22');
    await page.locator('#dashboard .dash-row', { hasText: 'Hors politique' }).locator('.dash-row-count', { hasText: '3' }).waitFor();
    await page.selectOption('#dashboard label.row:has-text("Renouvellement") select', '0');
    assert.equal(await healthCount(page, 'À renouveler'), 'Désactivé');
  });

  await step('HIBP : préfixes seuls, avec remplissage ; mot de passe fuité signalé', async () => {
    await page.click('#dashboard button:has-text("Vérifier")');
    await toast.filter({ hasText: '1 mot de passe compromis' }).waitFor();
    assert.equal(asked.length, 3, 'un appel par mot de passe distinct');
    assert.ok(asked.every((a) => a.prefix.length === 5 && a.padding === 'true'));
    assert.equal(await healthCount(page, 'Compromis'), '1');
    assert.match(await page.locator('.dash-sites').textContent(), /Vieux.*1\s?234\s?567/s);
  });

  await step('rien en clair : réglages et résultats dans le coffre', async () => {
    const raw = await page.evaluate(() => JSON.stringify(localStorage));
    assert.ok(!raw.includes('mymfa.settings.v1'), 'réglages hors du stockage en clair');
    assert.ok(!raw.includes('1234567'));
  });

  await step('préférence copiée dans le coffre (thème sombre)', async () => {
    await page.goto(`${BASE}/#/settings`);
    await page.click('#theme-cards [data-theme-value="dark"]');
    await page.waitForTimeout(300); // chiffrement du coffre
    vaultRaw = await page.evaluate(() => localStorage.getItem('mymfa.vault.v1'));
    assert.ok(vaultRaw);
  });

  await step('autre appareil : le coffre rend politique, fuites, historique et thème', async () => {
    const other = await newPage();
    await other.goto(`${BASE}/`);
    await other.evaluate((raw) => { localStorage.clear(); localStorage.setItem('mymfa.locale', 'fr'); localStorage.setItem('mymfa.vault.v1', raw); }, vaultRaw);
    await other.goto(`${BASE}/#/dashboard`);
    await other.reload(); // le coffre recopié n'est lu qu'au chargement
    await unlock(other);
    await other.goto(`${BASE}/#/dashboard`);
    await other.locator('.dash-tile').first().waitFor();
    assert.equal(await healthCount(other, 'Compromis'), '1');
    assert.equal(await healthCount(other, 'Hors politique'), '3');
    assert.equal(await other.locator('#dashboard .gen-value').textContent(), '22');
    assert.equal(await healthCount(other, 'À renouveler'), 'Désactivé');
    assert.ok(await other.locator('#dashboard .gen-chip:has-text("Symboles") input').isChecked());
    assert.match(await other.textContent('.dash-usage-head'), /événements/);
    assert.equal(await other.evaluate(() => document.documentElement.dataset.theme), 'dark');
    await other.close();
  });

  await step('mobile : accès depuis Activité', async () => {
    const mobile = await newPage({ width: 390, height: 844 });
    await mobile.goto(`${BASE}/`);
    await mobile.evaluate((raw) => { localStorage.clear(); localStorage.setItem('mymfa.locale', 'fr'); localStorage.setItem('mymfa.vault.v1', raw); }, vaultRaw);
    await mobile.goto(`${BASE}/#/activity`);
    await mobile.reload(); // le coffre recopié n'est lu qu'au chargement
    await unlock(mobile);
    await mobile.goto(`${BASE}/#/activity`);
    await mobile.click('.view-activity a[href="#/dashboard"]');
    await mobile.locator('.dash-tile').first().waitFor();
    const width = await mobile.evaluate(() => document.documentElement.scrollWidth);
    assert.ok(width <= 390, `pas de défilement horizontal (${width}px)`);
    await mobile.screenshot({ path: join(SHOTS, 'dashboard-mobile.png'), fullPage: true });
    await mobile.close();
  });

  assert.deepEqual(errors, [], `erreurs console : ${errors.join(' | ')}`);
  console.log(`\n${steps.length} étapes réussies, aucune erreur console.`);
} catch (err) {
  console.error(`\n✗ Échec après « ${steps[steps.length - 1] || 'démarrage'} »\n`, err);
  if (errors.length) console.error('Erreurs console :', errors);
  await page.screenshot({ path: join(SHOTS, 'e2e-failure.png') }).catch(() => {});
  process.exitCode = 1;
} finally {
  await browser.close();
}
