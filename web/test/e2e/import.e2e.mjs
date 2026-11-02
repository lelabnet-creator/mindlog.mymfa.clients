// Scénario de bout en bout : import d'un CSV Proton Pass (sans puis avec coffre chiffré) et d'un JSON Proton Authenticator.
// Lancement : serveur de dev démarré, puis `node test/e2e/import.e2e.mjs`.
//   BASE_URL (défaut http://localhost:4173) · CHROMIUM (chemin d'un Chromium, sinon cache Playwright)
import { chromium } from 'playwright-core';
import { existsSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';

const BASE = process.env.BASE_URL || 'http://localhost:4173';
const PASSWORD = 'phrase de test longue 1';
const CSV = [
  'type,name,url,autofillUrls,email,username,password,note,totp,createTime,modifyTime,vault',
  'login,GitHub,https://github.com/login,,me@exemple.fr,octocat,gh-secret-1,,otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub,1700000000,1700000100,Personal',
  'login,Banque,https://www.banque.fr,,client@exemple.fr,,bq-secret-2,,,1700000000,1700000000,Personal',
  'note,Codes Wi-Fi,,,,,,"wifi: x",,1700000000,1700000000,Personal',
].join('\n');

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
await page.route('**/js/config.js', (route) =>
  route.fulfill({ contentType: 'text/javascript', body: "window.MYMFA_CONFIG = { googleClientId: '' };" })
);

const toast = page.locator('#toast');
const file = (name, text) => ({ name, mimeType: 'text/csv', buffer: Buffer.from(text) });
const importFile = (name, text) => page.setInputFiles('#import-file', file(name, text));

try {
  await step('page vierge', async () => {
    await page.goto(`${BASE}/`);
    await page.evaluate(() => { localStorage.clear(); localStorage.setItem('mymfa.locale', 'fr'); });
    await page.goto(`${BASE}/#/settings`);
    assert.match(await page.textContent('label[for="import-file"]'), /Proton Pass \(CSV\) ou Proton Authenticator \(JSON\)/);
  });

  await step('CSV inconnu refusé', async () => {
    await importFile('autre.csv', 'name,login,secret\nx,y,z');
    await toast.filter({ hasText: 'Format non reconnu' }).waitFor();
  });

  await step('sans coffre chiffré : compte 2FA importé, mots de passe refusés', async () => {
    await importFile('Proton Pass_export.csv', CSV);
    await toast.filter({ hasText: 'Proton Pass : 0 mot(s) de passe et 1 compte(s) 2FA importés, 1 ignoré(s).' }).waitFor();
    assert.match(await toast.textContent(), /2 mot\(s\) de passe non importé\(s\) : activez le mot de passe maître/);
    assert.equal(await page.evaluate(() => localStorage.getItem('mymfa.logins.v1')), null);
    await page.goto(`${BASE}/#/`);
    assert.equal(await page.locator('#accounts .card').count(), 1);
  });

  await step('mot de passe maître activé', async () => {
    await page.goto(`${BASE}/#/passwords`);
    await page.click('#btn-cred-enable');
    await page.fill('#security-form input[name="next"]', PASSWORD);
    await page.fill('#security-form input[name="confirm"]', PASSWORD);
    await page.click('#security-form button[type="submit"]');
    await toast.filter({ hasText: 'Coffre chiffré' }).waitFor();
    const later = page.locator('#security-form button', { hasText: 'Plus tard' });
    if (await later.isVisible().catch(() => false)) await later.click();
  });

  await step('coffre ouvert : mots de passe importés, doublon 2FA ignoré, rien en clair', async () => {
    await page.goto(`${BASE}/#/settings`);
    await importFile('Proton Pass_export.csv', CSV);
    await toast.filter({ hasText: 'Proton Pass : 2 mot(s) de passe et 0 compte(s) 2FA importés, 2 ignoré(s).' }).waitFor();
    assert.match(await toast.textContent(), /Supprimez le fichier CSV/);
    const raw = await page.evaluate(() => JSON.stringify(localStorage));
    assert.ok(!raw.includes('gh-secret-1') && !raw.includes('bq-secret-2'), 'aucun mot de passe en clair');
  });

  await step('vue Mots de passe : les deux sites, avec leur identifiant', async () => {
    await page.goto(`${BASE}/#/passwords`);
    const list = page.locator('#cred-list');
    await list.getByText('octocat').waitFor();
    await list.getByText('client@exemple.fr').waitFor();
  });

  await step('gros import : barre de progression (compte, puis chiffrement du coffre), masquée à la fin', async () => {
    await page.goto(`${BASE}/#/settings`);
    // Tout ce que la barre affiche, relevé à chaque changement.
    await page.evaluate(() => {
      window.__progress = [];
      const box = document.getElementById('import-progress');
      new MutationObserver(() => {
        if (!box.hidden) window.__progress.push(`${box.querySelector('#import-progress-text').textContent}|${box.querySelector('#import-progress-count').textContent}`);
      }).observe(box, { subtree: true, childList: true, characterData: true, attributes: true });
    });
    const rows = Array.from({ length: 300 }, (_, i) => `login,Site ${i},https://site${i}.exemple.fr,,,user${i},pw-${i},,,1,1,Personal`);
    await importFile('gros.csv', [CSV.split('\n')[0], ...rows].join('\n'));
    await toast.filter({ hasText: 'Proton Pass : 300 mot(s) de passe et 0 compte(s) 2FA importés' }).waitFor();
    const seen = await page.evaluate(() => window.__progress);
    assert.ok(seen.includes('Import Proton Pass…|300 / 300'), `progression : ${seen.join(' · ')}`);
    assert.ok(seen.some((x) => /^Import Proton Pass…\|(20|40|60) \/ 300$/.test(x)), 'étapes intermédiaires');
    assert.ok(seen.includes('Chiffrement du coffre…|'), 'phase de chiffrement');
    assert.equal(await page.isVisible('#import-progress'), false);
    assert.equal(await page.isDisabled('#import-file'), false);
    // Le coffre écrit contient bien les 302 mots de passe.
    assert.equal(await page.evaluate(() => Store.createStore(Lock.storage).logins().length), 302);
  });

  await step('réimport : tout est ignoré', async () => {
    await page.goto(`${BASE}/#/settings`);
    await importFile('Proton Pass_export.csv', CSV);
    await toast.filter({ hasText: '0 mot(s) de passe et 0 compte(s) 2FA importés, 4 ignoré(s).' }).waitFor();
  });

  await step('JSON Proton Authenticator : compte 2FA importé avec sa note, Steam signalé', async () => {
    const json = JSON.stringify({
      version: 1,
      entries: [
        { id: 'a1', content: { uri: 'otpauth://totp/Notion:moi%40exemple.fr?secret=GEZDGNBVGY3TQOJQ&issuer=Notion', entry_type: 'Totp', name: 'moi@exemple.fr' }, note: 'compte pro' },
        { id: 'a2', content: { uri: 'otpauth://totp/Steam:joueur?secret=KRSXG5CTMVRXEZLU&issuer=Steam', entry_type: 'Steam', name: 'joueur' }, note: null },
      ],
    });
    await page.setInputFiles('#import-file', { name: 'Proton_Authenticator_backup.json', mimeType: 'application/json', buffer: Buffer.from(json) });
    await toast.filter({ hasText: 'Proton Authenticator : 1 compte(s) 2FA importé(s), 1 ignoré(s).' }).waitFor();
    assert.match(await toast.textContent(), /1 compte\(s\) Steam non importé\(s\)/);
    await page.goto(`${BASE}/#/`);
    await page.locator('#accounts .card', { hasText: 'Notion' }).waitFor();
    assert.equal(await page.locator('#accounts .card').count(), 2);
  });

  await step('activité : import Proton Pass tracé, sans mot de passe', async () => {
    await page.goto(`${BASE}/#/activity`);
    const activity = await page.textContent('#activity');
    assert.match(activity, /Import Proton Pass/);
    assert.match(activity, /Import Proton Authenticator/);
    assert.match(activity, /Via import Proton Pass/);
    assert.ok(!activity.includes('gh-secret-1'));
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
