// Scénario de bout en bout de l'extension : chargée dans un Chromium isolé (profil temporaire),
// avec l'app servie en local. Couvre : synchronisation app → extension, carte « déjà enregistré »
// + remplissage, ajout depuis la page + synchronisation extension → app, popup, coffre chiffré
// (verrouillage, déverrouillage dans la popup), suppression propagée.
// Prérequis : une app HÉBERGÉE à synchroniser, servie par le serveur de dev (`cd ../web && npm start`), puis `npm run build`.
// Les pages de test sont servies à part, sur leur propre origine. Lancement : node test/e2e/extension.e2e.mjs
import { chromium } from 'playwright-core';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { serveFixtures } from './fixtures-server.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const EXT = join(ROOT, 'src');
const BASE = process.env.BASE_URL || 'http://localhost:4173';
const fixtures = await serveFixtures();
const FIX = fixtures.url;
const PASSWORD = 'phrase de test longue 1';
const KNOWN_SECRET = 'JBSWY3DPEHPK3PXP';
const NEW_SECRET = 'KRSXG5CTMVRXEZLU';

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

if (!existsSync(join(EXT, 'lib', 'jsQR.js'))) throw new Error('Extension non construite : lancez `npm run build`');

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

const userDataDir = mkdtempSync(join(process.env.E2E_TMP || tmpdir(), 'mymfa-ext-'));
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
// L'app hébergée est facultative : on la déclare, comme dans les réglages du popup.
await worker.evaluate((url) => saveSettings({ appUrl: url }), BASE);
const extStorage = () => worker.evaluate(() => chrome.storage.local.get(null));

/* La carte vit dans un shadow root fermé : on la lit et on y clique via le protocole DevTools. */
async function cardApi(page) {
  const cdp = await page.context().newCDPSession(page);
  async function shadow() {
    const { root } = await cdp.send('DOM.getDocument', { depth: -1, pierce: true });
    const find = (node) => {
      if (node.nodeName === 'MYMFA-CARD') return node;
      for (const child of [...(node.children || []), ...(node.shadowRoots || [])]) {
        const hit = find(child);
        if (hit) return hit;
      }
      return null;
    };
    const host = find(root);
    return host && host.shadowRoots && host.shadowRoots[0];
  }
  return {
    async text() {
      const root = await shadow();
      if (!root) return '';
      const { outerHTML } = await cdp.send('DOM.getOuterHTML', { nodeId: root.nodeId });
      return outerHTML.replace(/<style>[\s\S]*?<\/style>/, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
    },
    async click(selector, textMatch) {
      const root = await shadow();
      const { nodeIds } = await cdp.send('DOM.querySelectorAll', { nodeId: root.nodeId, selector });
      for (const nodeId of nodeIds) {
        if (textMatch) {
          const { outerHTML } = await cdp.send('DOM.getOuterHTML', { nodeId });
          if (!outerHTML.replace(/<[^>]+>/g, '').includes(textMatch)) continue;
        }
        const { model } = await cdp.send('DOM.getBoxModel', { nodeId });
        const [x1, y1, , , x3, y3] = model.content;
        await page.mouse.click((x1 + x3) / 2, (y1 + y3) / 2);
        return;
      }
      throw new Error(`Élément introuvable dans la carte : ${selector} ${textMatch || ''}`);
    },
  };
}

const app = watch(await context.newPage());
const appAccounts = () => app.evaluate(() => JSON.parse(localStorage.getItem('mymfa.accounts.v1') || '[]').map((a) => a.issuer));
const totp = (secret) => app.evaluate((s) => OTP.totp(s), secret);

try {
  await step('extension chargée (service d’arrière-plan actif)', async () => {
    assert.match(extId, /^[a-p]{32}$/);
  });

  await step('app : ajout d’un compte, synchronisé vers l’extension', async () => {
    await app.goto(`${BASE}/`);
    await app.evaluate(() => { localStorage.clear(); localStorage.setItem('mymfa.locale', 'fr'); });
    await app.goto(`${BASE}/#/new`);
    await app.fill('#f-secret', KNOWN_SECRET);
    await app.fill('#f-issuer', 'Proton');
    await app.fill('#f-account', 'moi@exemple.fr');
    await app.click('#add-form button[type="submit"]');
    await until(async () => JSON.stringify((await extStorage())['ext.snapshot'] || {}).includes(KNOWN_SECRET), { label: 'synchro app → extension' });
  });

  const known = watch(await context.newPage());
  const knownCard = await cardApi(known);
  await step('page avec un QR connu : carte « Déjà enregistré » et bon code', async () => {
    await known.goto(`${FIX}/2fa-known.html`);
    const text = await until(async () => {
      const t = await knownCard.text();
      return t.includes('Déjà enregistré') && t;
    }, { label: 'carte compte connu' });
    assert.match(text, /Proton/);
    const code = await totp(KNOWN_SECRET);
    assert.ok(text.replace(/ /g, '').includes(code), `code ${code} affiché`);
    assert.equal(await known.evaluate(() => getComputedStyle(document.querySelector('img')).outlineStyle), 'solid');
  });

  await step('« Remplir le champ » insère le code dans la page', async () => {
    await knownCard.click('button.primary', 'Remplir');
    const value = await until(() => known.inputValue('#otp'), { label: 'champ rempli' });
    assert.equal(value, await totp(KNOWN_SECRET));
  });

  const fresh = watch(await context.newPage());
  const freshCard = await cardApi(fresh);
  await step('page avec un nouveau QR : ajout depuis la carte', async () => {
    await fresh.goto(`${FIX}/2fa-new.html`);
    await until(async () => (await freshCard.text()).includes('Non enregistré'), { label: 'carte nouveau compte' });
    await freshCard.click('button.primary', 'Ajouter');
    const text = await until(async () => {
      const t = await freshCard.text();
      return t.includes('Compte ajouté') && t;
    }, { label: 'compte ajouté' });
    assert.ok(text.replace(/ /g, '').includes(await totp(NEW_SECRET)));
  });

  await step('synchronisation extension → app (le compte apparaît dans l’app)', async () => {
    await until(async () => (await appAccounts()).includes('Nimbus'), { label: 'Nimbus dans l’app' });
    await app.goto(`${BASE}/#/activity`);
    assert.match(await app.textContent('#activity'), /Via l’extension navigateur/);
  });

  const popup = watch(await context.newPage());
  await step('popup : les deux comptes et leurs codes', async () => {
    await popup.goto(`chrome-extension://${extId}/popup.html`);
    await until(async () => (await popup.locator('#all-list li').count()) === 2, { label: 'deux comptes dans la popup' });
    const codes = await popup.locator('#all-list .item-code').allTextContents();
    const expected = [await totp(KNOWN_SECRET), await totp(NEW_SECRET)].sort();
    assert.deepEqual(codes.map((c) => c.replace(' ', '')).sort(), expected);
  });

  await step('mot de passe maître activé dans l’app : l’extension adopte le coffre chiffré', async () => {
    await app.goto(`${BASE}/#/settings`);
    await app.click('#security-rows button');
    await app.fill('#security-form input[name="next"]', PASSWORD);
    await app.fill('#security-form input[name="confirm"]', PASSWORD);
    await app.click('#security-form button[type="submit"]');
    await app.locator('#toast').filter({ hasText: 'Coffre chiffré' }).waitFor();
    const snap = await until(async () => {
      const s = (await extStorage())['ext.snapshot'] || {};
      return s['mymfa.vault.v1'] && s;
    }, { label: 'coffre dans l’extension' });
    assert.ok(!JSON.stringify(snap).includes(KNOWN_SECRET), 'aucun secret en clair dans l’extension');
  });

  await step('extension verrouillée : popup demande le mot de passe, carte « Verrouillé »', async () => {
    await popup.reload();
    await popup.locator('[data-view="unlock"]').waitFor();
    await known.reload();
    await until(async () => (await knownCard.text()).includes('myMFA est verrouillé'), { label: 'carte verrouillée' });
  });

  await step('déverrouillage dans la popup : comptes visibles, carte mise à jour d’elle-même', async () => {
    await popup.fill('#unlock-password', 'mauvais mot de passe');
    await popup.click('#unlock-form button[type="submit"]');
    await popup.locator('#unlock-error', { hasText: 'Mot de passe incorrect' }).waitFor();
    await popup.fill('#unlock-password', PASSWORD);
    await popup.click('#unlock-form button[type="submit"]');
    await until(async () => (await popup.locator('#all-list li').count()) === 2, { label: 'comptes après déverrouillage' });
    // Le déverrouillage prévient les onglets : la carte se met à jour sans « Réessayer ».
    await until(async () => (await knownCard.text()).includes('Déjà enregistré'), { label: 'carte après déverrouillage' });
  });

  await step('suppression dans l’app (coffre chiffré) propagée à l’extension', async () => {
    await app.goto(`${BASE}/#/`);
    const card = app.locator('#accounts .card', { hasText: 'Nimbus' });
    await card.locator('.card-name').click();
    await app.click('#btn-delete');
    await app.click('#btn-delete-yes');
    await popup.reload();
    await until(async () => {
      const names = await popup.locator('#all-list .item-issuer').allTextContents();
      return names.length === 1 && names[0] === 'Proton';
    }, { label: 'suppression propagée' });
  });

  /* Google Drive simulé : la sauvegarde vit côté test, l'échange réel (driveExchange) tourne dans le service. */
  // Faux client Drive (forme de js/drive.js) : une version fixe tant que personne n'écrit.
  // Réponse résumée à ce que le popup lit : { changed, uploaded } ou { needsUnlock }.
  const driveExchange = (content) =>
    worker.evaluate(async (content) => {
      let uploaded = null;
      const fichier = content ? { id: 'f1', modifiedTime: new Date().toISOString(), headRevisionId: 'r1' } : null;
      const client = {
        async find() {
          return fichier;
        },
        async download() {
          return { content, modifiedTime: fichier.modifiedTime };
        },
        async upload(body) {
          uploaded = body;
          return { id: 'f1', modifiedTime: new Date().toISOString() };
        },
      };
      const res = await driveExchange(client);
      return { res: res.needsUnlock ? { needsUnlock: true } : { changed: res.changed, uploaded: res.uploaded }, uploaded };
    }, content);
  // Sauvegarde d'un « autre appareil » : le coffre de l'extension, plus un compte.
  const forgeBackup = (uri) =>
    worker.evaluate(async (uri) => {
      const dek = await getDek();
      const record = Vault.parse((await getSnapshot())[Vault.VAULT_KEY]);
      const storage = mapStorage(await Vault.decryptData(dek, record.data));
      Store.createStore(storage).add(OTP.parseOtpauthUri(uri), 'test');
      return JSON.stringify({ ...record, data: await Vault.encryptData(dek, storage.map) });
    }, uri);
  const backupIssuers = (content) =>
    worker.evaluate(async (content) => {
      const map = await Vault.decryptData(await getDek(), Vault.parse(content).data);
      // Comptes vivants : un compte supprimé (v2) reste dans la copie avec sa trace.
      return JSON.parse(map[Store.ACCOUNTS_KEY]).filter((a) => Sync2.estVivant(a)).map((a) => a.issuer).sort();
    }, content);

  let backup = null;

  await step('Drive vide : l’extension y dépose son coffre chiffré', async () => {
    const { res, uploaded } = await driveExchange(null);
    assert.deepEqual(res, { changed: false, uploaded: true });
    assert.ok(uploaded && !uploaded.includes('Proton'), 'coffre chiffré attendu');
    assert.deepEqual(await backupIssuers(uploaded), ['Proton']);
    backup = uploaded;
  });

  await step('sauvegarde Drive plus récente : compte récupéré, puis transmis à l’app', async () => {
    backup = await forgeBackup('otpauth://totp/Atlas:alice?secret=JBSWY3DPEHPK3PXQ&issuer=Atlas');
    const { res, uploaded } = await driveExchange(backup);
    assert.deepEqual(res, { changed: true, uploaded: false });
    assert.equal(uploaded, null);
    await popup.reload();
    await until(async () => (await popup.locator('#all-list .item-issuer').allTextContents()).sort().join() === 'Atlas,Proton', {
      label: 'compte Drive dans la popup',
    });
    await app.locator('#accounts .card', { hasText: 'Atlas' }).waitFor();
  });

  await step('ajout dans l’extension : renvoyé sur Drive, rien si déjà à jour', async () => {
    await worker.evaluate(() => handlers['content:add']({ uri: 'otpauth://totp/Borealis:bob?secret=KRSXG5CTMVRXEZLU&issuer=Borealis' }));
    const { res, uploaded } = await driveExchange(backup);
    assert.deepEqual(res, { changed: false, uploaded: true });
    assert.deepEqual(await backupIssuers(uploaded), ['Atlas', 'Borealis', 'Proton']);
    backup = uploaded;
    assert.deepEqual((await driveExchange(backup)).res, { changed: false, uploaded: false });
  });

  await step('extension verrouillée et Drive différent : déverrouillage demandé', async () => {
    const newer = await forgeBackup('otpauth://totp/Cirrus:carol?secret=MFRGGZDFMZTWQ2LK&issuer=Cirrus');
    await worker.evaluate(() => setDek(null));
    const before = (await extStorage())['ext.snapshot'];
    const { res, uploaded } = await driveExchange(newer);
    assert.deepEqual(res, { needsUnlock: true });
    assert.equal(uploaded, null);
    assert.deepEqual((await extStorage())['ext.snapshot'], before, 'copie de l’extension inchangée');
  });

  assert.deepEqual(errors, [], `erreurs console : ${errors.join(' | ')}`);
  console.log(`\n${steps.length} étapes réussies, aucune erreur console.`);
} catch (err) {
  console.error(`\n✗ Échec après « ${steps[steps.length - 1] || 'démarrage'} »\n`, err);
  if (errors.length) console.error('Erreurs console :', errors);
  for (const [i, page] of context.pages().entries()) {
    await page.screenshot({ path: join(process.env.E2E_SHOTS || '.', `ext-failure-${i}.png`) }).catch(() => {});
  }
  process.exitCode = 1;
} finally {
  await context.close();
  await fixtures.close();
  rmSync(userDataDir, { recursive: true, force: true });
}
