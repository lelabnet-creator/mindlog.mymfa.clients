// Scénario de bout en bout : mots de passe, codes et passkeys des sites, par les toasts de l'extension.
// Extension seule au départ (aucune app ouverte) : enregistrement d'un mot de passe → coffre créé dans
// l'extension → remplissage → mise à jour → code demandé par un site → passkey créée puis utilisée
// (y compris en saisie automatique) et vérifiée comme un serveur → coffre fermé → l'app reçoit le coffre.
// Prérequis : une app HÉBERGÉE à synchroniser, servie par le serveur de dev (`cd ../web && npm start`), puis `npm run build`.
// Les pages de test sont servies à part, sur leur propre origine. Lancement : node test/e2e/credentials.e2e.mjs
import { chromium } from 'playwright-core';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';
import assert from 'node:assert/strict';
import { serveFixtures } from './fixtures-server.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const EXT = join(ROOT, 'src');
const BASE = process.env.BASE_URL || 'http://localhost:4173';
const fixtures = await serveFixtures();
const FIX = fixtures.url; // origine du « site » visité, distincte de celle de l'app
const MASTER = 'phrase maîtresse de test 1';
const SECRET = 'JBSWY3DPEHPK3PXP';
const Authn = createRequire(import.meta.url)('../../src/lib/webauthn.js');

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

if (!existsSync(join(EXT, 'lib', 'webauthn.js'))) throw new Error('Extension non construite : lancez `npm run build`');

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

const userDataDir = mkdtempSync(join(process.env.E2E_TMP || tmpdir(), 'mymfa-cred-'));
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
  page.on('console', (m) => m.type() === 'error' && !/favicon|ERR_|status of 4/.test(m.text()) && errors.push(`${page.url()} : ${m.text()}`));
  return page;
};

let worker = context.serviceWorkers()[0];
if (!worker) worker = await context.waitForEvent('serviceworker');
const extId = new URL(worker.url()).host;
// L'app hébergée est facultative : on la déclare, comme dans les réglages du popup.
await worker.evaluate((url) => saveSettings({ appUrl: url }), BASE);
const popupData = () => worker.evaluate(() => popupList());

/* Le toast vit dans un shadow root fermé : lecture et clics par le protocole DevTools (clics réels). */
function toastApi(page) {
  let cdp = null;
  async function shadow() {
    if (!cdp) cdp = await page.context().newCDPSession(page);
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
    reset() {
      cdp = null;
    },
    async text() {
      const root = await shadow();
      if (!root) return '';
      const { outerHTML } = await cdp.send('DOM.getOuterHTML', { nodeId: root.nodeId });
      // Valeurs des champs gardées (identifiant proposé à l'enregistrement).
      return outerHTML
        .replace(/<style>[\s\S]*?<\/style>/, '')
        .replace(/<input[^>]*?value="([^"]*)"[^>]*>/g, ' $1 ')
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s+/g, ' ');
    },
    async waitFor(text, label) {
      return until(async () => (await this.text()).includes(text), { label: label || `toast « ${text} »` });
    },
    /** Identité DOM du premier élément du toast qui répond au sélecteur (change s'il est recréé). */
    async nodeId(selector) {
      const root = await shadow();
      const { nodeId } = await cdp.send('DOM.querySelector', { nodeId: root.nodeId, selector });
      if (!nodeId) return null;
      const { node } = await cdp.send('DOM.describeNode', { nodeId });
      return node.backendNodeId;
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
      throw new Error(`Élément introuvable dans le toast : ${selector} ${textMatch || ''}`);
    },
  };
}

/* Vérifications d'un serveur WebAuthn, à partir de credential.toJSON(). */
const sha256 = async (bytes) => new Uint8Array(await webcrypto.subtle.digest('SHA-256', bytes));
const decode = (b64) => JSON.parse(new TextDecoder().decode(Authn.fromB64Url(b64)));

async function verifyRegistration(created) {
  const data = decode(created.json.response.clientDataJSON);
  assert.equal(data.type, 'webauthn.create');
  assert.equal(data.origin, FIX);
  assert.equal(data.challenge, Authn.toB64Url(Uint8Array.from(created.challenge)));
  const authData = Authn.cborDecode(Authn.fromB64Url(created.json.response.attestationObject)).value.get('authData');
  assert.deepEqual(authData.slice(0, 32), await sha256(new TextEncoder().encode('localhost')));
  const idLength = (authData[53] << 8) | authData[54];
  const cose = Authn.cborDecode(authData, 55 + idLength).value;
  return webcrypto.subtle.importKey('raw', new Uint8Array([4, ...cose.get(-2), ...cose.get(-3)]), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
}

async function verifyAssertion(got, publicKey) {
  const data = decode(got.json.response.clientDataJSON);
  assert.equal(data.type, 'webauthn.get');
  assert.equal(data.origin, FIX);
  assert.equal(data.challenge, Authn.toB64Url(Uint8Array.from(got.challenge)));
  const authData = Authn.fromB64Url(got.json.response.authenticatorData);
  const signed = new Uint8Array([...authData, ...(await sha256(Authn.fromB64Url(got.json.response.clientDataJSON)))]);
  const signature = Authn.derToRaw(Authn.fromB64Url(got.json.response.signature));
  assert.ok(await webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, signed), 'signature valide');
  assert.equal(new TextDecoder().decode(Authn.fromB64Url(got.json.response.userHandle)), 'user-42');
}

const site = watch(await context.newPage());
const toast = toastApi(site);
let publicKey = null;

/** Une fois rempli, le toast se retire et ne revient pas, même si la page continue de bouger. */
async function staysClosed(page, what) {
  await until(async () => !(await toast.text()).trim(), { label: `toast ${what} retiré` });
  for (let i = 0; i < 8; i += 1) {
    await page.evaluate((n) => document.body.classList.toggle(`tick-${n}`), i);
    await page.waitForTimeout(400);
    assert.equal((await toast.text()).trim(), '', `toast ${what} revenu après remplissage`);
  }
}

async function goto(url) {
  await site.goto(url);
  toast.reset();
}

try {
  await step('extension chargée, sans app ni coffre', async () => {
    assert.match(extId, /^[a-p]{32}$/);
    assert.equal((await popupData()).status, 'empty');
  });

  await step('connexion à un site : « Enregistrer le mot de passe ? » sur la page suivante', async () => {
    await goto(`${FIX}/login.html`);
    await site.fill('#email', 'alice@test');
    await site.fill('#password', 'premier-secret');
    await site.click('button[type="submit"]');
    await site.waitForURL(/login-ok\.html$/);
    toast.reset();
    await toast.waitFor('Enregistrer le mot de passe ?');
    assert.match(await toast.text(), /alice@test/);
    assert.ok(!(await toast.text()).includes('premier-secret'), 'mot de passe jamais affiché dans la page');
  });

  await step('pas de coffre : « Créer mon coffre », mot de passe maître choisi dans le popup, enregistrement aussitôt', async () => {
    await toast.click('button.primary', 'Enregistrer');
    await toast.waitFor('Créer mon coffre');
    await toast.click('button.primary', 'Créer mon coffre');
    const popup = watch(await context.newPage());
    await popup.goto(`chrome-extension://${extId}/popup.html`);
    await popup.locator('[data-view="create"]').waitFor();
    await popup.fill('#create-password', MASTER);
    await popup.fill('#create-confirm', MASTER);
    await popup.click('#create-form button[type="submit"]');
    await popup.locator('[data-view="main"]').waitFor();
    await toast.waitFor('Mot de passe enregistré');
    const data = await popupData();
    assert.equal(data.status, 'unlocked');
    assert.deepEqual(data.logins.map((l) => [l.origin, l.username, l.password]), [[FIX, 'alice@test', 'premier-secret']]);
    const snapshot = (await worker.evaluate(() => chrome.storage.local.get('ext.snapshot')))['ext.snapshot'];
    assert.ok(!JSON.stringify(snapshot).includes('premier-secret'), 'coffre chiffré');
    await popup.close();
  });

  await step('retour sur le site : toast « Se connecter », un clic remplit identifiant et mot de passe', async () => {
    await goto(`${FIX}/login.html`);
    await toast.waitFor('Se connecter à localhost');
    await toast.click('button.row', 'alice@test');
    await until(async () => (await site.inputValue('#password')) === 'premier-secret', { label: 'mot de passe rempli' });
    assert.equal(await site.inputValue('#email'), 'alice@test');
    await staysClosed(site, 'de connexion');
  });

  await step('mot de passe changé : « Mettre à jour le mot de passe ? »', async () => {
    await site.fill('#password', 'second-secret');
    await site.click('button[type="submit"]');
    await site.waitForURL(/login-ok\.html$/);
    toast.reset();
    await toast.waitFor('Mettre à jour le mot de passe ?');
    await toast.click('button.primary', 'Mettre à jour');
    await toast.waitFor('Mot de passe enregistré');
    const { logins } = await popupData();
    assert.equal(logins.length, 1);
    assert.equal(logins[0].password, 'second-secret');
  });

  await step('code MFA demandé par le site : toast avec le code, un clic le remplit', async () => {
    await worker.evaluate((uri) => handlers['content:add']({ uri }), `otpauth://totp/Localhost:alice?secret=${SECRET}&issuer=Localhost`);
    await goto(`${FIX}/otp.html`);
    await toast.waitFor('Code de vérification demandé');
    // Le décompte avance sans recréer la carte : sinon elle rejoue son entrée et semble resurgir.
    const remaining = async () => Number((await toast.text()).match(/ (\d{1,2}) /)[1]);
    if ((await remaining()) < 5) await site.waitForTimeout(6000); // nouvelle période : la liste est redemandée
    const card = await toast.nodeId('aside');
    const secs = await remaining();
    await site.waitForTimeout(2500);
    toast.reset();
    assert.equal(await toast.nodeId('aside'), card, 'carte du code recréée à chaque seconde');
    assert.notEqual(await remaining(), secs, 'décompte figé');
    await toast.click('button.primary', 'Remplir');
    const expected = await worker.evaluate((s) => OTP.totp(s), SECRET);
    await until(async () => (await site.inputValue('#code')) === expected, { label: 'code rempli' });
    await staysClosed(site, 'du code');
  });

  await step('passkey : création proposée par myMFA, attestation vérifiable par le site', async () => {
    await goto(`${FIX}/passkey.html`);
    await site.click('#register');
    await toast.waitFor('Créer une passkey pour localhost ?');
    assert.match(await toast.text(), /alice@test/);
    await toast.click('button.primary', 'Enregistrer dans myMFA');
    const created = await until(() => site.evaluate(() => window.results.created), { label: 'passkey créée' });
    assert.equal(created.isCredential, true, 'instanceof PublicKeyCredential');
    assert.deepEqual(created.ext, { credProps: { rk: true } });
    publicKey = await verifyRegistration(created);
    const { passkeys } = await popupData();
    assert.equal(passkeys.length, 1);
    assert.equal(passkeys[0].rpId, 'localhost');
    assert.equal(passkeys[0].privateKey, undefined, 'clé privée jamais transmise au popup');
  });

  await step('passkey : connexion par le toast, signature vérifiée comme un serveur', async () => {
    await site.click('#login');
    await toast.waitFor('Se connecter à localhost avec une passkey');
    await toast.click('button.row', 'Alice');
    const got = await until(() => site.evaluate(() => window.results.got), { label: 'connexion par passkey' });
    assert.equal(got.isCredential, true);
    await verifyAssertion(got, publicKey);
  });

  await step('passkey en saisie automatique (mediation conditional) : proposée d’emblée par le toast', async () => {
    await goto(`${FIX}/passkey.html?conditional`);
    await toast.waitFor('Se connecter à localhost avec une passkey');
    await toast.click('button.row', 'Alice');
    const got = await until(() => site.evaluate(() => window.results.conditional), { label: 'connexion conditionnelle' });
    await verifyAssertion(got, publicKey);
  });

  await step('coffre fermé : le site connu propose de déverrouiller, sans rien révéler', async () => {
    await worker.evaluate(() => setDek(null));
    await goto(`${FIX}/login.html`);
    await toast.waitFor('Un mot de passe est enregistré pour ce site');
    assert.ok(!(await toast.text()).includes('alice@test'));
    const res = await site.evaluate(() => document.querySelector('#password').value);
    assert.equal(res, '');
  });

  await step('l’app reçoit le coffre créé dans l’extension : mots de passe et passkey visibles après déverrouillage', async () => {
    await worker.evaluate((pw) => unlock(pw), MASTER);
    const app = watch(await context.newPage());
    await app.goto(`${BASE}/`);
    await app.locator('#lock-screen').waitFor({ timeout: 15000 });
    await app.fill('#lock-password', MASTER);
    await app.click('#lock-form button[type="submit"]');
    await app.locator('#lock-screen').waitFor({ state: 'hidden' });
    await app.goto(`${BASE}/#/passwords`);
    // Liste : le site, avec ce qui en dépend (compte 2FA, passkey).
    const item = app.locator('#cred-list .cred-item', { hasText: 'alice@test' }).first();
    await item.waitFor();
    assert.match(await item.textContent(), /2FA/);
    assert.match(await item.textContent(), /Passkey/);
    assert.equal(await app.locator('#cred-list .section-label', { hasText: 'Récemment utilisés' }).count(), 1, 'rempli par l’extension : récemment utilisé');
    // Détail (bureau : à côté de la liste) : identifiant, code 2FA en direct, passkey du site.
    const detail = app.locator('#cred-detail');
    await detail.locator('.cred-fields .cred-field-value', { hasText: 'alice@test' }).waitFor();
    const expected = await worker.evaluate((s) => OTP.totp(s), SECRET);
    await until(async () => (await detail.locator('.cred-code').textContent()).replace(' ', '') === expected, { label: 'code 2FA en direct' });
    await detail.locator('.cred-passkey', { hasText: 'Alice' }).waitFor();
    // Mot de passe masqué, puis affiché à la demande.
    assert.ok(!(await detail.textContent()).includes('second-secret'));
    await detail.getByRole('button', { name: 'Afficher' }).click();
    await detail.locator('.cred-secret', { hasText: 'second-secret' }).waitFor();
    assert.equal(await app.evaluate(() => localStorage.getItem('mymfa.logins.v1')), null, 'rien en clair dans l’app');
    await app.close();
  });

  await step('inscription : mot de passe fort selon les règles du site, rempli, puis enregistré', async () => {
    await goto(`${FIX}/signup.html`);
    await toast.waitFor('Mot de passe fort pour localhost');
    // Règles lues dans l'aide du champ (pas celles du pseudo) : 10 à 16 caractères, sans symbole.
    await toast.waitFor('10 à 16 caractères · sans symbole');
    await toast.click('button.btn', 'Un autre');
    await toast.click('button.primary', 'Utiliser');
    await toast.waitFor('Mot de passe rempli');
    const generated = await site.inputValue('#password');
    assert.match(generated, /^[A-Za-z0-9]{16}$/);
    assert.match(generated, /[A-Z]/);
    assert.match(generated, /\d/);
    assert.equal(await site.inputValue('#confirm'), generated);
    await site.fill('#user', 'bob');
    await site.click('button[type="submit"]');
    await site.waitForURL(/login-ok\.html$/);
    toast.reset();
    await toast.waitFor('Enregistrer le mot de passe ?');
    await toast.click('button.primary', 'Enregistrer');
    await toast.waitFor('Mot de passe enregistré');
    const { logins } = await popupData();
    assert.ok(logins.some((l) => l.username === 'bob' && l.password === generated), 'mot de passe généré enregistré');
  });

  await step('connexion : aucune proposition de mot de passe généré', async () => {
    await goto(`${FIX}/login.html`);
    await toast.waitFor('Se connecter à localhost');
    assert.ok(!(await toast.text()).includes('Mot de passe fort'));
  });

  await step('popup, vue « Tout » : un compte par ligne avec son code, son mot de passe et sa passkey', async () => {
    const popup = watch(await context.newPage());
    await popup.goto(`chrome-extension://${extId}/popup.html`);
    await popup.click('#tabs [data-tab="all"]');
    // Une entrée pour le site, deux comptes (alice, bob).
    const entry = popup.locator('#merged-list li.entry', { hasText: '2 comptes' });
    await entry.waitFor();
    const alice = entry.locator('li.line', { hasText: 'alice@test' });
    await alice.waitFor();
    // Dans le domaine : ordre alphabétique des comptes.
    assert.deepEqual(await entry.locator('li.line .item-user').allTextContents(), ['alice@test', 'bob']);
    const expected = await worker.evaluate((s) => OTP.totp(s), SECRET);
    await until(async () => (await alice.locator('.item-code').textContent()).replace(' ', '') === expected, { label: 'code dans la ligne' });
    assert.equal(await alice.locator('[data-action="copy-password"]').count(), 1);
    assert.equal(await alice.locator('.item-passkey').count(), 1);
    // Deuxième compte du même site : son mot de passe, sans le code ni la passkey d'alice.
    const bob = entry.locator('li.line', { hasText: 'bob' });
    assert.equal(await bob.locator('.item-code').count(), 0);
    assert.equal(await bob.locator('.item-passkey').count(), 0);
    await popup.click('[data-filter="fav"]');
    await popup.locator('#empty-merged', { hasText: 'Aucun favori' }).waitFor();
    await popup.click('[data-filter="all"]');
    await popup.close();
  });

  await step('popup : modifier mot de passe et code 2FA d’une même ligne, favori', async () => {
    const popup = watch(await context.newPage());
    await popup.goto(`chrome-extension://${extId}/popup.html`);
    // Onglet retenu d'une ouverture à l'autre.
    await popup.locator('[data-pane="all"]:not([hidden])').waitFor();
    await popup.locator('#merged-list li.line', { hasText: 'alice@test' }).locator('[data-action="edit"]').click();
    await popup.locator('[data-view="edit"]:not([hidden])').waitFor();
    assert.equal(await popup.isVisible('#edit-login'), true);
    assert.equal(await popup.isVisible('#edit-account'), true);
    assert.equal(await popup.inputValue('#edit-form [name="username"]'), 'alice@test');
    assert.equal(await popup.getAttribute('#edit-password', 'type'), 'password');
    await popup.click('#edit-generate');
    const generated = await popup.inputValue('#edit-password');
    assert.equal(generated.length, 20);
    await popup.fill('#edit-form [name="title"]', 'Compte perso');
    await popup.fill('#edit-form [name="issuer"]', 'Localhost Pro');
    await popup.fill('#edit-form [name="description"]', 'clé principale');
    await popup.fill('#edit-form [name="tag"]', 'Perso');
    await popup.click('#sw-favorite');
    await popup.click('#edit-form button[type="submit"]');
    await popup.locator('#toast', { hasText: 'Modifications enregistrées' }).waitFor();
    const data = await popupData();
    const login = data.logins.find((l) => l.username === 'alice@test');
    assert.deepEqual([login.title, login.password, login.favorite, login.tag], ['Compte perso', generated, true, 'perso']);
    const account = data.accounts.find((a) => a.secret === SECRET);
    assert.deepEqual([account.issuer, account.description, account.favorite, account.tag], ['Localhost Pro', 'clé principale', true, 'perso']);
    // Favoris : la ligne modifiée, avec son étoile.
    await popup.click('[data-filter="fav"]');
    await until(async () => (await popup.locator('#merged-list li.line').count()) === 1, { label: 'un favori' });
    assert.match(await popup.locator('#merged-list li.line').textContent(), /alice@test/);
    assert.match(await popup.locator('#merged-list').textContent(), /Compte perso/);
    assert.equal(await popup.locator('#merged-list .item-star').count(), 1);
    // Affichage : comptes à plat, par dernier usage (alice a servi, bob jamais), puis A → Z ; choix retenu.
    await popup.click('[data-filter="all"]');
    await popup.selectOption('#merged-order', 'recent');
    assert.equal(await popup.locator('#merged-list li.entry').count(), 0, 'plus de regroupement');
    const recent = await popup.locator('#merged-list li.line .item-account').allTextContents();
    assert.deepEqual(recent.slice(0, 1), ['alice@test']);
    assert.equal(recent[recent.length - 1], 'bob');
    await popup.selectOption('#merged-order', 'alpha');
    const names = await popup.locator('#merged-list li.line .item-issuer').allTextContents();
    assert.deepEqual(names, [...names].sort((a, b) => a.localeCompare(b)));
    await popup.reload();
    await until(async () => (await popup.inputValue('#merged-order')) === 'alpha', { label: 'affichage retenu' });
    // Par tag : #perso (alice), puis « Sans tag » (bob).
    await popup.selectOption('#merged-order', 'tag');
    const groups = popup.locator('#merged-list li.tag-group');
    assert.deepEqual(await groups.locator('.tag-name').allTextContents(), ['#perso', 'Sans tag']);
    assert.match(await groups.nth(0).textContent(), /alice@test/);
    assert.match(await groups.nth(1).textContent(), /bob/);
    await popup.selectOption('#merged-order', 'domain');
    await popup.locator('#merged-list li.entry', { hasText: 'localhost' }).waitFor();
    // Mot de passe modifié : historique sans le mot de passe.
    const history = await worker.evaluate(async () => JSON.stringify(Store.createStore(mapStorage({ ...(await readData()).map })).history()));
    assert.ok(!history.includes(generated));
    // Adresse invalide refusée, message dans le formulaire.
    await popup.locator('#merged-list li.line', { hasText: 'alice@test' }).locator('[data-action="edit"]').click();
    await popup.fill('#edit-form [name="origin"]', 'http://');
    await popup.click('#edit-form button[type="submit"]');
    await popup.locator('#edit-error', { hasText: 'Adresse invalide' }).waitFor();
    await popup.close();
  });

  await step('popup, par domaine : les adresses IP réunies dans une entrée « Adresses IP »', async () => {
    await worker.evaluate(() =>
      mutate((store) => {
        store.addLogin({ url: 'http://192.168.1.10/admin', username: 'admin', password: 'routeur' });
        store.addLogin({ url: 'https://192.168.1.2:8443', username: 'root', password: 'nas' });
        store.addLogin({ url: 'http://[fd00::1]:8080', username: 'ops', password: 'v6' });
      }, { secure: true })
    );
    const popup = watch(await context.newPage());
    await popup.goto(`chrome-extension://${extId}/popup.html`);
    await popup.click('#tabs [data-tab="all"]');
    await popup.selectOption('#merged-order', 'domain');
    const ip = popup.locator('#merged-list li.entry', { hasText: 'Adresses IP' });
    await ip.waitFor();
    assert.match(await ip.locator('.entry-head').textContent(), /3 comptes/);
    assert.equal((await ip.locator('.tile').textContent()).trim(), 'IP');
    // Par adresse (ordre numérique), avec le port.
    assert.deepEqual(await ip.locator('li.line .item-account').allTextContents(), ['192.168.1.2:8443', '192.168.1.10', '[fd00::1]:8080']);
    assert.equal(await popup.locator('#merged-list li.line', { hasText: '192.168.1.10' }).locator('[data-action="copy-password"]').count(), 1);
    await popup.close();
  });

  assert.deepEqual(errors, [], `erreurs console : ${errors.join(' | ')}`);
  console.log(`\n${steps.length} étapes réussies, aucune erreur console.`);
} catch (err) {
  console.error(`\n✗ Échec après « ${steps[steps.length - 1] || 'démarrage'} »\n`, err);
  if (errors.length) console.error('Erreurs console :', errors);
  for (const [i, page] of context.pages().entries()) {
    await page.screenshot({ path: join(process.env.E2E_SHOTS || '.', `cred-failure-${i}.png`) }).catch(() => {});
  }
  process.exitCode = 1;
} finally {
  await context.close();
  await fixtures.close();
  rmSync(userDataDir, { recursive: true, force: true });
}
