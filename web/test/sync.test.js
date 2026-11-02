const test = require('node:test');
const assert = require('node:assert/strict');
const Store = require('../js/store.js');
const Sync = require('../js/sync.js');
const { memoryStorage } = require('./helpers.js');

function side() {
  const storage = memoryStorage();
  return { storage, store: Store.createStore(storage) };
}
const snapshot = (s) => Object.fromEntries(Sync.KEYS.map((k) => [k, s.storage.getItem(k)]).filter(([, v]) => v !== null));
const load = (s, map) => Object.entries(map).forEach(([k, v]) => s.storage.setItem(k, v));

test('ajouts des deux côtés : union, ordre de création conservé', () => {
  const app = side();
  const ext = side();
  app.store.add({ issuer: 'GitHub', account: 'a', secret: 'JBSWY3DPEHPK3PXP' });
  ext.store.add({ issuer: 'Proton', account: 'b', secret: 'KRSXG5CTMVRXEZLU' });
  const merged = Sync.merge(snapshot(app), snapshot(ext));
  load(app, merged);
  assert.deepEqual(app.store.list().map((a) => a.issuer), ['GitHub', 'Proton']);
  assert.equal(app.store.history().length, 2);
});

test('suppression d’un côté : le compte ne revient pas', () => {
  const app = side();
  const acc = app.store.add({ issuer: 'GitHub', account: 'a', secret: 'JBSWY3DPEHPK3PXP' });
  const ext = side();
  load(ext, snapshot(app)); // l'extension a la même copie
  app.store.remove(acc.id);
  const merged = Sync.merge(snapshot(app), snapshot(ext));
  load(ext, merged);
  assert.equal(ext.store.list().length, 0);
  assert.ok(ext.store.tombstones().accounts[acc.id]);
});

test('modification : la version la plus récente l’emporte', async () => {
  const app = side();
  const acc = app.store.add({ issuer: 'GitHub', account: 'a', secret: 'JBSWY3DPEHPK3PXP', tag: 'pro' });
  const ext = side();
  load(ext, snapshot(app));
  await new Promise((r) => setTimeout(r, 5));
  ext.store.update(acc.id, { tag: 'perso' });
  const merged = Sync.merge(snapshot(app), snapshot(ext));
  load(app, merged);
  assert.equal(app.store.get(acc.id).tag, 'perso');
});

test('même compte ajouté des deux côtés : un seul conservé, le plus ancien', async () => {
  const app = side();
  const first = app.store.add({ issuer: 'GitHub', account: 'a', secret: 'JBSWY3DPEHPK3PXP' });
  await new Promise((r) => setTimeout(r, 5));
  const ext = side();
  ext.store.add({ issuer: 'GitHub', account: 'a', secret: 'JBSWY3DPEHPK3PXP' });
  const merged = Sync.merge(snapshot(app), snapshot(ext));
  load(app, merged);
  assert.deepEqual(app.store.list().map((a) => a.id), [first.id]);
});

test('historique vidé d’un côté : les anciennes entrées ne reviennent pas', async () => {
  const app = side();
  app.store.add({ issuer: 'GitHub', account: 'a', secret: 'JBSWY3DPEHPK3PXP' });
  const ext = side();
  load(ext, snapshot(app));
  await new Promise((r) => setTimeout(r, 5));
  app.store.clearHistory();
  const merged = Sync.merge(snapshot(app), snapshot(ext));
  load(ext, merged);
  assert.equal(ext.store.history().length, 0);
  assert.equal(ext.store.list().length, 1);
});

test('fusion idempotente et données corrompues tolérées', () => {
  const app = side();
  app.store.add({ issuer: 'GitHub', account: 'a', secret: 'JBSWY3DPEHPK3PXP' });
  const once = Sync.merge(snapshot(app), {});
  const twice = Sync.merge(once, once);
  assert.ok(Sync.same(once, twice));
  assert.doesNotThrow(() => Sync.merge({ [Store.ACCOUNTS_KEY]: '{pas du json' }, {}));
});

test('mots de passe : union, même site + identifiant fusionné, suppression respectée', () => {
  const app = side();
  const ext = side();
  const shared = app.store.addLogin({ url: 'https://exemple.fr/login', username: 'alice', password: 'un' });
  load(ext, snapshot(app));
  app.store.addLogin({ url: 'https://autre.fr', username: 'bob', password: 'deux' });
  ext.store.addLogin({ url: 'https://exemple.fr/autre', username: 'carol', password: 'trois' });
  ext.store.addLogin({ url: 'https://autre.fr', username: 'bob', password: 'deux bis' }); // même compte ajouté des deux côtés
  app.store.removeLogin(shared.id);
  const merged = Sync.merge(snapshot(app), snapshot(ext));
  load(app, merged);
  assert.deepEqual(app.store.logins().map((l) => `${l.origin} ${l.username}`).sort(), ['https://autre.fr bob', 'https://exemple.fr carol']);
  assert.equal(app.store.logins().find((l) => l.username === 'bob').password, 'deux', 'le plus ancien est gardé');
  assert.ok(Sync.hasCredentials(merged));
});

test('passkeys : union par id, même credentialId fusionné', () => {
  const app = side();
  const ext = side();
  const data = { credentialId: 'cred-1', rpId: 'exemple.fr', userHandle: 'u1', userName: 'alice', privateKey: 'k' };
  app.store.addPasskey(data);
  ext.store.addPasskey(data);
  ext.store.addPasskey({ ...data, credentialId: 'cred-2', rpId: 'autre.fr' });
  const merged = Sync.merge(snapshot(app), snapshot(ext));
  load(app, merged);
  assert.deepEqual(app.store.passkeys().map((p) => p.credentialId).sort(), ['cred-1', 'cred-2']);
});

test('collections récentes absentes des deux côtés : non créées (pas de réécriture inutile)', () => {
  const app = side();
  app.store.add({ issuer: 'GitHub', account: 'a', secret: 'JBSWY3DPEHPK3PXP' });
  const merged = Sync.merge(snapshot(app), snapshot(app));
  assert.equal(merged[Store.LOGINS_KEY], undefined);
  assert.equal(merged[Store.PASSKEYS_KEY], undefined);
  assert.equal(Sync.hasCredentials(merged), false);
});

test('réglages du coffre : fusionnés par nom, le plus récent l’emporte', () => {
  const app = side();
  const ext = side();
  app.storage.setItem(Store.SETTINGS_KEY, JSON.stringify({ policy: { value: { minLength: 16 }, at: '2026-01-02T00:00:00Z' }, prefs: { value: { theme: 'dark' }, at: '2026-01-01T00:00:00Z' } }));
  ext.storage.setItem(Store.SETTINGS_KEY, JSON.stringify({ policy: { value: { minLength: 10 }, at: '2026-01-01T00:00:00Z' }, prefs: { value: { theme: 'light' }, at: '2026-01-03T00:00:00Z' } }));
  load(app, Sync.merge(snapshot(app), snapshot(ext)));
  assert.deepEqual(app.store.setting('policy'), { minLength: 16 });
  assert.deepEqual(app.store.setting('prefs'), { theme: 'light' });
});

test('réglages absents des deux côtés : aucune clé écrite', () => {
  const merged = Sync.merge(snapshot(side()), snapshot(side()));
  assert.equal(merged[Store.SETTINGS_KEY], undefined);
});
