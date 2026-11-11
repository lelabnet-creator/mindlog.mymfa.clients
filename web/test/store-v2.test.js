/*
 * Store en mode v2 (SYN-07) : `createStore(storage, temps)` tamponne les champs
 * (item.h), marque les suppressions (item.t) au lieu d'enterrer, filtre les
 * éléments morts des lectures, tamponne les réglages et le vidage d'historique.
 * Sans `temps`, le comportement v1 historique est inchangé (voir store.test.js).
 */
const test = require('node:test');
const assert = require('node:assert');
const { createStore } = require('../js/store.js');
const Sync2 = require('../js/sync2.js');

const ACCOUNTS_KEY = 'mymfa.accounts.v1';
const LOGINS_KEY = 'mymfa.logins.v1';
const SETTINGS_KEY = 'mymfa.settings.v1';
const SYNC_KEY = 'mymfa.sync.v2';

const T0 = 1_794_405_900_000;
const MINUT = 60_000;

/** Une horloge hybride contrôlée : chaque tampon demandé avance d'une minute. */
function tempsFactice() {
  let tic = 0;
  return {
    tampon: (plancher) => {
      tic += 1;
      const t = Sync2.encoderTampon(T0 + tic * MINUT, 0, 'pc');
      return plancher && t <= plancher ? Sync2.encoderTampon(Sync2.decoderL(plancher), Sync2.decoderC(plancher) + 1, 'pc') : t;
    },
    dernier: () => Sync2.encoderTampon(T0 + tic * MINUT, 0, 'pc'),
  };
}

function stockageMemoire() {
  const carte = new Map();
  return {
    getItem: (k) => (carte.has(k) ? carte.get(k) : null),
    setItem: (k, v) => carte.set(k, String(v)),
    removeItem: (k) => carte.delete(k),
  };
}

test('mode v2 : un ajout tamponne tous ses champs', () => {
  const temps = tempsFactice();
  const store = createStore(stockageMemoire(), temps);
  const compte = store.add({ issuer: 'GitHub', secret: 'JBSWY3DPEHPK3PXP' });
  assert.ok(compte.h, 'l\u2019élément ajouté porte ses tampons');
  const brut = store.list()[0];
  assert.ok(brut.h && brut.h.issuer === brut.h.secret, 'un seul tampon pour la création');
  assert.ok(brut.h.issuer > Sync2.encoderTampon(T0, 0, 'pc'));
  assert.strictEqual(brut.updatedAt, Sync2.isoDepuisTampon(brut.h.issuer));
  assert.ok(Sync2.estVivant(brut));
});

test('mode v2 : une modification ne retamponne que les champs changés', () => {
  const temps = tempsFactice();
  const store = createStore(stockageMemoire(), temps);
  const compte = store.add({ issuer: 'GitHub', secret: 'JBSWY3DPEHPK3PXP', tag: 'avant', description: 'note' });
  const avant = store.list()[0];
  store.update(compte.id, { tag: 'après' });
  const après = store.list()[0];
  assert.notStrictEqual(après.h.tag, avant.h.tag, 'le champ modifié est retamponné');
  assert.strictEqual(après.h.description, avant.h.description, 'les champs intacts gardent leur tampon');
  assert.strictEqual(après.updatedAt, Sync2.isoDepuisTampon(après.h.tag));
});

test('mode v2 : une suppression garde l\u2019élément mort dans la copie, invisible des lectures', () => {
  const temps = tempsFactice();
  const storage = stockageMemoire();
  const store = createStore(storage, temps);
  const compte = store.add({ issuer: 'GitHub', secret: 'JBSWY3DPEHPK3PXP' });
  assert.ok(store.remove(compte.id));
  assert.strictEqual(store.list().length, 0, 'invisible côté interface');
  assert.strictEqual(store.get(compte.id), null);
  const bruts = JSON.parse(storage.getItem(ACCOUNTS_KEY));
  assert.strictEqual(bruts.length, 1, 'l\u2019élément mort reste pour propager la trace');
  assert.ok(!Sync2.estVivant(bruts[0]));
  assert.ok(bruts[0].t > bruts[0].h.issuer, 'la trace est plus récente que les champs');
});

test('mode v2 : une modification postérieure à la trace fait revivre l\u2019élément', () => {
  const temps = tempsFactice();
  const storage = stockageMemoire();
  const store = createStore(storage, temps);
  const compte = store.add({ issuer: 'GitHub', secret: 'JBSWY3DPEHPK3PXP' });
  store.remove(compte.id);
  store.update(compte.id, { tag: 'revécu' });
  assert.strictEqual(store.list().length, 1, 'l\u2019élément vit de nouveau');
  const brut = JSON.parse(storage.getItem(ACCOUNTS_KEY))[0];
  assert.ok(Sync2.estVivant(brut));
  assert.strictEqual(brut.tag, 'revécu');
});

test('mode v2 : logins tamponnés, passwordChangedAt suit le tampon du mot de passe', () => {
  const temps = tempsFactice();
  const storage = stockageMemoire();
  const store = createStore(storage, temps);
  const login = store.addLogin({ origin: 'https://exemple.fr', username: 'moi', password: 'mot-de-passe' });
  const brut = JSON.parse(storage.getItem(LOGINS_KEY))[0];
  assert.strictEqual(brut.h.password, brut.h.origin);
  assert.strictEqual(brut.passwordChangedAt, Sync2.isoDepuisTampon(brut.h.password));
  store.updateLogin(login.id, { password: 'autre' });
  const après = JSON.parse(storage.getItem(LOGINS_KEY))[0];
  assert.ok(après.h.password > brut.h.password);
  assert.strictEqual(après.passwordChangedAt, Sync2.isoDepuisTampon(après.h.password));
});

test('mode v2 : le vidage d\u2019historique pose un tampon dans le marqueur', () => {
  const temps = tempsFactice();
  const storage = stockageMemoire();
  const store = createStore(storage, temps);
  store.clearHistory();
  const m = JSON.parse(storage.getItem(SYNC_KEY));
  assert.ok(typeof m.historiqueVideLe === 'string' && m.historiqueVideLe.length > 0);
  assert.ok(m.historiqueVideLe > Sync2.encoderTampon(T0, 0, 'pc'));
});

test('mode v2 : les réglages portent leur tampon, une modification retamponne', () => {
  const temps = tempsFactice();
  const storage = stockageMemoire();
  const store = createStore(storage, temps);
  store.setSetting('policy', { minLength: 12 });
  const avant = JSON.parse(storage.getItem(SETTINGS_KEY)).policy;
  assert.ok(typeof avant.h === 'string');
  store.setSetting('policy', { minLength: 16 });
  const après = JSON.parse(storage.getItem(SETTINGS_KEY)).policy;
  assert.ok(après.h > avant.h);
  assert.strictEqual(après.value.minLength, 16);
});

test('mode v2 : remplacer une passkey de même compte trace l\u2019ancienne', () => {
  const temps = tempsFactice();
  const storage = stockageMemoire();
  const store = createStore(storage, temps);
  const premiere = store.addPasskey({ credentialId: 'c1', rpId: 'exemple.com', userHandle: 'u1', privateKey: 'k' });
  store.addPasskey({ credentialId: 'c2', rpId: 'exemple.com', userHandle: 'u1', privateKey: 'k2' });
  const bruts = JSON.parse(storage.getItem('mymfa.passkeys.v1'));
  assert.strictEqual(bruts.length, 2);
  const ancienne = bruts.find((p) => p.id === premiere.id);
  assert.ok(!Sync2.estVivant(ancienne), "l'ancienne passkey est tracée, pas enterrée");
  assert.strictEqual(store.passkeys().length, 1);
  assert.strictEqual(store.passkeys()[0].credentialId, 'c2');
});

test('sans temps (mode v1) : aucun tampon, suppression avec enterrement', () => {
  const storage = stockageMemoire();
  const store = createStore(storage);
  const compte = store.add({ issuer: 'GitHub', secret: 'JBSWY3DPEHPK3PXP' });
  const brut = JSON.parse(storage.getItem(ACCOUNTS_KEY))[0];
  assert.ok(!brut.h, 'pas de tampons en mode v1');
  store.remove(compte.id);
  assert.strictEqual(JSON.parse(storage.getItem(ACCOUNTS_KEY)).length, 0);
  const supprimes = JSON.parse(storage.getItem('mymfa.deleted.v1'));
  assert.ok(supprimes.accounts[compte.id], 'enterrement v1');
});
