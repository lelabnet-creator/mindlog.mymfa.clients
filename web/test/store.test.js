const test = require('node:test');
const assert = require('node:assert/strict');
const Store = require('../js/store.js');
const { createStore, normalizeTag, ACCOUNTS_KEY } = Store;
const { memoryStorage } = require('./helpers.js');

const sample = { issuer: ' GitHub ', account: 'me', secret: 'JBSWY3DPEHPK3PXP', tag: ' Pro  Perso ', description: 'clé principale' };

test('add → list, tag normalisé, historique « create »', () => {
  const store = createStore(memoryStorage());
  const a = store.add(sample, 'qr');
  assert.equal(a.issuer, 'GitHub');
  assert.equal(a.tag, 'pro-perso');
  assert.deepEqual(store.list(), [a]);
  const [entry] = store.history();
  assert.equal(entry.action, 'create');
  assert.equal(entry.accountId, a.id);
  assert.deepEqual(entry.details, { source: 'qr' });
});

test('update journalise uniquement les champs modifiés', () => {
  const store = createStore(memoryStorage());
  const a = store.add(sample);
  store.update(a.id, { issuer: 'GitHub', description: 'nouvelle' });
  const [entry] = store.history();
  assert.equal(entry.action, 'update');
  assert.deepEqual(entry.details, { changes: [{ field: 'description', from: 'clé principale', to: 'nouvelle' }] });
  // aucun changement → pas d'entrée
  store.update(a.id, { description: 'nouvelle' });
  assert.equal(store.history().length, 2);
  assert.throws(() => store.update('inconnu', {}), { code: 'accountNotFound' });
});

test('remove, tags, doublons', () => {
  const store = createStore(memoryStorage());
  const a = store.add(sample);
  store.add({ ...sample, account: 'other', tag: 'infra' });
  assert.deepEqual(store.tags(), ['infra', 'pro-perso']);
  assert.ok(store.findDuplicate('JBSWY3DPEHPK3PXP', 'GitHub', 'me'));
  assert.equal(store.findDuplicate('JBSWY3DPEHPK3PXP', 'GitHub', 'nope'), null);
  assert.equal(store.remove(a.id), true);
  assert.equal(store.remove(a.id), false);
  assert.equal(store.list().length, 1);
  assert.equal(store.history()[0].action, 'delete');
});

test('export → import dans un autre stockage, doublons ignorés', () => {
  const src = createStore(memoryStorage());
  src.add(sample);
  src.add({ ...sample, account: 'b' });
  const dump = JSON.parse(JSON.stringify(src.exportAll()));
  const dst = createStore(memoryStorage());
  assert.deepEqual(dst.importAll(dump), { added: 2, skipped: 0 });
  assert.deepEqual(dst.importAll(dump), { added: 0, skipped: 2 });
  assert.throws(() => dst.importAll({}), { code: 'invalidImport' });
});

test('stockage corrompu → liste vide, pas de plantage', () => {
  const storage = memoryStorage();
  storage.setItem(ACCOUNTS_KEY, '{pas du json');
  assert.deepEqual(createStore(storage).list(), []);
});

test('favori : basculé sans entrée d’historique', () => {
  const store = createStore(memoryStorage());
  const a = store.add(sample);
  assert.equal(a.favorite, false);
  const historyBefore = store.history().length;
  assert.equal(store.update(a.id, { favorite: true }).favorite, true);
  assert.equal(store.get(a.id).favorite, true);
  assert.equal(store.history().length, historyBefore);
});

test('normalizeTag', () => {
  assert.equal(normalizeTag('  Mon   Tag '), 'mon-tag');
  assert.equal(normalizeTag(undefined), '');
});

test('mots de passe : ajout par adresse (origine seule), mise à jour, jamais de mot de passe dans l’historique', () => {
  const store = Store.createStore(memoryStorage());
  const login = store.addLogin({ url: 'https://exemple.fr/connexion?x=1', username: ' alice ', password: 's3cret' });
  assert.equal(login.origin, 'https://exemple.fr');
  assert.equal(login.username, 'alice');
  assert.equal(store.findLogin('https://exemple.fr', 'alice').id, login.id);
  store.updateLogin(login.id, { password: 'n0uveau' });
  assert.equal(store.logins()[0].password, 'n0uveau');
  assert.ok(!JSON.stringify(store.history()).includes('s3cret'));
  assert.ok(!JSON.stringify(store.history()).includes('n0uveau'));
  assert.deepEqual(store.history()[0].details, { kind: 'login', fields: ['password'] });
  assert.throws(() => store.addLogin({ url: 'pas une adresse', password: 'x' }), { code: 'invalidUrl' });
  assert.throws(() => store.addLogin({ url: 'https://a.fr', password: '' }), { code: 'passwordEmpty' });
  assert.ok(store.removeLogin(login.id));
  assert.ok(store.tombstones().accounts[login.id]);
});

test('passkeys : une seule par compte du site (la nouvelle remplace l’ancienne)', () => {
  const store = Store.createStore(memoryStorage());
  const first = store.addPasskey({ credentialId: 'a', rpId: 'exemple.fr', userHandle: 'u1', userName: 'alice', privateKey: 'k' });
  store.addPasskey({ credentialId: 'b', rpId: 'exemple.fr', userHandle: 'u2', userName: 'bob', privateKey: 'k' });
  store.addPasskey({ credentialId: 'c', rpId: 'exemple.fr', userHandle: 'u1', userName: 'alice', privateKey: 'k' });
  assert.deepEqual(store.passkeys().map((p) => p.credentialId), ['b', 'c']);
  assert.ok(store.tombstones().accounts[first.id]);
});

test('site d’un hôte : sous-domaines regroupés, suffixes publics à plusieurs niveaux jamais confondus', () => {
  assert.equal(Store.siteOf('accounts.google.com'), 'google.com');
  assert.equal(Store.siteOf('www.notion.so'), 'notion.so');
  assert.equal(Store.siteOf('login.bbc.co.uk'), 'bbc.co.uk');
  assert.equal(Store.siteOf('impots.gouv.fr'), 'impots.gouv.fr');
  assert.notEqual(Store.siteOf('impots.gouv.fr'), Store.siteOf('ameli.gouv.fr'));
  assert.notEqual(Store.siteOf('alice.github.io'), Store.siteOf('bob.github.io'));
  assert.equal(Store.siteOf('bucket.s3.amazonaws.com'), 'bucket.s3.amazonaws.com');
  assert.equal(Store.siteOf('localhost'), 'localhost');
  assert.equal(Store.siteOf('192.168.1.10'), '192.168.1.10');
  // Développement : même découpage qu'en production.
  assert.equal(Store.siteOf('idp.mindlog.today.localhost'), 'mindlog.today.localhost');
  assert.equal(Store.siteOf('app.localhost'), 'app.localhost');
});

test('compte 2FA d’un site : par libellé de l’hôte', () => {
  assert.ok(Store.accountMatchesHost({ issuer: 'GitHub', account: 'alice' }, 'github.com'));
  assert.ok(Store.accountMatchesHost({ issuer: 'Google', account: 'a@gmail.com' }, 'accounts.google.com'));
  assert.ok(!Store.accountMatchesHost({ issuer: 'GitHub', account: 'alice' }, 'gitlab.com'));
  assert.ok(Store.accountMatchesHost({ issuer: 'OVH', account: 'ab1234-ovh' }, 'www.ovhcloud.com'));
  assert.ok(Store.accountMatchesHost({ issuer: 'Google Workspace', account: 'moi' }, 'accounts.google.com'));
  assert.ok(Store.accountMatchesHost({ issuer: 'ownCloud', account: 'jacques' }, 'owncloud.jacques.fr'));
});

test('accountMatchesHost : ni l’identifiant ni la description ne rattachent un compte à un site', () => {
  // Régression : tous les comptes « jacques@… » rattachés au site owncloud.jacques.fr.
  assert.ok(!Store.accountMatchesHost({ issuer: 'Proton', account: 'jacques@hullu.fr' }, 'owncloud.jacques.fr'));
  assert.ok(!Store.accountMatchesHost({ issuer: 'GitHub', account: 'jacques@hullu.fr' }, 'hullu.fr'));
  assert.ok(!Store.accountMatchesHost({ issuer: 'Banque', account: 'moi', description: 'aussi pour github' }, 'github.com'));
  // Morceaux génériques de l'adresse : pas un service.
  assert.ok(!Store.accountMatchesHost({ issuer: 'Gmail', account: 'moi' }, 'mail.exemple.fr'));
  assert.ok(!Store.accountMatchesHost({ issuer: 'Nextcloud', account: 'moi' }, 'cloud.exemple.fr'));
  // Sans service : aucun rattachement automatique.
  assert.ok(!Store.accountMatchesHost({ issuer: '', account: 'github' }, 'github.com'));
});

test('accountMatchesHost : un service nommé par une adresse ne vaut que pour cette adresse', () => {
  // Régression : le code de idp.mindlog.today proposé sur orp.mindlog.today (« mindlog », « today »
  // de l'adresse étaient contenus dans le nom du service).
  const idp = { issuer: 'idp.mindlog.today', account: 'jacques' };
  assert.ok(Store.accountMatchesHost(idp, 'idp.mindlog.today'));
  assert.ok(Store.accountMatchesHost(idp, 'idp.mindlog.today.localhost'));
  assert.ok(!Store.accountMatchesHost(idp, 'orp.mindlog.today'));
  assert.ok(!Store.accountMatchesHost(idp, 'orp.mindlog.today.localhost'));
  assert.ok(!Store.accountMatchesHost(idp, 'mindlog.today'));
  assert.ok(!Store.accountMatchesHost(idp, 'today.com'));
  // Domaine parent : vaut pour ses sous-domaines.
  assert.ok(Store.accountMatchesHost({ issuer: 'Booking.com', account: 'moi' }, 'account.booking.com'));
  assert.ok(Store.accountMatchesHost({ issuer: 'https://github.com/', account: 'moi' }, 'gist.github.com'));
  // Un libellé de l'adresse contenu dans le service ne suffit pas.
  assert.ok(!Store.accountMatchesHost({ issuer: 'MindlogToday', account: 'moi' }, 'today.fr'));
  assert.ok(!Store.accountMatchesHost({ issuer: 'Ubisoft', account: 'moi' }, 'soft.fr'));
});

test('clés de rattachement : comparaison exacte, reprise par l’index du coffre verrouillé', () => {
  assert.deepEqual(Store.accountKeys({ issuer: 'idp.mindlog.today' }), ['host:idp.mindlog.today']);
  assert.deepEqual(Store.accountKeys({ issuer: 'Google Workspace', account: 'jacques', description: 'perso' }), ['word:google', 'word:workspace', 'word:googleworkspace']);
  const keys = Store.hostKeys('orp.mindlog.today.localhost');
  assert.ok(keys.includes('host:orp.mindlog.today') && keys.includes('host:mindlog.today'));
  assert.ok(!keys.includes('host:idp.mindlog.today'));
  assert.ok(Store.hostKeys('www.ovhcloud.com').includes('word:ovh'));
});

test('updateLogin : favori sans entrée d’historique, champs modifiés journalisés', () => {
  const store = createStore(memoryStorage());
  const login = store.addLogin({ url: 'https://exemple.fr/connexion', username: 'moi', password: 'secret' });
  const before = store.history().length;
  const fav = store.updateLogin(login.id, { favorite: true });
  assert.equal(fav.favorite, true);
  assert.equal(store.history().length, before, 'favori : pas d’historique');
  const edited = store.updateLogin(login.id, { username: 'autre', password: 'nouveau', favorite: true });
  assert.equal(edited.username, 'autre');
  assert.deepEqual(store.history()[0].details, { kind: 'login', fields: ['username', 'password'] });
  assert.ok(!JSON.stringify(store.history()).includes('nouveau'));
});

test('touchAccount / touchPasskey : date de dernier usage, sans historique', () => {
  const store = createStore(memoryStorage());
  const account = store.add(sample);
  const passkey = store.addPasskey({ credentialId: 'c', rpId: 'exemple.fr', userHandle: 'u', privateKey: {} });
  const before = store.history().length;
  store.touchAccount(account.id);
  store.touchPasskey(passkey.id);
  assert.ok(store.get(account.id).usedAt);
  assert.ok(store.passkeys()[0].usedAt);
  assert.equal(store.history().length, before);
});

test('mot de passe : tag normalisé, modifiable', () => {
  const store = createStore(memoryStorage());
  const login = store.addLogin({ url: 'https://exemple.fr', username: 'moi', password: 'secret', tag: ' Pro  Perso ' });
  assert.equal(login.tag, 'pro-perso');
  store.add({ ...sample, tag: 'banque' });
  assert.deepEqual(store.tags(), ['banque'], 'tags() : ceux des comptes 2FA (filtres de l’accueil)');
  const next = store.updateLogin(login.id, { tag: 'Travail' });
  assert.equal(next.tag, 'travail');
  assert.deepEqual(store.history()[0].details, { kind: 'login', fields: ['tag'] });
});
