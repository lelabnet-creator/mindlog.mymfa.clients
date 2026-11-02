const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const Audit = require('../js/audit.js');
const Store = require('../js/store.js');
const Vault = require('../js/vault.js');
const { memoryStorage } = require('./helpers.js');

const DAY = 86400000;
const NOW = Date.parse('2026-11-02T12:00:00Z');
const policy = Audit.normalizePolicy({ minLength: 12, upper: true, digits: true, symbols: false, minStrength: 3, maxAgeDays: 90 });
const login = (id, password, days, extra = {}) => ({ id, origin: `https://${id}.example`, username: 'alice', password, createdAt: new Date(NOW - days * DAY).toISOString(), ...extra });

test('politique : valeurs bornées, défauts pour le reste', () => {
  assert.deepEqual(Audit.normalizePolicy(null), Audit.DEFAULT_POLICY);
  const p = Audit.normalizePolicy({ minLength: 3, minStrength: 9, maxAgeDays: 42, symbols: 'oui' });
  assert.equal(p.minLength, 8);
  assert.equal(p.minStrength, 4);
  assert.equal(p.maxAgeDays, Audit.DEFAULT_POLICY.maxAgeDays);
  assert.equal(p.symbols, Audit.DEFAULT_POLICY.symbols);
});

test('violations : longueur, casse, chiffres, symboles, solidité', () => {
  assert.deepEqual(Audit.violations('abc', policy), ['length', 'upper', 'digits']);
  assert.deepEqual(Audit.violations('Correct-Horse-7-Battery', policy, Vault.passwordStrength), []);
  assert.deepEqual(Audit.violations('Password1234', policy, Vault.passwordStrength), ['strength']);
  assert.ok(Audit.violations('Abcdefghijk1', { ...policy, symbols: true }).includes('symbols'));
});

test('renouvellement : date du changement de mot de passe, sinon de création ; 0 = jamais', () => {
  const old = login('old', 'x', 120);
  assert.equal(Audit.isExpired(old, policy, NOW), true);
  assert.equal(Audit.isExpired({ ...old, passwordChangedAt: new Date(NOW - 10 * DAY).toISOString() }, policy, NOW), false);
  assert.equal(Audit.isExpired(old, { ...policy, maxAgeDays: 0 }, NOW), false);
});

test('analyse : faibles, réutilisés, à renouveler, compromis, note et 2FA', () => {
  const logins = [
    login('github', 'Correct-Horse-7-Battery', 10),
    login('a', 'Mauve-Tiroir-58-Lune', 10),
    login('b', 'Mauve-Tiroir-58-Lune', 200),
    login('weak', 'azerty', 5),
  ];
  const accounts = [{ id: 'x', type: 'totp', issuer: 'GitHub', tag: 'pro' }];
  const a = Audit.analyze({ accounts, logins, passkeys: [], history: [] }, policy, {
    now: NOW,
    strength: Vault.passwordStrength,
    matchesHost: Store.accountMatchesHost,
    hostOf: Store.hostOf,
    breaches: new Map([['github', 0], ['weak', 1234]]),
  });
  assert.deepEqual(a.weak.map((i) => i.login.id), ['weak']);
  assert.deepEqual(a.reused.map((i) => i.login.id), ['a', 'b']);
  assert.deepEqual(a.expired.map((i) => i.login.id), ['b']);
  assert.deepEqual(a.pwned.map((i) => i.login.id), ['weak']);
  assert.equal(a.checked, 2);
  assert.equal(a.score, 25); // seul github est sans problème
  assert.equal(a.counts.with2fa, 1);
  assert.equal(a.counts.tags, 1);
});

test('usage : événements par jour sur 30 jours, répartition par action', () => {
  const history = [
    { action: 'copy', at: new Date(NOW - 1000).toISOString() },
    { action: 'copy', at: new Date(NOW - 2 * DAY).toISOString() },
    { action: 'create', at: new Date(NOW - 2 * DAY).toISOString() },
    { action: 'create', at: new Date(NOW - 45 * DAY).toISOString() }, // hors fenêtre
  ];
  const u = Audit.usage(history, NOW, 30);
  assert.equal(u.perDay.length, 30);
  assert.equal(u.total, 3);
  assert.equal(u.copies, 2);
  assert.deepEqual(u.byAction, { copy: 2, create: 1 });
  assert.equal(u.perDay[29].count, 1);
  assert.equal(u.perDay[27].count, 2);
});

test('fuites enregistrées : invalidées quand le mot de passe change', () => {
  const l = login('site', 'x', 10);
  const record = Audit.breachRecord(new Map([['site', 3]]), [l], 'now');
  assert.equal(JSON.stringify(record).includes('"x"'), false); // ni mot de passe ni empreinte
  assert.equal(Audit.savedBreaches(record, [l]).get('site'), 3);
  assert.equal(Audit.savedBreaches(record, [{ ...l, passwordChangedAt: new Date(NOW).toISOString() }]).has('site'), false);
});

test('HIBP : seul le préfixe de 5 caractères part, le suffixe est comparé ici', async () => {
  const hash = crypto.createHash('sha1').update('password').digest('hex').toUpperCase();
  let asked = null;
  const fetchImpl = async (url, init) => {
    asked = { url, init };
    return { ok: true, text: async () => `0000000000000000000000000000000000A:0\r\n${hash.slice(5)}:9545824\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:2` };
  };
  assert.equal(await Audit.pwnedCount('password', fetchImpl), 9545824);
  assert.equal(asked.url, Audit.PWNED_RANGE_URL + hash.slice(0, 5));
  assert.equal(asked.url.includes(hash.slice(5)), false);
  assert.equal(asked.init.headers['Add-Padding'], 'true');
  assert.equal(await Audit.pwnedCount('unique-mot-de-passe', fetchImpl), 0);
  await assert.rejects(Audit.pwnedCount('x', async () => ({ ok: false })), /pwnedUnavailable/);
});

test('store : date de changement du mot de passe, distincte des autres modifications', () => {
  const store = Store.createStore(memoryStorage());
  const l = store.addLogin({ url: 'https://exemple.fr', username: 'a', password: 'p1' });
  assert.equal(l.passwordChangedAt, l.createdAt);
  const renamed = store.updateLogin(l.id, { title: 'Exemple' });
  assert.equal(renamed.passwordChangedAt, l.passwordChangedAt);
  const changed = store.updateLogin(l.id, { password: 'p2' });
  assert.equal(changed.passwordChangedAt, changed.updatedAt);
});

test('store : réglages datés, sans écriture inutile', () => {
  const storage = memoryStorage();
  const store = Store.createStore(storage);
  assert.equal(store.setting('policy'), undefined);
  store.setSetting('policy', { minLength: 14 });
  const first = storage.getItem(Store.SETTINGS_KEY);
  store.setSetting('policy', { minLength: 14 });
  assert.equal(storage.getItem(Store.SETTINGS_KEY), first);
  assert.deepEqual(store.setting('policy'), { minLength: 14 });
  assert.equal(store.history().length, 0);
});
