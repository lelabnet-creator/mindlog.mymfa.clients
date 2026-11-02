const test = require('node:test');
const assert = require('node:assert/strict');
const Vault = require('../js/vault.js');

// Itérations réduites pour les tests ; la valeur réelle est vérifiée à part.
const FAST = { iterations: 1000 };
const DATA = { 'mymfa.accounts.v1': '[{"id":"a","secret":"JBSWY3DPEHPK3PXP"}]', 'mymfa.history.v1': '[]' };

test('paramètres par défaut : PBKDF2 1 000 000 itérations, minimum 10 caractères', () => {
  assert.equal(Vault.PBKDF2_ITERATIONS, 1000000);
  assert.equal(Vault.PASSWORD_MIN_LENGTH, 10);
});

test('passwordStrength : entropie, mots courants, suites, répétitions', () => {
  assert.equal(Vault.passwordStrength('').level, 0);
  assert.equal(Vault.passwordStrength('password').level, 1, 'mot courant : plafonné');
  assert.equal(Vault.passwordStrength('motdepasse123').level, 1, 'mot courant + chiffres : plafonné');
  assert.equal(Vault.passwordStrength('aaaaaaaa').level, 1, 'un caractère répété');
  assert.equal(Vault.passwordStrength('azertyuiop').level, 1, 'suite de clavier');
  assert.ok(Vault.passwordStrength('Br3iz-kouign-amann!').level >= 3, 'long et varié');
  assert.ok(Vault.passwordStrength('correct horse battery staple').bits >= 80, 'longue phrase');
  const { level, bits } = Vault.passwordStrength('xK9#mL2v');
  assert.ok(bits > 0 && level >= 2, 'court mais varié : au moins moyen');
});

test('création → déverrouillage par mot de passe → données intactes', async () => {
  const { record } = await Vault.create('correct horse battery', DATA, FAST);
  assert.equal(record.v, 1);
  assert.ok(!JSON.stringify(record).includes('JBSWY3DP'), 'le secret ne doit pas apparaître en clair');
  const dek = await Vault.unlockWithPassword(record, 'correct horse battery');
  assert.deepEqual(await Vault.decryptData(dek, record.data), DATA);
});

test('mauvais mot de passe → erreur wrongPassword', async () => {
  const { record } = await Vault.create('correct horse battery', DATA, FAST);
  await assert.rejects(Vault.unlockWithPassword(record, 'mauvais mot de passe'), { code: 'wrongPassword' });
});

test('mot de passe trop court refusé', async () => {
  await assert.rejects(Vault.create('court', DATA, FAST), { code: 'passwordTooShort' });
  await assert.rejects(Vault.create('neuf.char', DATA, FAST), { code: 'passwordTooShort' }); // 9 caractères, sous le minimum
  const { record } = await Vault.create('dix-caractères', DATA, FAST); // 14 : accepté
  assert.equal(record.v, 1);
});

test('changement de mot de passe : ancien refusé, nouveau accepté, même DEK', async () => {
  const { record, dek } = await Vault.create('ancien mot de passe', DATA, FAST);
  const next = await Vault.changePassword(record, dek, 'nouveau mot de passe', FAST);
  await assert.rejects(Vault.unlockWithPassword(next, 'ancien mot de passe'), { code: 'wrongPassword' });
  const dek2 = await Vault.unlockWithPassword(next, 'nouveau mot de passe');
  assert.deepEqual(await Vault.decryptData(dek2, next.data), DATA);
});

test('passkey (sortie PRF simulée) : ajout, déverrouillage, mauvaise sortie, retrait', async () => {
  const { record, dek } = await Vault.create('mot de passe maître', DATA, FAST);
  const prfOutput = Vault.randomBytes(32);
  const withKey = await Vault.addPasskey(record, dek, { id: 'cred-1', name: 'Portable', prfSalt: Vault.randomBytes(32), prfOutput });
  assert.equal(withKey.passkeys.length, 1);
  const dek2 = await Vault.unlockWithPrf(withKey, 'cred-1', prfOutput);
  assert.deepEqual(await Vault.decryptData(dek2, withKey.data), DATA);
  await assert.rejects(Vault.unlockWithPrf(withKey, 'cred-1', Vault.randomBytes(32)), { code: 'passkeyRejected' });
  await assert.rejects(Vault.unlockWithPrf(withKey, 'inconnu', prfOutput), { code: 'unknownPasskey' });
  assert.equal(Vault.removePasskey(withKey, 'cred-1').passkeys.length, 0);
});

test('le passkey reste valide après un changement de mot de passe', async () => {
  const { record, dek } = await Vault.create('mot de passe maître', DATA, FAST);
  const prfOutput = Vault.randomBytes(32);
  let r = await Vault.addPasskey(record, dek, { id: 'cred-1', name: 'Clé', prfSalt: Vault.randomBytes(32), prfOutput });
  r = await Vault.changePassword(r, dek, 'autre mot de passe', FAST);
  const dek2 = await Vault.unlockWithPrf(r, 'cred-1', prfOutput);
  assert.deepEqual(await Vault.decryptData(dek2, r.data), DATA);
});

test('enveloppes non interchangeables (AAD) et altération détectée', async () => {
  const { record, dek } = await Vault.create('mot de passe maître', DATA, FAST);
  const prfOutput = Vault.randomBytes(32);
  const r = await Vault.addPasskey(record, dek, { id: 'cred-1', name: 'Clé', prfSalt: Vault.randomBytes(32), prfOutput });
  // Enveloppe du passkey copiée sous un autre identifiant : refusée.
  const swapped = { ...r, passkeys: [{ ...r.passkeys[0], id: 'cred-2' }] };
  await assert.rejects(Vault.unlockWithPrf(swapped, 'cred-2', prfOutput), { code: 'passkeyRejected' });
  // Données altérées : refusées.
  const ct = Vault.fromB64(r.data.ct);
  ct[0] ^= 1;
  await assert.rejects(Vault.decryptData(dek, { ...r.data, ct: Vault.toB64(ct) }), { code: 'corrupted' });
});

test('parse : enregistrement valide, invalide, absent', async () => {
  const { record } = await Vault.create('mot de passe maître', DATA, FAST);
  assert.deepEqual(Vault.parse(JSON.stringify(record)), record);
  assert.equal(Vault.parse('{pas du json'), null);
  assert.equal(Vault.parse(null), null);
  assert.equal(Vault.parse('{"v":2}'), null);
});

test('base64url aller-retour', () => {
  const bytes = Vault.randomBytes(40);
  assert.deepEqual(Vault.fromB64Url(Vault.toB64Url(bytes)), bytes);
  assert.ok(!/[+/=]/.test(Vault.toB64Url(bytes)));
});
