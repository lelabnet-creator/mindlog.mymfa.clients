// Authentificateur WebAuthn logiciel : une passkey créée puis utilisée doit être vérifiable par un site,
// avec les contrôles qu'un serveur WebAuthn applique (rpIdHash, drapeaux, challenge, origine, signature).
const test = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
const Authn = require('../js/webauthn.js');

const ORIGIN = 'https://login.exemple.fr';
const challenge = () => Authn.toB64Url(webcrypto.getRandomValues(new Uint8Array(32)));
const sha256 = async (bytes) => new Uint8Array(await webcrypto.subtle.digest('SHA-256', bytes));
const utf8 = (text) => new TextEncoder().encode(text);

function createOptions(extra = {}) {
  return {
    origin: ORIGIN,
    rpId: 'exemple.fr',
    rpName: 'Exemple',
    user: { id: Authn.toB64Url(utf8('user-42')), name: 'alice@exemple.fr', displayName: 'Alice' },
    challenge: challenge(),
    pubKeyCredParams: [{ alg: -8 }, { alg: -7 }],
    ...extra,
  };
}

/** Ce que fait un serveur à l'enregistrement : clé publique extraite de authData. */
async function verifyRegistration(response, options) {
  const data = JSON.parse(new TextDecoder().decode(Authn.fromB64Url(response.clientDataJSON)));
  assert.deepEqual(data, { type: 'webauthn.create', challenge: options.challenge, origin: options.origin, crossOrigin: false });
  const att = Authn.cborDecode(Authn.fromB64Url(response.attestationObject)).value;
  assert.equal(att.get('fmt'), 'none');
  const authData = att.get('authData');
  assert.deepEqual(authData.slice(0, 32), await sha256(utf8(options.rpId)));
  const flags = authData[32];
  assert.equal(flags & 0x45, 0x45, 'UP, UV et AT');
  const idLength = (authData[53] << 8) | authData[54];
  const credentialId = authData.slice(55, 55 + idLength);
  assert.equal(Authn.toB64Url(credentialId), response.id);
  const cose = Authn.cborDecode(authData, 55 + idLength).value;
  assert.equal(cose.get(3), -7);
  const point = new Uint8Array([4, ...cose.get(-2), ...cose.get(-3)]);
  return webcrypto.subtle.importKey('raw', point, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
}

test('création : attestation « none » vérifiable, clé publique cohérente', async () => {
  const options = createOptions();
  const { passkey, response } = await Authn.create(options);
  await verifyRegistration(response, options);
  assert.equal(passkey.rpId, 'exemple.fr');
  assert.equal(passkey.credentialId, response.id);
  assert.equal(passkey.userName, 'alice@exemple.fr');
  assert.ok(passkey.privateKey.length > 100);
});

test('authentification : signature DER valide sur authData ‖ SHA-256(clientDataJSON)', async () => {
  const options = createOptions();
  const { passkey, response } = await Authn.create(options);
  const publicKey = await verifyRegistration(response, options);
  const get = { origin: ORIGIN, rpId: 'exemple.fr', challenge: challenge() };
  const assertion = await Authn.get(get, passkey);
  const authData = Authn.fromB64Url(assertion.authenticatorData);
  const clientDataJSON = Authn.fromB64Url(assertion.clientDataJSON);
  assert.equal(JSON.parse(new TextDecoder().decode(clientDataJSON)).type, 'webauthn.get');
  assert.equal(JSON.parse(new TextDecoder().decode(clientDataJSON)).challenge, get.challenge);
  assert.equal(authData[32] & 0x05, 0x05, 'UP et UV');
  const signed = new Uint8Array([...authData, ...(await sha256(clientDataJSON))]);
  const signature = Authn.derToRaw(Authn.fromB64Url(assertion.signature));
  assert.ok(await webcrypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, signature, signed));
  assert.equal(assertion.userHandle, options.user.id);
});

test('DER : r et s à bit de poids fort ou zéros en tête, aller-retour exact', () => {
  for (const raw of [new Uint8Array(64).fill(0x80), new Uint8Array([0, 0, ...new Uint8Array(30).fill(7), 0, ...new Uint8Array(31).fill(0xff)])]) {
    assert.deepEqual(Authn.derToRaw(Authn.rawToDer(raw)), raw);
  }
});

test('rpId : domaine égal ou parent seulement, https ou localhost', () => {
  assert.equal(Authn.checkRpId('https://login.exemple.fr', undefined), 'login.exemple.fr');
  assert.equal(Authn.checkRpId('https://login.exemple.fr', 'exemple.fr'), 'exemple.fr');
  assert.equal(Authn.checkRpId('http://localhost:4173', 'localhost'), 'localhost');
  assert.throws(() => Authn.checkRpId('https://login.exemple.fr', 'autre.fr'), { name: 'SecurityError' });
  assert.throws(() => Authn.checkRpId('https://login.exemple.fr', 'fr'), { name: 'SecurityError' });
  assert.throws(() => Authn.checkRpId('http://exemple.fr', 'exemple.fr'), { name: 'SecurityError' });
  assert.throws(() => Authn.checkRpId('https://exemple.fr.evil.com', 'exemple.fr'), { name: 'SecurityError' });
});

test('refus : algorithme absent, passkey exclue, passkey d’un autre site', async () => {
  await assert.rejects(Authn.create(createOptions({ pubKeyCredParams: [{ alg: -257 }] })), { name: 'NotSupportedError' });
  const { passkey } = await Authn.create(createOptions());
  await assert.rejects(Authn.create(createOptions({ excludeCredentials: [passkey.credentialId] }), [passkey.credentialId]), { name: 'InvalidStateError' });
  await assert.rejects(Authn.get({ origin: 'https://autre.fr', rpId: 'autre.fr', challenge: challenge() }, passkey), { name: 'NotAllowedError' });
});

test('usable : filtre par site et par allowCredentials', () => {
  const list = [{ rpId: 'a.fr', credentialId: 'x' }, { rpId: 'a.fr', credentialId: 'y' }, { rpId: 'b.fr', credentialId: 'z' }];
  assert.deepEqual(Authn.usable(list, 'a.fr', []).map((p) => p.credentialId), ['x', 'y']);
  assert.deepEqual(Authn.usable(list, 'a.fr', ['y', 'z']).map((p) => p.credentialId), ['y']);
});
