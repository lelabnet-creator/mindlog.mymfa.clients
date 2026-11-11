/*
 * Sens inverse de l'interopérabilité : le test Rust tests/interop_out.rs écrit
 * un coffre créé par mymfa-core (crates/mymfa-core/tests/fixtures/vault-rust.json) ;
 * ce script vérifie que web/js/vault.js l'ouvre — mot de passe ET passkey — et
 * retrouve les données. Un coffre écrit par l'Android doit s'ouvrir sur le web.
 *
 *   node scripts/interop-check.mjs     (après `cargo test --test interop_out`)
 */
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const Vault = require(join('..', '..', 'web', 'js', 'vault.js'));
const Sync2 = require(join('..', '..', 'web', 'js', 'sync2.js'));

const fixture = JSON.parse(
  readFileSync(join(here, '..', 'crates', 'mymfa-core', 'tests', 'fixtures', 'vault-rust.json'), 'utf8'),
);

function fail(message) {
  console.error(`✗ interop : ${message}`);
  process.exit(1);
}

// 1. Déverrouillage par mot de passe et données intactes.
const dek = await Vault.unlockWithPassword(fixture.record, fixture.password).catch((error) => fail(error.code));
const data = await Vault.decryptData(dek, fixture.record.data).catch((error) => fail(error.code));
for (const [key, expected] of Object.entries(fixture.data)) {
  if (data[key] !== expected) fail(`donnée « ${key} » différente :\n  rust : ${data[key]}\n  web  : ${expected}`);
}

// 2. Structure de l'enregistrement conforme au format du web.
if (fixture.record.v !== 1) fail('v ≠ 1');
if (fixture.record.password.kdf !== 'PBKDF2-SHA256') fail('kdf inattendu');
if (fixture.record.password.iterations !== fixture.iterations) fail('iterations inattendues');

// 3. Passkey : sortie PRF fixe → déverrouillage de la même DEK.
if (fixture.record.passkeys?.length) {
  const prfOutput = Buffer.from(fixture.prfOutput, 'base64');
  const dek2 = await Vault.unlockWithPrf(fixture.record, 'cred-rust', prfOutput).catch((error) => fail(error.code));
  await Vault.decryptData(dek2, fixture.record.data).catch((error) => fail(error.code));
}

// 4. Changement de mot de passe par le web : l'ancien doit être refusé (DEK intacte).
const changed = await Vault.changePassword(fixture.record, dek, 'nouveau mot de passe web', { iterations: fixture.iterations });
await Vault.unlockWithPassword(changed, 'nouveau mot de passe web').catch((error) => fail(`nouveau mot de passe refusé : ${error.code}`));

console.log('✓ interop : le coffre écrit par Rust s’ouvre côté web (mot de passe, passkey, re-chiffrement)');

/* ───── Synchro v2 : les fusions calculées par sync2.rs (sync2-rust.json,
 * écrit par tests/sync2_interop.rs) sont rejouées par web/js/sync2.js —
 * mêmes résultats (JSON parsé), mêmes a_envoyer, mêmes genres de rapport. */

/** Égalité JSON profonde (l'ordre des clés n'engage pas). */
function jsonEgal(a, b) {
  if (a === b) return true;
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  if (Array.isArray(a)) return a.length === b.length && a.every((x, i) => jsonEgal(x, b[i]));
  const clesA = Object.keys(a);
  const clesB = Object.keys(b);
  if (clesA.length !== clesB.length) return false;
  return clesA.every((cle) => cle in b && jsonEgal(a[cle], b[cle]));
}

const sync2 = JSON.parse(
  readFileSync(join(here, '..', 'crates', 'mymfa-core', 'tests', 'fixtures', 'sync2-rust.json'), 'utf8'),
);
if (!sync2.cases?.length) fail('sync2-rust.json sans cas');
for (const cas of sync2.cases) {
  const etat = {
    appareil: cas.etat.appareil,
    horloge: new Sync2.Horloge(cas.etat.horloge.l),
    repere: cas.etat.repere ?? '',
  };
  etat.horloge.c = cas.etat.horloge.c;
  const { donnees, rapport } = Sync2.fusion(cas.locale, cas.distante, etat, cas.maintenant);
  const cles = new Set([...Object.keys(cas.attendu), ...Object.keys(donnees)]);
  for (const cle of cles) {
    let a, b;
    try {
      a = JSON.parse(cas.attendu[cle] ?? 'null');
      b = JSON.parse(donnees[cle] ?? 'null');
    } catch (error) {
      fail(`${cas.name} : clé « ${cle} » illisible (${error.message})`);
    }
    if (!jsonEgal(a, b)) fail(`${cas.name} : clé « ${cle} » différente de la fusion Rust`);
  }
  if (rapport.aEnvoyer !== cas.aEnvoyer) fail(`${cas.name} : aEnvoyer différent`);
  const genres = rapport.entrees.map((e) => e.genre).sort();
  const genresAttendus = [...cas.genres].sort();
  if (JSON.stringify(genres) !== JSON.stringify(genresAttendus)) {
    fail(`${cas.name} : genres de rapport différents (rust : [${genresAttendus}], web : [${genres}])`);
  }
}
console.log(`✓ interop : les ${sync2.cases.length} fusions v2 de Rust sont reproduites par web/js/sync2.js`);
