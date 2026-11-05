/*
 * Produit les fixtures d'interopérabilité : des coffres réellement chiffrés par
 * web/js/vault.js et des fusions attendues calculées par web/js/sync.js. Les
 * tests Rust (crates/mymfa-core/tests/) les rejouent : un coffre écrit par le
 * web doit s'ouvrir en Rust, et la fusion Rust doit rendre exactement ce que
 * rend la fusion web.
 *
 *   node scripts/make-fixtures.mjs     (depuis android/, itérations PBKDF2 réduites)
 */
import { createRequire } from 'node:module';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const Vault = require(join('..', '..', 'web', 'js', 'vault.js'));
const Sync = require(join('..', '..', 'web', 'js', 'sync.js'));
const outDir = join(here, '..', 'crates', 'mymfa-core', 'tests', 'fixtures');

const FAST = { iterations: 1000 };
const DATA = {
  'mymfa.accounts.v1': JSON.stringify([
    { id: 'a1', type: 'totp', issuer: 'GitHub', account: 'moi@example.net', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30, counter: 0, tag: 'travail', description: '', favorite: true, createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z' },
  ]),
  'mymfa.history.v1': '[]',
  'mymfa.deleted.v1': '{"accounts":{},"historyClearedAt":null}',
  'mymfa.settings.v1': JSON.stringify({ policy: { value: { minLength: 12 }, at: '2026-02-01T00:00:00.000Z' } }),
};

const prfOutput = Buffer.alloc(32, 7);
const prfSalt = Buffer.alloc(32, 3);

async function vaultFixtures() {
  const simple = await Vault.create('correct horse battery', DATA, FAST);
  // Mot de passe avec accent décomposé (NFD) : la dérivation doit normaliser en NFC.
  const decomposed = 'mot de passe accentue\u0301 suffisamment long';
  const nfc = await Vault.create(decomposed, DATA, FAST);
  const withPasskey = await Vault.addPasskey(simple.record, simple.dek, {
    id: 'cred-fixture', name: 'Clé de test', prfSalt, prfOutput,
  });
  return {
    iterations: FAST.iterations,
    data: DATA,
    decomposedPassword: decomposed,
    prfOutput: prfOutput.toString('base64'),
    records: {
      simple: simple.record,
      decomposed: nfc.record,
      withPasskey,
    },
  };
}

function account(id, secret, issuer, createdAt, updatedAt, extra = {}) {
  return { id, type: 'totp', issuer, account: 'moi@example.net', secret, algorithm: 'SHA1', digits: 6, period: 30, counter: 0, tag: '', description: '', favorite: false, createdAt, updatedAt, ...extra };
}

function history(id, at) {
  return { id, at, action: 'create', accountId: id, label: 'Test — moi@example.net', tag: '', details: { source: 'qr' } };
}

function syncCases() {
  const NOW = '2026-11-05T12:00:00.000Z';
  const wrap = (items) => JSON.stringify(items);
  const cases = [
    {
      name: 'union-simple',
      left: { 'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-01-01')]) },
      right: { 'mymfa.accounts.v1': wrap([account('a2', 'JBSWY3DPEHPK3PXPZ', 'OVH', '2026-02-01', '2026-02-01')]) },
    },
    {
      name: 'conflit-updatedAt',
      left: { 'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-03-01', { tag: 'vieux-quete' })]) },
      right: { 'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-02-01')]) },
    },
    {
      name: 'egalite-updatedAt-premier-vu-gagne',
      left: { 'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-02-01', { description: 'côté gauche' })]) },
      right: { 'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-02-01', { description: 'côté droit' })]) },
    },
    {
      name: 'tombstone-le-cote-droit-ne-ranimme-pas',
      left: {
        'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-01-01')]),
        'mymfa.deleted.v1': JSON.stringify({ accounts: { a1: '2026-06-01T00:00:00.000Z' }, historyClearedAt: null }),
      },
      right: { 'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-07-01')]) },
    },
    {
      name: 'doublon-par-identite',
      left: { 'mymfa.accounts.v1': wrap([account('recent', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-05-01', '2026-05-01')]) },
      right: { 'mymfa.accounts.v1': wrap([account('ancien', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-01-01')]) },
    },
    {
      name: 'usedAt-fusionne-sans-compter',
      left: { 'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-01-01', { usedAt: '2026-06-01T00:00:00.000Z' })]) },
      right: { 'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-02-01', { usedAt: '2026-03-01T00:00:00.000Z' })]) },
    },
    {
      name: 'historique-vidage-et-plafond',
      left: {
        'mymfa.history.v1': wrap(
          Array.from({ length: 20 }, (_, i) => history(`h${i}`, `2026-10-${String(i + 1).padStart(2, '0')}T00:00:00.000Z`)),
        ),
      },
      right: {
        'mymfa.history.v1': wrap([history('gauche-seulement', '2026-09-01T00:00:00.000Z')]),
        'mymfa.deleted.v1': JSON.stringify({ accounts: {}, historyClearedAt: '2026-10-05T00:00:00.000Z' }),
      },
    },
    {
      name: 'reglages-le-plus-recent-gagne',
      left: { 'mymfa.settings.v1': JSON.stringify({ policy: { value: { minLength: 12 }, at: '2026-01-01T00:00:00.000Z' }, prefs: { value: { theme: 'dark' }, at: '2026-05-01T00:00:00.000Z' } }) },
      right: { 'mymfa.settings.v1': JSON.stringify({ policy: { value: { minLength: 16 }, at: '2026-06-01T00:00:00.000Z' }, prefs: { value: { theme: 'light' }, at: '2026-03-01T00:00:00.000Z' } }) },
    },
    {
      name: 'collections-absentes-des-deux-cotes',
      left: { 'mymfa.accounts.v1': '[]' },
      right: {},
    },
    {
      name: 'logins-et-passkeys-fusionnes',
      left: {
        'mymfa.logins.v1': JSON.stringify([
          { id: 'l1', origin: 'https://github.com', username: 'moi', password: 'x', title: '', note: '', tag: '', source: '', createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', passwordChangedAt: '2026-01-01T00:00:00.000Z' },
        ]),
      },
      right: {
        'mymfa.passkeys.v1': JSON.stringify([
          { id: 'p1', credentialId: 'c1', rpId: 'example.com', rpName: 'Example', origin: 'https://example.com', userHandle: 'u1', userName: 'moi', userDisplayName: 'Moi', algorithm: -7, privateKey: 'k', createdAt: '2026-02-01T00:00:00.000Z', updatedAt: '2026-02-01T00:00:00.000Z' },
        ]),
      },
    },
  ];
  return {
    now: NOW,
    cases: cases.map((c) => ({ ...c, expected: Sync.merge(c.left, c.right, NOW) })),
  };
}

mkdirSync(outDir, { recursive: true });
const vault = await vaultFixtures();
writeFileSync(join(outDir, 'vault-web.json'), `${JSON.stringify(vault, null, 2)}\n`);
const sync = syncCases();
writeFileSync(join(outDir, 'sync-web.json'), `${JSON.stringify(sync, null, 2)}\n`);
console.log(`fixtures : vault-web.json (3 coffres), sync-web.json (${sync.cases.length} cas de fusion)`);
