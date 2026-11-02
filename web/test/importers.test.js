const test = require('node:test');
const assert = require('node:assert/strict');
const Importers = require('../js/importers.js');
const { createStore } = require('../js/store.js');
const { memoryStorage } = require('./helpers.js');

const HEADER = 'type,name,url,autofillUrls,email,username,password,note,totp,createTime,modifyTime,vault';
const PROTON = [
  '﻿' + HEADER,
  'login,GitHub,https://github.com/login,,me@exemple.fr,octocat,"pa,ss""word",,otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub,1700000000,1700000100,Personal',
  'login,Banque,,https://www.banque.fr/espace,client@exemple.fr,,s3cret,"ligne 1\nligne 2",,1700000000,1700000000,Personal',
  'login,Notion,notion.so,,me@exemple.fr,,n0t10n,,JBSW Y3DP EHPK 3PXP,1700000000,1700000000,Work',
  'login,Appli mobile,android://com.exemple.app,,,user,mobile,,,1700000000,1700000000,Personal',
  'login,Vide,https://vide.fr,,,,,,,1700000000,1700000000,Personal',
  'note,Codes Wi-Fi,,,,,,"wifi: x",,1700000000,1700000000,Personal',
  'creditCard,Visa,,,,,,,,1700000000,1700000000,Personal',
  '',
].join('\r\n');

test('parseCsv : guillemets, "" échappés, sauts de ligne dans un champ, CRLF, BOM', () => {
  const rows = Importers.parseCsv('﻿a,b\r\n"x,1","dit ""oui""\nfin"\r\n\r\n');
  assert.deepEqual(rows, [['a', 'b'], ['x,1', 'dit "oui"\nfin']]);
});

test('parse Proton Pass : mots de passe, comptes 2FA, lignes ignorées', () => {
  const result = Importers.parse(PROTON);
  assert.equal(result.format, 'protonpass');
  assert.equal(result.name, 'Proton Pass');
  assert.deepEqual(result.logins, [
    { origin: 'https://github.com', username: 'octocat', password: 'pa,ss"word', title: 'GitHub', note: '' },
    // url vide : l'adresse vient d'autofillUrls ; pas d'identifiant : l'e-mail
    { origin: 'https://www.banque.fr', username: 'client@exemple.fr', password: 's3cret', title: 'Banque', note: 'ligne 1\nligne 2' },
    // sans schéma : https
    { origin: 'https://notion.so', username: 'me@exemple.fr', password: 'n0t10n', title: 'Notion', note: '' },
  ]);
  assert.equal(result.accounts.length, 2);
  assert.deepEqual(
    result.accounts.map(({ issuer, account, secret }) => ({ issuer, account, secret })),
    [
      { issuer: 'GitHub', account: 'octocat', secret: 'JBSWY3DPEHPK3PXP' },
      // clé seule : service = nom de l'élément, compte = identifiant
      { issuer: 'Notion', account: 'me@exemple.fr', secret: 'JBSWY3DPEHPK3PXP' },
    ]
  );
  assert.deepEqual(result.ignored, { noUrl: 1, empty: 1, note: 1, creditCard: 1 });
});

test('parse : en-tête inconnu → unknownImportFormat', () => {
  assert.throws(() => Importers.parse('name,login,secret\nx,y,z'), { code: 'unknownImportFormat' });
  assert.throws(() => Importers.parse(''), { code: 'unknownImportFormat' });
});

test('parse : export Proton plus ancien, sans autofillUrls ni email', () => {
  const csv = 'type,name,url,username,password,note,totp,createTime,modifyTime,vault\nlogin,X,https://x.fr,me,pw,,,1,1,Personal';
  assert.deepEqual(Importers.parse(csv).logins, [{ origin: 'https://x.fr', username: 'me', password: 'pw', title: 'X', note: '' }]);
});

test('apply : ajoute, ignore les doublons, journalise l’import', async () => {
  const store = createStore(memoryStorage());
  const result = Importers.parse(PROTON);
  const first = await Importers.apply(store, result, { logins: true });
  assert.deepEqual(first, { logins: 3, accounts: 2, skipped: 4, needVault: 0 });
  assert.equal(store.logins().length, 3);
  assert.equal(store.logins()[0].source, 'protonpass');
  assert.equal(store.list().length, 2);
  assert.deepEqual(store.history()[0].details, { format: 'protonpass', added: 5, skipped: 4 });
  // Deuxième passe : tout est déjà là.
  const again = await Importers.apply(store, result, { logins: true });
  assert.deepEqual(again, { logins: 0, accounts: 0, skipped: 9, needVault: 0 });
  // Jamais de mot de passe dans l'historique.
  assert.ok(!JSON.stringify(store.history()).includes('s3cret'));
});

test('apply sans coffre chiffré : comptes 2FA importés, mots de passe comptés à part', async () => {
  const store = createStore(memoryStorage());
  const stats = await Importers.apply(store, Importers.parse(PROTON), { logins: false });
  assert.deepEqual(stats, { logins: 0, accounts: 2, skipped: 4, needVault: 3 });
  assert.equal(store.logins().length, 0);
});

const AUTHENTICATOR = JSON.stringify({
  version: 1,
  entries: [
    {
      id: '5f0c9a62-1d7e-4c1a-9a51-3f0f6d2b8e01',
      content: { uri: 'otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60', entry_type: 'Totp', name: 'octocat' },
      note: 'clé principale',
    },
    {
      id: '5f0c9a62-1d7e-4c1a-9a51-3f0f6d2b8e02',
      // Libellé sans compte : le nom de l'entrée le complète.
      content: { uri: 'otpauth://totp/?secret=GEZDGNBVGY3TQOJQ&issuer=Notion', entry_type: 'Totp', name: 'moi@exemple.fr' },
      note: null,
    },
    {
      id: '5f0c9a62-1d7e-4c1a-9a51-3f0f6d2b8e03',
      content: { uri: 'otpauth://totp/Steam:joueur?secret=KRSXG5CTMVRXEZLU&issuer=Steam', entry_type: 'Steam', name: 'joueur' },
      note: null,
    },
    {
      id: '5f0c9a62-1d7e-4c1a-9a51-3f0f6d2b8e04',
      content: { uri: 'otpauth://totp/X?secret=pas-du-base32!', entry_type: 'Totp', name: 'X' },
      note: null,
    },
  ],
});

test('parse Proton Authenticator : comptes 2FA, paramètres de l’URI, note, Steam ignoré', () => {
  const result = Importers.parse('﻿' + AUTHENTICATOR);
  assert.equal(result.format, 'protonauthenticator');
  assert.equal(result.name, 'Proton Authenticator');
  assert.equal(result.passwords, false);
  assert.deepEqual(result.logins, []);
  assert.deepEqual(
    result.accounts.map(({ type, issuer, account, secret, algorithm, digits, period, description }) => ({ type, issuer, account, secret, algorithm, digits, period, description })),
    [
      { type: 'totp', issuer: 'GitHub', account: 'octocat', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA256', digits: 8, period: 60, description: 'clé principale' },
      { type: 'totp', issuer: 'Notion', account: 'moi@exemple.fr', secret: 'GEZDGNBVGY3TQOJQ', algorithm: 'SHA1', digits: 6, period: 30, description: '' },
    ]
  );
  assert.deepEqual(result.ignored, { steam: 1, invalid: 1 });
});

test('Proton Authenticator : import sans coffre, réimport sans doublon', async () => {
  const store = createStore(memoryStorage());
  const result = Importers.parse(AUTHENTICATOR);
  assert.deepEqual(await Importers.apply(store, result), { logins: 0, accounts: 2, skipped: 2, needVault: 0 });
  assert.equal(store.list()[0].description, 'clé principale');
  assert.equal(store.history()[1].details.source, 'protonauthenticator');
  assert.deepEqual(await Importers.apply(store, result), { logins: 0, accounts: 0, skipped: 4, needVault: 0 });
});

test('JSON non reconnu ou illisible', () => {
  assert.throws(() => Importers.parse('{"version":2,"entries":[]}'), { code: 'unknownImportFormat' });
  assert.throws(() => Importers.parse('{"accounts":[]}'), { code: 'unknownImportFormat' });
  assert.throws(() => Importers.parse('{pas du json'), { code: 'invalidImport' });
});

test('apply : progression par lots, jusqu’au total', async () => {
  const store = createStore(memoryStorage());
  const rows = Array.from({ length: 45 }, (_, i) => `login,Site ${i},https://site${i}.fr,,,user,pw${i},,,1,1,Personal`);
  const result = Importers.parse([HEADER, ...rows].join('\n'));
  const seen = [];
  await Importers.apply(store, result, { logins: true, onProgress: (done, total) => seen.push(`${done}/${total}`) });
  assert.deepEqual(seen, ['0/45', '20/45', '40/45', '45/45']);
  assert.equal(store.logins().length, 45);
});
